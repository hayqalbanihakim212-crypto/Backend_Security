use std::{env, net::SocketAddr, process, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

use argon2::{
    password_hash::{rand_core::OsRng as PhOsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rand::{rngs::OsRng, Rng, RngCore};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use ed25519_dalek::{SigningKey, Signer};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

const MAX_PASSWORD_BYTES: usize = 256;
const MAX_CHALLENGE_LEN: usize = 32;
const MAX_TAPS: u32 = 10_000;

struct AppState {
    pepper: Vec<u8>,
    api_key: Vec<u8>,
    params: Params,
    hash_slots: Semaphore,
    signing_key: SigningKey,
}

type Shared = Arc<AppState>;

struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

fn bad(code: &'static str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, code)
}
fn internal() -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal")
}

fn argon(st: &AppState) -> Result<Argon2<'_>, ApiError> {
    Argon2::new_with_secret(&st.pepper, Algorithm::Argon2id, Version::V0x13, st.params.clone())
        .map_err(|_| internal())
}

fn env_required(name: &str, min_len: usize) -> String {
    match env::var(name) {
        Ok(v) if v.len() >= min_len => v,
        _ => {
            eprintln!("FATAL: env {name} wajib diisi (minimal {min_len} karakter)");
            process::exit(1);
        }
    }
}

fn env_num<T: std::str::FromStr>(name: &str, default: T) -> T {
    env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

async fn require_key(State(st): State<Shared>, req: Request, next: Next) -> Result<Response, ApiError> {
    let given = req
        .headers()
        .get("x-core-key")
        .map(|v| v.as_bytes())
        .unwrap_or_default();
    if bool::from(given.ct_eq(st.api_key.as_slice())) {
        Ok(next.run(req).await)
    } else {
        Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))
    }
}

#[derive(Deserialize)]
struct HashReq {
    password: String,
}
#[derive(Serialize)]
struct HashRes {
    hash: String,
}

async fn hash_password(State(st): State<Shared>, Json(req): Json<HashReq>) -> Result<Json<HashRes>, ApiError> {
    if req.password.is_empty() || req.password.len() > MAX_PASSWORD_BYTES {
        return Err(bad("password_length"));
    }
    let _permit = st.hash_slots.acquire().await.map_err(|_| internal())?;
    let st2 = st.clone();
    let hash = tokio::task::spawn_blocking(move || -> Result<String, ApiError> {
        let a = argon(&st2)?;
        let salt = SaltString::generate(&mut PhOsRng);
        a.hash_password(req.password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|_| internal())
    })
    .await
    .map_err(|_| internal())??;
    Ok(Json(HashRes { hash }))
}

#[derive(Deserialize)]
struct VerifyReq {
    password: String,
    hash: String,
}
#[derive(Serialize)]
struct VerifyRes {
    valid: bool,
}

async fn verify_password(State(st): State<Shared>, Json(req): Json<VerifyReq>) -> Result<Json<VerifyRes>, ApiError> {
    if req.password.len() > MAX_PASSWORD_BYTES {
        return Ok(Json(VerifyRes { valid: false }));
    }
    let _permit = st.hash_slots.acquire().await.map_err(|_| internal())?;
    let st2 = st.clone();
    let valid = tokio::task::spawn_blocking(move || -> Result<bool, ApiError> {
        let a = argon(&st2)?;
        let parsed = match PasswordHash::new(&req.hash) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };
        Ok(a.verify_password(req.password.as_bytes(), &parsed).is_ok())
    })
    .await
    .map_err(|_| internal())??;
    Ok(Json(VerifyRes { valid }))
}

#[derive(Deserialize)]
struct NewChallengeReq {
    length: usize,
}
#[derive(Serialize)]
struct NewChallengeRes {
    rotations: Vec<u8>,
}

async fn challenge_new(Json(req): Json<NewChallengeReq>) -> Result<Json<NewChallengeRes>, ApiError> {
    if req.length == 0 || req.length > MAX_CHALLENGE_LEN {
        return Err(bad("length"));
    }
    let mut rng = OsRng;
    let mut rotations: Vec<u8> = (0..req.length).map(|_| rng.gen_range(0..4u8)).collect();
    if rotations.iter().all(|r| *r == 0) {
        let i = rng.gen_range(0..req.length);
        rotations[i] = rng.gen_range(1..4u8);
    }
    Ok(Json(NewChallengeRes { rotations }))
}

#[derive(Deserialize)]
struct VerifyChallengeReq {
    initial: Vec<u8>,
    taps: Vec<u32>,
}
#[derive(Serialize)]
struct VerifyChallengeRes {
    ok: bool,
    wrong: Vec<bool>,
}

async fn challenge_verify(Json(req): Json<VerifyChallengeReq>) -> Result<Json<VerifyChallengeRes>, ApiError> {
    let n = req.initial.len();
    if n == 0 || n > MAX_CHALLENGE_LEN || req.taps.len() != n {
        return Err(bad("length"));
    }
    if req.initial.iter().any(|r| *r > 3) || req.taps.iter().any(|t| *t > MAX_TAPS) {
        return Err(bad("range"));
    }
    let wrong: Vec<bool> = req
        .initial
        .iter()
        .zip(req.taps.iter())
        .map(|(i, t)| (*i as u32 + *t) % 4 != 0)
        .collect();
    Ok(Json(VerifyChallengeRes { ok: !wrong.iter().any(|w| *w), wrong }))
}



// Public Ed25519 signing key is pinned by each client's backend. The private seed
// is REQUIRED from the environment and never auto-generated at boot.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PassportReq {
    site_key: String,
    origin: String,
    target_path: String,
    method: String,
    body_sha256: String,
    checks_passed: Vec<String>,
    subject: Option<String>,
    ttl_sec: u64,
}
#[derive(Serialize)]
struct PassportRes {
    passport: String,
    expires_at: u64,
}
#[derive(Serialize)]
struct PublicKeyRes {
    public_key_b64: String,
    alg: &'static str,
}

fn current_time() -> Result<u64, ApiError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| internal())?.as_secs())
}
fn valid_path(path: &str) -> bool {
    path.starts_with('/') && !path.starts_with("//") && path.len() <= 256 &&
    path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_~.-".contains(&b))
}
async fn passport_sign(State(st): State<Shared>, Json(req): Json<PassportReq>) -> Result<Json<PassportRes>, ApiError> {
    if req.site_key.len() < 12 || req.site_key.len() > 100 ||
       req.origin.len() > 256 || req.origin.is_empty() || !req.origin.starts_with("http") ||
       !valid_path(&req.target_path) ||
       !matches!(req.method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") ||
       req.body_sha256.len() != 43 ||
       URL_SAFE_NO_PAD.decode(&req.body_sha256).map_or(true, |v| v.len() != 32) ||
       req.ttl_sec == 0 || req.ttl_sec > 60 || req.checks_passed.len() > 8 ||
       req.checks_passed.iter().any(|c| c.len() > 32 || c.is_empty()) ||
       req.subject.as_deref().is_some_and(|sub| sub.is_empty() || sub.len() > 64) {
        return Err(bad("invalid_passport_claims"));
    }
    let now = current_time()?;
    let exp = now + req.ttl_sec;
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT" });
    let payload = serde_json::json!({
        "iss": "qx-gatekeeper", "aud": req.site_key, "org": req.origin,
        "pth": req.target_path, "mth": req.method, "bsh": req.body_sha256,
        "chk": req.checks_passed, "sub": req.subject,
        "iat": now, "nbf": now, "exp": exp,
        "jti": URL_SAFE_NO_PAD.encode(nonce),
    });
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| internal())?);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).map_err(|_| internal())?);
    let content = format!("{header}.{payload}");
    let signature = st.signing_key.sign(content.as_bytes());
    let passport = format!("{content}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    Ok(Json(PassportRes { passport, expires_at: exp }))
}

async fn passport_public_key(State(st): State<Shared>) -> Json<PublicKeyRes> {
    Json(PublicKeyRes { public_key_b64: URL_SAFE_NO_PAD.encode(st.signing_key.verifying_key().to_bytes()), alg: "EdDSA" })
}

async fn healthz() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() {
    let pepper_text = env_required("QX_PEPPER_B64", 43);
    let pepper = STANDARD.decode(&pepper_text).unwrap_or_else(|_| {
        eprintln!("FATAL: QX_PEPPER_B64 must be standard base64 of 32 random bytes");
        process::exit(1);
    });
    if pepper.len() != 32 {
        eprintln!("FATAL: QX_PEPPER_B64 must decode to 32 bytes");
        process::exit(1);
    }
    let api_key = env_required("QX_CORE_KEY", 32);
    let seed_text = env_required("QX_SIGNING_SEED_B64", 43);
    let seed_bytes = STANDARD.decode(&seed_text).unwrap_or_else(|_| {
        eprintln!("FATAL: QX_SIGNING_SEED_B64 must contain 32 random bytes in standard base64");
        process::exit(1);
    });
    let signing_key = SigningKey::from_bytes(&seed_bytes.try_into().unwrap_or_else(|_| {
        eprintln!("FATAL: invalid Ed25519 signing seed length");
        process::exit(1);
    }));
    let bind: SocketAddr = env::var("QX_CORE_BIND")
        .unwrap_or_else(|_| "127.0.0.1:7001".into())
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("FATAL: QX_CORE_BIND tidak valid");
            process::exit(1);
        });

    if !bind.ip().is_loopback() {
        eprintln!("FATAL: qx-core must bind loopback only");
        process::exit(1);
    }
    let params = Params::new(
        env_num("QX_ARGON_M_KIB", 19_456u32),
        env_num("QX_ARGON_T", 2u32),
        env_num("QX_ARGON_P", 1u32),
        None,
    )
    .unwrap_or_else(|e| {
        eprintln!("FATAL: parameter argon2 tidak valid: {e}");
        process::exit(1);
    });

    let state: Shared = Arc::new(AppState {
        pepper,
        api_key: api_key.into_bytes(),
        params,
        hash_slots: Semaphore::new(env_num("QX_HASH_CONCURRENCY", 4usize).clamp(1, 8)),
        signing_key,
    });

    let protected = Router::new()
        .route("/v1/password/hash", post(hash_password))
        .route("/v1/password/verify", post(verify_password))
        .route("/v1/challenge/new", post(challenge_new))
        .route("/v1/challenge/verify", post(challenge_verify))
        .route("/v1/passport/sign", post(passport_sign))
        .route("/v1/passport/public-key", get(passport_public_key))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_key));

    let app = Router::new()
        .route("/healthz", get(healthz))
        .merge(protected)
        .layer(DefaultBodyLimit::max(4 * 1024))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind).await.unwrap_or_else(|e| {
        eprintln!("FATAL: gagal bind {bind}: {e}");
        process::exit(1);
    });
    println!("qx-core listening on {bind}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .unwrap();
}
