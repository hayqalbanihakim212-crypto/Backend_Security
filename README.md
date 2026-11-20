# qX Security Gatekeeper — backend kosong, multi-tenant, untuk frontend pihak ketiga

**Tujuan:** menyediakan preflight inspection + bot friction + verifikasi kode keamanan yang telah diprovisikan oleh pihak tepercaya, kemudian menerbitkan **Security Passport Ed25519** untuk diverifikasi *server-side* oleh backend milik klien. Tidak ada data pengguna, tenant, kode keamanan, akun demo, atau kunci rahasia dalam distribusi ini.

**Penting:** Menambahkan `<script>` saja **tidak** mengamankan endpoint. Backend klien **wajib** memvalidasi paspor dan tetap menjalankan autentikasi, otorisasi, validasi input, CSRF, dan keamanan bisnis miliknya. qX adalah lapisan tambahan, **bukan** pengganti login ataupun WAF reverse-proxy.

## Struktur sumber

```
qx-backend/
  .env.example              Konfigurasi kosong; isi sendiri di mesin server
  api/src/server.js          HTTP API Express, static SDK, health
  api/src/routes/gate.js     Preflight, challenge, 2FA, provisioning admin
  api/src/tenants.js         Penyimpanan konfigurasi tenant (tanpa seed)
  api/src/users.js           Kode keamanan per tenant (tanpa seed)
  api/data/tenants.json      {"tenants": []}
  api/data/users.json        {"users": []}
  api/test/security.test.mjs Tes isolasi, kontrol admin, passport (core mock)
  core/src/main.rs           Rust Argon2id, challenge, signer Ed25519
  sdk/qx-guard.js            SDK vanilla JS untuk frontend pihak ketiga
  sdk/qx-passport-verifier.js  Middleware Express backend milik klien
```

Folder `target/`, `node_modules/`, `.env`, dan log **tidak dibundel**. Data tenant/pengguna baru ditulis hanya setelah provisioning tepercaya. Jangan menyalin kembali `.env`, file JSON pengguna, atau log dari ZIP lama ke paket kosong ini tanpa audit dan rotasi secret.

## Menjalankan di server

Prasyarat: Node.js >= 20.6, npm, Rust stable/Cargo, HTTPS reverse proxy di depan port API. Layanan inti Rust **hanya** boleh di localhost. Gunakan user non-root dan proteksi file `.env` dengan izin 600.

```bash
cp .env.example .env
chmod 600 .env
# Buat EMPAT nilai terpisah, jangan disimpan di repositori:
openssl rand -base64 48   # QX_CORE_KEY
openssl rand -base64 48   # QX_ADMIN_KEY (nilai berbeda)
openssl rand -base64 32   # QX_PEPPER_B64
openssl rand -base64 32   # QX_SIGNING_SEED_B64 (simpan dan cadangkan dengan aman)
# Masukkan masing-masing output di .env sesuai namanya.

# Terminal 1: Rust, dari direktori qx-backend/
set -a; . ./.env; set +a
cd core && cargo run --locked --release

# Terminal 2: Node, dari direktori qx-backend/
set -a; . ./.env; set +a
cd api && npm ci && npm start
```

Untuk sistem produksi, jangan menjalankan `.env` melalui shell bersama proses yang tidak tepercaya. Gunakan secrets manager atau environment service manager. **Jangan buat ulang** `QX_PEPPER_B64` atau `QX_SIGNING_SEED_B64` setiap boot: pepper diperlukan untuk verifikasi hash, dan signing key yang berubah akan membatalkan kunci publik yang dipin klien. `QX_CORE_KEY` juga harus cocok di Node dan Rust. Hindari forwarding endpoint admin di reverse proxy; port default API `127.0.0.1:4000` dan inti `127.0.0.1:7001`.

`QX_PUBLIC_BASE_URL=https://gate.example.com` (opsional, konfigurasi server) membuat API mengembalikan snippet embeddable. Domain tersebut adalah contoh placeholder, bukan URL aktif.

## 1. Registrasi frontend/tenant (admin server, bukan JavaScript browser)

Jalankan hanya di terminal host backend qX setelah kunci admin terpasang:

```bash
curl -sS http://127.0.0.1:4000/api/gate/tenants/register \
  -H "X-QX-Admin-Key: $QX_ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Website Klien","allowedOrigins":["https://frontend-klien.example"],"modules":{"waf":true,"botChallenge":true,"require2fa":true}}'
```

Hasilnya mengandung `siteKey` unik `pk_live_...` (ini **public identifier**, bukan secret). `allowedOrigins` harus persis origin `https://...`; wildcard dilarang. HTTP hanya didukung untuk `localhost`/loopback selama development. API registrasi membutuhkan admin key **dan** sumber koneksi langsung dari loopback. Tidak ada registrasi tenant anonim.

## 2. Provision kode keamanan user (hanya dari backend tepercaya)

Setelah sistem klien mengautentikasi identitas user melalui jalur miliknya dan memastikan proses pendaftaran kode/identitas sah, operator atau backend klien tepercaya meminta admin qX memprovisikan kode panjang (12–128 karakter). Contoh bentuk permintaan **tanpa kredensial nilai bawaan**:

```http
POST /api/gate/tenants/users/provision
X-QX-Admin-Key: <RAHASIA_ADMIN_SERVER>
Content-Type: application/json

{"siteKey":"<SITE_KEY>","username":"<ID_USER_TERVALIDASI>","securityCode":"<KODE_RAHASIA_USER>"}
```

Gunakan HTTPS/kanal aman server-ke-server, atau panggil dari loopback melalui proses admin. Tidak tersedia pendaftaran mandiri dari browser; user yang belum diprovisikan akan **ditolak** tanpa membuat data baru. Kode disimpan sebagai hash Argon2id + pepper di inti Rust. **Kode statis bukan TOTP/WebAuthn/MFA independen**, sehingga jangan mengiklankannya sebagai autentikasi dua faktor kuat. Ganti dengan TOTP atau WebAuthn tervalidasi jika memerlukan MFA sebenarnya. Jangan menyimpan kode user atau admin key di browser.

## 3. Pasang SDK pada frontend pihak ketiga

Frontend pihak ketiga tidak perlu dipindah atau ditulis ulang. Tambahkan tag skrip dan sesuaikan daftar endpoint pada `data-protect`:

```html
<script src="https://gate.example.com/sdk/qx-guard.js"
        data-site-key="<SITE_KEY_DARI_REGISTRASI>"
        data-protect="/api/login,/api/checkout"
        defer></script>
```

SDK hanya mengintersepsi `fetch()` **same-origin** ke path terpilih; integrasi `XMLHttpRequest`, form HTML biasa, GraphQL, streaming, multipart, dan websocket **belum** otomatis dilindungi. Untuk request yang terproteksi, SDK mengharuskan body JSON (atau kosong) dan membawa paspor ke `X-QX-Passport` pada request asli. Jangan menempatkan `data-protect` kosong bila ingin mengaktifkan proteksi. Browser dapat memalsukan telemetri; CAPTCHA putar huruf hanyalah gesekan anti-otomasi, bukan bukti manusia.

## 4. Verifikasi di backend asli klien (WAJIB)

Salin `sdk/qx-passport-verifier.js` ke proyek Node milik klien; ambil kunci publik **sekali** dari `GET https://gate.example.com/api/gate/public-key` melalui kanal tepercaya, verifikasi fingerprint out-of-band, kemudian pin nilainya di konfigurasi backend klien. Jangan mengunduh public key setiap request secara otomatis. Contoh:

```js
import express from "express";
import { requireQxPassport } from "./qx-passport-verifier.js";

const app = express();
app.use(express.json({ limit: "16kb" }));
app.use(yourExistingAuthenticationMiddleware); // wajib mengisi req.user secara tepercaya
app.post("/api/checkout", requireQxPassport({
  expectedSiteKey: process.env.QX_SITE_KEY,
  expectedPublicKeyB64: process.env.QX_PINNED_PUBLIC_KEY_B64,
  expectedOrigin: "https://frontend-klien.example",
  requiredChecks: ["waf", "2fa_verified"],
  getAuthenticatedSubject: (req) => req.user?.id, // harus identik dengan username/ID di qX
}), yourExistingAuthorizationAndCheckoutHandler);
```

Middleware memvalidasi signature Ed25519, `iss`, `aud` (tenant), `org` (origin), `pth` (path), `mth` (metode), `bsh` (hash body JSON), `iat`, `nbf`, `exp`, `chk` (pemeriksaan wajib), identitas `sub` dan `jti` sekali pakai (anti-replay per proses). Default `requiredChecks` mencakup `waf` + `2fa_verified`. **Untuk multi-replica, pindahkan anti-replay ke penyimpanan bersama yang mendukung atomic SET NX, misalnya Redis.** Integritas body menggunakan `JSON.stringify` pada body JSON yang sudah diparse Express, jadi parser body harus kompatibel di kedua sisi. Middleware ini tidak mengautentikasi user dengan sendirinya.

## Kontrak API publik

Semua JSON memakai `{ok:true,...}` atau `{ok:false,error:{code,message}}`. Untuk `/api/gate/*` selain provisioning admin, kirim `Origin` terdaftar, `X-QX-Site-Key` dan `Content-Type: application/json` saat POST. Pada verifikasi lanjutan kirim `X-QX-Gate-Token` (token sementara; jangan dicatat di log).

| Endpoint | Fungsi |
|---|---|
| `GET /healthz` | Status API+core (503 jika core tidak sehat) |
| `GET /api/gate/public-key` | Public key Ed25519 terpin (`public_key_b64`) |
| `POST /api/gate/tenants/register` | Provision tenant, **admin loopback + secret** |
| `POST /api/gate/tenants/users/provision` | Provision identitas dan kode, **admin loopback + secret** |
| `POST /api/gate/preflight` | `{targetPath,method,payloadSample,telemetry}` → `ALLOW`/`CHALLENGE_REQUIRED`/`2FA_REQUIRED` |
| `POST /api/gate/verify-challenge` | `{taps:[...]}` + gate token → tahap berikutnya |
| `POST /api/gate/verify-2fa` | `{username,securityCode}` + gate token → paspor |

`targetPath` harus path terkanonisasi tanpa query/encoding (`/a/b`), `method` GET/POST/PUT/PATCH/DELETE. `payloadSample` **wajib**: isi JSON yang sama persis secara semantik dengan request yang diterima backend klien atau `null` bila request tanpa body. Token paspor 30 detik; permintaan salah path/metode/body atau replay ditolak verifier. Semua data tetap kosong sebelum provisioning.

## Batasan keamanan sebelum produksi

- **Tidak setara WAF upstream:** inspeksi regex hanya menyaring payload yang dikirim pada *preflight*. Endpoint backend klien **WAJIB** memakai verifier, dan WAF/proxy serta sanitasi server milik klien tetap diperlukan. Field seperti encoded payload, multipart, atau serangan lain bisa luput.
- **Origin/CORS dan script browser tidak membuktikan identitas:** `Origin` dapat dipalsukan non-browser; site key publik; telemetri/CAPTCHA/Closed Shadow DOM tidak dapat menghentikan aktor dengan kontrol browser. Selalu pertahankan autentikasi + otorisasi klien dan kode keamanan yang terprovisi dari jalur tepercaya.
- **Single instance sementara:** flow, lockout, rate limit, dan anti-replay masih dalam memori; untuk multi-node/produksi besar gunakan Redis/DB, pembatasan beban di reverse proxy, cadangan aman, monitoring, dan policy audit.
- **Cryptographic key rotation** masih manual. Klien harus memperbarui kunci publik terpin dengan rollout terencana sebelum kunci privat dirotasi; jangan menerbitkan paspor dari server yang kuncinya hilang.
- **Batas body API** 16 KB; tidak mendukung request JSON besar, file atau stream. Pelajari risiko false positive/false negative dari regex WAF pada data klien.
- **Kunci admin** tidak boleh digunakan dari frontend, SDK atau halaman web. Hanya jalur operator/server internal. Blokir rute `/api/gate/tenants/*` pada proxy publik selain pengecekan internal yang sudah ada.

## Pengujian

```bash
cd api
npm ci
npm test
```

Tes otomatis Node mencakup: basis data awal kosong, larangan pendaftaran publik/wildcard, isolasi tenant-origin, preflight CORS browser, inspeksi WAF, larangan auto-enrollment, proteksi provisioning, flow antar-tenant dan sekali pakai, integritas signature, body/path mismatch, dan replay. **Tes menggunakan core tiruan untuk menguji kontrak Node serta verifier; bukan kompilasi atau uji kriptografi Rust asli.** Pastikan `cargo test --locked` dan `cargo build --locked --release` di host dengan toolchain Rust, kemudian lakukan tes end-to-end dengan qx-core sungguhan, TLS, browser, dan backend klien sebelum deployment produksi.
