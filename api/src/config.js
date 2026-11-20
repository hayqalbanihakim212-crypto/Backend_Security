// No default/admin credentials. Service fails closed until explicitly configured.
const env = process.env;
const isProd = env.NODE_ENV === "production";
function int(name, def, min, max) {
  const v = env[name];
  const n = v === undefined || v === "" ? def : Number(v);
  if (!Number.isSafeInteger(n) || n < min || n > max) throw new Error(`Invalid ${name}`);
  return n;
}
function required(name, minLen = 32) {
  const v = env[name];
  if (!v || v.length < minLen || /^(.)(\1)+$/.test(v)) throw new Error(`Missing/unsafe ${name}`);
  return v;
}
const url = new URL(env.QX_CORE_URL || "http://127.0.0.1:7001");
if (url.protocol !== "http:" || !["127.0.0.1", "[::1]", "localhost"].includes(url.hostname) ||
    url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
  throw new Error("QX_CORE_URL must target loopback HTTP only");
}
const host = env.HOST || "127.0.0.1";
const publicUrl = env.QX_PUBLIC_BASE_URL ? new URL(env.QX_PUBLIC_BASE_URL) : null;
if (publicUrl && (publicUrl.username || publicUrl.password || publicUrl.pathname !== "/" ||
    publicUrl.search || publicUrl.hash || !(publicUrl.protocol === "https:" ||
    (publicUrl.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(publicUrl.hostname))))) {
  throw new Error("QX_PUBLIC_BASE_URL must be a HTTPS origin (HTTP allowed on localhost only)");
}
const trustProxy = env.TRUST_PROXY ? int("TRUST_PROXY", 0, 0, 2) : false;
export const config = Object.freeze({
  isProd, host, port: int("PORT", 4000, 1, 65535), trustProxy,
  adminKey: required("QX_ADMIN_KEY"),
  publicBaseUrl: publicUrl?.origin || null,
  core: { url: url.origin, key: required("QX_CORE_KEY"), timeoutMs: int("QX_CORE_TIMEOUT_MS", 5000, 250, 10000) },
  challenge: { ttlMs: int("CHALLENGE_TTL_MS", 120000, 30000, 300000),
    maxAttempts: int("CHALLENGE_MAX_ATTEMPTS", 5, 1, 10),
    minSolveMs: int("CHALLENGE_MIN_SOLVE_MS", 800, 300, 10000) },
  team: { stageTtlMs: int("TEAM_STAGE_TTL_MS", 300000, 30000, 600000), maxCodeAttempts: int("TEAM_MAX_CODE_ATTEMPTS", 5, 1, 10) },
  lockout: { maxFailures: int("LOCKOUT_MAX_FAILURES", 5, 1, 20),
    windowMs: int("LOCKOUT_WINDOW_MS", 900000, 60000, 3600000),
    durationMs: int("LOCKOUT_DURATION_MS", 900000, 60000, 3600000) },
  rate: { gatePerMinPerIp: int("RATE_GATE_PER_MIN", 60, 1, 1000) },
  dataDir: env.QX_DATA_DIR || new URL("../data/", import.meta.url).pathname,
  logDir: env.QX_LOG_DIR || new URL("../logs/", import.meta.url).pathname,
});
