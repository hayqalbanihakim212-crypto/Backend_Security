// Drop-in Node.js/Express server-side verifier for third-party backends.
// Pinned PUBLIC key is required: do not trust a per-request network key fetch.
import { createPublicKey, verify, createHash } from "node:crypto";

const PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const spent = new Map(); // Single-process replay defense; use Redis SET NX for multiple replicas.
const isB64u = (s) => typeof s === "string" && /^[A-Za-z0-9_-]+$/.test(s);
const fail = (res) => res.status(403).json({ ok: false, error: { code: "INVALID_PASSPORT", message: "Security passport rejected." } });
const hashBody = (body) => createHash("sha256").update(JSON.stringify(body === undefined ? null : body)).digest("base64url");

export function requireQxPassport({ expectedSiteKey, expectedPublicKeyB64, expectedOrigin, requiredChecks = ["waf", "2fa_verified"], getAuthenticatedSubject }) {
  if (typeof expectedSiteKey !== "string" || !expectedSiteKey || !expectedOrigin ||
      (requiredChecks.includes("2fa_verified") && typeof getAuthenticatedSubject !== "function") ||
      !isB64u(expectedPublicKeyB64) || !Array.isArray(requiredChecks) || !requiredChecks.every((x) => typeof x === "string")) {
    throw new Error("Provide site key, pinned public key, and required checks");
  }
  const bytes = Buffer.from(expectedPublicKeyB64, "base64url");
  if (bytes.length !== 32) throw new Error("Expected 32-byte Ed25519 public key");
  const key = createPublicKey({ key: Buffer.concat([PREFIX, bytes]), format: "der", type: "spki" });
  return function verifyQxPassport(req, res, next) {
    try {
      const token = req.get("x-qx-passport") || "";
      if (token.length > 4096) return fail(res);
      const chunks = token.split(".");
      if (chunks.length !== 3 || !chunks.every(isB64u)) return fail(res);
      const [head, pay, sig] = chunks;
      const signature = Buffer.from(sig, "base64url");
      if (signature.length !== 64 || !verify(null, Buffer.from(`${head}.${pay}`), key, signature)) return fail(res);
      const header = JSON.parse(Buffer.from(head, "base64url").toString("utf8"));
      const claims = JSON.parse(Buffer.from(pay, "base64url").toString("utf8"));
      const now = Math.floor(Date.now() / 1000);
      const origin = expectedOrigin || req.get("origin");
      if (!origin || header?.alg !== "EdDSA" || header?.typ !== "JWT" || claims?.iss !== "qx-gatekeeper" ||
          claims.aud !== expectedSiteKey || claims.org !== origin ||
          claims.pth !== req.path || claims.mth !== req.method || claims.bsh !== hashBody(req.body) ||
          !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.nbf) ||
          !Number.isSafeInteger(claims.exp) || claims.exp <= now || claims.nbf > now + 5 ||
          claims.iat > now + 5 || claims.exp - claims.iat > 60 || claims.exp <= claims.iat ||
          !isB64u(claims.jti) || claims.jti.length > 64 || !Array.isArray(claims.chk) ||
          !requiredChecks.every((x) => claims.chk.includes(x))) return fail(res);
      if (claims.chk.includes("2fa_verified") && (typeof claims.sub !== "string" || !claims.sub)) return fail(res);
      if (requiredChecks.includes("2fa_verified") && claims.sub !== getAuthenticatedSubject(req)) return fail(res);
      for (const [jti, exp] of spent) if (exp <= now) spent.delete(jti);
      const id = `${expectedSiteKey}:${claims.jti}`;
      if (spent.has(id)) return fail(res);
      if (spent.size >= 20000) return fail(res); // never evict live JTIs and re-enable replay
      spent.set(id, claims.exp);
      req.qxSecurity = claims;
      return next();
    } catch { return fail(res); }
  };
}
