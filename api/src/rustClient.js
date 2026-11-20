import crypto from "node:crypto";
import { config } from "./config.js";
import { HttpError } from "./errors.js";

async function call(path, body) {
  let res;
  try {
    res = await fetch(config.core.url + path, {
      method: "POST",
      headers: { "content-type": "application/json", "x-core-key": config.core.key },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(config.core.timeoutMs),
    });
  } catch {
    throw new HttpError(503, "CORE_UNAVAILABLE", "Layanan keamanan sedang tidak tersedia.");
  }
  if (!res.ok) {
    throw new HttpError(res.status === 400 ? 400 : 503, "CORE_ERROR", "Layanan keamanan menolak permintaan.");
  }
  return res.json();
}

export const core = {
  async hashPassword(password) {
    return (await call("/v1/password/hash", { password })).hash;
  },
  async verifyPassword(password, hash) {
    return (await call("/v1/password/verify", { password, hash })).valid === true;
  },
  async newChallenge(length) {
    return (await call("/v1/challenge/new", { length })).rotations;
  },
  async verifyChallenge(initial, taps) {
    return call("/v1/challenge/verify", { initial, taps });
  },
  async signPassport({ siteKey, origin, targetPath, method, bodySha256, checksPassed, subject, ttlSec }) {
    return call("/v1/passport/sign", {
      site_key: siteKey,
      origin,
      target_path: targetPath,
      method,
      body_sha256: bodySha256,
      subject,
      checks_passed: checksPassed,
      ttl_sec: ttlSec,
    });
  },
  async getPublicKey() {
    const r = await fetch(config.core.url + "/v1/passport/public-key", {
      headers: { "x-core-key": config.core.key },
      signal: AbortSignal.timeout(2000),
    });
    if (!r.ok) throw new HttpError(503, "CORE_UNAVAILABLE", "Gagal mengambil public key.");
    return r.json();
  },
  async health() {
    try {
      const r = await fetch(config.core.url + "/healthz", { signal: AbortSignal.timeout(2000) });
      return r.ok;
    } catch {
      return false;
    }
  },
};

let dummy;
export function dummyHash() {
  dummy ??= core.hashPassword(`dummy-${crypto.randomBytes(32).toString("hex")}`).catch((e) => {
    dummy = undefined;
    throw e;
  });
  return dummy;
}