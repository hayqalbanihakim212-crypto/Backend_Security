import crypto from "node:crypto";

/** Token acak 256-bit untuk cookie (flow / session). */
export const newToken = () => crypto.randomBytes(32).toString("base64url");
/** Yang disimpan di server hanya hash token, jadi dump memori tidak membocorkan token valid. */
export const hashToken = (t) => crypto.createHash("sha256").update(t).digest("hex");

/**
 * Store key-value dengan TTL, in-memory.
 * Antarmukanya (get/set/touch/delete) sengaja kecil supaya mudah diganti Redis
 * saat API dijalankan lebih dari satu instance.
 */
export class TtlStore {
  #m = new Map();
  constructor(sweepMs = 60_000) {
    setInterval(() => this.sweep(), sweepMs).unref();
  }
  set(key, value, ttlMs) {
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw new Error("Invalid TTL");
    if (this.#m.size >= 20000) this.sweep();
    if (this.#m.size >= 20000) throw new Error("Security flow capacity exhausted");
    this.#m.set(key, { value, exp: Date.now() + ttlMs });
  }
  get(key) {
    const e = this.#m.get(key);
    if (!e) return undefined;
    if (e.exp <= Date.now()) {
      this.#m.delete(key);
      return undefined;
    }
    return e.value;
  }
  /** Ubah masa berlaku tanpa mengganti nilai. */
  touch(key, ttlMs) {
    const e = this.#m.get(key);
    if (e) e.exp = Date.now() + ttlMs;
  }
  expiresAt(key) {
    return this.#m.get(key)?.exp;
  }
  delete(key) {
    this.#m.delete(key);
  }
  sweep() {
    const now = Date.now();
    for (const [k, e] of this.#m) if (e.exp <= now) this.#m.delete(k);
  }
}
