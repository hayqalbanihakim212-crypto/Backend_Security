import { config } from "./config.js";
import { TtlStore } from "./store.js";

const store = new TtlStore();
const key = (username, accessType) =>
  `lk:${String(accessType).slice(0, 16)}:${String(username).toLowerCase().slice(0, 64)}`;
const { maxFailures, windowMs, durationMs } = config.lockout;

/** Penguncian sementara terpisah per jenis akses setelah kegagalan autentikasi. */
export const lockout = {
  check(username, accessType) {
    const e = store.get(key(username, accessType));
    if (e?.lockedUntil && e.lockedUntil > Date.now()) {
      return { locked: true, retryAfterSec: Math.ceil((e.lockedUntil - Date.now()) / 1000) };
    }
    return { locked: false };
  },
  fail(username, accessType) {
    const k = key(username, accessType);
    const e = store.get(k) ?? { fails: 0 };
    e.fails += 1;
    if (e.fails >= maxFailures) {
      e.lockedUntil = Date.now() + durationMs;
      store.set(k, e, durationMs);
      return { locked: true };
    }
    store.set(k, e, windowMs);
    return { locked: false, remaining: maxFailures - e.fails };
  },
  reset(username, accessType) {
    store.delete(key(username, accessType));
  },
};
