import { TtlStore, newToken, hashToken } from "./store.js";

/**
 * "Flow" = proses login yang sedang berjalan (belum jadi sesi).
 * Tahapan:  challenge → (khusus Tim) team_account → team_code → sesi dibuat.
 * Seluruh status ada di server; frontend hanya memegang cookie opak (HttpOnly).
 * Ini menggantikan penanda `sessionStorage("qx-first-verification-at")` di frontend lama,
 * yang bisa dipalsukan siapa pun lewat DevTools.
 */
const store = new TtlStore();

export function createFlow(data, ttlMs) {
  const token = newToken();
  const flow = { ...data, createdAt: Date.now() };
  store.set(hashToken(token), flow, ttlMs);
  return { token, flow };
}

export function readFlow(token) {
  if (!token) return null;
  const flow = store.get(hashToken(token));
  return flow ? { token, flow, expiresAt: store.expiresAt(hashToken(token)) } : null;
}

export const extendFlow = (token, ttlMs) => store.touch(hashToken(token), ttlMs);
export const destroyFlow = (token) => token && store.delete(hashToken(token));
