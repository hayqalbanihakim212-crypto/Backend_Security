import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { config } from "./config.js";

const file = path.join(config.dataDir, "tenants.json");
let cache = { mtime: -1, byKey: new Map() };
const validOrigin = (value) => {
  if (typeof value !== "string" || value.length > 256) return false;
  try {
    const u = new URL(value);
    const dev = u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
    return (u.protocol === "https:" || dev) && u.origin === value && !u.username && !u.password;
  } catch { return false; }
};

function load() {
  let st;
  try { st = fs.statSync(file); }
  catch (e) {
    if (e.code !== "ENOENT") throw e;
    cache = { mtime: -1, byKey: new Map() }; return;
  }
  if (st.mtimeMs === cache.mtime) return;
  if (st.size > 1024 * 1024) throw new Error("Tenant database exceeds safe limit");
  const json = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!Array.isArray(json.tenants)) throw new Error("Invalid tenant database");
  const byKey = new Map();
  for (const tenant of json.tenants) {
    if (typeof tenant.siteKey !== "string" || !Array.isArray(tenant.allowedOrigins) ||
        !tenant.allowedOrigins.length || !tenant.allowedOrigins.every(validOrigin) || byKey.has(tenant.siteKey)) {
      throw new Error("Invalid tenant database record");
    }
    byKey.set(tenant.siteKey, tenant);
  }
  cache = { mtime: st.mtimeMs, byKey };
}

function atomicWrite(records) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
  try {
    fs.writeFileSync(tmp, JSON.stringify({ tenants: records }, null, 2) + "\n", { mode: 0o600, flag: "wx" });
    fs.renameSync(tmp, file);
    fs.chmodSync(file, 0o600);
  } finally { try { fs.unlinkSync(tmp); } catch (e) { if (e.code !== "ENOENT") throw e; } }
  cache.mtime = -1;
}

export function findTenant(siteKey) {
  if (typeof siteKey !== "string" || !siteKey) return null;
  load(); return cache.byKey.get(siteKey) ?? null;
}

export function isRegisteredOrigin(origin) {
  if (!validOrigin(origin)) return false;
  load();
  return [...cache.byKey.values()].some((t) => t.allowedOrigins.includes(origin));
}

export function isOriginAllowedForTenant(tenant, origin) {
  return Boolean(tenant && validOrigin(origin) && tenant.allowedOrigins.includes(origin));
}

/** Provisioned only by an authenticated, loopback-only administrator. */
export function registerTenant({ name, allowedOrigins, modules }) {
  load();
  if (!Array.isArray(allowedOrigins) || !allowedOrigins.length || allowedOrigins.length > 10 ||
      !allowedOrigins.every(validOrigin) || new Set(allowedOrigins).size !== allowedOrigins.length) {
    throw new Error("Invalid allowed origin list");
  }
  const siteKey = `pk_live_${crypto.randomBytes(24).toString("hex")}`;
  const tenant = {
    siteKey, name, allowedOrigins,
    modules: {
      waf: modules?.waf ?? true,
      botChallenge: modules?.botChallenge ?? true,
      require2fa: modules?.require2fa ?? true,
    },
    passportTtlSec: 30,
    createdAt: new Date().toISOString(),
  };
  atomicWrite([...cache.byKey.values(), tenant]);
  return tenant;
}
