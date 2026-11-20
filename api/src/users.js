import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { config } from "./config.js";

const file = path.join(config.dataDir, "users.json");
let cache = { mtime: -1, users: new Map() };
const userKey = (siteKey, username) => JSON.stringify([siteKey, username.toLowerCase()]);
function load() {
  let st;
  try { st = fs.statSync(file); }
  catch (e) {
    if (e.code !== "ENOENT") throw e;
    cache = { mtime: -1, users: new Map() }; return;
  }
  if (st.mtimeMs === cache.mtime) return;
  if (st.size > 8 * 1024 * 1024) throw new Error("User database exceeds safe limit");
  const json = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!Array.isArray(json.users)) throw new Error("Invalid user database");
  const users = new Map();
  for (const u of json.users) {
    if (!u.siteKey || !u.username || !u.teamCodeHash) throw new Error("Invalid user record");
    const key = userKey(u.siteKey, u.username);
    if (users.has(key)) throw new Error("Duplicate tenant user");
    users.set(key, u);
  }
  cache = { mtime: st.mtimeMs, users };
}
export function findTenantUser(siteKey, username) {
  if (!siteKey || !username) return null;
  load(); return cache.users.get(userKey(siteKey, String(username))) ?? null;
}
/** Enrollment only from trusted server-side admin, never from an unauthenticated browser. */
export function saveTenantUser(siteKey, username, codeHash) {
  load();
  const key = userKey(siteKey, username);
  if (cache.users.has(key)) return null; // no silent overwrite/credential takeover
  const record = { siteKey, username: username.toLowerCase(), teamCodeHash: codeHash, createdAt: new Date().toISOString() };
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  try {
    fs.writeFileSync(tmp, JSON.stringify({ users: [...cache.users.values(), record] }, null, 2) + "\n", { mode: 0o600, flag: "wx" });
    fs.renameSync(tmp, file);
    fs.chmodSync(file, 0o600);
  } finally { try { fs.unlinkSync(tmp); } catch (e) { if (e.code !== "ENOENT") throw e; } }
  cache.mtime = -1;
  return record;
}
