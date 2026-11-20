import fs from "node:fs";
import path from "node:path";
import { config } from "./config.js";

fs.mkdirSync(config.logDir, { recursive: true });
const stream = fs.createWriteStream(path.join(config.logDir, "audit.log"), { flags: "a", mode: 0o600 });

/**
 * Catatan audit (JSON lines). JANGAN pernah memasukkan password, kode tim, atau token ke sini.
 */
export function audit(event, req, fields = {}) {
  const line = {
    ts: new Date().toISOString(),
    event,
    ip: req?.ip,
    ua: String(req?.get?.("user-agent") ?? "").slice(0, 120),
    ...fields,
  };
  stream.write(JSON.stringify(line) + "\n");
  if (!config.isProd) console.log("[audit]", event, JSON.stringify(fields));
}
