import crypto from "node:crypto";
import { config } from "../config.js";
import { findTenant, isOriginAllowedForTenant, isRegisteredOrigin } from "../tenants.js";
import { fail } from "../errors.js";

const isLoopback = (addr) => ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(addr);

/** Never expose the administrative provisioning API to the embedded browser SDK. */
export function requireAdmin(req, res, next) {
  const token = req.get("x-qx-admin-key") || "";
  const expected = Buffer.from(config.adminKey);
  const given = Buffer.from(token);
  if (!isLoopback(req.socket.remoteAddress) || !token ||
      given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
    return fail(res, 403, "ADMIN_FORBIDDEN", "Administrator access denied.");
  }
  next();
}

export function cors(req, res, next) {
  const origin = req.get("origin");
  const siteKey = req.get("x-qx-site-key");
  const tenant = findTenant(siteKey);
  req.tenant = tenant;
  res.vary("Origin");
  const allowed = req.method === "OPTIONS" ? isRegisteredOrigin(origin) : isOriginAllowedForTenant(tenant, origin);
  if (origin && req.path.startsWith("/api/gate/") && !req.path.startsWith("/api/gate/tenants/") && allowed) {
    res.set({
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-QX-Site-Key, X-QX-Gate-Token",
      "Access-Control-Max-Age": "300",
    });
    if (req.method === "OPTIONS") return res.sendStatus(204);
  }
  if (req.method === "OPTIONS") return fail(res, 403, "BAD_ORIGIN", "Unapproved CORS origin.");
  next();
}

export function originGuard(req, res, next) {
  if (["GET", "HEAD"].includes(req.method)) return next();
  if (req.path.startsWith("/api/gate/tenants/")) return next(); // requireAdmin enforces this
  if (req.path.startsWith("/api/gate/")) {
    const tenant = req.tenant || findTenant(req.get("x-qx-site-key"));
    if (!isOriginAllowedForTenant(tenant, req.get("origin"))) {
      return fail(res, 403, "BAD_ORIGIN", "Origin or Site Key is not approved.");
    }
    req.tenant = tenant;
    return next();
  }
  return fail(res, 403, "BAD_ORIGIN", "Unapproved origin.");
}

export function noStore(_req, res, next) {
  res.set("Cache-Control", "no-store");
  next();
}
