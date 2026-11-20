import { Router } from "express";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import crypto from "node:crypto";

import { config } from "../config.js";
import { core, dummyHash } from "../rustClient.js";
import { findTenant, isOriginAllowedForTenant, registerTenant } from "../tenants.js";
import { requireAdmin } from "../middleware/security.js";
import { inspectPayloadWaf } from "../middleware/waf.js";
import { findTenantUser, saveTenantUser } from "../users.js";
import { lockout } from "../lockout.js";
import { audit } from "../audit.js";
import { WORDS } from "../words.js";
import { createFlow, readFlow, extendFlow, destroyFlow } from "../flows.js";
import { fail, wrap, parse } from "../errors.js";

export const gateRouter = Router();
const { challenge: C, team: T } = config;
const b64hash = (data) => crypto.createHash("sha256").update(JSON.stringify(data)).digest("base64url");

// Public gate operations are rate-limited separately from administrator provisioning.
gateRouter.use(rateLimit({
  windowMs: 60_000,
  limit: config.rate.gatePerMinPerIp,
  standardHeaders: "draft-7", legacyHeaders: false,
  handler: (_req, res) => fail(res, 429, "RATE_LIMITED", "Too many requests."),
}));

function requireTenant(req, res) {
  const tenant = req.tenant || findTenant(req.get("x-qx-site-key"));
  const origin = req.get("origin");
  if (!tenant || !isOriginAllowedForTenant(tenant, origin)) {
    fail(res, 403, "INVALID_TENANT", "Site Key or origin is not approved."); return null;
  }
  return { tenant, origin };
}
function flowFor(req, res, stage, ctx) {
  const token = req.get("x-qx-gate-token");
  const record = readFlow(token);
  if (!record || record.flow.stage !== stage || record.flow.siteKey !== ctx.tenant.siteKey ||
      record.flow.origin !== ctx.origin || record.flow.inflight) {
    fail(res, 401, "GATE_FLOW_INVALID", "Gate flow invalid or expired."); return null;
  }
  return record;
}
async function issuePassportResponse(req, res, { tenant, origin, targetPath, method, bodySha256, checksPassed, subject }) {
  const signed = await core.signPassport({
    siteKey: tenant.siteKey, origin, targetPath, method, bodySha256, checksPassed,
    subject: subject || null, ttlSec: tenant.passportTtlSec,
  });
  audit("passport_issued", req, { siteKey: tenant.siteKey, targetPath, method, checksPassed });
  return res.json({ ok: true, status: "ALLOW", passport: signed.passport,
    expiresAt: signed.expires_at, checksPassed });
}

// Provisioning endpoints are loopback-only, authenticated, and have no browser-side CORS grants.
const registerSchema = z.object({
  name: z.string().trim().min(1).max(64),
  allowedOrigins: z.array(z.string().min(1).max(256)).min(1).max(10),
  modules: z.object({
    waf: z.literal(true).optional(), // WAF never disabled for protected endpoints
    botChallenge: z.boolean().optional(),
    require2fa: z.boolean().optional(),
  }).strict().optional(),
}).strict();
gateRouter.post("/tenants/register", requireAdmin, wrap(async (req, res) => {
  const body = parse(registerSchema, req.body);
  if (body.allowedOrigins.some((v) => { try {
    const u = new URL(v); return u.origin !== v ||
      !(u.protocol === "https:" || (u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)));
  } catch { return true; } })) return fail(res, 400, "INVALID_ORIGIN", "Explicit HTTPS origins are required (localhost HTTP allowed for development).");
  const tenant = registerTenant(body);
  audit("tenant_registered", req, { siteKey: tenant.siteKey });
  const sdkUrl = config.publicBaseUrl ? `${config.publicBaseUrl}/sdk/qx-guard.js` : null;
  res.status(201).json({ ok: true, siteKey: tenant.siteKey, allowedOrigins: tenant.allowedOrigins,
    modules: tenant.modules, sdkUrl,
    embedSnippet: sdkUrl ? `<script src="${sdkUrl}" data-site-key="${tenant.siteKey}" data-protect="/api/protected" defer></script>` : null });
}));

// Trusted client backend/administrator provisions an identity and its secret securely.
// An arbitrary browser can NEVER enroll itself by claiming someone else's username.
const provisionSchema = z.object({
  siteKey: z.string().min(1).max(100),
  username: z.string().trim().regex(/^[a-zA-Z0-9._@-]{1,64}$/),
  securityCode: z.string().min(12).max(128),
}).strict();
gateRouter.post("/tenants/users/provision", requireAdmin, wrap(async (req, res) => {
  const { siteKey, username, securityCode } = parse(provisionSchema, req.body);
  if (!findTenant(siteKey)) return fail(res, 404, "INVALID_TENANT", "Unknown tenant.");
  if (findTenantUser(siteKey, username)) return fail(res, 409, "ALREADY_PROVISIONED", "Identity already exists.");
  const hash = await core.hashPassword(securityCode);
  const user = saveTenantUser(siteKey, username, hash);
  if (!user) return fail(res, 409, "ALREADY_PROVISIONED", "Identity already exists.");
  audit("identity_provisioned", req, { siteKey, username: user.username });
  res.status(201).json({ ok: true, siteKey, username: user.username });
}));

gateRouter.get("/public-key", wrap(async (_req, res) => {
  res.json({ ok: true, ...await core.getPublicKey() });
}));

const targetPath = z.string().min(1).max(256).regex(/^\/(?!\/)[a-zA-Z0-9/_~.-]*$/);
const methodSchema = z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const preflightSchema = z.object({
  targetPath,
  method: methodSchema,
  payloadSample: z.unknown(), // exact JSON request body, null for bodyless requests
  telemetry: z.object({
    webdriver: z.boolean().optional(),
    pointerMoves: z.number().int().min(0).max(10000).optional(),
    timeOnPageMs: z.number().int().min(0).max(86_400_000).optional(),
  }).strict().optional(),
}).strict();

gateRouter.post("/preflight", wrap(async (req, res) => {
  const ctx = requireTenant(req, res);
  if (!ctx) return;
  const { tenant, origin } = ctx;
  const body = parse(preflightSchema, req.body);
  if (!Object.hasOwn(req.body, "payloadSample")) return fail(res, 400, "VALIDATION", "payloadSample is required (use null if no JSON body).");
  const checksPassed = [];
  const waf = inspectPayloadWaf(req, body.payloadSample);
  if (waf.blocked) return fail(res, 403, "WAF_BLOCKED", "Request blocked by security inspection.", { rule: waf.rule });
  checksPassed.push("waf");
  const bodySha256 = b64hash(body.payloadSample);
  const common = { siteKey: tenant.siteKey, origin, targetPath: body.targetPath,
    method: body.method, bodySha256, checksPassed, subject: null };
  const tel = body.telemetry || {};
  const suspiciousBot = tel.webdriver === true || (tel.pointerMoves ?? 0) < 2 || (tel.timeOnPageMs ?? 0) < 500;
  if (tenant.modules.botChallenge && suspiciousBot) {
    const word = WORDS[crypto.randomInt(WORDS.length)];
    const initial = await core.newChallenge(word.length);
    const { token } = createFlow({ ...common, stage: "bot_challenge",
      challenge: { word, initial, attempts: 0, issuedAt: Date.now() },
      require2fa: Boolean(tenant.modules.require2fa), twoFaAttempts: 0 }, C.ttlMs);
    return res.json({ ok: true, status: "CHALLENGE_REQUIRED", stage: "bot_challenge", gateToken: token,
      challenge: { word, rotations: initial.map((r) => r * 90), maxAttempts: C.maxAttempts, attemptsLeft: C.maxAttempts } });
  }
  if (tenant.modules.botChallenge) checksPassed.push("bot_passive");
  if (tenant.modules.require2fa) {
    const { token } = createFlow({ ...common, stage: "stepup_2fa", twoFaAttempts: 0 }, T.stageTtlMs);
    return res.json({ ok: true, status: "2FA_REQUIRED", stage: "stepup_2fa", gateToken: token });
  }
  return issuePassportResponse(req, res, { tenant, origin, ...common });
}));

const challengeSchema = z.object({ taps: z.array(z.number().int().min(0).max(10000)).min(1).max(32) }).strict();
gateRouter.post("/verify-challenge", wrap(async (req, res) => {
  const ctx = requireTenant(req, res); if (!ctx) return;
  const f = flowFor(req, res, "bot_challenge", ctx); if (!f) return;
  const { taps } = parse(challengeSchema, req.body);
  const ch = f.flow.challenge;
  if (ch.attempts >= C.maxAttempts) {
    destroyFlow(f.token); return fail(res, 403, "CHALLENGE_LOCKED", "Challenge attempts exhausted.");
  }
  if (taps.length !== ch.word.length) return fail(res, 400, "VALIDATION", "Wrong challenge length.");
  ch.attempts += 1;
  f.flow.inflight = true;
  let result;
  try {
    const tooFast = Date.now() - ch.issuedAt < C.minSolveMs;
    result = tooFast ? { ok: false, wrong: taps.map(() => true) } : await core.verifyChallenge(ch.initial, taps);
    if (!result.ok) {
      if (ch.attempts >= C.maxAttempts) destroyFlow(f.token);
      return fail(res, 422, tooFast ? "TOO_FAST" : "CHALLENGE_WRONG", "Challenge not completed.",
        { wrongPositions: result.wrong, attemptsLeft: Math.max(0, C.maxAttempts - ch.attempts) });
    }
    f.flow.checksPassed.push("bot_challenge");
    if (f.flow.require2fa) {
      f.flow.stage = "stepup_2fa"; f.flow.challenge = null;
      extendFlow(f.token, T.stageTtlMs);
      return res.json({ ok: true, status: "2FA_REQUIRED", stage: "stepup_2fa", gateToken: f.token });
    }
    destroyFlow(f.token);
    return await issuePassportResponse(req, res, { tenant: ctx.tenant, origin: ctx.origin, ...f.flow });
  } finally { f.flow.inflight = false; }
}));

const twoFaSchema = z.object({
  username: z.string().trim().regex(/^[a-zA-Z0-9._@-]{1,64}$/),
  securityCode: z.string().min(1).max(128),
}).strict();
gateRouter.post("/verify-2fa", wrap(async (req, res) => {
  const ctx = requireTenant(req, res); if (!ctx) return;
  const f = flowFor(req, res, "stepup_2fa", ctx); if (!f) return;
  const { username, securityCode } = parse(twoFaSchema, req.body);
  const uname = username.toLowerCase();
  const lockId = `${ctx.tenant.siteKey}:${uname}`;
  const lk = lockout.check(lockId, "gate_2fa");
  if (lk.locked) return fail(res, 429, "LOCKED", "Too many failures.", { retryAfterSec: lk.retryAfterSec });
  f.flow.twoFaAttempts += 1;
  f.flow.inflight = true;
  try {
    const user = findTenantUser(ctx.tenant.siteKey, uname);
    const valid = await core.verifyPassword(securityCode, user?.teamCodeHash ?? (await dummyHash()));
    if (!user || !valid) {
      lockout.fail(lockId, "gate_2fa");
      const left = Math.max(0, T.maxCodeAttempts - f.flow.twoFaAttempts);
      audit("gate_2fa_failed", req, { siteKey: ctx.tenant.siteKey });
      if (left === 0) destroyFlow(f.token);
      return fail(res, left === 0 ? 403 : 401, left === 0 ? "2FA_LOCKED" : "BAD_2FA_CODE",
        "Security verification failed.", { attemptsLeft: left });
    }
    lockout.reset(lockId, "gate_2fa");
    f.flow.checksPassed.push("2fa_verified");
    f.flow.subject = uname;
    destroyFlow(f.token);
    return await issuePassportResponse(req, res, { tenant: ctx.tenant, origin: ctx.origin, ...f.flow });
  } finally { f.flow.inflight = false; }
}));
