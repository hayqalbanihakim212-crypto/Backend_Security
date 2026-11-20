import express from "express";
import helmet from "helmet";
import { fileURLToPath } from "node:url";

import { config } from "./config.js";
import { core } from "./rustClient.js";
import { cors, originGuard, noStore } from "./middleware/security.js";
import { gateRouter } from "./routes/gate.js";
import { HttpError, fail } from "./errors.js";

const app = express();
const sdkDir = fileURLToPath(new URL("../../sdk/", import.meta.url));

app.disable("x-powered-by");
if (config.trustProxy !== false) app.set("trust proxy", config.trustProxy);

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);
app.use(cors);
app.use("/api", noStore);
app.use(express.json({ limit: "16kb" }));
app.use(originGuard);

// Sajikan skrip embeddable SDK untuk frontend pihak ketiga
app.use("/sdk", express.static(sdkDir));

app.get("/healthz", async (_req, res) => {
  const coreOk = await core.health();
  res.status(coreOk ? 200 : 503).json({ ok: coreOk, core: coreOk });
});

app.use("/api/gate", gateRouter);

app.use((_req, res) => fail(res, 404, "NOT_FOUND", "Endpoint tidak ditemukan."));

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  if (err instanceof HttpError) return fail(res, err.status, err.code, err.message, err.extra);
  if (err?.type === "entity.parse.failed" || err?.type === "entity.too.large") {
    return fail(res, 400, "VALIDATION", "Permintaan tidak valid.");
  }
  console.error("[error]", err?.message);
  return fail(res, 500, "INTERNAL", "Terjadi kesalahan pada server.");
});

const server = app.listen(config.port, config.host, () => {
  console.log(`qx-api gatekeeper listening on http://${config.host}:${config.port}`);
});

for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => server.close(() => process.exit(0)));