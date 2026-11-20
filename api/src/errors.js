export class HttpError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

/** Format respons error yang konsisten untuk frontend. */
export function fail(res, status, code, message, extra = {}) {
  return res.status(status).json({ ok: false, error: { code, message }, ...extra });
}

/** Bungkus handler async supaya error masuk ke error-handler Express. */
export const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

export function parse(schema, data) {
  const r = schema.safeParse(data);
  if (!r.success) throw new HttpError(400, "VALIDATION", "Permintaan tidak valid.");
  return r.data;
}
