// pino's `redact` paths cannot match key-name fragments, so this walks the log
// object and censors any key that looks sensitive. Header paths stay in
// REDACT_PATHS as a second layer.
export const REDACT_PATHS = [
  "req.headers.authorization",
  "req.headers.cookie",
  'res.headers["set-cookie"]',
];

const SENSITIVE_KEY = /secret|token|password|passwd|authorization|cookie|api[-_]?key/i;
const CENSOR = "[redacted]";

function redactDeep(value: unknown, depth = 0): unknown {
  if (depth > 8 || value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, depth + 1));
  // Only plain objects: live req/res/socket objects are left for the serializers.
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return value;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = SENSITIVE_KEY.test(k) ? CENSOR : redactDeep(v, depth + 1);
  }
  return out;
}

export const loggerFormatters = {
  log: (obj: Record<string, unknown>) => redactDeep(obj) as Record<string, unknown>,
};

// pino-http wraps these around its own std serializers, so they receive the
// already-serialized plain req/res; redact that.
// pino-http serialized values carry a prototype; copy their enumerable fields to a plain object.
const plain = (v: unknown) =>
  v !== null && typeof v === "object" ? { ...(v as Record<string, unknown>) } : v;

export const loggerSerializers = {
  req: (req: unknown) => redactDeep(plain(req)),
  res: (res: unknown) => redactDeep(plain(res)),
};
