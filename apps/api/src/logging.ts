import type { Params } from "nestjs-pino";

// pino's `redact` paths accept `*` only as a whole segment, so credential headers are listed exactly and every other
// field is scrubbed by name (secret, token, password, authorization, cookie, key material) at any depth.
const REDACT_PATHS = [
  "req.headers.authorization",
  "req.headers.cookie",
  'res.headers["set-cookie"]',
];

const SENSITIVE = /secret|token|password|passwd|authorization|cookie|private[_-]?key|api[_-]?key/i;
const CENSOR = "[redacted]";

function scrub(value: unknown, depth = 0): unknown {
  if (depth > 8 || value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => scrub(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = SENSITIVE.test(k) ? CENSOR : scrub(v, depth + 1);
  }
  return out;
}

export const pinoOptions = {
  redact: { paths: REDACT_PATHS, censor: CENSOR },
  formatters: { log: (o: Record<string, unknown>) => scrub(o) as Record<string, unknown> },
};

export function loggerParams(level: string): Params {
  return { pinoHttp: { level, ...pinoOptions } };
}
