import type { Params } from "nestjs-pino";
import { stdSerializers } from "pino";

// pino's `redact` paths accept `*` only as a whole segment, so credential headers are listed exactly and every other
// field is scrubbed by name (secret, token, password, authorization, cookie, key material) at any depth.
const REDACT_PATHS = [
  "req.headers.authorization",
  "req.headers.cookie",
  'res.headers["set-cookie"]',
];

const SENSITIVE = /secret|token|x-auth|password|passwd|authorization|cookie|private[_-]?key|api[_-]?key/i;
const CENSOR = "[redacted]";

const SENSITIVE_QUERY = /([?&][^=&#\s]*(?:secret|token|password|key|code)[^=&#\s]*=)[^&#\s]*/gi;
function scrubText(t: string): string {
  return t.replace(SENSITIVE_QUERY, "$1[redacted]");
}

function scrub(value: unknown, depth = 0): unknown {
  if (depth > 8 || value === null || typeof value !== "object") return value;
  if (value instanceof Error) {
    // Error fields are non-enumerable; keep them (message and stack), scrub the rest.
    return { type: value.name, message: scrubText(value.message), stack: scrubText(value.stack ?? ""), ...(scrub({ ...value }, depth + 1) as object) };
  }
  if (Array.isArray(value)) return value.map((v) => scrub(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = SENSITIVE.test(k) ? CENSOR : typeof v === "string" ? scrubText(v) : scrub(v, depth + 1);
  }
  return out;
}

export const pinoOptions = {
  redact: { paths: REDACT_PATHS, censor: CENSOR },
  // req and res are raw objects here; their serializers (which scrub by name) handle them.
  formatters: {
    log: (o: Record<string, unknown>) => {
      const { req, res, ...rest } = o;
      return { ...(scrub(rest) as Record<string, unknown>), ...(req ? { req } : {}), ...(res ? { res } : {}) };
    },
  },
  serializers: {
    req: (r: { url?: string }) => {
      const o = stdSerializers.req(r as never) as unknown as Record<string, unknown>;
      return { ...(scrub(o) as object), url: scrubText(r.url ?? "") };
    },
    res: (r: unknown) => scrub(stdSerializers.res(r as never)),
  },
};

export function loggerParams(level: string): Params {
  return { pinoHttp: { level, ...pinoOptions } };
}
