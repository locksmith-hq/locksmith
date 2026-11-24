import type { Exchange } from "./client.ts";
import type { Json } from "./normalise.ts";

export interface Difference {
  /** `METHOD /path` of the exchange, taken from the scenario step that differs. */
  where: string;
  field: string;
  a: unknown;
  b: unknown;
}

function firstJsonDiff(
  a: Json | null | undefined,
  b: Json | null | undefined,
  at: string,
): [string, unknown, unknown] | null {
  if (JSON.stringify(a) === JSON.stringify(b)) return null;
  if (
    a !== null &&
    b !== null &&
    typeof a === "object" &&
    typeof b === "object" &&
    Array.isArray(a) === Array.isArray(b)
  ) {
    const keys = Array.isArray(a)
      ? Array.from({ length: Math.max(a.length, (b as Json[]).length) }, (_, i) => String(i))
      : [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
    for (const k of keys) {
      const av = (a as Record<string, Json>)[k];
      const bv = (b as Record<string, Json>)[k];
      const d = firstJsonDiff(av, bv, Array.isArray(a) ? `${at}[${k}]` : `${at}.${k}`);
      if (d) return d;
    }
  }
  return [at, a, b];
}

/** First differing status, header or body field per exchange name; empty when the transcripts match. */
export function diffTranscripts(a: Exchange[], b: Exchange[]): Difference[] {
  const out: Difference[] = [];
  const byName = new Map(b.map((e) => [e.name, e]));
  const seenNames = new Set<string>();
  for (const ea of a) {
    seenNames.add(ea.name);
    const where = `${ea.method} ${ea.path} (${ea.name})`;
    const eb = byName.get(ea.name);
    if (!eb) {
      out.push({ where, field: "exchange", a: "present", b: "missing" });
    } else if (ea.status !== eb.status) {
      out.push({ where, field: "status", a: ea.status, b: eb.status });
    } else {
      const h = firstJsonDiff(ea.headers, eb.headers, "headers");
      const d = h ?? firstJsonDiff(ea.body, eb.body, "body");
      if (d) out.push({ where, field: d[0], a: d[1], b: d[2] });
    }
  }
  for (const eb of b) {
    if (!seenNames.has(eb.name)) {
      out.push({ where: `${eb.method} ${eb.path} (${eb.name})`, field: "exchange", a: "missing", b: "present" });
    }
  }
  return out;
}
