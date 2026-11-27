// Turns a recorded HTTP exchange into a transcript that two servers can be compared on:
// ids, timestamps and tokens become placeholders numbered by first appearance, so a reference
// between responses (the id created is the id read back) survives and a fresh run matches.

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const IS_UUID = new RegExp(`^${UUID.source}$`, "i");
const TIMESTAMP = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})/g;
const JWT = /eyJ[\w-]+\.[\w-]+\.[\w-]*/g;
const SECRET_KEY = /(token|secret|password|authorization)$/i;
// JWKS key material differs per process and page cursors encode row ids; the shape is what the contract pins.
const KEY_FIELD = /^(kid|x|next|handle|digest|prev_digest|ciphertext|wrapped_dek)$/;

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** Headers kept in a transcript; the rest (date, server, content-length) differ per server. */
const KEPT_HEADERS = ["content-type", "location", "cache-control", "www-authenticate"];

export class Normaliser {
  private readonly seen = new Map<string, string>();
  private readonly counts = new Map<string, number>();

  private placeholder(kind: string, value: string): string {
    const key = `${kind}:${value}`;
    let out = this.seen.get(key);
    if (out === undefined) {
      const n = (this.counts.get(kind) ?? 0) + 1;
      this.counts.set(kind, n);
      out = `<${kind}-${n}>`;
      this.seen.set(key, out);
    }
    return out;
  }

  private readonly literals = new Map<string, string>();

  /** Registers a value that is unique to this run (for example the seed suffix in names). */
  literal(value: string, placeholder: string): void {
    this.literals.set(value, placeholder);
  }

  /** Replaces every id, timestamp and token inside one string. */
  text(s: string): string {
    for (const [value, placeholder] of this.literals) s = s.split(value).join(placeholder);
    return s
      .replace(JWT, (m) => this.placeholder("token", m))
      .replace(TIMESTAMP, (m) => this.placeholder("ts", m))
      .replace(UUID, (m) => this.placeholder("id", m.toLowerCase()));
  }

  /** Walks a JSON value; string values under a token, secret or password key are redacted. */
  json(value: Json, key = ""): Json {
    if (typeof value === "string") {
      if (value !== "" && KEY_FIELD.test(key)) return this.placeholder("key", value);
      if (value !== "" && SECRET_KEY.test(key) && !IS_UUID.test(value)) {
        return this.placeholder("token", value);
      }
      return this.text(value);
    }
    if (Array.isArray(value)) return value.map((v) => this.json(v, key));
    if (value !== null && typeof value === "object") {
      const out: { [key: string]: Json } = {};
      for (const k of Object.keys(value).sort()) out[k] = this.json(value[k] as Json, k);
      return out;
    }
    return value;
  }

  /** Keeps the comparable headers, lower-cased and sorted, with their values normalised. */
  headers(h: Headers | Record<string, string>): Record<string, string> {
    const get = (n: string) => (h instanceof Headers ? h.get(n) : (h[n] ?? null));
    const out: Record<string, string> = {};
    for (const name of KEPT_HEADERS) {
      const v = get(name);
      // `charset=utf-8` is implied for JSON; Express adds it and axum does not, so it is not part of the contract.
      if (v !== null) out[name] = this.text(name === "content-type" ? v.replace(/;\s*charset=utf-8$/i, "") : v);
    }
    return out;
  }
}
