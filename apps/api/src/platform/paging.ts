import { z } from "zod";
import { ProblemException } from "./problem.js";

/** Rust `DEFAULT_PAGE_LIMIT` and `MAX_PAGE_LIMIT`. */
const DEFAULT_PAGE_LIMIT = 50;
const MAX_PAGE_LIMIT = 100;

const UUID = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})$/i;

/** Query of every list: unknown keys, repeated keys and non-integers are one 400, as in Rust's `ApiQuery`. */
const PageQuery = z.strictObject({ limit: z.string().optional(), cursor: z.string().optional() });

/** A path id: anything that is not a UUID cannot name a resource, so it is a 404 (Rust `ApiPath`). */
export function pathId(value: string): string {
  if (!UUID.test(value)) throw new ProblemException("not-found");
  return value.toLowerCase();
}

export interface Page {
  limit: number;
  after: string | null;
}

const encodeCursor = (id: string) => Buffer.from(id.replaceAll("-", ""), "hex").toString("base64url");

/** Canonical base64url of exactly 16 bytes, like the Rust engine (no padding, no stray trailing bits). */
function decodeCursor(cursor: string): string | null {
  if (!/^[A-Za-z0-9_-]+$/.test(cursor)) return null;
  const bytes = Buffer.from(cursor, "base64url");
  if (bytes.length !== 16 || bytes.toString("base64url") !== cursor) return null;
  const h = bytes.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Rust `PageParams::resolve`, after the query parse. `decode` maps a cursor to its key (null when invalid). */
export function resolvePage(raw: unknown, decode: (cursor: string) => string | null = decodeCursor): Page {
  const parsed = PageQuery.safeParse(raw);
  if (!parsed.success) throw new ProblemException("validation", "invalid query parameters");
  const { limit: l, cursor: c } = parsed.data;
  if (l !== undefined && !/^\d{1,10}$/.test(l)) throw new ProblemException("validation", "invalid query parameters");
  const limit = l === undefined ? DEFAULT_PAGE_LIMIT : Number(l);
  if (limit === 0 || limit > MAX_PAGE_LIMIT)
    throw new ProblemException("validation", `\`limit\` must be between 1 and ${MAX_PAGE_LIMIT}`);
  if (c === undefined) return { limit, after: null };
  const after = decode(c);
  if (after === null) throw new ProblemException("validation", "`cursor` is not valid");
  return { limit, after };
}

/** `rows` holds up to `limit + 1` rows ordered by id: the extra one says another page exists. */
export function paged<T extends { id: string }>(rows: T[], page: Page): { items: T[]; next?: string } {
  if (rows.length <= page.limit) return { items: rows };
  const items = rows.slice(0, page.limit);
  return { items, next: encodeCursor(items[items.length - 1]!.id) };
}
