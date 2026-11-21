// Locksmith SDK: a typed client over the control-plane OpenAPI schema.
// Nothing here logs or persists a response body.
import createClient, { type Client } from "openapi-fetch";
import type { paths, components } from "./schema";

export type { paths, components };
export type LocksmithClient = Client<paths>;

export interface LocksmithOptions {
  baseUrl: string;
  /** Bearer token, or a function read on every request so a renewed token is used. */
  token: string | (() => string | undefined);
  fetch?: typeof fetch;
}

export function createLocksmith(opts: LocksmithOptions): LocksmithClient {
  const client = createClient<paths>({ baseUrl: opts.baseUrl, fetch: opts.fetch });
  client.use({
    onRequest({ request }) {
      const token = typeof opts.token === "function" ? opts.token() : opts.token;
      if (token) request.headers.set("authorization", `Bearer ${token}`);
      return request;
    },
  });
  return client;
}

/** RFC 9457 problem details as the control plane returns them. */
export interface ProblemFields {
  type?: string;
  title?: string;
  detail?: string;
  [k: string]: unknown;
}

export class LocksmithError extends Error {
  constructor(
    public readonly status: number,
    public readonly problem: ProblemFields = {},
  ) {
    super(problem.detail ?? problem.title ?? `request failed with status ${status}`);
    this.name = "LocksmithError";
  }
}

/** Unwrap an openapi-fetch result: return data, or throw a `LocksmithError`. */
export function unwrap<T>(r: { data?: T; error?: unknown; response: Response }): T {
  if (r.error !== undefined || r.data === undefined) {
    const p = r.error && typeof r.error === "object" ? (r.error as ProblemFields) : {};
    throw new LocksmithError(r.response.status, p);
  }
  return r.data;
}

/** Follow `next` cursors, yielding each page until none remains. */
export async function* paginate<P extends { next?: string | null }>(
  fetchPage: (cursor: string | null) => Promise<P>,
): AsyncGenerator<P> {
  let cursor: string | null = null;
  do {
    const page: P = await fetchPage(cursor);
    yield page;
    cursor = page.next ?? null;
  } while (cursor);
}
