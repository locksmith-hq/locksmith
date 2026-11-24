import { HttpException } from "@nestjs/common";

// Mirror of services/control-plane/src/problem.rs: same kinds, statuses, titles and `type` URIs.
export const PROBLEM_JSON = "application/problem+json";

export const KINDS = {
  validation: { status: 400, title: "Invalid request" },
  unprocessable: { status: 422, title: "Request refused" },
  unauthenticated: { status: 401, title: "Authentication required" },
  "email-verification-required": { status: 403, title: "Email verification required" },
  // Not in Rust yet: a valid, verified caller whose role is too low (see progress.md, task 3.1).
  forbidden: { status: 403, title: "Forbidden" },
  "not-found": { status: 404, title: "Resource not found" },
  conflict: { status: 409, title: "Conflict" },
  "payload-too-large": { status: 413, title: "Request body too large" },
  "unsupported-media-type": { status: 415, title: "Unsupported media type" },
  unavailable: { status: 503, title: "Service unavailable" },
  internal: { status: 500, title: "Internal error" },
} as const;

export type Kind = keyof typeof KINDS;

export type Problem = { type: string; title: string; status: number; detail?: string };

export const typeUri = (kind: Kind) => `urn:locksmith:problem:${kind}`;

export function problemBody(kind: Kind, detail?: string): Problem {
  const { status, title } = KINDS[kind];
  return { type: typeUri(kind), title, status, ...(detail === undefined ? {} : { detail }) };
}

/** Throw this from a handler to return a problem. `detail` must never contain request data. */
export class ProblemException extends HttpException {
  constructor(
    readonly kind: Kind,
    readonly detail?: string,
  ) {
    super(problemBody(kind, detail), KINDS[kind].status);
  }
}

const BY_STATUS: Record<number, Kind> = {
  400: "validation",
  401: "unauthenticated",
  403: "forbidden",
  404: "not-found",
  409: "conflict",
  413: "payload-too-large",
  415: "unsupported-media-type",
  422: "unprocessable",
  503: "unavailable",
};

/** Map any thrown value to a problem. Framework messages are dropped: only the status picks the kind. */
export function toProblem(e: unknown): Problem {
  if (e instanceof ProblemException) return problemBody(e.kind, e.detail);
  if (e instanceof HttpException) return problemBody(BY_STATUS[e.getStatus()] ?? (e.getStatus() < 500 ? "validation" : "internal"));
  return problemBody("internal");
}
