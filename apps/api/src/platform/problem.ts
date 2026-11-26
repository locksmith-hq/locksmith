import { type ArgumentsHost, Catch, type ExceptionFilter, HttpException, Logger } from "@nestjs/common";
import type { Response } from "express";
import { ZodError } from "zod";

/** Media type of every error body (Rust `problem::PROBLEM_JSON`). */
export const PROBLEM_JSON = "application/problem+json";

/**
 * The error kinds, with the same status, title and `type` URI as the Rust `problem::Kind`.
 * `forbidden` exists only here: Rust has no per-org roles, so it has no generic 403 (decision B6-2).
 */
const KINDS = {
  validation: { status: 400, title: "Invalid request" },
  unprocessable: { status: 422, title: "Request refused" },
  unauthenticated: { status: 401, title: "Authentication required" },
  "email-verification-required": { status: 403, title: "Email verification required" },
  forbidden: { status: 403, title: "Forbidden" },
  "not-found": { status: 404, title: "Resource not found" },
  conflict: { status: 409, title: "Conflict" },
  "payload-too-large": { status: 413, title: "Request body too large" },
  "unsupported-media-type": { status: 415, title: "Unsupported media type" },
  unavailable: { status: 503, title: "Service unavailable" },
  internal: { status: 500, title: "Internal error" },
  "not-implemented": { status: 501, title: "Not implemented" },
} as const;

export type ProblemKind = keyof typeof KINDS;

/** The JSON body of an error response (Rust `problem::Problem`). */
interface Problem {
  type: string;
  title: string;
  status: number;
  detail?: string;
}

function problemBody(kind: ProblemKind, detail?: string): Problem {
  const { status, title } = KINDS[kind];
  return { type: `urn:locksmith:problem:${kind}`, title, status, ...(detail === undefined ? {} : { detail }) };
}

/** Throw this for an API error with a known kind. The detail never carries request data. */
export class ProblemException extends HttpException {
  constructor(
    readonly kind: ProblemKind,
    readonly detail?: string,
  ) {
    super(problemBody(kind, detail), KINDS[kind].status);
  }
}

const BY_STATUS: Record<number, ProblemKind> = {
  400: "validation",
  401: "unauthenticated",
  403: "forbidden",
  404: "not-found",
  409: "conflict",
  413: "payload-too-large",
  415: "unsupported-media-type",
  422: "unprocessable",
  501: "not-implemented",
  503: "unavailable",
};

/** Name of the first offending field, never its value (Rust names the field only). */
function zodDetail(e: ZodError): string {
  const issue = e.issues[0];
  const path = issue?.path.join(".");
  if (!path) return "invalid request";
  // serde's wording for an absent field, which the frozen contract records.
  return issue?.code === "invalid_type" && issue.message.endsWith("received undefined")
    ? `missing field \`${path}\``
    : `invalid field: ${path}`;
}

/**
 * Turns every thrown error into an RFC 9457 `application/problem+json` body. A Nest exception
 * keeps its status; its message is dropped (it may echo input). Anything unexpected is a bare 500
 * and only its class is logged, never its message or stack text.
 */
@Catch()
export class ProblemFilter implements ExceptionFilter {
  private readonly log = new Logger(ProblemFilter.name);

  catch(error: unknown, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();
    const { kind, detail } = this.classify(error);
    const body = problemBody(kind, detail);
    res.status(body.status).type(PROBLEM_JSON).send(body);
  }

  private classify(error: unknown): { kind: ProblemKind; detail?: string } {
    if (error instanceof ProblemException)
      return { kind: error.kind, ...(error.detail ? { detail: error.detail } : {}) };
    if (error instanceof ZodError) return { kind: "validation", detail: zodDetail(error) };
    if (error instanceof HttpException) {
      const kind = BY_STATUS[error.getStatus()];
      if (kind) return { kind };
      if (error.getStatus() < 500) return { kind: "unprocessable" };
    }
    // body-parser (malformed JSON, oversized body) throws http-errors, not Nest exceptions.
    const status = (error as { status?: unknown } | null)?.status;
    if (typeof status === "number" && BY_STATUS[status] && status < 500) return { kind: BY_STATUS[status]! };
    this.log.error(`unhandled error: ${error instanceof Error ? error.constructor.name : typeof error}`);
    return { kind: "internal" };
  }
}
