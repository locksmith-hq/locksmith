import { AuditSink, AuditSinkError, type AuditEventInput } from "./audit-sink.js";

const TIMEOUT_MS = 5_000;

/**
 * Appends through the Rust core's `POST /internal/v1/audit/human-events`
 * (services/control-plane/src/api/internal.rs, B8-1): service token plus `X-Locksmith-Org`, and a
 * body of kind, user id and issuer host only. Replaced by `@locksmith/core-client` when B1 5.4
 * lands. The token is sent only in the Authorization header; neither it nor any body is ever
 * logged or put in an error.
 */
export class CoreAuditSink extends AuditSink {
  private readonly url: string;

  constructor(
    baseUrl: string,
    private readonly token: string,
  ) {
    super();
    this.url = `${baseUrl.replace(/\/+$/, "")}/internal/v1/audit/human-events`;
  }

  async append(e: AuditEventInput): Promise<void> {
    const body = { kind: e.kind, user_id: e.actorUserId, ...(e.issuerHost ? { issuer: e.issuerHost } : {}) };
    let res: Response;
    try {
      res = await fetch(this.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.token}`,
          "x-locksmith-org": e.orgId,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch {
      throw new AuditSinkError("unreachable");
    }
    // Drain without reading into memory or logs.
    await res.body?.cancel().catch(() => {});
    if (!res.ok) throw new AuditSinkError("rejected");
  }
}
