import { AuditSink, AuditSinkError, type AuditEventInput } from "./audit-sink.js";

const TIMEOUT_MS = 5_000;

/**
 * Appends through the Rust core's `POST /v1/audit/events` (services/core/src/audit_event.rs).
 * Replaced by `@locksmith/core-client` when B1 5.4 lands. The token is sent only in the
 * Authorization header; neither it nor any body is ever logged or put in an error.
 */
export class CoreAuditSink extends AuditSink {
  private readonly url: string;

  constructor(
    baseUrl: string,
    private readonly token: string,
  ) {
    super();
    this.url = `${baseUrl.replace(/\/+$/, "")}/v1/audit/events`;
  }

  async append(e: AuditEventInput): Promise<void> {
    const body = {
      org_id: e.orgId,
      kind: e.kind,
      outcome: "ok",
      actor: { type: "user", id: e.actorUserId },
      target: { type: "org", id: e.orgId },
      attrs: e.issuerHost ? { issuer: e.issuerHost } : {},
      ...(e.idempotencyKey ? { idempotency_key: e.idempotencyKey } : {}),
    };
    let res: Response;
    try {
      res = await fetch(this.url, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${this.token}` },
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
