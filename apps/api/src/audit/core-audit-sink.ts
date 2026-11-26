import { Inject, Injectable, ServiceUnavailableException } from "@nestjs/common";
import type { CoreClient } from "@locksmith/core-client";
import { CORE_CLIENT } from "../core/core.tokens.js";
import type { AuditSink, AuthAuditEvent } from "./audit-sink.js";

/**
 * The real audit sink: appends through the Rust core, which hashes, chains and signs. Fails
 * closed: any core failure (down, 4xx, 5xx, refused attrs) refuses the request with 503, so an
 * action never succeeds unrecorded. The event carries ids and the issuer host only.
 */
@Injectable()
export class CoreAuditSink implements AuditSink {
  constructor(@Inject(CORE_CLIENT) private readonly core: CoreClient) {}

  async append(event: AuthAuditEvent): Promise<void> {
    try {
      await this.core.appendAuditEvent({
        org_id: event.orgId,
        kind: event.kind,
        outcome: event.outcome,
        actor: { type: "user", id: event.userId },
        target: { type: "org", id: event.orgId },
        attrs: event.issuerHost ? { issuer: event.issuerHost } : {},
      });
    } catch {
      // Never forward the cause: it could echo core response text.
      throw new ServiceUnavailableException();
    }
  }
}
