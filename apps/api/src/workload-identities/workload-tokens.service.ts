import { Inject, Injectable, Logger, ServiceUnavailableException } from "@nestjs/common";
import type { CoreClient } from "@locksmith/core-client";
import { AUDIT_SINK, type AuditSink, issuerHost } from "../audit/audit-sink.js";
import { CORE_CLIENT } from "../core/core.tokens.js";
import { ProblemException } from "../platform/problem.js";
import { TenantService } from "../tenant/tenant.service.js";
import { FixedWindowLimiter } from "./fixed-window.js";
import { decodeHandle } from "./validate.js";

/** A `last_used_at` write is skipped when the stored value is newer than this many seconds. */
const LAST_USED_THROTTLE_SECS = 300;
const PER_POLICY = 60;
const PER_SOURCE = 30;

export interface WorkloadToken {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  expires_at: string;
}

/**
 * `POST /v1/workload-tokens` (Rust `api/workload_tokens.rs`). The external token is the credential and is passed to
 * the core once (it verifies issuer, audience, conditions and `jti` replay, and mints the agent token); this service
 * never parses, stores or logs it. Every credential failure is the same 401, with a static reason only in the
 * `workload_identity.denied` ledger event. A refusal by rate limit is not written to the ledger.
 *
 * Differences from Rust, by design of the core boundary: the ledger event carries the agent and the issuer host but
 * not the policy's named claim values (the core's verdict does not return claims), and the per-source and
 * per-policy limits here run on top of the core's own per-policy limit.
 */
@Injectable()
export class WorkloadTokensService {
  private readonly log = new Logger(WorkloadTokensService.name);
  private readonly perSource = new FixedWindowLimiter(PER_SOURCE);
  private readonly perPolicy = new FixedWindowLimiter(PER_POLICY);

  constructor(
    @Inject(TenantService) private readonly tenant: TenantService,
    @Inject(CORE_CLIENT) private readonly core: CoreClient,
    @Inject(AUDIT_SINK) private readonly audit: AuditSink,
  ) {}

  async exchange(handle: string, externalToken: string, source: string | undefined): Promise<WorkloadToken> {
    if (source !== undefined && !this.perSource.allow(source)) throw new ProblemException("unauthenticated");
    const ids = decodeHandle(handle);
    if (!ids) throw new ProblemException("unauthenticated");
    if (!this.perPolicy.allow(ids.policyId)) throw new ProblemException("unauthenticated");

    const policy = await this.tenant.run(ids.orgId, (tx) =>
      tx
        .selectFrom("workload_identities")
        .select(["issuer", "agent_id"])
        .where("id", "=", ids.policyId)
        .executeTakeFirst(),
    );
    if (!policy) throw new ProblemException("unauthenticated");

    let reason = "not_trusted";
    try {
      const verdict = await this.core.verifyWorkloadToken({ policy: handle, token: externalToken });
      if (verdict.valid) {
        const t = await this.core.mintWorkloadToken({
          org_id: ids.orgId,
          agent_id: policy.agent_id,
          policy_id: ids.policyId,
        });
        // Fail closed: the token is returned only once the exchange is on the ledger.
        await this.audit.appendAdmin({
          kind: "workload_identity.exchanged",
          orgId: ids.orgId,
          actor: { type: "agent", id: policy.agent_id },
          target: { type: "workload", id: ids.policyId },
          attrs: { agent_id: policy.agent_id, ...hostAttr(policy.issuer) },
        });
        await this.touchLastUsed(ids.orgId, ids.policyId);
        return { access_token: t.token, token_type: "Bearer", expires_in: t.expires_in, expires_at: t.expires_at };
      }
      reason = verdict.reason ?? "not_trusted";
    } catch (e) {
      if (e instanceof ProblemException) throw e;
      // A core failure (4xx, 5xx, unreachable, or the audit sink failing closed) is never a credential verdict:
      // no ledger denial and no core text.
      throw new ServiceUnavailableException();
    }
    await this.recordDenied(ids.orgId, ids.policyId, policy, reason);
    throw new ProblemException("unauthenticated");
  }

  private async touchLastUsed(orgId: string, policyId: string): Promise<void> {
    try {
      await this.tenant.run(orgId, async (tx) => {
        await tx
          .updateTable("workload_identities")
          .set({ last_used_at: new Date() })
          .where("id", "=", policyId)
          .where((eb) =>
            eb.or([
              eb("last_used_at", "is", null),
              eb("last_used_at", "<", new Date(Date.now() - LAST_USED_THROTTLE_SECS * 1000)),
            ]),
          )
          .execute();
      });
    } catch {
      this.log.warn("workload identity last_used_at could not be updated");
    }
  }

  /** Best effort: a refusal is still a 401 when the ledger write fails. */
  private async recordDenied(
    orgId: string,
    policyId: string,
    policy: { issuer: string; agent_id: string },
    reason: string,
  ): Promise<void> {
    try {
      await this.audit.appendAdmin({
        kind: "workload_identity.denied",
        orgId,
        outcome: "denied",
        actor: { type: "service", code: "control_plane" },
        target: { type: "workload", id: policyId },
        attrs: { agent_id: policy.agent_id, ...hostAttr(policy.issuer), reason },
      });
    } catch {
      this.log.warn("workload_identity.denied event could not be recorded");
    }
  }
}

function hostAttr(issuer: string): { issuer?: string } {
  const h = issuerHost(issuer);
  return h ? { issuer: h } : {};
}
