import { Inject, Injectable, Logger } from "@nestjs/common";
import { AUDIT_SINK, type AuditSink, DEV_AUTH_ACTOR, issuerHost } from "../audit/audit-sink.js";
import { validateName, uuidv7 } from "../orgs/orgs.service.js";
import { type Page, paged } from "../platform/paging.js";
import { ProblemException } from "../platform/problem.js";
import { TenantService, type Tx } from "../tenant/tenant.service.js";
import type { NewWorkloadIdentity, WorkloadIdentity } from "./workload-identities.schemas.js";
import {
  type Condition,
  encodeHandle,
  issuerHostAllowed,
  parseIssuerKind,
  PolicyError,
  toPattern,
  validate,
} from "./validate.js";

type Row = {
  id: string;
  org_id: string;
  name: string;
  issuer_kind: string;
  issuer: string;
  audience: string;
  agent_id: string;
  conditions: unknown;
  created_at: Date;
  last_used_at: Date | null;
};
const COLS = [
  "id",
  "org_id",
  "name",
  "issuer_kind",
  "issuer",
  "audience",
  "agent_id",
  "conditions",
  "created_at",
  "last_used_at",
] as const;
const iso = (d: Date) => new Date(d).toISOString();

const toView = (r: Row): WorkloadIdentity => ({
  id: r.id,
  name: r.name,
  issuer_kind: r.issuer_kind,
  issuer: r.issuer,
  audience: r.audience,
  agent_id: r.agent_id,
  conditions: (r.conditions as Condition[]).map((c) => ({ claim: c.claim, pattern: toPattern(c) })),
  handle: encodeHandle(r.org_id, r.id),
  created_at: iso(r.created_at),
  last_used_at: r.last_used_at ? iso(r.last_used_at) : null,
});

/**
 * Workload identity trust policies (Rust `api/workload_identities.rs`). Configuration only: no row or response
 * holds a token or secret. Create and delete append their audit event before the transaction commits (a failing
 * sink rolls the change back), so neither lands without the other.
 */
@Injectable()
export class WorkloadIdentitiesService {
  private readonly log = new Logger(WorkloadIdentitiesService.name);

  constructor(
    @Inject(TenantService) private readonly tenant: TenantService,
    @Inject(AUDIT_SINK) private readonly audit: AuditSink,
  ) {}

  private get tx(): Tx {
    return this.tenant.tx();
  }

  private get orgId(): string {
    return this.tenant.orgId()!;
  }

  async create(input: NewWorkloadIdentity): Promise<WorkloadIdentity> {
    validateName(input.name);
    const kind = parseIssuerKind(input.issuer_kind);
    if (kind === null) throw new ProblemException("validation", "issuer_kind must be `github` or `oidc`");
    let policy;
    try {
      policy = validate(
        input.name,
        kind,
        input.issuer,
        input.audience,
        input.conditions.map((c) => ({ claim: c.claim, value: c.pattern })),
      );
    } catch (e) {
      if (e instanceof PolicyError) throw new ProblemException("unprocessable", e.detail);
      throw e;
    }
    // A private or metadata issuer address is refused at create time. Makes no HTTP request.
    if (!issuerHostAllowed(policy.issuer, process.env["LOCKSMITH_WORKLOAD_ALLOW_PRIVATE_ISSUERS"] === "1"))
      throw new ProblemException("unprocessable", "the issuer host is not an allowed address");

    const agent = await this.tx.selectFrom("agents").select("id").where("id", "=", input.agent_id).executeTakeFirst();
    if (!agent) throw new ProblemException("not-found");

    const id = uuidv7();
    let row: Row;
    try {
      row = await this.tx
        .insertInto("workload_identities")
        .values({
          id,
          org_id: this.orgId,
          name: input.name.trim(),
          issuer_kind: policy.issuer_kind,
          issuer: policy.issuer,
          audience: policy.audience,
          agent_id: input.agent_id,
          conditions: JSON.stringify(policy.conditions),
        })
        .returning(COLS)
        .executeTakeFirstOrThrow();
    } catch (e) {
      if ((e as { code?: string }).code === "23505")
        throw new ProblemException("conflict", "a workload identity with this name exists");
      throw e;
    }
    const host = issuerHost(policy.issuer);
    await this.audit.appendAdmin({
      kind: "workload_identity.created",
      orgId: this.orgId,
      actor: DEV_AUTH_ACTOR,
      target: { type: "workload", id },
      attrs: { agent_id: input.agent_id, ...(host ? { issuer: host } : {}) },
    });
    this.log.log(`workload identity created policy=${id} agent=${input.agent_id}`);
    return toView(row);
  }

  async list(page: Page) {
    let q = this.tx.selectFrom("workload_identities").select(COLS);
    if (page.after) q = q.where("id", ">", page.after);
    const rows = await q
      .orderBy("id")
      .limit(page.limit + 1)
      .execute();
    return paged(rows.map(toView), page);
  }

  async get(id: string): Promise<WorkloadIdentity> {
    const row = await this.tx.selectFrom("workload_identities").select(COLS).where("id", "=", id).executeTakeFirst();
    if (!row) throw new ProblemException("not-found");
    return toView(row);
  }

  async remove(id: string): Promise<void> {
    const row = await this.tx
      .deleteFrom("workload_identities")
      .where("id", "=", id)
      .returning("agent_id")
      .executeTakeFirst();
    if (!row) throw new ProblemException("not-found");
    await this.audit.appendAdmin({
      kind: "workload_identity.deleted",
      orgId: this.orgId,
      actor: DEV_AUTH_ACTOR,
      target: { type: "workload", id },
      attrs: { agent_id: row.agent_id },
    });
    this.log.log(`workload identity deleted policy=${id}`);
  }
}
