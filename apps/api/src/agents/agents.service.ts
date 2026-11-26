import { Inject, Injectable, ServiceUnavailableException } from "@nestjs/common";
import { sql } from "kysely";
import type { CoreClient } from "@locksmith/core-client";
import { AUDIT_SINK, type AuditSink, DEV_AUTH_ACTOR } from "../audit/audit-sink.js";
import { CORE_CLIENT } from "../core/core.tokens.js";
import { validateName, uuidv7 } from "../orgs/orgs.service.js";
import { type Page, paged } from "../platform/paging.js";
import { ProblemException } from "../platform/problem.js";
import { validateDescription } from "../projects/validate.js";
import { TenantService, type Tx } from "../tenant/tenant.service.js";
import type { Agent, AgentGrant, GrantScope, NewAgentGrant } from "./agents.schemas.js";

type AgentRow = { id: string; name: string; description: string; created_at: Date; updated_at: Date };
const iso = (d: Date) => new Date(d).toISOString();
const toAgent = (r: AgentRow): Agent => ({
  id: r.id,
  name: r.name,
  description: r.description,
  created_at: iso(r.created_at),
  updated_at: iso(r.updated_at),
});
const AGENT_COLS = ["id", "name", "description", "created_at", "updated_at"] as const;

type GrantRow = {
  id: string;
  agent_id: string;
  secret_id: string;
  secret_name: string;
  mode: string;
  scope: unknown;
  expires_at: Date | null;
  created_at: Date;
};
const toGrant = (r: GrantRow): AgentGrant => ({
  id: r.id,
  agent_id: r.agent_id,
  secret_id: r.secret_id,
  secret_name: r.secret_name,
  mode: r.mode === "delegate" ? "delegate" : "relay",
  scope: (r.scope as GrantScope | null) ?? null,
  expires_at: r.expires_at ? iso(r.expires_at) : null,
  created_at: iso(r.created_at),
});

/** Rust `GrantScope::validate`. */
function validateScope(scope: { actions: string[]; resources: string[]; max_duration_secs?: number | null }): void {
  const MAX_ITEMS = 64;
  const MAX_LEN = 512;
  const bad = (m: string) => new ProblemException("validation", m);
  if (scope.actions.length === 0 || scope.resources.length === 0)
    throw bad("scope needs at least one action and one resource");
  if (scope.actions.length > MAX_ITEMS || scope.resources.length > MAX_ITEMS) throw bad("scope has too many entries");
  const invalid = (v: string) => v === "" || [...v].length > MAX_LEN || /\p{Cc}/u.test(v);
  if (scope.actions.some(invalid) || scope.resources.some(invalid))
    throw bad("scope entries must be non-empty printable strings");
  if (scope.max_duration_secs === 0) throw bad("max_duration_secs must be positive");
}

/**
 * Agents and their grants, in the request's tenant transaction. Every write appends its audit
 * event through the core before the transaction commits: a failing core rolls the change back
 * (fail closed), so neither lands without the other (Rust `api/agents.rs`).
 */
@Injectable()
export class AgentsService {
  constructor(
    @Inject(TenantService) private readonly tenant: TenantService,
    @Inject(CORE_CLIENT) private readonly core: CoreClient,
    @Inject(AUDIT_SINK) private readonly audit: AuditSink,
  ) {}

  private get tx(): Tx {
    return this.tenant.tx();
  }

  private get orgId(): string {
    return this.tenant.orgId()!;
  }

  /** A new enrollment secret and its Argon2id hash, made by the core. Any core failure is a 503 with no core text. */
  private async newEnrollment(agentId: string): Promise<{ secret: string; hash: string }> {
    try {
      const r = await this.core.generateEnrollmentSecret({ org_id: this.orgId, agent_id: agentId });
      return { secret: r.enrollment_secret, hash: r.enrollment_hash };
    } catch {
      throw new ServiceUnavailableException();
    }
  }

  async create(name: string, description: string): Promise<{ agent: Agent; enrollment_secret: string }> {
    validateName(name);
    validateDescription(description);
    const id = uuidv7();
    const { secret, hash } = await this.newEnrollment(id);
    const row = await this.tx
      .insertInto("agents")
      .values({ id, org_id: this.orgId, name, description, enrollment_hash: hash })
      .returning(AGENT_COLS)
      .executeTakeFirstOrThrow();
    await this.audit.appendAdmin({
      kind: "agent.created",
      orgId: this.orgId,
      actor: DEV_AUTH_ACTOR,
      target: { type: "agent", id },
      attrs: {},
    });
    return { agent: toAgent(row), enrollment_secret: secret };
  }

  async list(page: Page) {
    let q = this.tx.selectFrom("agents").select(AGENT_COLS);
    if (page.after) q = q.where("id", ">", page.after);
    const rows = await q
      .orderBy("id")
      .limit(page.limit + 1)
      .execute();
    return paged(rows.map(toAgent), page);
  }

  async get(id: string): Promise<Agent> {
    const row = await this.tx.selectFrom("agents").select(AGENT_COLS).where("id", "=", id).executeTakeFirst();
    if (!row) throw new ProblemException("not-found");
    return toAgent(row);
  }

  /** Grants go with the agent (ON DELETE CASCADE); their count is recorded on the event. */
  async remove(id: string): Promise<void> {
    const count = await this.tx
      .selectFrom("agent_grants")
      .select(sql<string>`count(*)`.as("n"))
      .where("agent_id", "=", id)
      .executeTakeFirstOrThrow();
    const res = await this.tx.deleteFrom("agents").where("id", "=", id).executeTakeFirst();
    if (res.numDeletedRows === 0n) throw new ProblemException("not-found");
    await this.audit.appendAdmin({
      kind: "agent.deleted",
      orgId: this.orgId,
      actor: DEV_AUTH_ACTOR,
      target: { type: "agent", id },
      attrs: { grants_revoked: Number(count.n) },
    });
  }

  async rotate(id: string): Promise<{ agent: Agent; enrollment_secret: string }> {
    const { secret, hash } = await this.newEnrollment(id);
    const row = await this.tx
      .updateTable("agents")
      .set({ enrollment_hash: hash, updated_at: sql<Date>`now()` })
      .where("id", "=", id)
      .returning(AGENT_COLS)
      .executeTakeFirst();
    if (!row) throw new ProblemException("not-found");
    await this.audit.appendAdmin({
      kind: "agent.rotated",
      orgId: this.orgId,
      actor: DEV_AUTH_ACTOR,
      target: { type: "agent", id },
      attrs: {},
    });
    return { agent: toAgent(row), enrollment_secret: secret };
  }

  private async requireAgent(id: string): Promise<void> {
    const row = await this.tx.selectFrom("agents").select("id").where("id", "=", id).executeTakeFirst();
    if (!row) throw new ProblemException("not-found");
  }

  private grantQuery() {
    return this.tx
      .selectFrom("agent_grants as g")
      .innerJoin("secrets as s", (j) => j.onRef("s.org_id", "=", "g.org_id").onRef("s.id", "=", "g.secret_id"))
      .select([
        "g.id",
        "g.agent_id",
        "g.secret_id",
        "s.name as secret_name",
        "g.mode",
        "g.scope",
        "g.expires_at",
        "g.created_at",
      ]);
  }

  async createGrant(agentId: string, input: NewAgentGrant): Promise<AgentGrant> {
    if (input.expires_at != null && new Date(input.expires_at).getTime() <= Date.now())
      throw new ProblemException("validation", "`expires_at` must be in the future");
    let scope: GrantScope | null = null;
    if (input.mode === "relay") {
      if (input.scope != null) throw new ProblemException("validation", "`scope` is only for `delegate` grants");
    } else {
      if (input.scope == null) throw new ProblemException("validation", "a `delegate` grant needs a `scope`");
      validateScope(input.scope);
      scope = {
        actions: input.scope.actions,
        resources: input.scope.resources,
        ...(input.scope.max_duration_secs != null ? { max_duration_secs: input.scope.max_duration_secs } : {}),
      };
    }
    await this.requireAgent(agentId);
    const secret = await this.tx.selectFrom("secrets").select("id").where("id", "=", input.secret_id).executeTakeFirst();
    if (!secret) throw new ProblemException("not-found");
    let inserted: { id: string };
    try {
      inserted = await this.tx
        .insertInto("agent_grants")
        .values({
          org_id: this.orgId,
          agent_id: agentId,
          secret_id: input.secret_id,
          mode: input.mode,
          scope: scope === null ? null : JSON.stringify(scope),
          expires_at: input.expires_at != null ? new Date(input.expires_at) : null,
        })
        .returning("id")
        .executeTakeFirstOrThrow();
    } catch (e) {
      if ((e as { code?: string }).code === "23505")
        throw new ProblemException("conflict", "the agent already holds a grant for this secret and mode");
      throw e;
    }
    const row = await this.grantQuery().where("g.id", "=", inserted.id).executeTakeFirstOrThrow();
    const grant = toGrant(row);
    await this.audit.appendAdmin({
      kind: "grant.created",
      orgId: this.orgId,
      actor: DEV_AUTH_ACTOR,
      target: { type: "grant", id: grant.id },
      attrs: {
        agent_id: agentId,
        secret_id: grant.secret_id,
        mode: grant.mode,
        ...(grant.expires_at ? { expires_at: Math.floor(new Date(grant.expires_at).getTime() / 1000) } : {}),
      },
    });
    return grant;
  }

  async listGrants(agentId: string, page: Page) {
    await this.requireAgent(agentId);
    let q = this.grantQuery().where("g.agent_id", "=", agentId);
    if (page.after) q = q.where("g.id", ">", page.after);
    const rows = await q
      .orderBy("g.id")
      .limit(page.limit + 1)
      .execute();
    return paged(rows.map(toGrant), page);
  }

  async revokeGrant(agentId: string, grantId: string): Promise<void> {
    const res = await this.tx
      .deleteFrom("agent_grants")
      .where("id", "=", grantId)
      .where("agent_id", "=", agentId)
      .executeTakeFirst();
    if (res.numDeletedRows === 0n) throw new ProblemException("not-found");
    await this.audit.appendAdmin({
      kind: "grant.revoked",
      orgId: this.orgId,
      actor: DEV_AUTH_ACTOR,
      target: { type: "grant", id: grantId },
      attrs: { agent_id: agentId },
    });
  }
}
