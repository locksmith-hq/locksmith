import { Inject, Injectable } from "@nestjs/common";
import { ProblemException } from "../platform/problem.js";
import { type Page, paged } from "../platform/paging.js";
import { TenantService, type Tx } from "../tenant/tenant.service.js";
import type { Agent, AgentGrant, GrantScope } from "./agents.schemas.js";

const iso = (d: Date) => new Date(d).toISOString();

/** Explicit column lists: `enrollment_hash` is never selected. */
const AGENT_COLS = ["id", "name", "description", "created_at", "updated_at"] as const;

type AgentRow = { id: string; name: string; description: string; created_at: Date; updated_at: Date };
const toAgent = (r: AgentRow): Agent => ({
  id: r.id,
  name: r.name,
  description: r.description,
  created_at: iso(r.created_at),
  updated_at: iso(r.updated_at),
});

/** Same key order and omissions as Rust's `GrantScope` serializer (`max_duration_secs` is skipped when null). */
function toScope(raw: unknown): GrantScope | null {
  if (raw === null || raw === undefined) return null;
  const v = raw as { actions?: string[]; resources?: string[]; max_duration_secs?: number | null };
  return {
    actions: v.actions ?? [],
    resources: v.resources ?? [],
    ...(v.max_duration_secs != null ? { max_duration_secs: v.max_duration_secs } : {}),
  };
}

/** Agents and their grants, read-only, in the request's tenant transaction (row-level security scopes every query). */
@Injectable()
export class AgentsService {
  constructor(@Inject(TenantService) private readonly tenant: TenantService) {}

  private get tx(): Tx {
    return this.tenant.tx();
  }

  async listAgents(page: Page) {
    let q = this.tx.selectFrom("agents").select(AGENT_COLS);
    if (page.after) q = q.where("id", ">", page.after);
    const rows = await q
      .orderBy("id")
      .limit(page.limit + 1)
      .execute();
    return paged(rows.map(toAgent), page);
  }

  async getAgent(id: string): Promise<Agent> {
    const row = await this.tx.selectFrom("agents").select(AGENT_COLS).where("id", "=", id).executeTakeFirst();
    if (!row) throw new ProblemException("not-found");
    return toAgent(row);
  }

  async listGrants(agentId: string, page: Page) {
    const agent = await this.tx.selectFrom("agents").select("id").where("id", "=", agentId).executeTakeFirst();
    if (!agent) throw new ProblemException("not-found");
    let q = this.tx
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
      ])
      .where("g.agent_id", "=", agentId);
    if (page.after) q = q.where("g.id", ">", page.after);
    const rows = await q
      .orderBy("g.id")
      .limit(page.limit + 1)
      .execute();
    const grants: AgentGrant[] = rows.map((r) => ({
      id: r.id,
      agent_id: r.agent_id,
      secret_id: r.secret_id,
      secret_name: r.secret_name,
      mode: r.mode as AgentGrant["mode"],
      scope: toScope(r.scope),
      expires_at: r.expires_at ? iso(r.expires_at) : null,
      created_at: iso(r.created_at),
    }));
    return paged(grants, page);
  }
}
