import { Inject, Injectable, Logger } from "@nestjs/common";
import { sql } from "kysely";
import { ProblemException } from "../../platform/problem/problem.js";
import { TenantService, type Tx } from "../../tenant/tenant.service.js";
import { HONEY_MINTER, type HoneyMinter, type HoneyTemplate } from "./honey-minter.js";

/** Metadata only. There is deliberately no value: the decoy lives sealed in the core. */
export type HoneyTokenView = {
  id: string;
  name: string;
  template: HoneyTemplate;
  created_at: string;
  disabled_at: string | null;
  last_triggered_at: string | null;
};

type Scope = { orgId: string; projectId: string; environmentId: string };

const UNIQUE_VIOLATION = "23505";

// The ledger target of a triggered honey token is `secret:<id>` (crates/ls-audit, change t5).
const select = (tx: Tx) =>
  tx
    .selectFrom("secrets as s")
    .select([
      "s.id",
      "s.name",
      "s.honey_template",
      "s.created_at",
      "s.disabled_at",
      (eb) =>
        eb
          .selectFrom("audit_events as a")
          .select((b) => b.fn.max("a.at").as("at"))
          .where("a.kind", "=", "honey.triggered")
          .whereRef("a.target", "=", sql<string>`'secret:' || s.id::text`)
          .as("last_triggered_at"),
    ])
    .where("s.kind", "=", "honey");

type Row = Awaited<ReturnType<ReturnType<typeof select>["execute"]>>[number];

const iso = (v: unknown): string | null => (v == null ? null : new Date(v as string | Date).toISOString());

const view = (r: Row): HoneyTokenView => ({
  id: r.id,
  name: r.name,
  template: r.honey_template as HoneyTemplate,
  created_at: iso(r.created_at)!,
  disabled_at: iso(r.disabled_at),
  last_triggered_at: iso(r.last_triggered_at),
});

/**
 * Honey token metadata for an environment (t5 task 2.3). Every step runs in its own tenant transaction
 * (`TenantService.run`), so row-level security scopes it to the org and the secret row is committed before
 * the core is asked to seal its value.
 */
@Injectable()
export class HoneyTokensService {
  private readonly log = new Logger("honey-tokens");

  constructor(
    @Inject(TenantService) private readonly tenant: TenantService,
    @Inject(HONEY_MINTER) private readonly minter: HoneyMinter | null,
  ) {}

  list(s: Scope): Promise<HoneyTokenView[]> {
    return this.tenant.run(s.orgId, async (tx) => {
      await this.requireEnvironment(tx, s);
      const rows = await select(tx)
        .where("s.project_id", "=", s.projectId)
        .where("s.environment_id", "=", s.environmentId)
        .orderBy("s.created_at")
        .orderBy("s.id")
        .execute();
      return rows.map(view);
    });
  }

  async create(s: Scope, input: { name: string; template: HoneyTemplate }): Promise<HoneyTokenView> {
    if (!this.minter) throw new ProblemException("unavailable");
    const id = await this.tenant.run(s.orgId, async (tx) => {
      await this.requireEnvironment(tx, s);
      try {
        const row = await tx
          .insertInto("secrets")
          .values({
            org_id: s.orgId,
            project_id: s.projectId,
            environment_id: s.environmentId,
            name: input.name,
            kind: "honey",
            honey_template: input.template,
          })
          .returning("id")
          .executeTakeFirstOrThrow();
        return row.id;
      } catch (e) {
        if ((e as { code?: string }).code === UNIQUE_VIOLATION) throw new ProblemException("conflict");
        throw e;
      }
    });
    try {
      await this.minter.mint(s.orgId, id, input.template);
    } catch (e) {
      // No sealed value: remove the row so the name can be reused. Best effort; the original error wins.
      await this.tenant
        .run(s.orgId, (tx) => tx.deleteFrom("secrets").where("id", "=", id).where("kind", "=", "honey").execute())
        .catch(() => this.log.error({ event: "honey.mint_cleanup_failed" }));
      throw e;
    }
    return this.get(s, id);
  }

  async disable(s: Scope, id: string): Promise<HoneyTokenView> {
    const done = await this.tenant.run(s.orgId, (tx) =>
      tx
        .updateTable("secrets")
        .set({ disabled_at: sql<Date>`coalesce(disabled_at, now())`, updated_at: sql<Date>`now()` })
        .where("id", "=", id)
        .where("kind", "=", "honey")
        .where("project_id", "=", s.projectId)
        .where("environment_id", "=", s.environmentId)
        .returning("id")
        .executeTakeFirst(),
    );
    if (!done) throw new ProblemException("not-found");
    return this.get(s, id);
  }

  async remove(s: Scope, id: string): Promise<void> {
    const gone = await this.tenant.run(s.orgId, (tx) =>
      tx
        .deleteFrom("secrets")
        .where("id", "=", id)
        .where("kind", "=", "honey")
        .where("project_id", "=", s.projectId)
        .where("environment_id", "=", s.environmentId)
        .returning("id")
        .executeTakeFirst(),
    );
    if (!gone) throw new ProblemException("not-found");
  }

  private async get(s: Scope, id: string): Promise<HoneyTokenView> {
    const row = await this.tenant.run(s.orgId, (tx) =>
      select(tx)
        .where("s.id", "=", id)
        .where("s.project_id", "=", s.projectId)
        .where("s.environment_id", "=", s.environmentId)
        .executeTakeFirst(),
    );
    if (!row) throw new ProblemException("not-found");
    return view(row);
  }

  private async requireEnvironment(tx: Tx, s: Scope): Promise<void> {
    const env = await tx
      .selectFrom("environments")
      .select("id")
      .where("id", "=", s.environmentId)
      .where("project_id", "=", s.projectId)
      .executeTakeFirst();
    if (!env) throw new ProblemException("not-found");
  }
}
