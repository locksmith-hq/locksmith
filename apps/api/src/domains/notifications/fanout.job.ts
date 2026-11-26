import { Inject, Injectable, Logger, type OnModuleInit } from "@nestjs/common";
import { PgBoss } from "pg-boss";
import { KYSELY, type Database } from "../../db/db.module.js";
import { PG_BOSS } from "../../jobs/jobs.service.js";
import { TenantService, type Tx } from "../../tenant/tenant.service.js";
import { NotifyKind } from "./notification.schemas.js";

const FANOUT_QUEUE = "notify.fanout";
/** pg-boss cron has one-minute resolution, so the job re-queues itself 2 s after each run (design decision 1). */
const FANOUT_INTERVAL_SECONDS = 2;
const BATCH = 500;

type Kind = (typeof NotifyKind.options)[number];

/** Allow-listed payload (design decision 6), built from typed ledger columns, never from `attrs`. */
export interface Payload {
  kind: Kind;
  actor: { id: string; name: string } | null;
  object_name: string | null;
  occurred_at: string;
  link: string;
  /** Present only on `honey.triggered` (t5 honey tokens); mirrors `HoneyTriggeredDetail`. */
  honey?: HoneyDetail;
}

export interface HoneyDetail {
  token: { id: string; name: string };
  template: "aws_access_key" | "github_pat" | "slack_token" | "generic_api_key";
  agent: { id: string; name: string } | null;
  binding: string | null;
  path: string | null;
  peer_address: string | null;
  occurred_at: string;
  console_link: string;
}

const HONEY_TEMPLATES = new Set(["aws_access_key", "github_pat", "slack_token", "generic_api_key"]);
const PATH_CODE = /^[a-z][a-z0-9_.-]{0,31}$/;
const PEER = /^[a-z0-9.:[\]-]{1,255}$/i;

/**
 * One typed attr of a ledger event (`{"<key>": {"<tag>": "<value>"}}`), only when it has one of the
 * expected tags and matches `ok`; anything else reads as absent.
 */
function attr(attrs: unknown, key: string, tags: string[], ok: (v: string) => boolean): string | null {
  const entry = attrs && typeof attrs === "object" ? (attrs as Record<string, unknown>)[key] : null;
  if (!entry || typeof entry !== "object") return null;
  for (const tag of tags) {
    const v = (entry as Record<string, unknown>)[tag];
    if (typeof v === "string" && ok(v)) return v;
  }
  return null;
}

const REF = /^([a-z]+):([a-z0-9_.-]{1,64})$/;
const REF_ID = /^[a-z0-9_.-]{1,64}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function parseRef(ref: string | null): { type: string; id: string } | null {
  const m = ref ? REF.exec(ref) : null;
  return m ? { type: m[1]!, id: m[2]! } : null;
}

/**
 * Fan-out from committed ledger rows (n1 design decision 1): per org, read `audit_events` after the
 * cursor, map notifiable kinds, resolve recipients from the rules matrix and write inbox and delivery
 * rows, advancing the cursor in the same transaction (so a rerun creates no duplicates).
 */
@Injectable()
export class FanoutJob implements OnModuleInit {
  private readonly log = new Logger(FanoutJob.name);

  constructor(
    @Inject(KYSELY) private readonly db: Database,
    @Inject(TenantService) private readonly tenant: TenantService,
    @Inject(PG_BOSS) private readonly boss: PgBoss,
  ) {}

  async onModuleInit(): Promise<void> {
    await this.boss.createQueue(FANOUT_QUEUE);
    await this.boss.work(FANOUT_QUEUE, async () => {
      try {
        await this.runOnce();
      } finally {
        await this.boss.send(FANOUT_QUEUE, {}, { startAfter: FANOUT_INTERVAL_SECONDS, singletonKey: FANOUT_QUEUE });
      }
    });
    // Bootstraps the chain and restarts it if it ever dies.
    await this.boss.schedule(FANOUT_QUEUE, "* * * * *", {}, { singletonKey: FANOUT_QUEUE });
  }

  /** One pass over every org (also how tests drive the job). Returns the notifications written. */
  async runOnce(): Promise<number> {
    // The cursor table is listable with no org bound (migration 0019); everything else needs one.
    const orgs = await this.db.selectFrom("notification_cursors").select("org_id").execute();
    let written = 0;
    for (const { org_id } of orgs) {
      try {
        written += await this.tenant.run(org_id, (tx) => this.processOrg(tx, org_id));
      } catch (err) {
        // Fixed message: one org's failure must not stop the others, and no row data is logged.
        this.log.error(`fanout failed for one org: ${err instanceof Error ? err.name : "error"}`);
      }
    }
    return written;
  }

  private async processOrg(tx: Tx, orgId: string): Promise<number> {
    const cursor = await tx
      .selectFrom("notification_cursors")
      .select("last_seq")
      .where("org_id", "=", orgId)
      .forUpdate()
      .executeTakeFirst();
    if (!cursor) return 0;
    const events = await tx
      .selectFrom("audit_events")
      .select(["seq", "kind", "actor", "target", "attrs", "at"])
      .where("org_id", "=", orgId)
      .where("seq", ">", cursor.last_seq)
      .orderBy("seq")
      .limit(BATCH)
      .execute();
    if (events.length === 0) return 0;

    const rules = await tx
      .selectFrom("notification_rules")
      .select(["kind", "channel", "audience", "audience_user_id"])
      .where("org_id", "=", orgId)
      .where("enabled", "=", true)
      .execute();
    // Until T6 roles exist the org owner is the user whose personal org this is.
    const owners = await tx.selectFrom("users").select("id").where("personal_org_id", "=", orgId).execute();

    let written = 0;
    for (const ev of events) {
      const kind = NotifyKind.safeParse(ev.kind);
      if (!kind.success) continue;
      const matching = rules.filter((r) => r.kind === kind.data);
      if (matching.length === 0) continue;
      const payload = await this.buildPayload(tx, orgId, kind.data, ev);
      const recipients = new Map<string, Set<string>>();
      for (const r of matching) {
        const users = r.audience === "owner" ? owners.map((o) => o.id) : r.audience_user_id ? [r.audience_user_id] : [];
        for (const u of users) (recipients.get(u) ?? recipients.set(u, new Set()).get(u)!).add(r.channel);
      }
      for (const [userId, channels] of recipients) {
        const row = await tx
          .insertInto("notifications")
          .values({ org_id: orgId, user_id: userId, kind: kind.data, payload: JSON.stringify(payload) })
          .returning("id")
          .executeTakeFirstOrThrow();
        await tx
          .insertInto("notification_deliveries")
          .values(
            [...channels].map((channel) => ({
              org_id: orgId,
              notification_id: row.id,
              channel,
              // The inbox row is the delivery; email and Slack are picked up by their jobs.
              state: channel === "inbox" ? "sent" : "pending",
            })),
          )
          .execute();
        written += 1;
      }
    }
    await tx
      .updateTable("notification_cursors")
      .set({ last_seq: events[events.length - 1]!.seq })
      .where("org_id", "=", orgId)
      .execute();
    return written;
  }

  private async buildPayload(
    tx: Tx,
    orgId: string,
    kind: Kind,
    ev: { actor: string; target: string | null; attrs: unknown; at: Date | string },
  ): Promise<Payload> {
    const actor = parseRef(ev.actor);
    const target = parseRef(ev.target);
    const agentName = async (ref: { type: string; id: string } | null): Promise<string | null> => {
      if (ref?.type !== "agent" || !UUID.test(ref.id)) return null;
      const a = await tx
        .selectFrom("agents")
        .select("name")
        .where("org_id", "=", orgId)
        .where("id", "=", ref.id)
        .executeTakeFirst();
      return a?.name ?? null;
    };
    const actorName = (await agentName(actor)) ?? actor?.id ?? null;
    const objectName = (await agentName(target)) ?? target?.id ?? null;
    const payload: Payload = {
      kind,
      actor: actor && actorName ? { id: actor.id, name: actorName } : null,
      object_name: objectName,
      occurred_at: new Date(ev.at).toISOString(),
      link: target?.type === "agent" && UUID.test(target.id) ? `/agents/${target.id}` : "/audit",
    };
    if (kind === "honey.triggered") {
      const honey = await this.honeyDetail(tx, orgId, ev, actor, target, agentName);
      if (honey) {
        payload.honey = honey;
        payload.object_name = honey.token.name;
        payload.link = honey.console_link;
      }
    }
    return payload;
  }

  /**
   * The allow-listed `honey` detail, from typed ledger fields: the target secret (id, looked up for its
   * name), the agent actor, and the template, binding, path and peer attrs, each validated against a
   * fixed shape. Never copies `attrs` and never touches a secret value. Null when the target is not a
   * secret of this org.
   */
  private async honeyDetail(
    tx: Tx,
    orgId: string,
    ev: { attrs: unknown; at: Date | string },
    actor: { type: string; id: string } | null,
    target: { type: string; id: string } | null,
    agentName: (ref: { type: string; id: string } | null) => Promise<string | null>,
  ): Promise<HoneyDetail | null> {
    if (target?.type !== "secret" || !UUID.test(target.id)) return null;
    const secret = await tx
      .selectFrom("secrets as s")
      .innerJoin("environments as e", "e.id", "s.environment_id")
      .select(["s.name", "s.honey_template", "s.project_id", "s.environment_id"])
      .where("s.org_id", "=", orgId)
      .where("s.id", "=", target.id)
      .executeTakeFirst();
    const template = attr(ev.attrs, "honey_template", ["code"], (v) => HONEY_TEMPLATES.has(v)) ?? secret?.honey_template ?? null;
    if (!template || !HONEY_TEMPLATES.has(template)) return null;
    const name = await agentName(actor);
    return {
      token: { id: target.id, name: secret?.name ?? target.id },
      template: template as HoneyDetail["template"],
      agent: actor?.type === "agent" && UUID.test(actor.id) && name ? { id: actor.id, name } : null,
      binding: attr(ev.attrs, "binding_id", ["id", "code"], (v) => REF_ID.test(v)),
      path: attr(ev.attrs, "path", ["code"], (v) => PATH_CODE.test(v)),
      peer_address: attr(ev.attrs, "peer_address", ["host", "code"], (v) => PEER.test(v)),
      occurred_at: new Date(ev.at).toISOString(),
      console_link: secret ? `/projects/${secret.project_id}/environments/${secret.environment_id}/honey-tokens` : "/audit",
    };
  }
}
