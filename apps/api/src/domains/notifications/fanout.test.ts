import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { GenericContainer, Wait, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createKysely, type Database } from "../../db/db.module.js";
import { TenantService } from "../../tenant/tenant.service.js";
import { FanoutJob } from "./fanout.job.js";

// N1 task 3.2: the fan-out job against a real Postgres as the app role. Needs Docker.
const ORG_A = "0192f3a0-0000-7000-8000-0000000000a1";
const ORG_B = "0192f3a0-0000-7000-8000-0000000000b1";
const USER_A = "0192f3a0-0000-7000-8000-0000000000a2";
const USER_B = "0192f3a0-0000-7000-8000-0000000000b2";
const AGENT_A = "0192f3a0-0000-7000-8000-0000000000a3";
const ADMIN_PASSWORD = "admin-test-only";
const CANARY = "CANARY-sk_live_0123456789";

let container: StartedTestContainer;
let admin: pg.Client;
let db: Database;
let tenant: TenantService;
let job: FanoutJob;

const migrationsDir = new URL("../../../../../services/control-plane/migrations/", import.meta.url);
const hash = "'\\x" + "00".repeat(32) + "'";

async function event(org: string, seq: number, kind: string, actor: string, target: string | null, attrs = "{}") {
  await admin.query(
    `insert into audit_events (org_id, seq, id, at, kind, actor, target, outcome, attrs, prev_hash, hash)
     values ($1, $2, gen_random_uuid(), now(), $3, $4, $5, 'success', $6::jsonb, ${hash}, ${hash})`,
    [org, seq, kind, actor, target, attrs],
  );
}

beforeAll(async () => {
  container = await new GenericContainer("postgres:18.7")
    .withEnvironment({ POSTGRES_PASSWORD: ADMIN_PASSWORD })
    .withExposedPorts(5432)
    .withWaitStrategy(Wait.forLogMessage(/database system is ready to accept connections/, 2))
    .start();
  const hostPort = `${container.getHost()}:${container.getMappedPort(5432)}`;
  admin = new pg.Client({ connectionString: `postgres://postgres:${ADMIN_PASSWORD}@${hostPort}/postgres` });
  await admin.connect();
  const files = readdirSync(fileURLToPath(migrationsDir))
    .filter((f) => f.endsWith(".sql"))
    .sort();
  for (const name of files) await admin.query(readFileSync(fileURLToPath(new URL(name, migrationsDir)), "utf8"));
  await admin.query(
    `insert into orgs (id, name) values ('${ORG_A}', 'org-a'), ('${ORG_B}', 'org-b');
     insert into users (id, issuer, subject, personal_org_id) values
       ('${USER_A}', 'https://issuer.test', 'a', '${ORG_A}'),
       ('${USER_B}', 'https://issuer.test', 'b', '${ORG_B}');
     insert into agents (id, org_id, name, enrollment_hash) values ('${AGENT_A}', '${ORG_A}', 'ci-bot', '$argon2id$test');`,
  );
  db = createKysely(`postgres://locksmith_app:locksmith-app-dev-only@${hostPort}/postgres`, 2);
  tenant = new TenantService(db, { set() {}, get() {} } as never);
  job = new FanoutJob(db, tenant, {} as never);
}, 180_000);

afterAll(async () => {
  await db?.destroy();
  await admin?.end();
  await container?.stop();
});

const inbox = (org: string) => tenant.run(org, (tx) => tx.selectFrom("notifications").selectAll().execute());
const cursor = async (org: string) =>
  (await tenant.run(org, (tx) => tx.selectFrom("notification_cursors").select("last_seq").where("org_id", "=", org).executeTakeFirstOrThrow()))
    .last_seq;

describe("fan-out job", () => {
  it("routes a notifiable event to the org owner's inbox and ignores other kinds", async () => {
    await event(ORG_A, 1, "agent.created", `user:${USER_A}`, `agent:${AGENT_A}`);
    await event(ORG_A, 2, "grant.revoked", `user:${USER_A}`, `agent:${AGENT_A}`, `{"token": "${CANARY}"}`);
    expect(await job.runOnce()).toBe(1);
    const rows = await inbox(ORG_A);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ user_id: USER_A, kind: "grant.revoked", read_at: null });
    expect(rows[0]!.payload).toMatchObject({
      kind: "grant.revoked",
      actor: { id: USER_A, name: USER_A },
      object_name: "ci-bot",
      link: `/agents/${AGENT_A}`,
    });
    const deliveries = await tenant.run(ORG_A, (tx) => tx.selectFrom("notification_deliveries").selectAll().execute());
    expect(deliveries.map((d) => [d.channel, d.state])).toEqual([["inbox", "sent"]]);
    expect(await cursor(ORG_A)).toBe("2");
  });

  it("never copies a non-allow-listed ledger field (canary) into a payload", async () => {
    expect(JSON.stringify(await inbox(ORG_A))).not.toContain(CANARY);
    expect(Object.keys((await inbox(ORG_A))[0]!.payload as object).sort()).toEqual(
      ["actor", "kind", "link", "object_name", "occurred_at"],
    );
  });

  it("a rerun creates no duplicates", async () => {
    expect(await job.runOnce()).toBe(0);
    expect(await inbox(ORG_A)).toHaveLength(1);
  });

  it("orgs advance independently", async () => {
    await event(ORG_B, 1, "relay.denied", "agent:x1", null);
    await event(ORG_B, 2, "git.denied", "agent:x1", null);
    await event(ORG_A, 3, "agent.deleted", `user:${USER_A}`, `agent:${AGENT_A}`);
    expect(await job.runOnce()).toBe(3);
    expect((await inbox(ORG_B)).map((r) => [r.user_id, r.kind])).toEqual([
      [USER_B, "relay.denied"],
      [USER_B, "git.denied"],
    ]);
    expect(await inbox(ORG_A)).toHaveLength(2);
    expect([await cursor(ORG_A), await cursor(ORG_B)]).toEqual(["3", "2"]);
  });

  it("a disabled rule produces nothing, an enabled email rule adds a pending delivery", async () => {
    await admin.query(
      `update notification_rules set enabled = false where org_id = '${ORG_B}' and kind = 'relay.denied';
       update notification_rules set enabled = true where org_id = '${ORG_B}' and kind = 'git.denied' and channel = 'email'`,
    );
    await event(ORG_B, 3, "relay.denied", "agent:x1", null);
    await event(ORG_B, 4, "git.denied", "agent:x1", null);
    expect(await job.runOnce()).toBe(1);
    const d = await tenant.run(ORG_B, (tx) =>
      tx.selectFrom("notification_deliveries").select(["channel", "state"]).orderBy("created_at", "desc").execute(),
    );
    expect(d.slice(0, 2).map((x) => `${x.channel}:${x.state}`).sort()).toEqual(["email:pending", "inbox:sent"]);
    expect(await cursor(ORG_B)).toBe("4");
  });
});
