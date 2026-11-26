import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { GenericContainer, Wait, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createKysely, type Database } from "../../db/db.module.js";
import { TenantService } from "../../tenant/tenant.service.js";
import { EmailDeliveryJob } from "./email.job.js";
import { FanoutJob } from "./fanout.job.js";

// t5-honey-tokens 4.2: one honey.triggered event gives the owner one inbox item and one email naming the
// token, agent and path, and a canary planted in every non-allow-listed field never reaches either.
// Real Postgres (app role) and Mailpit. Needs Docker.
const ORG = "0192f3a0-0000-7000-8000-0000000000d1";
const USER = "0192f3a0-0000-7000-8000-0000000000d2";
const AGENT = "0192f3a0-0000-7000-8000-0000000000d3";
const PROJ = "0192f3a0-0000-7000-8000-0000000000d4";
const ENV = "0192f3a0-0000-7000-8000-0000000000d5";
const SECRET = "0192f3a0-0000-7000-8000-0000000000d6";
const ADMIN_PASSWORD = "admin-test-only";
const CANARY = "CANARY-AKIA" + "HONEYDECOY0123";

let pgc: StartedTestContainer;
let mail: StartedTestContainer;
let admin: pg.Client;
let db: Database;
let tenant: TenantService;

const migrationsDir = new URL("../../../../../services/control-plane/migrations/", import.meta.url);
const hash = "'\\x" + "00".repeat(32) + "'";

beforeAll(async () => {
  pgc = await new GenericContainer("postgres:18.7")
    .withEnvironment({ POSTGRES_PASSWORD: ADMIN_PASSWORD })
    .withExposedPorts(5432)
    .withWaitStrategy(Wait.forLogMessage(/database system is ready to accept connections/, 2))
    .start();
  mail = await new GenericContainer("axllent/mailpit:v1.21.8")
    .withExposedPorts(1025, 8025)
    .withWaitStrategy(Wait.forLogMessage(/accessible via/))
    .start();
  const hostPort = `${pgc.getHost()}:${pgc.getMappedPort(5432)}`;
  admin = new pg.Client({ connectionString: `postgres://postgres:${ADMIN_PASSWORD}@${hostPort}/postgres` });
  await admin.connect();
  const files = readdirSync(fileURLToPath(migrationsDir))
    .filter((f) => f.endsWith(".sql"))
    .sort();
  for (const name of files) await admin.query(readFileSync(fileURLToPath(new URL(name, migrationsDir)), "utf8"));
  // The CANARY sits in the free-text description columns, which are never part of a payload.
  await admin.query(
    `insert into orgs (id, name) values ('${ORG}', 'org-d');
     insert into users (id, issuer, subject, personal_org_id, email) values ('${USER}', 'https://issuer.test', 'd', '${ORG}', 'owner@example.test');
     insert into agents (id, org_id, name, description, enrollment_hash) values ('${AGENT}', '${ORG}', 'ci-bot', '${CANARY}', '$argon2id$test');
     insert into projects (id, org_id, name) values ('${PROJ}', '${ORG}', 'p');
     insert into environments (id, org_id, project_id, name) values ('${ENV}', '${ORG}', '${PROJ}', 'prod');
     insert into secrets (id, org_id, project_id, environment_id, name, description, kind, honey_template)
       values ('${SECRET}', '${ORG}', '${PROJ}', '${ENV}', 'decoy-aws', '${CANARY}', 'honey', 'aws_access_key');`,
  );
  db = createKysely(`postgres://locksmith_app:locksmith-app-dev-only@${hostPort}/postgres`, 2);
  tenant = new TenantService(db, { set() {}, get() {} } as never);
}, 240_000);

afterAll(async () => {
  await db?.destroy();
  await admin?.end();
  await pgc?.stop();
  await mail?.stop();
});

describe("honey.triggered alert", () => {
  it("the org's default rules deliver it to the owner by inbox and email", async () => {
    const r = await admin.query(
      `select channel, enabled from notification_rules where org_id = $1 and kind = 'honey.triggered' order by channel`,
      [ORG],
    );
    expect(r.rows).toEqual([
      { channel: "email", enabled: true },
      { channel: "inbox", enabled: true },
      { channel: "slack", enabled: false },
    ]);
  });

  it("gives one inbox item and one email naming token, agent and path, and no canary", async () => {
    // Canaries in non-allow-listed attrs: unknown keys, a nested object, and values that fail their
    // field's shape (a path and a peer that are not codes or hosts).
    const attrs = {
      honey_template: { code: "aws_access_key" },
      binding_id: { id: "0192f3a0-0000-7000-8000-0000000000d7" },
      path: { code: "relay" },
      peer_address: { host: "10.0.0.7" },
      value: { text: CANARY },
      authorization: { text: `Bearer ${CANARY}` },
      body: { nested: { deep: CANARY } },
      session_id: { text: CANARY },
    };
    await admin.query(
      `insert into audit_events (org_id, seq, id, at, kind, actor, target, outcome, attrs, prev_hash, hash)
       values ($1, 1, gen_random_uuid(), now(), 'honey.triggered', $2, $3, 'denied', $4::jsonb, ${hash}, ${hash})`,
      [ORG, `agent:${AGENT}`, `secret:${SECRET}`, JSON.stringify(attrs)],
    );

    const fanout = new FanoutJob(db, tenant, {} as never);
    expect(await fanout.runOnce()).toBe(1);
    expect(await fanout.runOnce()).toBe(0);

    const items = await tenant.run(ORG, (tx) => tx.selectFrom("notifications").selectAll().execute());
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ user_id: USER, kind: "honey.triggered", read_at: null });
    expect(items[0]!.payload).toMatchObject({
      kind: "honey.triggered",
      actor: { id: AGENT, name: "ci-bot" },
      object_name: "decoy-aws",
      honey: {
        token: { id: SECRET, name: "decoy-aws" },
        template: "aws_access_key",
        agent: { id: AGENT, name: "ci-bot" },
        binding: "0192f3a0-0000-7000-8000-0000000000d7",
        path: "relay",
        peer_address: "10.0.0.7",
        console_link: `/projects/${PROJ}/environments/${ENV}/honey-tokens`,
      },
    });
    expect(Object.keys((items[0]!.payload as { honey: object }).honey).sort()).toEqual(
      ["agent", "binding", "console_link", "occurred_at", "path", "peer_address", "template", "token"],
    );
    expect(JSON.stringify(items[0]!.payload)).not.toContain(CANARY);

    const job = new EmailDeliveryJob(db, tenant, {} as never, { get: () => undefined } as never);
    job.configure({ host: mail.getHost(), port: mail.getMappedPort(1025), from: "locksmith@example.test" });
    expect((await job.runOnce()).sent).toBe(1);

    const base = `http://${mail.getHost()}:${mail.getMappedPort(8025)}/api/v1`;
    const list = (await (await fetch(`${base}/messages`)).json()) as { total: number; messages: { ID: string }[] };
    expect(list.total).toBe(1);
    const full = await (await fetch(`${base}/message/${list.messages[0]!.ID}`)).text();
    expect(full).toContain("owner@example.test");
    for (const named of ["decoy-aws", "ci-bot", "relay"]) expect(full).toContain(named);
    expect(full).not.toContain(CANARY);
  });

  it("a path or peer that fails its shape is dropped, never copied", async () => {
    const attrs = {
      path: { code: `relay ${CANARY}` },
      peer_address: { text: CANARY },
      binding_id: { text: CANARY },
    };
    await admin.query(
      `insert into audit_events (org_id, seq, id, at, kind, actor, target, outcome, attrs, prev_hash, hash)
       values ($1, 2, gen_random_uuid(), now(), 'honey.triggered', $2, $3, 'denied', $4::jsonb, ${hash}, ${hash})`,
      [ORG, `agent:${AGENT}`, `secret:${SECRET}`, JSON.stringify(attrs)],
    );
    expect(await new FanoutJob(db, tenant, {} as never).runOnce()).toBe(1);
    const items = await tenant.run(ORG, (tx) => tx.selectFrom("notifications").selectAll().orderBy("created_at", "desc").execute());
    expect(items[0]!.payload).toMatchObject({ honey: { path: null, peer_address: null, binding: null } });
    expect(JSON.stringify(items.map((i) => i.payload))).not.toContain(CANARY);
  });
});
