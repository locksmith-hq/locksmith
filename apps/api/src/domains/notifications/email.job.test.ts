import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { GenericContainer, Wait, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createKysely, type Database } from "../../db/db.module.js";
import { TenantService } from "../../tenant/tenant.service.js";
import { EmailDeliveryJob, MAX_ATTEMPTS, ORG_CAP_PER_MINUTE, renderEmail } from "./email.job.js";

// N1 task 5.2: the email delivery job against real Postgres and Mailpit. Needs Docker.
const ORG = "0192f3a0-0000-7000-8000-0000000000c1";
const USER = "0192f3a0-0000-7000-8000-0000000000c2";
const ADMIN_PASSWORD = "admin-test-only";
const CANARY = "CANARY-sk_" + "live_0123456789";

let pgc: StartedTestContainer;
let mail: StartedTestContainer;
let admin: pg.Client;
let db: Database;
let tenant: TenantService;
let seq = 0;

const migrationsDir = new URL("../../../../../services/control-plane/migrations/", import.meta.url);

const payload = (kind = "relay.denied") => ({
  kind,
  actor: { id: "a1", name: "ci-bot" },
  object_name: "stripe",
  occurred_at: "2026-11-25T10:00:00.000Z",
  link: "/audit",
});

async function seed(n: number, extra: Record<string, unknown> = {}): Promise<string[]> {
  const ids: string[] = [];
  for (let i = 0; i < n; i++) {
    seq += 1;
    const r = await admin.query(
      `insert into notifications (org_id, user_id, kind, payload) values ($1, $2, 'relay.denied', $3::jsonb) returning id`,
      [ORG, USER, JSON.stringify({ ...payload(), ...extra })],
    );
    const d = await admin.query(
      `insert into notification_deliveries (org_id, notification_id, channel) values ($1, $2, 'email') returning id`,
      [ORG, r.rows[0].id],
    );
    ids.push(d.rows[0].id);
  }
  return ids;
}

const deliveries = (ids: string[]) =>
  admin.query(`select id, state, attempts, last_error_code from notification_deliveries where id = any($1::uuid[])`, [ids]).then((r) => r.rows);

async function mailpitMessages(): Promise<{ total: number; messages: { ID: string; Subject: string }[] }> {
  const res = await fetch(`http://${mail.getHost()}:${mail.getMappedPort(8025)}/api/v1/messages`);
  return (await res.json()) as never;
}

function makeJob(host: string, port: number): EmailDeliveryJob {
  const job = new EmailDeliveryJob(db, tenant, {} as never, { get: () => undefined } as never);
  job.configure({ host, port, from: "locksmith@example.test" });
  job.backoffMs = () => 0;
  return job;
}

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
  await admin.query(
    `insert into orgs (id, name) values ('${ORG}', 'org-c');
     insert into users (id, issuer, subject, personal_org_id, email) values ('${USER}', 'https://issuer.test', 'c', '${ORG}', 'owner@example.test');`,
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

describe("email delivery", () => {
  it("renders only allow-listed fields", () => {
    const m = renderEmail({ ...payload(), kind: "relay.denied" } as never);
    expect(m.subject).toBe("Locksmith: relay.denied");
    expect(m.text).toContain("stripe");
  });

  it("delivers a pending email, marks it sent, and the message holds no secret value", async () => {
    // A canary in a field outside the allow-list must not reach the message.
    const ids = await seed(1, { token: CANARY });
    const job = makeJob(mail.getHost(), mail.getMappedPort(1025));
    expect((await job.runOnce()).sent).toBe(1);
    expect((await deliveries(ids))[0]).toMatchObject({ state: "sent", attempts: 1, last_error_code: null });
    const list = await mailpitMessages();
    expect(list.total).toBe(1);
    const full = await (await fetch(`http://${mail.getHost()}:${mail.getMappedPort(8025)}/api/v1/message/${list.messages[0]!.ID}`)).text();
    expect(full).not.toContain(CANARY);
    expect(full).toContain("owner@example.test");
    expect((await job.runOnce()).sent).toBe(0);
  });

  it("retries while the relay is down, then fails once with a fixed slug", async () => {
    const ids = await seed(1);
    const job = makeJob("127.0.0.1", 1); // nothing listens on port 1
    for (let i = 1; i < MAX_ATTEMPTS; i++) {
      expect((await job.runOnce()).retried).toBe(1);
      expect((await deliveries(ids))[0]).toMatchObject({ state: "pending", attempts: i, last_error_code: "email.smtp_unreachable" });
    }
    expect((await job.runOnce()).failed).toBe(1);
    expect((await deliveries(ids))[0]).toMatchObject({ state: "failed", attempts: MAX_ATTEMPTS, last_error_code: "email.smtp_unreachable" });
    const none = await job.runOnce();
    expect(none).toMatchObject({ sent: 0, retried: 0, failed: 0 });
  });

  it("caps an org at 60 sends a minute and sends the rest later", async () => {
    const ids = await seed(ORG_CAP_PER_MINUTE + 3);
    let t = 1_000_000;
    const job = makeJob(mail.getHost(), mail.getMappedPort(1025));
    job.now = () => t;
    const first = await job.runOnce();
    expect(first.sent).toBe(ORG_CAP_PER_MINUTE);
    expect(first.deferred).toBe(3);
    t += 61_000;
    expect((await job.runOnce()).sent).toBe(3);
    expect((await deliveries(ids)).every((d) => d.state === "sent")).toBe(true);
  }, 120_000);
});
