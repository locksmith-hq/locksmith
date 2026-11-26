import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { sql } from "kysely";
import pg from "pg";
import { GenericContainer, Wait, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createKysely, type Database } from "../../db/db.module.js";
import { TenantService } from "../../tenant/tenant.service.js";

// N1 task 2.3: the notification tables against a real Postgres, as the app role (not owner, not
// BYPASSRLS). Two orgs; a cross-org read returns nothing. Needs Docker; the migrations are the
// Rust control plane's own SQL files.
const ORG_A = "0192f3a0-0000-7000-8000-0000000000a1";
const ORG_B = "0192f3a0-0000-7000-8000-0000000000b1";
const USER_A = "0192f3a0-0000-7000-8000-0000000000a2";
const USER_B = "0192f3a0-0000-7000-8000-0000000000b2";
const ADMIN_PASSWORD = "admin-test-only";

let container: StartedTestContainer;
let db: Database;
let tenant: TenantService;

const migrationsDir = new URL("../../../../../services/control-plane/migrations/", import.meta.url);

beforeAll(async () => {
  container = await new GenericContainer("postgres:18.7")
    .withEnvironment({ POSTGRES_PASSWORD: ADMIN_PASSWORD })
    .withExposedPorts(5432)
    .withWaitStrategy(Wait.forLogMessage(/database system is ready to accept connections/, 2))
    .start();
  const hostPort = `${container.getHost()}:${container.getMappedPort(5432)}`;
  const admin = new pg.Client({ connectionString: `postgres://postgres:${ADMIN_PASSWORD}@${hostPort}/postgres` });
  await admin.connect();
  const files = readdirSync(fileURLToPath(migrationsDir))
    .filter((f) => f.endsWith(".sql"))
    .sort();
  for (const name of files) await admin.query(readFileSync(fileURLToPath(new URL(name, migrationsDir)), "utf8"));
  // The superuser bypasses RLS: seed two orgs (the org trigger seeds rules and cursors), a user
  // each and one inbox item each.
  await admin.query(
    `insert into orgs (id, name) values ('${ORG_A}', 'org-a'), ('${ORG_B}', 'org-b');
     insert into users (id, issuer, subject, personal_org_id) values
       ('${USER_A}', 'https://issuer.test', 'a', '${ORG_A}'),
       ('${USER_B}', 'https://issuer.test', 'b', '${ORG_B}');
     insert into notifications (org_id, user_id, kind, payload) values
       ('${ORG_A}', '${USER_A}', 'relay.denied', '{"kind":"relay.denied"}'),
       ('${ORG_B}', '${USER_B}', 'git.denied', '{"kind":"git.denied"}');`,
  );
  await admin.end();

  // One connection so pooled-connection reuse is guaranteed.
  db = createKysely(`postgres://locksmith_app:locksmith-app-dev-only@${hostPort}/postgres`, 1);
  tenant = new TenantService(db, { set() {}, get() {} } as never);
}, 180_000);

afterAll(async () => {
  await db?.destroy();
  await container?.stop();
});

describe("notification tables (app role, row-level security)", () => {
  it("a new org has the default rules matrix and a cursor", async () => {
    const rules = await tenant.run(ORG_A, (tx) => tx.selectFrom("notification_rules").selectAll().execute());
    expect(rules).toHaveLength(12);
    expect(rules.filter((r) => r.enabled).map((r) => [r.channel, r.audience])).toEqual(
      Array(4).fill(["inbox", "owner"]),
    );
    const cursors = await tenant.run(ORG_A, (tx) =>
      tx.selectFrom("notification_cursors").selectAll().where("org_id", "=", ORG_A).execute(),
    );
    expect(cursors).toEqual([{ org_id: ORG_A, last_seq: "0" }]);
  });

  it("returns only the bound org's inbox items", async () => {
    const rows = await tenant.run(ORG_A, (tx) => tx.selectFrom("notifications").select("kind").execute());
    expect(rows.map((r) => r.kind)).toEqual(["relay.denied"]);
  });

  it("cross-org reads return nothing", async () => {
    // Cursors are listable by design (the fan-out job visits every org; see migration 0019).
    for (const table of ["notifications", "notification_rules", "notification_deliveries"] as const) {
      const rows = await tenant.run(ORG_A, (tx) =>
        tx.selectFrom(table).selectAll().where("org_id", "=", ORG_B).execute(),
      );
      expect(rows, table).toEqual([]);
    }
  });

  it("another org's item cannot be marked read", async () => {
    const res = await tenant.run(ORG_A, (tx) =>
      tx.updateTable("notifications").set({ read_at: new Date() }).where("org_id", "=", ORG_B).executeTakeFirst(),
    );
    expect(res.numUpdatedRows).toBe(0n);
  });

  it("cross-org writes are rejected", async () => {
    await expect(
      tenant.run(ORG_A, (tx) =>
        tx
          .insertInto("notifications")
          .values({ org_id: ORG_B, user_id: USER_B, kind: "relay.denied", payload: "{}" })
          .execute(),
      ),
    ).rejects.toThrow(/row-level security/);
  });

  it("with no org bound only cursors are listable", async () => {
    const cursors = await sql`select org_id from notification_cursors`.execute(db);
    expect(cursors.rows).toHaveLength(2);
    for (const table of ["notifications", "notification_rules", "notification_deliveries"]) {
      const { rows } = await sql.raw(`select 1 from ${table}`).execute(db);
      expect(rows, table).toEqual([]);
    }
  });
});
