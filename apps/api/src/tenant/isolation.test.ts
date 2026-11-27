import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { sql } from "kysely";
import pg from "pg";
import { GenericContainer, Wait, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createKysely, type Database } from "../db/db.module.js";
import { TenantService } from "./tenant.service.js";

// Task 2.5: tenant isolation against a real Postgres, as the app role (not owner, not BYPASSRLS).
// The container needs Docker; the migrations are the Rust control plane's own SQL files.
const MIGRATIONS = ["0001_roles.sql", "0002_tenancy_schema.sql"];
const ORG_A = "0192f3a0-0000-7000-8000-00000000000a";
const ORG_B = "0192f3a0-0000-7000-8000-00000000000b";
const ADMIN_PASSWORD = "admin-test-only";

let container: StartedTestContainer;
let adminUrl: string;
let appUrl: string;
let db: Database;
let tenant: TenantService;

function migration(name: string): string {
  return readFileSync(
    fileURLToPath(new URL(`../../../../services/control-plane/migrations/${name}`, import.meta.url)),
    "utf8",
  );
}

beforeAll(async () => {
  container = await new GenericContainer("postgres:18.7")
    .withEnvironment({ POSTGRES_PASSWORD: ADMIN_PASSWORD })
    .withExposedPorts(5432)
    .withWaitStrategy(Wait.forLogMessage(/database system is ready to accept connections/, 2))
    .start();
  const hostPort = `${container.getHost()}:${container.getMappedPort(5432)}`;
  adminUrl = `postgres://postgres:${ADMIN_PASSWORD}@${hostPort}/postgres`;
  appUrl = `postgres://locksmith_app:locksmith-app-dev-only@${hostPort}/postgres`;

  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  for (const name of MIGRATIONS) await admin.query(migration(name));
  // Seed as the table owner path: the superuser bypasses RLS, so two orgs and one project each.
  await admin.query(
    `insert into orgs (id, name) values ('${ORG_A}', 'org-a'), ('${ORG_B}', 'org-b');
     insert into projects (org_id, name) values ('${ORG_A}', 'proj-a'), ('${ORG_B}', 'proj-b');`,
  );
  await admin.end();

  // One connection so pooled-connection reuse is guaranteed in the leakage test.
  db = createKysely(appUrl, 1);
  tenant = new TenantService(db, { set() {}, get() {} } as never);
}, 180_000);

afterAll(async () => {
  await db?.destroy();
  await container?.stop();
});

describe("tenant isolation (app role, row-level security)", () => {
  it("connects as a role that is neither superuser nor BYPASSRLS", async () => {
    const { rows } = await sql<{ rolsuper: boolean; rolbypassrls: boolean }>`
      select rolsuper, rolbypassrls from pg_roles where rolname = current_user`.execute(db);
    expect(rows[0]).toEqual({ rolsuper: false, rolbypassrls: false });
  });

  it("returns only the bound org's rows", async () => {
    const names = await tenant.run(ORG_A, (tx) => tx.selectFrom("projects").select("name").execute());
    expect(names.map((r) => r.name)).toEqual(["proj-a"]);
  });

  it("cross-tenant read returns nothing", async () => {
    const rows = await tenant.run(ORG_A, (tx) =>
      tx.selectFrom("projects").selectAll().where("org_id", "=", ORG_B).execute(),
    );
    expect(rows).toEqual([]);
  });

  it("cross-tenant write is rejected", async () => {
    await expect(
      tenant.run(ORG_A, (tx) => tx.insertInto("projects").values({ org_id: ORG_B, name: "evil" }).execute()),
    ).rejects.toThrow(/row-level security/);
  });

  it("with no org bound, every table reads as empty", async () => {
    const { rows } = await sql`select * from projects`.execute(db);
    expect(rows).toEqual([]);
  });

  it("does not leak the org to the next user of a pooled connection", async () => {
    // The pool has one connection, so the next statement reuses the one that just served org A.
    await tenant.run(ORG_A, (tx) => tx.selectFrom("projects").selectAll().execute());
    const { rows } = await sql`select * from projects`.execute(db);
    expect(rows).toEqual([]);
    const org = await sql<{ v: string | null }>`select current_setting('app.org_id', true) as v`.execute(db);
    expect(org.rows[0]?.v ?? "").toBe("");
  });

  it("a rolled-back transaction does not leak either", async () => {
    await expect(
      tenant.run(ORG_B, async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    const { rows } = await sql`select * from projects`.execute(db);
    expect(rows).toEqual([]);
  });
});
