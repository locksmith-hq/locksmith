import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { GenericContainer, Wait, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createKysely, type Database } from "../../db/db.module.js";
import { ProblemException } from "../../platform/problem/problem.js";
import { TenantService } from "../../tenant/tenant.service.js";
import { HoneyMinter, type HoneyTemplate } from "./honey-minter.js";
import { HoneyTokensService } from "./honey-tokens.service.js";

// T5 task 2.3 against a real Postgres as the app role (not owner, not BYPASSRLS), with two orgs.
// The minter is a fake that records calls: sealing is covered by the core's own tests.
const ORG_A = "0192f3a0-0000-7000-8000-0000000000a1";
const ORG_B = "0192f3a0-0000-7000-8000-0000000000b1";
const PROJ_A = "0192f3a0-0000-7000-8000-0000000000a3";
const PROJ_B = "0192f3a0-0000-7000-8000-0000000000b3";
const ENV_A = "0192f3a0-0000-7000-8000-0000000000a4";
const ENV_B = "0192f3a0-0000-7000-8000-0000000000b4";
const ADMIN_PASSWORD = "admin-test-only";
const scopeA = { orgId: ORG_A, projectId: PROJ_A, environmentId: ENV_A };
const scopeB = { orgId: ORG_B, projectId: PROJ_B, environmentId: ENV_B };

class FakeMinter extends HoneyMinter {
  calls: { orgId: string; secretId: string; template: HoneyTemplate }[] = [];
  failWith: ProblemException | null = null;
  async mint(orgId: string, secretId: string, template: HoneyTemplate): Promise<void> {
    this.calls.push({ orgId, secretId, template });
    if (this.failWith) throw this.failWith;
  }
}

let container: StartedTestContainer;
let db: Database;
let admin: pg.Client;
let tenant: TenantService;
let minter: FakeMinter;
let svc: HoneyTokensService;

const migrationsDir = new URL("../../../../../services/control-plane/migrations/", import.meta.url);

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
     insert into projects (id, org_id, name) values ('${PROJ_A}', '${ORG_A}', 'p'), ('${PROJ_B}', '${ORG_B}', 'p');
     insert into environments (id, org_id, project_id, name) values
       ('${ENV_A}', '${ORG_A}', '${PROJ_A}', 'dev'), ('${ENV_B}', '${ORG_B}', '${PROJ_B}', 'dev');`,
  );
  db = createKysely(`postgres://locksmith_app:locksmith-app-dev-only@${hostPort}/postgres`, 2);
  tenant = new TenantService(db, { set() {}, get() {} } as never);
  minter = new FakeMinter();
  svc = new HoneyTokensService(tenant, minter);
}, 180_000);

afterAll(async () => {
  await db?.destroy();
  await admin?.end();
  await container?.stop();
});

const problem = async (p: Promise<unknown>) => {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(ProblemException);
    return (e as ProblemException).kind;
  }
  return expect.unreachable("expected a problem");
};

describe("honey tokens service", () => {
  it("create stores metadata only, asks the core to seal, and returns no value", async () => {
    const t = await svc.create(scopeA, { name: "aws-decoy", template: "aws_access_key" });
    expect(Object.keys(t).sort()).toEqual(
      ["created_at", "disabled_at", "id", "last_triggered_at", "name", "template"].sort(),
    );
    expect(t).toMatchObject({ name: "aws-decoy", template: "aws_access_key", disabled_at: null, last_triggered_at: null });
    expect(minter.calls.at(-1)).toEqual({ orgId: ORG_A, secretId: t.id, template: "aws_access_key" });
    const { rows } = await admin.query("select kind, honey_template, disabled_at from secrets where id = $1", [t.id]);
    expect(rows).toEqual([{ kind: "honey", honey_template: "aws_access_key", disabled_at: null }]);
  });

  it("a duplicate name is a 409 and never reaches the core", async () => {
    const before = minter.calls.length;
    expect(await problem(svc.create(scopeA, { name: "aws-decoy", template: "github_pat" }))).toBe("conflict");
    expect(minter.calls).toHaveLength(before);
  });

  it("a refused mint removes the row so the name can be reused", async () => {
    minter.failWith = new ProblemException("unavailable");
    expect(await problem(svc.create(scopeA, { name: "slack-decoy", template: "slack_token" }))).toBe("unavailable");
    minter.failWith = null;
    const { rows } = await admin.query("select 1 from secrets where name = 'slack-decoy'");
    expect(rows).toHaveLength(0);
    const t = await svc.create(scopeA, { name: "slack-decoy", template: "slack_token" });
    expect(t.name).toBe("slack-decoy");
  });

  it("without a configured core, create answers 503 and stores nothing", async () => {
    const bare = new HoneyTokensService(tenant, null);
    expect(await problem(bare.create(scopeA, { name: "no-core", template: "generic_api_key" }))).toBe("unavailable");
    const { rows } = await admin.query("select 1 from secrets where name = 'no-core'");
    expect(rows).toHaveLength(0);
  });

  it("an unknown environment or one of another project is a 404", async () => {
    const other = { ...scopeA, environmentId: "0192f3a0-0000-7000-8000-0000000000ff" };
    expect(await problem(svc.create(other, { name: "x", template: "slack_token" }))).toBe("not-found");
    expect(await problem(svc.list({ ...scopeA, projectId: PROJ_B }))).toBe("not-found");
  });

  it("list shows only honey tokens, with the last trigger time from the ledger", async () => {
    await admin.query(
      `insert into secrets (org_id, project_id, environment_id, name) values ('${ORG_A}', '${PROJ_A}', '${ENV_A}', 'plain')`,
    );
    const [a] = (await svc.list(scopeA)).filter((t) => t.name === "aws-decoy");
    expect(a!.last_triggered_at).toBeNull();
    for (const [seq, at] of [
      [1, "2026-11-20T10:00:00Z"],
      [2, "2026-11-21T10:00:00Z"],
    ] as const) {
      await admin.query(
        `insert into audit_events (id, org_id, seq, at, kind, actor, outcome, target, attrs, prev_hash, hash)
         values (gen_random_uuid(), $1, $2, $3, 'honey.triggered', 'agent:x', 'denied', $4, '{}', decode(repeat('00', 32), 'hex'), decode(repeat('01', 32), 'hex'))`,
        [ORG_A, seq, at, `secret:${a!.id}`],
      );
    }
    const items = await svc.list(scopeA);
    expect(items.map((t) => t.name).sort()).toEqual(["aws-decoy", "slack-decoy"]);
    expect(items.find((t) => t.id === a!.id)!.last_triggered_at).toBe("2026-11-21T10:00:00.000Z");
    expect(items.find((t) => t.name === "slack-decoy")!.last_triggered_at).toBeNull();
  });

  it("disable stamps disabled_at once and is idempotent", async () => {
    const [a] = (await svc.list(scopeA)).filter((t) => t.name === "aws-decoy");
    const first = await svc.disable(scopeA, a!.id);
    expect(first.disabled_at).not.toBeNull();
    const second = await svc.disable(scopeA, a!.id);
    expect(second.disabled_at).toBe(first.disabled_at);
  });

  it("disable and delete refuse a standard secret", async () => {
    const { rows } = await admin.query("select id from secrets where name = 'plain'");
    expect(await problem(svc.disable(scopeA, rows[0].id))).toBe("not-found");
    expect(await problem(svc.remove(scopeA, rows[0].id))).toBe("not-found");
    expect((await admin.query("select 1 from secrets where name = 'plain'")).rows).toHaveLength(1);
  });

  it("org B cannot see, disable or delete org A's tokens", async () => {
    const a = (await svc.list(scopeA))[0]!;
    await svc.create(scopeB, { name: "b-decoy", template: "generic_api_key" });
    expect((await svc.list(scopeB)).map((t) => t.name)).toEqual(["b-decoy"]);
    // B's own project and environment, A's token id: nothing there.
    expect(await problem(svc.disable(scopeB, a.id))).toBe("not-found");
    expect(await problem(svc.remove(scopeB, a.id))).toBe("not-found");
    // B naming A's own project and environment: only row-level security stops this one.
    const asB = { orgId: ORG_B, projectId: PROJ_A, environmentId: ENV_A };
    expect(await problem(svc.disable(asB, a.id))).toBe("not-found");
    expect(await problem(svc.remove(asB, a.id))).toBe("not-found");
    // B naming A's project is not even an environment B can see.
    expect(await problem(svc.list({ orgId: ORG_B, projectId: PROJ_A, environmentId: ENV_A }))).toBe("not-found");
    expect(await problem(svc.create({ orgId: ORG_B, projectId: PROJ_A, environmentId: ENV_A }, { name: "x", template: "slack_token" }))).toBe("not-found");
    expect((await svc.list(scopeA)).some((t) => t.id === a.id)).toBe(true);
  });

  it("delete removes the token", async () => {
    const a = (await svc.list(scopeA)).find((t) => t.name === "slack-decoy")!;
    await svc.remove(scopeA, a.id);
    expect((await svc.list(scopeA)).some((t) => t.id === a.id)).toBe(false);
    expect(await problem(svc.remove(scopeA, a.id))).toBe("not-found");
  });
});
