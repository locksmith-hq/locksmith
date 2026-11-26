import "reflect-metadata";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Global, Module, type INestApplication } from "@nestjs/common";
import { APP_FILTER } from "@nestjs/core";
import { Test } from "@nestjs/testing";
import pg from "pg";
import request from "supertest";
import { GenericContainer, Wait, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AUDIT_SINK } from "../audit/audit-sink.js";
import { createKysely, KYSELY, type Database } from "../db/db.module.js";
import { ProblemFilter } from "../platform/problem.js";
import { TenantModule } from "../tenant/tenant.module.js";
import { OrgsModule } from "../orgs/orgs.module.js";
import { AgentsModule } from "./agents.module.js";

// B9 1.2: the agents read paths against a real Postgres as the app role (row-level security applies).
// Mirrors the GET exchanges of the `agents` scenario of `tests/api-contract`.
const MIGRATIONS = [
  "0001_roles.sql",
  "0002_tenancy_schema.sql",
  "0003_secret_versions.sql",
  "0006_agents.sql",
  "0011_users.sql",
  "0015_grant_delegate.sql",
];
const DEV_ORG = "x-locksmith-dev-org";

let container: StartedTestContainer;
let db: Database;
let adminUrl: string;

@Global()
@Module({
  providers: [
    { provide: KYSELY, useFactory: () => db },
    { provide: AUDIT_SINK, useValue: { append: async () => {} } },
  ],
  exports: [KYSELY, AUDIT_SINK],
})
class TestDbModule {}

async function appWith(devAuth: string | undefined): Promise<INestApplication> {
  if (devAuth === undefined) delete process.env["LOCKSMITH_DEV_AUTH"];
  else process.env["LOCKSMITH_DEV_AUTH"] = devAuth;
  @Module({
    imports: [TestDbModule, TenantModule, OrgsModule, AgentsModule],
    providers: [{ provide: APP_FILTER, useClass: ProblemFilter }],
  })
  class M {}
  const mod = await Test.createTestingModule({ imports: [M] }).compile();
  const app = mod.createNestApplication({ logger: false });
  await app.init();
  return app;
}

beforeAll(async () => {
  container = await new GenericContainer("postgres:18.7")
    .withEnvironment({ POSTGRES_PASSWORD: "admin-test-only" })
    .withExposedPorts(5432)
    .withWaitStrategy(Wait.forLogMessage(/database system is ready to accept connections/, 2))
    .start();
  const hostPort = `${container.getHost()}:${container.getMappedPort(5432)}`;
  adminUrl = `postgres://postgres:admin-test-only@${hostPort}/postgres`;
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  for (const name of MIGRATIONS) {
    await admin.query(
      readFileSync(
        fileURLToPath(new URL(`../../../../services/control-plane/migrations/${name}`, import.meta.url)),
        "utf8",
      ),
    );
  }
  await admin.end();
  db = createKysely(`postgres://locksmith_app:locksmith-app-dev-only@${hostPort}/postgres`, 4);
}, 180_000);

afterAll(async () => {
  await db?.destroy();
  await container?.stop();
});

const MISSING = "00000000-0000-4000-8000-000000000000";

/** Seeds through the admin connection (superuser, so row-level security does not apply to the setup only). */
async function seed(org: string, agents: number, grants = 0) {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  const q = async (text: string, v: unknown[]) => (await admin.query(text, v)).rows;
  const [{ id: project }] = await q("INSERT INTO projects (org_id, name) VALUES ($1, 'p') RETURNING id", [org]);
  const [{ id: env }] = await q(
    "INSERT INTO environments (org_id, project_id, name) VALUES ($1, $2, 'e') RETURNING id",
    [org, project],
  );
  const ids: string[] = [];
  for (let i = 0; i < agents; i++) {
    const [{ id }] = await q(
      "INSERT INTO agents (org_id, name, description, enrollment_hash) VALUES ($1, $2, 'd', '$argon2id$never-returned') RETURNING id",
      [org, `agent-${i}`],
    );
    ids.push(id);
  }
  const secretIds: string[] = [];
  for (let i = 0; i < grants; i++) {
    const [{ id: secret }] = await q(
      "INSERT INTO secrets (org_id, project_id, environment_id, name) VALUES ($1, $2, $3, $4) RETURNING id",
      [org, project, env, `s-${i}`],
    );
    secretIds.push(secret);
    if (i === 0) {
      await q("INSERT INTO agent_grants (org_id, agent_id, secret_id, mode) VALUES ($1, $2, $3, 'relay')", [
        org,
        ids[0],
        secret,
      ]);
    } else {
      await q(
        `INSERT INTO agent_grants (org_id, agent_id, secret_id, mode, scope, expires_at)
         VALUES ($1, $2, $3, 'delegate', '{"resources":["arn:x"],"actions":["s3:GetObject"]}'::jsonb, '2031-01-02T03:04:05Z')`,
        [org, ids[0], secret],
      );
    }
  }
  await admin.end();
  return { ids, secretIds };
}

async function twoOrgs() {
  const app = await appWith("1");
  const http = request(app.getHttpServer());
  const a = (await http.post("/v1/orgs").send({ name: "A" }).expect(201)).body.id as string;
  const b = (await http.post("/v1/orgs").send({ name: "B" }).expect(201)).body.id as string;
  return { app, http, a, b };
}

describe("agents reads", () => {
  it("lists agents in id order with keyset paging, and never returns the enrollment hash", async () => {
    const { app, http, a, b } = await twoOrgs();
    const { ids } = await seed(a, 3);
    await seed(b, 2);
    const all = await http.get("/v1/agents").set(DEV_ORG, a).expect(200);
    expect(all.body.items.map((i: { id: string }) => i.id)).toEqual([...ids].sort());
    expect(all.body.next).toBeUndefined();
    for (const i of all.body.items) {
      expect(Object.keys(i).sort()).toEqual(["created_at", "description", "id", "name", "updated_at"]);
      expect(i.created_at).toMatch(/^\d{4}-\d\d-\d\dT.*Z$/);
    }
    expect(JSON.stringify(all.body)).not.toContain("argon2id");
    const p1 = await http.get("/v1/agents?limit=2").set(DEV_ORG, a).expect(200);
    expect(p1.body.items).toHaveLength(2);
    const p2 = await http.get(`/v1/agents?limit=2&cursor=${p1.body.next}`).set(DEV_ORG, a).expect(200);
    expect(p2.body.items.map((i: { id: string }) => i.id)).toEqual([...ids].sort().slice(2));
    expect(p2.body.next).toBeUndefined();
    await http.get("/v1/agents?limit=0").set(DEV_ORG, a).expect(400);
    await http.get("/v1/agents?cursor=bad").set(DEV_ORG, a).expect(400);
    await http.get("/v1/agents").expect(401);
    expect((await http.get("/v1/agents").set(DEV_ORG, b).expect(200)).body.items).toHaveLength(2);
    await app.close();
  });

  it("gets one agent; unknown, malformed and another org's ids are 404", async () => {
    const { app, http, a, b } = await twoOrgs();
    const { ids } = await seed(a, 1);
    const one = await http.get(`/v1/agents/${ids[0]}`).set(DEV_ORG, a).expect(200);
    expect(one.body).toMatchObject({ id: ids[0], name: "agent-0", description: "d" });
    await http.get(`/v1/agents/${ids[0]}`).set(DEV_ORG, b).expect(404);
    await http.get(`/v1/agents/${MISSING}`).set(DEV_ORG, a).expect(404);
    await http.get("/v1/agents/not-a-uuid").set(DEV_ORG, a).expect(404);
    await http.get("/v1/agents/not-a-uuid").expect(401);
    await app.close();
  });

  it("lists grants with secret names, delegate scope and expiry, paged; another org's agent is 404", async () => {
    const { app, http, a, b } = await twoOrgs();
    const { ids, secretIds } = await seed(a, 2, 3);
    const res = await http.get(`/v1/agents/${ids[0]}/grants`).set(DEV_ORG, a).expect(200);
    expect(res.body.items).toHaveLength(3);
    const relay = res.body.items.find((g: { mode: string }) => g.mode === "relay");
    expect(relay).toMatchObject({
      agent_id: ids[0],
      secret_id: secretIds[0],
      secret_name: "s-0",
      scope: null,
      expires_at: null,
    });
    expect(Object.keys(relay).sort()).toEqual([
      "agent_id",
      "created_at",
      "expires_at",
      "id",
      "mode",
      "scope",
      "secret_id",
      "secret_name",
    ]);
    const del = res.body.items.find((g: { mode: string }) => g.mode === "delegate");
    expect(del.scope).toEqual({ actions: ["s3:GetObject"], resources: ["arn:x"] });
    expect(Object.keys(del.scope)).toEqual(["actions", "resources"]);
    expect(del.expires_at).toBe("2031-01-02T03:04:05.000Z");
    const p1 = await http.get(`/v1/agents/${ids[0]}/grants?limit=2`).set(DEV_ORG, a).expect(200);
    expect(p1.body.items).toHaveLength(2);
    const p2 = await http.get(`/v1/agents/${ids[0]}/grants?limit=2&cursor=${p1.body.next}`).set(DEV_ORG, a).expect(200);
    expect(p2.body.items).toHaveLength(1);
    expect((await http.get(`/v1/agents/${ids[1]}/grants`).set(DEV_ORG, a).expect(200)).body.items).toEqual([]);
    await http.get(`/v1/agents/${ids[0]}/grants`).set(DEV_ORG, b).expect(404);
    await http.get(`/v1/agents/${MISSING}/grants`).set(DEV_ORG, a).expect(404);
    await http.get("/v1/agents/not-a-uuid/grants").set(DEV_ORG, a).expect(404);
    await http.get(`/v1/agents/${ids[0]}/grants?limit=0`).set(DEV_ORG, a).expect(400);
    await app.close();
  });
});
