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
import { CORE_CLIENT } from "../core/core.tokens.js";
import { AgentsModule } from "./agents.module.js";

// Task 6.4: the agents and grants paths against a real Postgres as the app role (row-level security applies).
// Audit events go to a recording sink; the core client is a stub that makes enrollment secrets.
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
const sink: unknown[] = [];
let coreDown = false;
const core = {
  generateEnrollmentSecret: async (r: { org_id: string; agent_id: string }) => {
    if (coreDown) throw new Error("core LEAK-CANARY");
    return { enrollment_secret: `lse_${r.agent_id}`, enrollment_hash: "$argon2id$stub" };
  },
};

@Global()
@Module({
  providers: [
    { provide: KYSELY, useFactory: () => db },
    { provide: AUDIT_SINK, useValue: { append: async () => {}, appendAdmin: async (e: unknown) => sink.push(e) } },
    { provide: CORE_CLIENT, useValue: core },
  ],
  exports: [KYSELY, AUDIT_SINK, CORE_CLIENT],
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

async function twoOrgs() {
  const app = await appWith("1");
  const http = request(app.getHttpServer());
  const a = (await http.post("/v1/orgs").send({ name: "A" }).expect(201)).body.id as string;
  const b = (await http.post("/v1/orgs").send({ name: "B" }).expect(201)).body.id as string;
  return { app, http, a, b };
}

/** A secret in `org`, made as the admin role (the secrets API is not ported yet). */
async function secretIn(org: string): Promise<string> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    const p = (await admin.query("insert into projects (org_id, name) values ($1, 'p') returning id", [org])).rows[0]
      .id;
    const e = (
      await admin.query("insert into environments (org_id, project_id, name) values ($1, $2, 'e') returning id", [
        org,
        p,
      ])
    ).rows[0].id;
    return (
      await admin.query(
        "insert into secrets (org_id, project_id, environment_id, name) values ($1, $2, $3, 's') returning id",
        [org, p, e],
      )
    ).rows[0].id;
  } finally {
    await admin.end();
  }
}

describe("agents", () => {
  it("registers, reads, lists, rotates and deletes, auditing each write", async () => {
    sink.length = 0;
    const { app, http, a } = await twoOrgs();
    const c = await http.post("/v1/agents").set(DEV_ORG, a).send({ name: "bot", description: "d" }).expect(201);
    expect(c.headers["location"]).toBe(`/v1/agents/${c.body.agent.id}`);
    expect(c.headers["cache-control"]).toBe("no-store");
    expect(c.headers["pragma"]).toBe("no-cache");
    expect(Object.keys(c.body).sort()).toEqual(["agent", "enrollment_secret"]);
    expect(Object.keys(c.body.agent).sort()).toEqual(["created_at", "description", "id", "name", "updated_at"]);
    expect(c.body.enrollment_secret).toBe(`lse_${c.body.agent.id}`);
    const id = c.body.agent.id as string;
    const got = await http.get(`/v1/agents/${id}`).set(DEV_ORG, a).expect(200);
    expect(JSON.stringify(got.body)).not.toMatch(/lse_|argon2/);
    const l = await http.get("/v1/agents").set(DEV_ORG, a).expect(200);
    expect(l.body.items.map((x: { id: string }) => x.id)).toEqual([id]);
    const r = await http.post(`/v1/agents/${id}/enrollment-secret`).set(DEV_ORG, a).expect(200);
    expect(r.headers["cache-control"]).toBe("no-store");
    expect(r.body.agent.id).toBe(id);
    await http.delete(`/v1/agents/${id}`).set(DEV_ORG, a).expect(204);
    await http.delete(`/v1/agents/${id}`).set(DEV_ORG, a).expect(404);
    await http.post(`/v1/agents/${MISSING}/enrollment-secret`).set(DEV_ORG, a).expect(404);
    expect(sink).toEqual([
      expect.objectContaining({ kind: "agent.created", orgId: a, target: { type: "agent", id }, attrs: {} }),
      expect.objectContaining({ kind: "agent.rotated", target: { type: "agent", id } }),
      expect.objectContaining({ kind: "agent.deleted", attrs: { grants_revoked: 0 } }),
    ]);
    expect(JSON.stringify(sink)).not.toMatch(/bot|lse_|argon2/);
    await app.close();
  });

  it("validates input like Rust", async () => {
    const { app, http, a } = await twoOrgs();
    await http.post("/v1/agents").set(DEV_ORG, a).send({ name: "  " }).expect(400);
    await http.post("/v1/agents").set(DEV_ORG, a).send({ name: "x", extra: 1 }).expect(400);
    await http.post("/v1/agents").set(DEV_ORG, a).send({}).expect(400);
    await http.post("/v1/agents").send({ name: "x" }).expect(401);
    await http.get("/v1/agents/not-a-uuid").set(DEV_ORG, a).expect(404);
    await http.get("/v1/agents?limit=0").set(DEV_ORG, a).expect(400);
    await app.close();
  });

  it("isolates orgs", async () => {
    const { app, http, a, b } = await twoOrgs();
    const id = (await http.post("/v1/agents").set(DEV_ORG, a).send({ name: "x" }).expect(201)).body.agent.id;
    await http.get(`/v1/agents/${id}`).set(DEV_ORG, b).expect(404);
    await http.delete(`/v1/agents/${id}`).set(DEV_ORG, b).expect(404);
    await http.post(`/v1/agents/${id}/enrollment-secret`).set(DEV_ORG, b).expect(404);
    expect((await http.get("/v1/agents").set(DEV_ORG, b).expect(200)).body.items).toEqual([]);
    await app.close();
  });

  it("pages by keyset cursor", async () => {
    const { app, http, a } = await twoOrgs();
    for (const n of ["1", "2", "3"]) await http.post("/v1/agents").set(DEV_ORG, a).send({ name: n }).expect(201);
    const p1 = await http.get("/v1/agents?limit=2").set(DEV_ORG, a).expect(200);
    expect(p1.body.items).toHaveLength(2);
    const p2 = await http.get(`/v1/agents?limit=2&cursor=${p1.body.next}`).set(DEV_ORG, a).expect(200);
    expect(p2.body.items).toHaveLength(1);
    expect(p2.body.next).toBeUndefined();
    await app.close();
  });

  it("fails closed with 503 and no core text when the core is down, creating nothing", async () => {
    const { app, http, a } = await twoOrgs();
    coreDown = true;
    try {
      const res = await http.post("/v1/agents").set(DEV_ORG, a).send({ name: "x" }).expect(503);
      expect(JSON.stringify(res.body)).not.toContain("LEAK-CANARY");
    } finally {
      coreDown = false;
    }
    expect((await http.get("/v1/agents").set(DEV_ORG, a).expect(200)).body.items).toEqual([]);
    await app.close();
  });
});

describe("agent grants", () => {
  it("grants, lists, conflicts and revokes, auditing ids and codes only", async () => {
    sink.length = 0;
    const { app, http, a, b } = await twoOrgs();
    const secret = await secretIn(a);
    const agent = (await http.post("/v1/agents").set(DEV_ORG, a).send({ name: "x" }).expect(201)).body.agent.id;
    const url = `/v1/agents/${agent}/grants`;
    const future = new Date(Date.now() + 3_600_000).toISOString();
    const g = await http.post(url).set(DEV_ORG, a).send({ secret_id: secret, expires_at: future }).expect(201);
    expect(g.headers["location"]).toBe(`${url}/${g.body.id}`);
    expect(g.body).toMatchObject({ agent_id: agent, secret_id: secret, secret_name: "s", mode: "relay", scope: null });
    expect(g.body.expires_at).toBe(future);
    await http.post(url).set(DEV_ORG, a).send({ secret_id: secret }).expect(409);
    const d = await http
      .post(url)
      .set(DEV_ORG, a)
      .send({
        secret_id: secret,
        mode: "delegate",
        scope: { actions: ["s3:GetObject"], resources: ["arn:aws:s3:::b/*"], max_duration_secs: 900 },
      })
      .expect(201);
    expect(d.body.scope).toEqual({
      actions: ["s3:GetObject"],
      resources: ["arn:aws:s3:::b/*"],
      max_duration_secs: 900,
    });
    const l = await http.get(url).set(DEV_ORG, a).expect(200);
    expect(l.body.items).toHaveLength(2);
    await http.get(`/v1/agents/${agent}/grants`).set(DEV_ORG, b).expect(404);
    await http.delete(`${url}/${g.body.id}`).set(DEV_ORG, a).expect(204);
    await http.delete(`${url}/${g.body.id}`).set(DEV_ORG, a).expect(404);
    expect(sink.slice(1)).toEqual([
      expect.objectContaining({
        kind: "grant.created",
        target: { type: "grant", id: g.body.id },
        attrs: { agent_id: agent, secret_id: secret, mode: "relay", expires_at: Math.floor(Date.parse(future) / 1000) },
      }),
      expect.objectContaining({
        kind: "grant.created",
        attrs: { agent_id: agent, secret_id: secret, mode: "delegate" },
      }),
      expect.objectContaining({ kind: "grant.revoked", attrs: { agent_id: agent } }),
    ]);
    // Deleting the agent counts its remaining grants.
    await http.delete(`/v1/agents/${agent}`).set(DEV_ORG, a).expect(204);
    expect(sink.at(-1)).toMatchObject({ kind: "agent.deleted", attrs: { grants_revoked: 1 } });
    await app.close();
  });

  it("refuses bad grants", async () => {
    const { app, http, a, b } = await twoOrgs();
    const secret = await secretIn(a);
    const agent = (await http.post("/v1/agents").set(DEV_ORG, a).send({ name: "x" }).expect(201)).body.agent.id;
    const url = `/v1/agents/${agent}/grants`;
    const past = new Date(Date.now() - 1000).toISOString();
    const scope = { actions: ["a"], resources: ["r"] };
    const bad: unknown[] = [
      { secret_id: secret, expires_at: past },
      { secret_id: secret, scope },
      { secret_id: secret, mode: "delegate" },
      { secret_id: secret, mode: "delegate", scope: { actions: [], resources: ["r"] } },
      { secret_id: secret, mode: "delegate", scope: { ...scope, max_duration_secs: 0 } },
      { secret_id: secret, mode: "delegate", scope: { actions: ["bad\u0007"], resources: ["r"] } },
      { secret_id: secret, mode: "other" },
      { secret_id: secret, extra: true },
    ];
    for (const body of bad)
      await http
        .post(url)
        .set(DEV_ORG, a)
        .send(body as object)
        .expect(400);
    await http.post(url).set(DEV_ORG, a).send({ secret_id: MISSING }).expect(404);
    await http.post(`/v1/agents/${MISSING}/grants`).set(DEV_ORG, a).send({ secret_id: secret }).expect(404);
    // A secret of another org is not visible, so it is 404 and not a leak.
    await http.post(url).set(DEV_ORG, b).send({ secret_id: secret }).expect(404);
    await app.close();
  });
});

describe("GET /internal/v1/agents/{id}/grants", () => {
  const TOKEN = "gateway-service-token-0123456789abcdef";
  const withToken = async () => {
    process.env["LOCKSMITH_GATEWAY_SERVICE_TOKEN"] = TOKEN;
    return twoOrgs();
  };

  it("serves only unexpired grants to the gateway, scoped to the named org", async () => {
    const { app, http, a, b } = await withToken();
    const secret = await secretIn(a);
    const agent = (await http.post("/v1/agents").set(DEV_ORG, a).send({ name: "x" }).expect(201)).body.agent.id;
    const url = `/v1/agents/${agent}/grants`;
    const future = new Date(Date.now() + 3_600_000).toISOString();
    const live = (await http.post(url).set(DEV_ORG, a).send({ secret_id: secret, expires_at: future }).expect(201))
      .body;
    const admin = new pg.Client({ connectionString: adminUrl });
    await admin.connect();
    const second = (
      await admin.query(
        "insert into secrets (org_id, project_id, environment_id, name) select org_id, project_id, environment_id, 's2' from secrets where id = $1 returning id",
        [secret],
      )
    ).rows[0].id;
    const expired = (await http.post(url).set(DEV_ORG, a).send({ secret_id: second }).expect(201)).body;
    await admin.query("update agent_grants set expires_at = now() - interval '1 minute' where id = $1", [expired.id]);
    await admin.end();

    const internal = `/internal/v1/agents/${agent}/grants`;
    const r = await http.get(internal).set("Authorization", `Bearer ${TOKEN}`).set("X-Locksmith-Org", a).expect(200);
    expect(r.body).toEqual({
      agent_id: agent,
      items: [
        {
          grant_id: live.id,
          secret_id: secret,
          secret_name: "s",
          mode: "relay",
          scope: null,
          expires_at: future,
        },
      ],
    });
    // Another org's id is the same 404 as an agent that does not exist.
    await http.get(internal).set("Authorization", `Bearer ${TOKEN}`).set("X-Locksmith-Org", b).expect(404);
    await http
      .get(`/internal/v1/agents/${MISSING}/grants`)
      .set("Authorization", `Bearer ${TOKEN}`)
      .set("X-Locksmith-Org", a)
      .expect(404);
    await app.close();
  });

  it("refuses a missing or wrong token, a bad org header, and the dev header, all as 401", async () => {
    const { app, http, a } = await withToken();
    const agent = (await http.post("/v1/agents").set(DEV_ORG, a).send({ name: "x" }).expect(201)).body.agent.id;
    const internal = `/internal/v1/agents/${agent}/grants`;
    await http.get(internal).set("X-Locksmith-Org", a).expect(401);
    await http.get(internal).set("Authorization", "Bearer wrong").set("X-Locksmith-Org", a).expect(401);
    await http.get(internal).set("Authorization", `Bearer ${TOKEN}x`).set("X-Locksmith-Org", a).expect(401);
    await http.get(internal).set("Authorization", `Bearer ${TOKEN}`).expect(401);
    await http.get(internal).set("Authorization", `Bearer ${TOKEN}`).set("X-Locksmith-Org", "nope").expect(401);
    await http.get(internal).set(DEV_ORG, a).expect(401);
    await app.close();
    // No token configured: every internal call fails closed, even with the right-looking header.
    delete process.env["LOCKSMITH_GATEWAY_SERVICE_TOKEN"];
    const closed = await appWith("1");
    await request(closed.getHttpServer())
      .get(internal)
      .set("Authorization", `Bearer ${TOKEN}`)
      .set("X-Locksmith-Org", a)
      .expect(401);
    await closed.close();
  });
});
