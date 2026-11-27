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
import { CORE_CLIENT } from "../core/core.tokens.js";
import { createKysely, KYSELY, type Database } from "../db/db.module.js";
import { ProblemFilter } from "../platform/problem.js";
import { TenantModule } from "../tenant/tenant.module.js";
import { OrgsModule } from "../orgs/orgs.module.js";
import { WorkloadIdentitiesModule } from "./workload-identities.module.js";

// Task 6.5 slice: the workload-identities paths against a real Postgres as the app role (row-level security applies).
// Audit events go to a recording sink.
const MIGRATIONS = [
  "0001_roles.sql",
  "0002_tenancy_schema.sql",
  "0003_secret_versions.sql",
  "0006_agents.sql",
  "0011_users.sql",
  "0013_workload_identities.sql",
];
const DEV_ORG = "x-locksmith-dev-org";
const GH = "https://token.actions.githubusercontent.com";

let container: StartedTestContainer;
let db: Database;
let adminUrl: string;
const sink: { kind: string; orgId: string; target: unknown; attrs: unknown }[] = [];
let sinkDown = false;

@Global()
@Module({
  providers: [
    { provide: KYSELY, useFactory: () => db },
    { provide: CORE_CLIENT, useValue: {} },
    {
      provide: AUDIT_SINK,
      useValue: {
        append: async () => {},
        appendAdmin: async (e: (typeof sink)[number]) => {
          if (sinkDown) throw new Error("sink down");
          sink.push(e);
        },
      },
    },
  ],
  exports: [KYSELY, AUDIT_SINK, CORE_CLIENT],
})
class TestDbModule {}

async function appWith(devAuth: string | undefined): Promise<INestApplication> {
  if (devAuth === undefined) delete process.env["LOCKSMITH_DEV_AUTH"];
  else process.env["LOCKSMITH_DEV_AUTH"] = devAuth;
  @Module({
    imports: [TestDbModule, TenantModule, OrgsModule, WorkloadIdentitiesModule],
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

/** An agent in `org`, made as the admin role (the enrollment secret needs the core). */
async function agentIn(org: string, name = "bot"): Promise<string> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    return (
      await admin.query(
        "insert into agents (org_id, name, enrollment_hash) values ($1, $2, '$argon2id$stub') returning id",
        [org, name],
      )
    ).rows[0].id;
  } finally {
    await admin.end();
  }
}

const policy = (agent_id: string, over: Record<string, unknown> = {}) => ({
  name: "ci",
  issuer_kind: "github",
  audience: "https://locksmith.example",
  agent_id,
  conditions: [{ claim: "repository", pattern: "acme/app" }],
  ...over,
});

describe("workload identities", () => {
  it("creates, reads, lists and deletes, auditing each write", async () => {
    sink.length = 0;
    const { app, http, a } = await twoOrgs();
    const agent = await agentIn(a);
    const c = await http
      .post("/v1/workload-identities")
      .set(DEV_ORG, a)
      .send(policy(agent, { name: "  ci  ", conditions: [{ claim: "repository", pattern: "acme/*" }] }))
      .expect(201);
    const id = c.body.id as string;
    expect(c.headers["location"]).toBe(`/v1/workload-identities/${id}`);
    expect(Object.keys(c.body).sort()).toEqual([
      "agent_id",
      "audience",
      "conditions",
      "created_at",
      "handle",
      "id",
      "issuer",
      "issuer_kind",
      "last_used_at",
      "name",
    ]);
    expect(c.body).toMatchObject({
      name: "ci",
      issuer_kind: "github",
      issuer: GH,
      agent_id: agent,
      last_used_at: null,
      conditions: [{ claim: "repository", pattern: "acme/*" }],
    });
    const raw = Buffer.from((c.body.handle as string).slice(4), "base64url").toString("hex");
    expect(raw).toBe(a.replaceAll("-", "") + id.replaceAll("-", ""));

    expect((await http.get(`/v1/workload-identities/${id}`).set(DEV_ORG, a).expect(200)).body).toEqual(c.body);
    const l = await http.get("/v1/workload-identities").set(DEV_ORG, a).expect(200);
    expect(l.body.items.map((x: { id: string }) => x.id)).toEqual([id]);
    expect(l.body.next).toBeUndefined();

    await http.delete(`/v1/workload-identities/${id}`).set(DEV_ORG, a).expect(204);
    await http.delete(`/v1/workload-identities/${id}`).set(DEV_ORG, a).expect(404);
    await http.get(`/v1/workload-identities/${id}`).set(DEV_ORG, a).expect(404);

    expect(sink).toEqual([
      {
        kind: "workload_identity.created",
        orgId: a,
        actor: { type: "service", code: "dev_auth" },
        target: { type: "workload", id },
        attrs: { agent_id: agent, issuer: "token.actions.githubusercontent.com" },
      },
      {
        kind: "workload_identity.deleted",
        orgId: a,
        actor: { type: "service", code: "dev_auth" },
        target: { type: "workload", id },
        attrs: { agent_id: agent },
      },
    ]);
    expect(JSON.stringify(sink)).not.toMatch(/acme|locksmith\.example|"ci"/);
    await app.close();
  });

  it("creates an oidc policy with a normalised issuer, and pages the list", async () => {
    const { app, http, a } = await twoOrgs();
    const agent = await agentIn(a);
    const ids: string[] = [];
    for (const n of ["p1", "p2", "p3"]) {
      const r = await http
        .post("/v1/workload-identities")
        .set(DEV_ORG, a)
        .send(
          policy(agent, {
            name: n,
            issuer_kind: "oidc",
            issuer: "https://k8s.example/",
            conditions: [{ claim: "sub", pattern: "system:serviceaccount:prod:deployer" }],
          }),
        )
        .expect(201);
      expect(r.body.issuer).toBe("https://k8s.example");
      ids.push(r.body.id);
    }
    const p1 = await http.get("/v1/workload-identities?limit=2").set(DEV_ORG, a).expect(200);
    expect(p1.body.items.map((x: { id: string }) => x.id)).toEqual(ids.slice(0, 2));
    const p2 = await http
      .get(`/v1/workload-identities?limit=2&cursor=${encodeURIComponent(p1.body.next)}`)
      .set(DEV_ORG, a)
      .expect(200);
    expect(p2.body.items.map((x: { id: string }) => x.id)).toEqual(ids.slice(2));
    expect(p2.body.next).toBeUndefined();
    await app.close();
  });

  it("answers a duplicate name with 409, per org", async () => {
    const { app, http, a, b } = await twoOrgs();
    const agent = await agentIn(a);
    await http.post("/v1/workload-identities").set(DEV_ORG, a).send(policy(agent)).expect(201);
    const dup = await http
      .post("/v1/workload-identities")
      .set(DEV_ORG, a)
      .send(policy(agent, { name: " ci" }));
    expect(dup.status).toBe(409);
    expect(dup.body.detail).toBe("a workload identity with this name exists");
    await http
      .post("/v1/workload-identities")
      .set(DEV_ORG, b)
      .send(policy(await agentIn(b)))
      .expect(201);
    await app.close();
  });

  it("refuses bad policies with 400 and 422 like Rust", async () => {
    sink.length = 0;
    const { app, http, a } = await twoOrgs();
    const agent = await agentIn(a);
    const post = (body: unknown) =>
      http
        .post("/v1/workload-identities")
        .set(DEV_ORG, a)
        .send(body as object);
    // 400: body shape, name, issuer_kind
    await post({}).expect(400);
    await post({ ...policy(agent), extra: 1 }).expect(400);
    await post({ ...policy(agent), agent_id: "nope" }).expect(400);
    await post(policy(agent, { name: "  " })).expect(400);
    await post(policy(agent, { name: "x".repeat(201) })).expect(400);
    await post(policy(agent, { issuer_kind: "saml" })).expect(400);
    // 422: policy refused
    const refused: [string, Record<string, unknown>, string][] = [
      [
        "no subject pin",
        { conditions: [{ claim: "ref", pattern: "refs/heads/main" }] },
        "a condition must pin the subject (repository or sub)",
      ],
      [
        "bare star",
        { conditions: [{ claim: "repository", pattern: "*" }] },
        "a bare * is not allowed; pin the claim to a value",
      ],
      [
        "owner not fixed",
        { conditions: [{ claim: "repository", pattern: "acme*" }] },
        "a condition must pin the subject (repository or sub)",
      ],
      ["no conditions", { conditions: [] }, "at least one condition is required"],
      ["blank audience", { audience: " " }, "audience is required"],
      [
        "github issuer override",
        { issuer: "https://evil.example" },
        "a github policy can only use the GitHub Actions issuer",
      ],
      [
        "oidc without issuer",
        { issuer_kind: "oidc", conditions: [{ claim: "sub", pattern: "s" }] },
        "issuer must be an https URL without credentials, query or fragment",
      ],
      [
        "http issuer",
        { issuer_kind: "oidc", issuer: "http://k8s.example", conditions: [{ claim: "sub", pattern: "s" }] },
        "issuer must be an https URL without credentials, query or fragment",
      ],
      [
        "inner wildcard",
        { conditions: [{ claim: "repository", pattern: "ac*me/app" }] },
        "a condition needs a claim name and a value (a trailing * is the only wildcard)",
      ],
      [
        "metadata issuer",
        { issuer_kind: "oidc", issuer: "https://169.254.169.254", conditions: [{ claim: "sub", pattern: "s" }] },
        "the issuer host is not an allowed address",
      ],
      [
        "private issuer",
        { issuer_kind: "oidc", issuer: "https://10.0.0.5/realm", conditions: [{ claim: "sub", pattern: "s" }] },
        "the issuer host is not an allowed address",
      ],
      [
        "localhost issuer",
        { issuer_kind: "oidc", issuer: "https://localhost", conditions: [{ claim: "sub", pattern: "s" }] },
        "the issuer host is not an allowed address",
      ],
    ];
    for (const [label, over, detail] of refused) {
      const r = await post(policy(agent, over));
      expect(r.status, label).toBe(422);
      expect(r.body.detail, label).toBe(detail);
    }
    expect((await http.get("/v1/workload-identities").set(DEV_ORG, a).expect(200)).body.items).toEqual([]);
    expect(sink).toEqual([]);
    await http.post("/v1/workload-identities").send(policy(agent)).expect(401);
    await http.get("/v1/workload-identities/not-a-uuid").set(DEV_ORG, a).expect(404);
    await http.get("/v1/workload-identities?limit=0").set(DEV_ORG, a).expect(400);
    await app.close();
  });

  it("answers 404 for an agent that is not in the org", async () => {
    const { app, http, a, b } = await twoOrgs();
    const other = await agentIn(b);
    await http.post("/v1/workload-identities").set(DEV_ORG, a).send(policy(other)).expect(404);
    await http.post("/v1/workload-identities").set(DEV_ORG, a).send(policy(MISSING)).expect(404);
    expect((await http.get("/v1/workload-identities").set(DEV_ORG, a).expect(200)).body.items).toEqual([]);
    await app.close();
  });

  it("isolates orgs", async () => {
    sink.length = 0;
    const { app, http, a, b } = await twoOrgs();
    const id = (
      await http
        .post("/v1/workload-identities")
        .set(DEV_ORG, a)
        .send(policy(await agentIn(a)))
        .expect(201)
    ).body.id;
    await http.get(`/v1/workload-identities/${id}`).set(DEV_ORG, b).expect(404);
    await http.delete(`/v1/workload-identities/${id}`).set(DEV_ORG, b).expect(404);
    expect((await http.get("/v1/workload-identities").set(DEV_ORG, b).expect(200)).body.items).toEqual([]);
    await http.get(`/v1/workload-identities/${id}`).set(DEV_ORG, a).expect(200);
    expect(sink.map((e) => e.kind)).toEqual(["workload_identity.created"]);
    await app.close();
  });

  it("rolls the change back when the audit append fails", async () => {
    sink.length = 0;
    const { app, http, a } = await twoOrgs();
    const agent = await agentIn(a);
    sinkDown = true;
    try {
      await http.post("/v1/workload-identities").set(DEV_ORG, a).send(policy(agent)).expect(500);
    } finally {
      sinkDown = false;
    }
    expect((await http.get("/v1/workload-identities").set(DEV_ORG, a).expect(200)).body.items).toEqual([]);
    const id = (await http.post("/v1/workload-identities").set(DEV_ORG, a).send(policy(agent)).expect(201)).body.id;
    sinkDown = true;
    try {
      await http.delete(`/v1/workload-identities/${id}`).set(DEV_ORG, a).expect(500);
    } finally {
      sinkDown = false;
    }
    await http.get(`/v1/workload-identities/${id}`).set(DEV_ORG, a).expect(200);
    await app.close();
  });

  it("deleting the agent deletes its policies", async () => {
    const { app, http, a } = await twoOrgs();
    const agent = await agentIn(a);
    const id = (await http.post("/v1/workload-identities").set(DEV_ORG, a).send(policy(agent)).expect(201)).body.id;
    const admin = new pg.Client({ connectionString: adminUrl });
    await admin.connect();
    await admin.query("delete from agents where id = $1", [agent]);
    await admin.end();
    await http.get(`/v1/workload-identities/${id}`).set(DEV_ORG, a).expect(404);
    await app.close();
  });
});
