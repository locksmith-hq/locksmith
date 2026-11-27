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
import { FixedWindowLimiter } from "./fixed-window.js";
import { encodeHandle, decodeHandle } from "./validate.js";
import { WorkloadIdentitiesModule } from "./workload-identities.module.js";

// Task 6.5 slice: `POST /v1/workload-tokens` on a real Postgres (RLS) with a stub core and a recording audit sink.
const MIGRATIONS = [
  "0001_roles.sql",
  "0002_tenancy_schema.sql",
  "0003_secret_versions.sql",
  "0006_agents.sql",
  "0011_users.sql",
  "0013_workload_identities.sql",
];
const CANARY = "ext.canary.jwt-DO-NOT-LEAK";
const GH = "https://token.actions.githubusercontent.com";

let container: StartedTestContainer;
let db: Database;
let adminUrl: string;
const events: { kind: string; outcome?: string; actor: unknown; attrs: Record<string, unknown> }[] = [];
let sinkDown = false;
let verdict: { valid: boolean; reason?: string } = { valid: true };
let coreDown = false;
let mintCalls: unknown[] = [];
let verifyCalls: { policy: string; token: string }[] = [];

const core = {
  verifyWorkloadToken: async (b: { policy: string; token: string }) => {
    verifyCalls.push(b);
    if (coreDown) throw new Error("core down");
    return verdict;
  },
  mintWorkloadToken: async (b: unknown) => {
    mintCalls.push(b);
    return { token: "agent.jwt.minted", expires_in: 900, expires_at: "2030-01-01T00:00:00Z" };
  },
};

@Global()
@Module({
  providers: [
    { provide: KYSELY, useFactory: () => db },
    { provide: CORE_CLIENT, useValue: core },
    {
      provide: AUDIT_SINK,
      useValue: {
        append: async () => {},
        appendAdmin: async (e: (typeof events)[number]) => {
          if (sinkDown) throw new Error("sink down");
          events.push(e);
        },
      },
    },
  ],
  exports: [KYSELY, AUDIT_SINK, CORE_CLIENT],
})
class TestDbModule {}

async function appUp(): Promise<INestApplication> {
  @Module({
    imports: [TestDbModule, TenantModule, WorkloadIdentitiesModule],
    providers: [{ provide: APP_FILTER, useClass: ProblemFilter }],
  })
  class M {}
  const mod = await Test.createTestingModule({ imports: [M] }).compile();
  const app = mod.createNestApplication({ logger: false });
  await app.init();
  return app;
}

async function seed(): Promise<{ org: string; agent: string; policy: string; handle: string }> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    const org = (await admin.query("insert into orgs (name) values ('A') returning id")).rows[0].id as string;
    const agent = (
      await admin.query(
        "insert into agents (org_id, name, enrollment_hash) values ($1, 'bot', '$argon2id$stub') returning id",
        [org],
      )
    ).rows[0].id as string;
    const policy = (
      await admin.query(
        `insert into workload_identities (org_id, name, issuer_kind, issuer, audience, agent_id, conditions)
         values ($1, 'ci', 'github', $2, 'aud', $3, '[{"claim":"repository","op":"eq","value":"acme/app"}]'::jsonb) returning id`,
        [org, GH, agent],
      )
    ).rows[0].id as string;
    return { org, agent, policy, handle: encodeHandle(org, policy) };
  } finally {
    await admin.end();
  }
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

function reset() {
  events.length = 0;
  sinkDown = false;
  coreDown = false;
  verdict = { valid: true };
  mintCalls = [];
  verifyCalls = [];
}

describe("POST /v1/workload-tokens", () => {
  it("exchanges a verified token, records the exchange and stamps last_used_at", async () => {
    reset();
    const s = await seed();
    const app = await appUp();
    const res = await request(app.getHttpServer())
      .post("/v1/workload-tokens")
      .send({ policy: s.handle, token: CANARY })
      .expect(200);
    expect(res.body).toEqual({
      access_token: "agent.jwt.minted",
      token_type: "Bearer",
      expires_in: 900,
      expires_at: "2030-01-01T00:00:00Z",
    });
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(mintCalls).toEqual([{ org_id: s.org, agent_id: s.agent, policy_id: s.policy }]);
    expect(events).toEqual([
      {
        kind: "workload_identity.exchanged",
        orgId: s.org,
        actor: { type: "agent", id: s.agent },
        target: { type: "workload", id: s.policy },
        attrs: { agent_id: s.agent, issuer: "token.actions.githubusercontent.com" },
      },
    ]);
    const admin = new pg.Client({ connectionString: adminUrl });
    await admin.connect();
    const last = (await admin.query("select last_used_at from workload_identities where id=$1", [s.policy])).rows[0];
    await admin.end();
    expect(last.last_used_at).not.toBeNull();
    expect(JSON.stringify([res.body, events])).not.toContain(CANARY);
    await app.close();
  });

  it("answers every credential failure with the same 401 and records a denial with a static reason", async () => {
    reset();
    const s = await seed();
    const app = await appUp();
    const http = request(app.getHttpServer());
    verdict = { valid: false, reason: "unknown_key" };
    const a = await http.post("/v1/workload-tokens").send({ policy: s.handle, token: CANARY }).expect(401);
    const b = await http.post("/v1/workload-tokens").send({ policy: "lsw_nope", token: CANARY }).expect(401);
    const other = await seed();
    const unknownPolicy = encodeHandle(s.org, other.policy); // a policy of another org, under this org's RLS
    const c = await http.post("/v1/workload-tokens").send({ policy: unknownPolicy, token: CANARY }).expect(401);
    expect(b.body).toEqual(a.body);
    expect(c.body).toEqual(a.body);
    expect(mintCalls).toEqual([]);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      kind: "workload_identity.denied",
      outcome: "denied",
      attrs: { agent_id: s.agent, reason: "unknown_key" },
    });
    expect(JSON.stringify([a.body, events])).not.toContain(CANARY);
    await app.close();
  });

  it("is a 503, never a verdict, when the core or the ledger fails, and returns no token", async () => {
    reset();
    const s = await seed();
    const app = await appUp();
    const http = request(app.getHttpServer());
    coreDown = true;
    const down = await http.post("/v1/workload-tokens").send({ policy: s.handle, token: CANARY }).expect(503);
    expect(JSON.stringify(down.body)).not.toContain("core down");
    expect(events).toEqual([]);
    coreDown = false;
    sinkDown = true;
    const closed = await http.post("/v1/workload-tokens").send({ policy: s.handle, token: CANARY }).expect(503);
    expect(JSON.stringify(closed.body)).not.toContain("agent.jwt.minted");
    await app.close();
  });

  it("rejects unknown fields and missing fields as 400 and never reaches the core", async () => {
    reset();
    const s = await seed();
    const app = await appUp();
    const http = request(app.getHttpServer());
    await http.post("/v1/workload-tokens").send({ policy: s.handle, token: CANARY, extra: 1 }).expect(400);
    await http.post("/v1/workload-tokens").send({ policy: s.handle }).expect(400);
    expect(verifyCalls).toEqual([]);
    await app.close();
  });
});

describe("handles and limits", () => {
  it("decodeHandle inverts encodeHandle and refuses malformed handles", () => {
    const org = "0190f3a2-7b1c-7000-8000-000000000001";
    const pol = "0190f3a2-7b1c-7000-8000-000000000002";
    expect(decodeHandle(encodeHandle(org, pol))).toEqual({ orgId: org, policyId: pol });
    for (const bad of ["", "lsw_", "lsw_!!", "lse_AAAA", encodeHandle(org, pol).slice(0, -2)]) {
      expect(decodeHandle(bad), bad).toBeNull();
    }
  });

  it("the fixed window passes `limit` hits per key then refuses until the window ends", () => {
    let t = 0;
    const w = new FixedWindowLimiter(2, 1000, 10, () => t);
    expect([w.allow("a"), w.allow("a"), w.allow("a")]).toEqual([true, true, false]);
    expect(w.allow("b")).toBe(true);
    t = 1000;
    expect(w.allow("a")).toBe(true);
  });
});
