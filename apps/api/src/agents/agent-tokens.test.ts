import "reflect-metadata";
import { randomBytes } from "node:crypto";
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
import { AgentsModule } from "./agents.module.js";
import { enrollmentIds } from "./agent-tokens.service.js";

// Task 6.4: `POST /v1/agent-tokens` against a real Postgres as the app role. The core is a stub:
// the hash check is "hash === `$argon2id$stub:` + secret"; minting returns a canary token.
const MIGRATIONS = ["0001_roles.sql", "0002_tenancy_schema.sql", "0003_secret_versions.sql", "0006_agents.sql"];
let container: StartedTestContainer;
let db: Database;
let adminUrl: string;
let coreDown = false;
const verifyCalls: { enrollment_hash: string | null }[] = [];
const core = {
  verifyEnrollmentSecret: async (r: { enrollment_secret: string; enrollment_hash: string | null }) => {
    if (coreDown) throw new Error("core LEAK-CANARY");
    verifyCalls.push({ enrollment_hash: r.enrollment_hash });
    return { valid: r.enrollment_hash === `$argon2id$stub:${r.enrollment_secret}` };
  },
  mintAgentToken: async (r: { org_id: string; agent_id: string }) => ({
    token: `jwt.${r.org_id}.${r.agent_id}`,
    token_type: "Bearer" as const,
    expires_in: 900,
    expires_at: "2026-11-26T12:15:00Z",
  }),
};

@Global()
@Module({
  providers: [
    { provide: KYSELY, useFactory: () => db },
    { provide: AUDIT_SINK, useValue: { append: async () => {}, appendAdmin: async () => {} } },
    { provide: CORE_CLIENT, useValue: core },
  ],
  exports: [KYSELY, AUDIT_SINK, CORE_CLIENT],
})
class TestDbModule {}

const uuidBytes = (u: string) => Buffer.from(u.replaceAll("-", ""), "hex");
const secretFor = (org: string, agent: string) =>
  `lse_${Buffer.concat([uuidBytes(org), uuidBytes(agent), randomBytes(32)]).toString("base64url")}`;

let app: INestApplication;
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
  @Module({
    imports: [TestDbModule, TenantModule, AgentsModule],
    providers: [{ provide: APP_FILTER, useClass: ProblemFilter }],
  })
  class M {}
  const mod = await Test.createTestingModule({ imports: [M] }).compile();
  app = mod.createNestApplication({ logger: false });
  await app.init();
}, 180_000);

afterAll(async () => {
  await app?.close();
  await db?.destroy();
  await container?.stop();
});

async function agentIn(secret: (org: string, agent: string) => string) {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    const org = (await admin.query("insert into orgs (name) values ('o') returning id")).rows[0].id as string;
    const agent = (await admin.query("select gen_random_uuid() as id")).rows[0].id as string;
    const s = secret(org, agent);
    await admin.query("insert into agents (id, org_id, name, enrollment_hash) values ($1, $2, 'bot', $3)", [
      agent,
      org,
      `$argon2id$stub:${s}`,
    ]);
    return { org, agent, secret: s };
  } finally {
    await admin.end();
  }
}

describe("enrollmentIds", () => {
  it("decodes ids from a well-formed secret and rejects the rest", () => {
    const o = "11111111-1111-4111-8111-111111111111";
    const a = "22222222-2222-4222-8222-222222222222";
    expect(enrollmentIds(secretFor(o, a))).toEqual({ orgId: o, agentId: a });
    expect(enrollmentIds(`  ${secretFor(o, a)}\n`)).toEqual({ orgId: o, agentId: a });
    for (const bad of ["", "lse_", "lse_abc", `x${secretFor(o, a)}`, `lse_${"A".repeat(200)}`, "lse_!!!!"])
      expect(enrollmentIds(bad)).toBeNull();
  });
});

describe("POST /v1/agent-tokens", () => {
  it("exchanges a valid secret for a no-store token", async () => {
    const { org, agent, secret } = await agentIn(secretFor);
    const r = await request(app.getHttpServer())
      .post("/v1/agent-tokens")
      .send({ enrollment_secret: secret })
      .expect(200);
    expect(r.headers["cache-control"]).toBe("no-store");
    expect(r.headers["pragma"]).toBe("no-cache");
    expect(r.body).toEqual({
      access_token: `jwt.${org}.${agent}`,
      token_type: "Bearer",
      expires_in: 900,
      expires_at: "2026-11-26T12:15:00Z",
    });
  });

  it("refuses wrong, unknown, replaced and malformed secrets with the same 401", async () => {
    const { org, agent } = await agentIn(secretFor);
    const wrong = secretFor(org, agent);
    const unknown = secretFor(org, "33333333-3333-4333-8333-333333333333");
    const otherOrg = secretFor("44444444-4444-4444-8444-444444444444", agent);
    const bodies: string[] = [];
    verifyCalls.length = 0;
    for (const s of [wrong, unknown, otherOrg, "nonsense", "lse_abc"]) {
      const r = await request(app.getHttpServer()).post("/v1/agent-tokens").send({ enrollment_secret: s }).expect(401);
      expect(r.headers["content-type"]).toContain("application/problem+json");
      expect(JSON.stringify(r.body)).not.toContain(s);
      bodies.push(JSON.stringify(r.body));
    }
    expect(new Set(bodies).size).toBe(1);
    // Unknown agent and unknown org reach the core with a null hash (same Argon2id work); malformed never does.
    expect(verifyCalls.map((c) => c.enrollment_hash === null)).toEqual([false, true, true]);
  });

  it("does not let one org's agent id mint in another org (row-level security)", async () => {
    const a = await agentIn(secretFor);
    const b = await agentIn(secretFor);
    const crossed = secretFor(b.org, a.agent);
    await request(app.getHttpServer()).post("/v1/agent-tokens").send({ enrollment_secret: crossed }).expect(401);
  });

  it("is 400 for a bad body and 503 (no core text) when the core is down", async () => {
    const { secret } = await agentIn(secretFor);
    const http = request(app.getHttpServer());
    await http.post("/v1/agent-tokens").send({}).expect(400);
    await http.post("/v1/agent-tokens").send({ enrollment_secret: secret, extra: 1 }).expect(400);
    coreDown = true;
    try {
      const r = await http.post("/v1/agent-tokens").send({ enrollment_secret: secret }).expect(503);
      expect(JSON.stringify(r.body)).not.toContain("LEAK-CANARY");
    } finally {
      coreDown = false;
    }
  });
});
