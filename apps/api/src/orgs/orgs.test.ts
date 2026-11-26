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
import { createKysely, KYSELY, type Database } from "../db/db.module.js";
import { ProblemFilter } from "../platform/problem.js";
import { TenantModule } from "../tenant/tenant.module.js";
import { OrgsModule } from "./orgs.module.js";
import { uuidv7, validateName } from "./orgs.service.js";

// Task 6.2: the orgs paths against a real Postgres as the app role (row-level security applies).
// Mirrors the `orgs` scenario of `tests/api-contract`.
const MIGRATIONS = ["0001_roles.sql", "0002_tenancy_schema.sql", "0011_users.sql"];
const DEV_ORG = "x-locksmith-dev-org";

let container: StartedTestContainer;
let db: Database;
let adminUrl: string;

@Global()
@Module({ providers: [{ provide: KYSELY, useFactory: () => db }], exports: [KYSELY] })
class TestDbModule {}

async function appWith(devAuth: string | undefined): Promise<INestApplication> {
  if (devAuth === undefined) delete process.env["LOCKSMITH_DEV_AUTH"];
  else process.env["LOCKSMITH_DEV_AUTH"] = devAuth;
  @Module({
    imports: [TestDbModule, TenantModule, OrgsModule],
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

describe("orgs with dev auth", () => {
  it("creates an org, then reads it as current and by id; another org is 404", async () => {
    const app = await appWith("1");
    const http = request(app.getHttpServer());
    const a = await http.post("/v1/orgs").send({ name: "Acme" }).expect(201);
    const b = await http.post("/v1/orgs").send({ name: "Other" }).expect(201);
    expect(a.headers["location"]).toBe(`/v1/orgs/${a.body.id}`);
    expect(Object.keys(a.body).sort()).toEqual(["created_at", "id", "name", "region", "updated_at"]);
    expect(a.body.name).toBe("Acme");
    expect(a.body.created_at).toMatch(/^\d{4}-\d\d-\d\dT.*Z$/);

    const cur = await http.get("/v1/orgs/current").set(DEV_ORG, a.body.id).expect(200);
    expect(cur.body).toEqual(a.body);
    await http.get(`/v1/orgs/${a.body.id}`).set(DEV_ORG, a.body.id).expect(200);
    // Cross-tenant and malformed ids both look absent.
    await http.get(`/v1/orgs/${b.body.id}`).set(DEV_ORG, a.body.id).expect(404);
    await http.get("/v1/orgs/not-a-uuid").set(DEV_ORG, a.body.id).expect(404);
    await app.close();
  });

  it("refuses a missing or malformed binding with 401 problem details", async () => {
    const app = await appWith("1");
    const http = request(app.getHttpServer());
    const res = await http.get("/v1/orgs/current").expect(401);
    expect(res.headers["content-type"]).toMatch(/application\/problem\+json/);
    expect(res.body).toMatchObject({ type: "urn:locksmith:problem:unauthenticated", status: 401 });
    await http.get("/v1/orgs/current").set(DEV_ORG, "not-a-uuid").expect(401);
    await http.get(`/v1/orgs/${uuidv7()}`).expect(401);
    await app.close();
  });

  it("never downgrades a bearer token to the dev header", async () => {
    const app = await appWith("1");
    const org = (await request(app.getHttpServer()).post("/v1/orgs").send({ name: "Acme" }).expect(201)).body.id;
    // No issuer is configured, so every bearer token fails closed, dev header or not.
    await request(app.getHttpServer())
      .get("/v1/orgs/current")
      .set("authorization", "Bearer not.a.token")
      .set(DEV_ORG, org)
      .expect(401);
    await app.close();
  });

  it("returns 404 for a bound org that has no row", async () => {
    const app = await appWith("1");
    await request(app.getHttpServer()).get("/v1/orgs/current").set(DEV_ORG, uuidv7()).expect(404);
    await app.close();
  });

  it("rejects bad create bodies with 400", async () => {
    const app = await appWith("1");
    const http = request(app.getHttpServer());
    await http.post("/v1/orgs").send({}).expect(400);
    await http.post("/v1/orgs").send({ name: "" }).expect(400);
    await http.post("/v1/orgs").send({ name: "   " }).expect(400);
    await http
      .post("/v1/orgs")
      .send({ name: "x".repeat(201) })
      .expect(400);
    await http.post("/v1/orgs").send({ name: "ok", extra: 1 }).expect(400);
    await http.post("/v1/orgs").send({ name: 5 }).expect(400);
    await http
      .post("/v1/orgs")
      .send({ name: "x".repeat(200) })
      .expect(201);
    await app.close();
  });
});

describe("orgs without dev auth", () => {
  it.each([undefined, "0", ""])("refuses create and the dev header with 401 (LOCKSMITH_DEV_AUTH=%j)", async (flag) => {
    const app = await appWith(flag);
    const http = request(app.getHttpServer());
    await http.post("/v1/orgs").send({ name: "Refused" }).expect(401);
    // The check comes before the body is read.
    await http.post("/v1/orgs").send({}).expect(401);
    await http.get("/v1/orgs/current").set(DEV_ORG, uuidv7()).expect(401);
    const admin = new pg.Client({ connectionString: adminUrl });
    await admin.connect();
    const n = await admin.query("select count(*)::int as n from orgs where name = 'Refused'");
    expect(n.rows[0].n).toBe(0);
    await admin.end();
    await app.close();
  });
});

describe("helpers", () => {
  it("uuidv7 has version 7, the RFC variant and a sortable timestamp prefix", () => {
    const a = uuidv7(1_700_000_000_000);
    const b = uuidv7(1_700_000_000_001);
    expect(a).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(a.slice(0, 13) < b.slice(0, 13)).toBe(true);
  });

  it("counts characters, not UTF-16 units, for the name limit", () => {
    expect(() => validateName("😀".repeat(200))).not.toThrow();
    expect(() => validateName("😀".repeat(201))).toThrow();
  });
});
