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
import { ProjectsModule } from "../projects/projects.module.js";
import { SecretsModule } from "./secrets.module.js";

// Task 6.5: the secrets metadata paths against a real Postgres as the app role (row-level security applies).
// Mirrors the `secrets` scenarios of `tests/api-contract`.
const MIGRATIONS = ["0001_roles.sql", "0002_tenancy_schema.sql", "0003_secret_versions.sql", "0011_users.sql"];
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
    imports: [TestDbModule, TenantModule, OrgsModule, ProjectsModule, SecretsModule],
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

async function setup() {
  const app = await appWith("1");
  const http = request(app.getHttpServer());
  const org = async (n: string) => (await http.post("/v1/orgs").send({ name: n }).expect(201)).body.id as string;
  const a = await org("A");
  const b = await org("B");
  const p = (await http.post("/v1/projects").set(DEV_ORG, a).send({ name: "p" }).expect(201)).body.id as string;
  const e = (await http.post(`/v1/projects/${p}/environments`).set(DEV_ORG, a).send({ name: "dev" }).expect(201)).body
    .id as string;
  return { app, http, a, b, p, e, base: `/v1/projects/${p}/environments/${e}/secrets` };
}

describe("secrets metadata", () => {
  it("creates, reads, patches and deletes, counting versions and never taking a value", async () => {
    const { app, http, a, p, e, base } = await setup();
    const c = await http.post(base).set(DEV_ORG, a).send({ name: "db", description: "d" }).expect(201);
    expect(c.headers["location"]).toBe(`${base}/${c.body.id}`);
    expect(Object.keys(c.body).sort()).toEqual([
      "created_at",
      "description",
      "environment_id",
      "id",
      "name",
      "project_id",
      "updated_at",
      "version_count",
    ]);
    expect(c.body).toMatchObject({ project_id: p, environment_id: e, version_count: 0 });
    await http.post(base).set(DEV_ORG, a).send({ name: "x", value: "s3cret" }).expect(400);
    expect((await http.get(base).set(DEV_ORG, a).expect(200)).body.items).toHaveLength(1);
    const patched = await http.patch(`${base}/${c.body.id}`).set(DEV_ORG, a).send({ description: "n" }).expect(200);
    expect(patched.body).toMatchObject({ name: "db", description: "n", version_count: 0 });
    await http.patch(`${base}/${c.body.id}`).set(DEV_ORG, a).send({}).expect(400);
    await http.delete(`${base}/${c.body.id}`).set(DEV_ORG, a).expect(204);
    await http.get(`${base}/${c.body.id}`).set(DEV_ORG, a).expect(404);
    await http.delete(`${base}/${c.body.id}`).set(DEV_ORG, a).expect(404);
    await app.close();
  });

  it("counts stored versions", async () => {
    const { app, http, a, base } = await setup();
    const c = (await http.post(base).set(DEV_ORG, a).send({ name: "db" }).expect(201)).body;
    const admin = new pg.Client({ connectionString: adminUrl });
    await admin.connect();
    for (const v of [1, 2])
      await admin.query(
        "INSERT INTO secret_versions (org_id, secret_id, version, ciphertext, wrapped_dek, key_id) VALUES ((SELECT org_id FROM secrets WHERE id = $1), $1, $2, decode(repeat('00', 48), 'hex'), decode(repeat('00', 80), 'hex'), 'k')",
        [c.id, v],
      );
    await admin.end();
    expect((await http.get(`${base}/${c.id}`).set(DEV_ORG, a).expect(200)).body.version_count).toBe(2);
    expect((await http.get(base).set(DEV_ORG, a).expect(200)).body.items[0].version_count).toBe(2);
    expect(
      (await http.patch(`${base}/${c.id}`).set(DEV_ORG, a).send({ name: "db2" }).expect(200)).body.version_count,
    ).toBe(2);
    await app.close();
  });

  it("lists version metadata oldest first, with no key material", async () => {
    const { app, http, a, b, base } = await setup();
    const c = (await http.post(base).set(DEV_ORG, a).send({ name: "db" }).expect(201)).body;
    expect((await http.get(`${base}/${c.id}/versions`).set(DEV_ORG, a).expect(200)).body).toEqual({ items: [] });
    const admin = new pg.Client({ connectionString: adminUrl });
    await admin.connect();
    for (const v of [2, 1])
      await admin.query(
        "INSERT INTO secret_versions (org_id, secret_id, version, ciphertext, wrapped_dek, key_id) VALUES ((SELECT org_id FROM secrets WHERE id = $1), $1, $2, decode(repeat('00', 48), 'hex'), decode(repeat('00', 80), 'hex'), 'gateway:v1')",
        [c.id, v],
      );
    await admin.end();
    const r = await http.get(`${base}/${c.id}/versions`).set(DEV_ORG, a).expect(200);
    expect(r.body.items.map((x: { version: number }) => x.version)).toEqual([1, 2]);
    expect(Object.keys(r.body.items[0]).sort()).toEqual(["created_at", "key_id", "secret_id", "version"]);
    expect(r.body.items[0]).toMatchObject({ secret_id: c.id, key_id: "gateway:v1" });
    await http.get(`${base}/${c.id}/versions`).set(DEV_ORG, b).expect(404);
    await http.get(`${base}/${MISSING}/versions`).set(DEV_ORG, a).expect(404);
    await http.get(`${base}/${c.id}/versions`).expect(401);
    await app.close();
  });

  it("answers 401 first, 404 across orgs and for bad ids, 409 on a duplicate name", async () => {
    const { app, http, a, b, p, e, base } = await setup();
    await http.post(base).send({ name: "x" }).expect(401);
    const s = (await http.post(base).set(DEV_ORG, a).send({ name: "dup" }).expect(201)).body.id;
    await http.post(base).set(DEV_ORG, a).send({ name: "dup" }).expect(409);
    await http.get(`${base}/${s}`).set(DEV_ORG, b).expect(404);
    await http.get(base).set(DEV_ORG, b).expect(404);
    await http.post(base).set(DEV_ORG, b).send({ name: "x" }).expect(404);
    await http.patch(`${base}/${s}`).set(DEV_ORG, b).send({ description: "x" }).expect(404);
    await http.delete(`${base}/${s}`).set(DEV_ORG, b).expect(404);
    await http.get(`/v1/projects/${p}/environments/${MISSING}/secrets`).set(DEV_ORG, a).expect(404);
    await http.get(`/v1/projects/not-a-uuid/environments/${e}/secrets`).set(DEV_ORG, a).expect(404);
    await http.get(`${base}/${MISSING}`).set(DEV_ORG, a).expect(404);
    await app.close();
  });

  it("lists in id order with keyset cursors", async () => {
    const { app, http, a, base } = await setup();
    const ids: string[] = [];
    for (const n of ["s1", "s2", "s3"])
      ids.push((await http.post(base).set(DEV_ORG, a).send({ name: n }).expect(201)).body.id);
    const first = await http.get(`${base}?limit=2`).set(DEV_ORG, a).expect(200);
    expect(first.body.items.map((x: { id: string }) => x.id)).toEqual(ids.slice(0, 2));
    const second = await http.get(`${base}?limit=2&cursor=${first.body.next}`).set(DEV_ORG, a).expect(200);
    expect(second.body.items.map((x: { id: string }) => x.id)).toEqual(ids.slice(2));
    expect("next" in second.body).toBe(false);
    await http.get(`${base}?limit=0`).set(DEV_ORG, a).expect(400);
    await http.get(`${base}?cursor=zzz`).set(DEV_ORG, a).expect(400);
    await app.close();
  });
});
