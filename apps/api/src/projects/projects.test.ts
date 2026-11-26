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
import { OrgsModule } from "../orgs/orgs.module.js";
import { ProjectsModule } from "./projects.module.js";

// Task 6.3: the projects and environments paths against a real Postgres as the app role (row-level security applies).
// Mirrors the `projects` and `environments` scenarios of `tests/api-contract`.
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
    imports: [TestDbModule, TenantModule, OrgsModule, ProjectsModule],
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

describe("projects", () => {
  it("creates, reads, patches and deletes, with Location and RFC 3339 stamps", async () => {
    const { app, http, a } = await twoOrgs();
    const c = await http.post("/v1/projects").set(DEV_ORG, a).send({ name: "p", description: "d" }).expect(201);
    expect(c.headers["location"]).toBe(`/v1/projects/${c.body.id}`);
    expect(Object.keys(c.body).sort()).toEqual(["created_at", "description", "id", "name", "updated_at"]);
    expect(c.body.created_at).toMatch(/^\d{4}-\d\d-\d\dT.*Z$/);
    const noDesc = await http.post("/v1/projects").set(DEV_ORG, a).send({ name: "q" }).expect(201);
    expect(noDesc.body.description).toBe("");
    await http.get(`/v1/projects/${c.body.id}`).set(DEV_ORG, a).expect(200);
    const p = await http
      .patch(`/v1/projects/${c.body.id}`)
      .set(DEV_ORG, a)
      .send({ description: "changed" })
      .expect(200);
    expect(p.body).toMatchObject({ name: "p", description: "changed" });
    await http.patch(`/v1/projects/${c.body.id}`).set(DEV_ORG, a).send({ name: null, description: "x" }).expect(200);
    await http.delete(`/v1/projects/${c.body.id}`).set(DEV_ORG, a).expect(204);
    await http.get(`/v1/projects/${c.body.id}`).set(DEV_ORG, a).expect(404);
    await http.delete(`/v1/projects/${c.body.id}`).set(DEV_ORG, a).expect(404);
    await app.close();
  });

  it("answers 401 first, 404 for another org's or a malformed id, 409 for a duplicate", async () => {
    const { app, http, a, b } = await twoOrgs();
    await http.post("/v1/projects").send({ name: "x" }).expect(401);
    await http.get("/v1/projects/not-a-uuid").expect(401);
    const p = (await http.post("/v1/projects").set(DEV_ORG, a).send({ name: "dup" }).expect(201)).body.id;
    const dup = await http.post("/v1/projects").set(DEV_ORG, a).send({ name: "dup" }).expect(409);
    expect(dup.body).toMatchObject({ type: "urn:locksmith:problem:conflict", status: 409 });
    await http.post("/v1/projects").set(DEV_ORG, b).send({ name: "dup" }).expect(201);
    await http.get(`/v1/projects/${p}`).set(DEV_ORG, b).expect(404);
    await http.patch(`/v1/projects/${p}`).set(DEV_ORG, b).send({ description: "x" }).expect(404);
    await http.delete(`/v1/projects/${p}`).set(DEV_ORG, b).expect(404);
    await http.get("/v1/projects/not-a-uuid").set(DEV_ORG, a).expect(404);
    await http.get(`/v1/projects/${MISSING}`).set(DEV_ORG, a).expect(404);
    // The path is checked before the body, as with axum extractors.
    await http.patch("/v1/projects/not-a-uuid").set(DEV_ORG, a).send({}).expect(404);
    await app.close();
  });

  it("rejects bad bodies with 400 problem details that name only a field", async () => {
    const { app, http, a } = await twoOrgs();
    const post = (body: unknown) =>
      http
        .post("/v1/projects")
        .set(DEV_ORG, a)
        .send(body as object);
    expect((await post({}).expect(400)).body.detail).toBe("missing field `name`");
    await post({ name: "" }).expect(400);
    await post({ name: "x".repeat(201) }).expect(400);
    await post({ name: "ok", description: "d".repeat(4097) }).expect(400);
    await post({ name: "ok", extra: 1 }).expect(400);
    await post({ name: 5 }).expect(400);
    await http.post("/v1/projects").set(DEV_ORG, a).set("content-type", "application/json").send("{nope").expect(400);
    const p = (await post({ name: "ok" }).expect(201)).body.id;
    const patch = (body: object) => http.patch(`/v1/projects/${p}`).set(DEV_ORG, a).send(body);
    expect((await patch({}).expect(400)).body.detail).toBe("provide `name` and/or `description` to change");
    await patch({ name: null, description: null }).expect(400);
    await patch({ name: " " }).expect(400);
    await patch({ nope: 1 }).expect(400);
    await app.close();
  });

  it("lists in id order with keyset cursors, and validates limit and cursor", async () => {
    const { app, http, a, b } = await twoOrgs();
    const ids: string[] = [];
    for (const n of ["p1", "p2", "p3"])
      ids.push((await http.post("/v1/projects").set(DEV_ORG, a).send({ name: n }).expect(201)).body.id);
    const first = await http.get("/v1/projects?limit=2").set(DEV_ORG, a).expect(200);
    expect(first.body.items.map((x: { id: string }) => x.id)).toEqual(ids.slice(0, 2));
    expect(typeof first.body.next).toBe("string");
    const second = await http.get(`/v1/projects?limit=2&cursor=${first.body.next}`).set(DEV_ORG, a).expect(200);
    expect(second.body.items.map((x: { id: string }) => x.id)).toEqual(ids.slice(2));
    expect("next" in second.body).toBe(false);
    expect((await http.get("/v1/projects").set(DEV_ORG, b).expect(200)).body.items).toEqual([]);
    for (const q of [
      "limit=0",
      "limit=101",
      "limit=abc",
      "limit=-1",
      "limit=1&limit=2",
      "cursor=zzz",
      "cursor=AAAA",
      "x=1",
      "limit=",
    ]) {
      await http.get(`/v1/projects?${q}`).set(DEV_ORG, a).expect(400);
    }
    expect((await http.get("/v1/projects?limit=0").set(DEV_ORG, a)).body.detail).toBe(
      "`limit` must be between 1 and 100",
    );
    await http.get("/v1/projects").expect(401);
    await app.close();
  });

  it("refuses to delete a project that still has environments (409)", async () => {
    const { app, http, a } = await twoOrgs();
    const p = (await http.post("/v1/projects").set(DEV_ORG, a).send({ name: "p" }).expect(201)).body.id;
    const e = (await http.post(`/v1/projects/${p}/environments`).set(DEV_ORG, a).send({ name: "dev" }).expect(201)).body
      .id;
    const res = await http.delete(`/v1/projects/${p}`).set(DEV_ORG, a).expect(409);
    expect(res.body.detail).toBe("the resource still has child resources");
    await http.delete(`/v1/projects/${p}/environments/${e}`).set(DEV_ORG, a).expect(204);
    await http.delete(`/v1/projects/${p}`).set(DEV_ORG, a).expect(204);
    await app.close();
  });
});

describe("environments", () => {
  it("creates, lists, reads, patches and deletes under a project", async () => {
    const { app, http, a, b } = await twoOrgs();
    const p = (await http.post("/v1/projects").set(DEV_ORG, a).send({ name: "p" }).expect(201)).body.id;
    const base = `/v1/projects/${p}/environments`;
    const c = await http.post(base).set(DEV_ORG, a).send({ name: "dev", description: "d" }).expect(201);
    expect(c.headers["location"]).toBe(`${base}/${c.body.id}`);
    expect(c.body.project_id).toBe(p);
    await http.post(base).set(DEV_ORG, a).send({ name: "dev" }).expect(409);
    await http.post(base).set(DEV_ORG, a).send({}).expect(400);
    await http.post(base).send({ name: "x" }).expect(401);
    await http.post(base).set(DEV_ORG, b).send({ name: "x" }).expect(404);
    await http.post(`/v1/projects/${MISSING}/environments`).set(DEV_ORG, a).send({ name: "x" }).expect(404);
    const list = await http.get(base).set(DEV_ORG, a).expect(200);
    expect(list.body.items.map((x: { id: string }) => x.id)).toEqual([c.body.id]);
    await http.get(base).set(DEV_ORG, b).expect(404);
    await http.get(base).expect(401);
    await http.get(`${base}?limit=0`).set(DEV_ORG, a).expect(400);
    await http.get(`${base}/${c.body.id}`).set(DEV_ORG, a).expect(200);
    await http.get(`${base}/${c.body.id}`).set(DEV_ORG, b).expect(404);
    await http.get(`${base}/${MISSING}`).set(DEV_ORG, a).expect(404);
    const other = (await http.post("/v1/projects").set(DEV_ORG, a).send({ name: "q" }).expect(201)).body.id;
    await http.get(`/v1/projects/${other}/environments/${c.body.id}`).set(DEV_ORG, a).expect(404);
    const patched = await http
      .patch(`${base}/${c.body.id}`)
      .set(DEV_ORG, a)
      .send({ description: "changed" })
      .expect(200);
    expect(patched.body.description).toBe("changed");
    await http.patch(`${base}/${c.body.id}`).set(DEV_ORG, a).send({ name: "" }).expect(400);
    await http.patch(`${base}/${c.body.id}`).set(DEV_ORG, b).send({ description: "x" }).expect(404);
    await http.delete(`${base}/${c.body.id}`).set(DEV_ORG, b).expect(404);
    await http.delete(`${base}/${c.body.id}`).set(DEV_ORG, a).expect(204);
    await http.get(`${base}/${c.body.id}`).set(DEV_ORG, a).expect(404);
    await app.close();
  });
});
