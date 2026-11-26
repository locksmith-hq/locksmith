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

// B9 3.2: the secret metadata read paths against a real Postgres as the app role (row-level security applies).
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

async function appWith(): Promise<INestApplication> {
  process.env["LOCKSMITH_DEV_AUTH"] = "1";
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
const SECRET_KEYS = [
  "created_at",
  "description",
  "environment_id",
  "id",
  "name",
  "project_id",
  "updated_at",
  "version_count",
];
const VERSION_KEYS = ["created_at", "key_id", "secret_id", "version"];

/** Seeds through the admin connection (superuser, so row-level security does not apply to the setup only). */
async function seed(org: string, secrets: number, versions = 0) {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  const q = async (text: string, v: unknown[]) => (await admin.query(text, v)).rows;
  const [{ id: project }] = await q("INSERT INTO projects (org_id, name) VALUES ($1, 'p') RETURNING id", [org]);
  const [{ id: env }] = await q(
    "INSERT INTO environments (org_id, project_id, name) VALUES ($1, $2, 'e') RETURNING id",
    [org, project],
  );
  const [{ id: env2 }] = await q(
    "INSERT INTO environments (org_id, project_id, name) VALUES ($1, $2, 'e2') RETURNING id",
    [org, project],
  );
  const ids: string[] = [];
  for (let i = 0; i < secrets; i++) {
    const [{ id }] = await q(
      "INSERT INTO secrets (org_id, project_id, environment_id, name, description) VALUES ($1, $2, $3, $4, 'd') RETURNING id",
      [org, project, env, `s-${i}`],
    );
    ids.push(id);
  }
  for (let v = 1; v <= versions; v++) {
    await q(
      "INSERT INTO secret_versions (org_id, secret_id, version, ciphertext, wrapped_dek, key_id) VALUES ($1, $2, $3, $4, $5, 'gateway:v1')",
      [
        org,
        ids[0],
        v,
        Buffer.from("TOP-SECRET-CIPHERTEXT".padEnd(48, "x")),
        Buffer.from("TOP-SECRET-DEK".padEnd(80, "x")),
      ],
    );
  }
  await admin.end();
  return { project: project as string, env: env as string, env2: env2 as string, ids };
}

async function twoOrgs() {
  const app = await appWith();
  const http = request(app.getHttpServer());
  const a = (await http.post("/v1/orgs").send({ name: "A" }).expect(201)).body.id as string;
  const b = (await http.post("/v1/orgs").send({ name: "B" }).expect(201)).body.id as string;
  return { app, http, a, b };
}

const base = (p: string, e: string) => `/v1/projects/${p}/environments/${e}/secrets`;

describe("secret metadata reads", () => {
  it("lists secrets in id order with keyset paging and version counts, with only schema fields", async () => {
    const { app, http, a, b } = await twoOrgs();
    const s = await seed(a, 3, 2);
    await seed(b, 2);
    const all = await http.get(base(s.project, s.env)).set(DEV_ORG, a).expect(200);
    expect(all.body.items.map((i: { id: string }) => i.id)).toEqual([...s.ids].sort());
    expect(all.body.next).toBeUndefined();
    for (const i of all.body.items) expect(Object.keys(i).sort()).toEqual(SECRET_KEYS);
    const withVersions = all.body.items.find((i: { id: string }) => i.id === s.ids[0]);
    expect(withVersions).toMatchObject({
      version_count: 2,
      name: "s-0",
      description: "d",
      environment_id: s.env,
      project_id: s.project,
    });
    expect(all.body.items.filter((i: { version_count: number }) => i.version_count === 0)).toHaveLength(2);
    expect(JSON.stringify(all.body)).not.toMatch(/TOP-SECRET|ciphertext|wrapped_dek/i);
    const p1 = await http
      .get(`${base(s.project, s.env)}?limit=2`)
      .set(DEV_ORG, a)
      .expect(200);
    expect(p1.body.items).toHaveLength(2);
    const p2 = await http
      .get(`${base(s.project, s.env)}?limit=2&cursor=${p1.body.next}`)
      .set(DEV_ORG, a)
      .expect(200);
    expect(p2.body.items.map((i: { id: string }) => i.id)).toEqual([...s.ids].sort().slice(2));
    expect(p2.body.next).toBeUndefined();
    expect((await http.get(base(s.project, s.env2)).set(DEV_ORG, a).expect(200)).body.items).toEqual([]);
    await http
      .get(`${base(s.project, s.env)}?limit=0`)
      .set(DEV_ORG, a)
      .expect(400);
    await http
      .get(`${base(s.project, s.env)}?cursor=bad`)
      .set(DEV_ORG, a)
      .expect(400);
    await http.get(base(s.project, s.env)).expect(401);
    await app.close();
  });

  it("returns 404 for another org's environment, an unknown environment, and malformed ids", async () => {
    const { app, http, a, b } = await twoOrgs();
    const s = await seed(a, 1);
    await http.get(base(s.project, s.env)).set(DEV_ORG, b).expect(404);
    await http.get(base(s.project, MISSING)).set(DEV_ORG, a).expect(404);
    await http.get(base(MISSING, s.env)).set(DEV_ORG, a).expect(404);
    await http.get(base("not-a-uuid", s.env)).set(DEV_ORG, a).expect(404);
    await http.get(base("not-a-uuid", s.env)).expect(401);
    await app.close();
  });

  it("gets one secret; wrong parent, unknown, malformed and another org's ids are 404", async () => {
    const { app, http, a, b } = await twoOrgs();
    const s = await seed(a, 1, 3);
    const one = await http
      .get(`${base(s.project, s.env)}/${s.ids[0]}`)
      .set(DEV_ORG, a)
      .expect(200);
    expect(Object.keys(one.body).sort()).toEqual(SECRET_KEYS);
    expect(one.body).toMatchObject({ id: s.ids[0], version_count: 3 });
    await http
      .get(`${base(s.project, s.env)}/${s.ids[0]}`)
      .set(DEV_ORG, b)
      .expect(404);
    await http
      .get(`${base(s.project, s.env2)}/${s.ids[0]}`)
      .set(DEV_ORG, a)
      .expect(404);
    await http
      .get(`${base(s.project, s.env)}/${MISSING}`)
      .set(DEV_ORG, a)
      .expect(404);
    await http
      .get(`${base(s.project, s.env)}/not-a-uuid`)
      .set(DEV_ORG, a)
      .expect(404);
    await app.close();
  });

  it("lists versions oldest first as metadata only, never a value, DEK or ciphertext", async () => {
    const { app, http, a, b } = await twoOrgs();
    const s = await seed(a, 2, 3);
    const res = await http
      .get(`${base(s.project, s.env)}/${s.ids[0]}/versions`)
      .set(DEV_ORG, a)
      .expect(200);
    expect(res.body.items.map((v: { version: number }) => v.version)).toEqual([1, 2, 3]);
    for (const v of res.body.items) {
      expect(Object.keys(v).sort()).toEqual(VERSION_KEYS);
      expect(v).toMatchObject({ secret_id: s.ids[0], key_id: "gateway:v1" });
    }
    expect(Object.keys(res.body)).toEqual(["items"]);
    expect(JSON.stringify(res.body)).not.toMatch(/TOP-SECRET|ciphertext|wrapped_dek|dek/i);
    expect(
      (
        await http
          .get(`${base(s.project, s.env)}/${s.ids[1]}/versions`)
          .set(DEV_ORG, a)
          .expect(200)
      ).body.items,
    ).toEqual([]);
    await http
      .get(`${base(s.project, s.env)}/${s.ids[0]}/versions`)
      .set(DEV_ORG, b)
      .expect(404);
    await http
      .get(`${base(s.project, s.env2)}/${s.ids[0]}/versions`)
      .set(DEV_ORG, a)
      .expect(404);
    await http
      .get(`${base(s.project, s.env)}/${MISSING}/versions`)
      .set(DEV_ORG, a)
      .expect(404);
    await http
      .get(`${base(s.project, s.env)}/not-a-uuid/versions`)
      .set(DEV_ORG, a)
      .expect(404);
    await app.close();
  });
});
