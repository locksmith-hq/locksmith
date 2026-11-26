import "reflect-metadata";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Global, Inject, Injectable, Module, type CanActivate, type ExecutionContext } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { Test } from "@nestjs/testing";
import pg from "pg";
import request from "supertest";
import { GenericContainer, Wait, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { INestApplication } from "@nestjs/common";
import { KYSELY, createKysely, type Database } from "../../db/db.module.js";
import { TenantModule } from "../../tenant/tenant.module.js";
import { TenantService } from "../../tenant/tenant.service.js";
import { NotificationsModule } from "./notifications.module.js";

// N1 task 4.1: the inbox routes against a real Postgres as the app role. The B1 auth guard is not in
// the tree yet, so a test guard binds org and user from headers the way the real guard will.
const ORG_A = "0192f3a0-0000-7000-8000-0000000000a1";
const ORG_B = "0192f3a0-0000-7000-8000-0000000000b1";
const U1 = "0192f3a0-0000-7000-8000-0000000000a2";
const U2 = "0192f3a0-0000-7000-8000-0000000000a3";
const UB = "0192f3a0-0000-7000-8000-0000000000b2";
const N_U1_OLD = "0192f3a0-0000-7000-8000-000000000101";
const N_U1_NEW = "0192f3a0-0000-7000-8000-000000000102";
const N_U2 = "0192f3a0-0000-7000-8000-000000000103";
const N_B = "0192f3a0-0000-7000-8000-000000000104";
const ADMIN_PASSWORD = "admin-test-only";

const payload = (kind: string, extra: Record<string, unknown> = {}) =>
  JSON.stringify({
    kind,
    actor: { id: "agent-1", name: "Builder" },
    object_name: "stripe",
    occurred_at: "2026-01-01T00:00:00Z",
    link: "/audit",
    ...extra,
  });

@Injectable()
class TestAuthGuard implements CanActivate {
  constructor(@Inject(TenantService) private readonly tenant: TenantService) {}
  canActivate(ctx: ExecutionContext): boolean {
    const h = ctx.switchToHttp().getRequest().headers;
    if (typeof h["x-test-org"] === "string") this.tenant.setOrgId(h["x-test-org"]);
    if (typeof h["x-test-user"] === "string") this.tenant.setUserId(h["x-test-user"]);
    return true;
  }
}

let container: StartedTestContainer;
let app: INestApplication;
let admin: pg.Client;

const migrationsDir = new URL("../../../../../services/control-plane/migrations/", import.meta.url);
const as = (org: string, user: string) => ({ "x-test-org": org, "x-test-user": user });
const readAt = async (id: string) =>
  (await admin.query("select read_at from notifications where id = $1", [id])).rows[0].read_at as Date | null;

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
     insert into users (id, issuer, subject, personal_org_id) values
       ('${U1}', 'https://issuer.test', 'u1', '${ORG_A}'),
       ('${U2}', 'https://issuer.test', 'u2', '${ORG_A}'),
       ('${UB}', 'https://issuer.test', 'ub', '${ORG_B}');`,
  );
  const ins = "insert into notifications (id, org_id, user_id, kind, payload, created_at) values ($1,$2,$3,$4,$5,$6)";
  // The first item carries an extra stored field the response must not expose.
  await admin.query(ins, [
    N_U1_OLD,
    ORG_A,
    U1,
    "relay.denied",
    payload("relay.denied", { canary: "SECRET" }),
    "2026-01-01T00:00:00Z",
  ]);
  await admin.query(ins, [N_U1_NEW, ORG_A, U1, "git.denied", payload("git.denied"), "2026-01-02T00:00:00Z"]);
  await admin.query(ins, [N_U2, ORG_A, U2, "grant.revoked", payload("grant.revoked"), "2026-01-03T00:00:00Z"]);
  await admin.query(ins, [N_B, ORG_B, UB, "agent.deleted", payload("agent.deleted"), "2026-01-04T00:00:00Z"]);

  const db = createKysely(`postgres://locksmith_app:locksmith-app-dev-only@${hostPort}/postgres`, 2);
  @Global()
  @Module({ providers: [{ provide: KYSELY, useValue: db }], exports: [KYSELY] })
  class TestDb {}
  @Module({
    imports: [TestDb, TenantModule, NotificationsModule],
    providers: [{ provide: APP_GUARD, useClass: TestAuthGuard }],
  })
  class TestApp {}
  app = (await Test.createTestingModule({ imports: [TestApp] }).compile()).createNestApplication();
  await app.init();
}, 180_000);

afterAll(async () => {
  await app?.close();
  await app?.get<Database>(KYSELY, { strict: false })?.destroy();
  await admin?.end();
  await container?.stop();
});

describe("GET /v1/notifications", () => {
  it("returns only the caller's items, newest first, with the unread count", async () => {
    const res = await request(app.getHttpServer()).get("/v1/notifications").set(as(ORG_A, U1));
    expect(res.status).toBe(200);
    expect(res.body.items.map((i: { id: string }) => i.id)).toEqual([N_U1_NEW, N_U1_OLD]);
    expect(res.body.unread_count).toBe(2);
    expect(res.body.items[0]).toMatchObject({ kind: "git.denied", read_at: null });
  });

  it("exposes only the allow-listed payload fields", async () => {
    const res = await request(app.getHttpServer()).get("/v1/notifications").set(as(ORG_A, U1));
    expect(Object.keys(res.body.items[1].payload).sort()).toEqual(
      ["actor", "kind", "link", "object_name", "occurred_at"].sort(),
    );
    expect(JSON.stringify(res.body)).not.toContain("SECRET");
  });

  it("is empty for the same user bound to another org", async () => {
    const res = await request(app.getHttpServer()).get("/v1/notifications").set(as(ORG_B, U1));
    expect(res.body).toEqual({ items: [], unread_count: 0 });
  });

  it("rejects a request with no authenticated principal and a bad unread value", async () => {
    expect((await request(app.getHttpServer()).get("/v1/notifications")).status).toBe(401);
    const bad = await request(app.getHttpServer()).get("/v1/notifications?unread=maybe").set(as(ORG_A, U1));
    expect(bad.status).toBe(400);
  });
});

describe("POST /v1/notifications/{id}/read and read-all", () => {
  it("another user's id is 404 and stays unread", async () => {
    const res = await request(app.getHttpServer()).post(`/v1/notifications/${N_U2}/read`).set(as(ORG_A, U1));
    expect(res.status).toBe(404);
    expect(await readAt(N_U2)).toBeNull();
  });

  it("a cross-org id is 404", async () => {
    const res = await request(app.getHttpServer()).post(`/v1/notifications/${N_B}/read`).set(as(ORG_A, U1));
    expect(res.status).toBe(404);
    expect(await readAt(N_B)).toBeNull();
  });

  it("an unknown or malformed id is 404 or 400", async () => {
    const unknown = "0192f3a0-0000-7000-8000-0000000009ff";
    expect(
      (await request(app.getHttpServer()).post(`/v1/notifications/${unknown}/read`).set(as(ORG_A, U1))).status,
    ).toBe(404);
    expect((await request(app.getHttpServer()).post("/v1/notifications/nope/read").set(as(ORG_A, U1))).status).toBe(
      400,
    );
  });

  it("marks one read, idempotently, and lowers the unread count", async () => {
    const first = await request(app.getHttpServer()).post(`/v1/notifications/${N_U1_OLD}/read`).set(as(ORG_A, U1));
    expect(first.status).toBe(204);
    const stamp = await readAt(N_U1_OLD);
    expect(stamp).not.toBeNull();
    const second = await request(app.getHttpServer()).post(`/v1/notifications/${N_U1_OLD}/read`).set(as(ORG_A, U1));
    expect(second.status).toBe(204);
    expect(await readAt(N_U1_OLD)).toEqual(stamp);
    const list = await request(app.getHttpServer()).get("/v1/notifications").set(as(ORG_A, U1));
    expect(list.body.unread_count).toBe(1);
    const unread = await request(app.getHttpServer()).get("/v1/notifications?unread=true").set(as(ORG_A, U1));
    expect(unread.body.items.map((i: { id: string }) => i.id)).toEqual([N_U1_NEW]);
  });

  it("read-all marks only the caller's unread items", async () => {
    const res = await request(app.getHttpServer()).post("/v1/notifications/read-all").set(as(ORG_A, U1));
    expect(res.status).toBe(204);
    expect(await readAt(N_U1_NEW)).not.toBeNull();
    expect(await readAt(N_U2)).toBeNull();
    expect(await readAt(N_B)).toBeNull();
    const list = await request(app.getHttpServer()).get("/v1/notifications").set(as(ORG_A, U1));
    expect(list.body.unread_count).toBe(0);
    const other = await request(app.getHttpServer()).get("/v1/notifications").set(as(ORG_A, U2));
    expect(other.body.unread_count).toBe(1);
  });
});
