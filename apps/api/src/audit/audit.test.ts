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
import { AUDIT_SINK } from "./audit-sink.js";
import { createKysely, KYSELY, type Database } from "../db/db.module.js";
import { ProblemFilter } from "../platform/problem.js";
import { TenantModule } from "../tenant/tenant.module.js";
import { OrgsModule } from "../orgs/orgs.module.js";
import { AuditReadModule } from "./audit.module.js";
import { decodeSeqCursor, encodeSeqCursor } from "./audit.service.js";

// B9 2.2: the audit read paths against a real Postgres as the app role (row-level security applies).
const MIGRATIONS = [
  "0001_roles.sql",
  "0002_tenancy_schema.sql",
  "0003_secret_versions.sql",
  "0008_audit_ledger.sql",
  "0011_users.sql",
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

async function appWith(): Promise<INestApplication> {
  process.env["LOCKSMITH_DEV_AUTH"] = "1";
  @Module({
    imports: [TestDbModule, TenantModule, OrgsModule, AuditReadModule],
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

/** Seeds events through the admin connection (superuser, so row-level security does not apply to the setup only). */
async function seedEvents(org: string, count: number) {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  const ids: string[] = [];
  for (let seq = 1; seq <= count; seq++) {
    const prev = Buffer.alloc(32, seq - 1);
    const hash = Buffer.alloc(32, seq);
    const { rows } = await admin.query(
      `INSERT INTO audit_events (id, at, org_id, seq, kind, actor, target, outcome, attrs, prev_hash, hash)
       VALUES (gen_random_uuid(), now(), $1, $2, 'agent.created', 'user:u', $3, 'ok', '{"n": 1}'::jsonb, $4, $5) RETURNING id`,
      [org, seq, seq % 2 ? `agent:${seq}` : null, prev, hash],
    );
    ids.push(rows[0].id);
  }
  if (count > 0) {
    await admin.query("INSERT INTO audit_heads (org_id, seq, hash) VALUES ($1, $2, $3)", [
      org,
      count,
      Buffer.alloc(32, count),
    ]);
  }
  await admin.end();
  return ids;
}

async function twoOrgs() {
  const app = await appWith();
  const http = request(app.getHttpServer());
  const a = (await http.post("/v1/orgs").send({ name: "A" }).expect(201)).body.id as string;
  const b = (await http.post("/v1/orgs").send({ name: "B" }).expect(201)).body.id as string;
  return { app, http, a, b };
}

describe("audit cursors", () => {
  it("round-trips a seq and rejects non-canonical, wrong-length and non-positive cursors", () => {
    expect(decodeSeqCursor(encodeSeqCursor(42))).toBe("42");
    expect(decodeSeqCursor(Buffer.alloc(8).toString("base64url"))).toBeNull();
    expect(decodeSeqCursor("AAAA")).toBeNull();
    expect(decodeSeqCursor("not base64!")).toBeNull();
  });
});

describe("audit reads", () => {
  it("lists events newest first with keyset paging, hex digests and an omitted null target", async () => {
    const { app, http, a, b } = await twoOrgs();
    await seedEvents(a, 5);
    await seedEvents(b, 2);
    const all = await http.get("/v1/audit/events").set(DEV_ORG, a).expect(200);
    expect(all.body.items.map((e: { seq: number }) => e.seq)).toEqual([5, 4, 3, 2, 1]);
    expect(all.body.next).toBeUndefined();
    const [e5, e4] = all.body.items;
    expect(Object.keys(e5).sort()).toEqual([
      "actor",
      "at",
      "attrs",
      "digest",
      "id",
      "kind",
      "outcome",
      "prev_digest",
      "seq",
      "target",
    ]);
    expect(e5).toMatchObject({
      target: "agent:5",
      attrs: { n: 1 },
      digest: "05".repeat(32),
      prev_digest: "04".repeat(32),
    });
    expect("target" in e4).toBe(false);
    const p1 = await http.get("/v1/audit/events?limit=2").set(DEV_ORG, a).expect(200);
    expect(p1.body.items.map((e: { seq: number }) => e.seq)).toEqual([5, 4]);
    expect(p1.body.next).toBe(encodeSeqCursor(4));
    const p2 = await http.get(`/v1/audit/events?limit=2&cursor=${p1.body.next}`).set(DEV_ORG, a).expect(200);
    expect(p2.body.items.map((e: { seq: number }) => e.seq)).toEqual([3, 2]);
    const p3 = await http.get(`/v1/audit/events?limit=2&cursor=${p2.body.next}`).set(DEV_ORG, a).expect(200);
    expect(p3.body.items.map((e: { seq: number }) => e.seq)).toEqual([1]);
    expect(p3.body.next).toBeUndefined();
    await app.close();
  });

  it("never lists another org's events, and rejects bad queries and a missing binding", async () => {
    const { app, http, a, b } = await twoOrgs();
    await seedEvents(a, 3);
    const mine = await http.get("/v1/audit/events").set(DEV_ORG, a).expect(200);
    const theirs = await http.get("/v1/audit/events").set(DEV_ORG, b).expect(200);
    expect(mine.body.items).toHaveLength(3);
    expect(theirs.body.items).toEqual([]);
    await http.get("/v1/audit/events?limit=0").set(DEV_ORG, a).expect(400);
    await http.get("/v1/audit/events?limit=101").set(DEV_ORG, a).expect(400);
    await http.get("/v1/audit/events?cursor=bad").set(DEV_ORG, a).expect(400);
    await http.get("/v1/audit/events?other=1").set(DEV_ORG, a).expect(400);
    await http.get("/v1/audit/events").expect(401);
    await http.get("/v1/audit/status").expect(401);
    await app.close();
  });

  it("reports head 0 for an org with no events, then head, latest checkpoint and latest verify run", async () => {
    const { app, http, a, b } = await twoOrgs();
    expect((await http.get("/v1/audit/status").set(DEV_ORG, a).expect(200)).body).toEqual({ head_seq: 0 });
    await seedEvents(a, 3);
    const admin = new pg.Client({ connectionString: adminUrl });
    await admin.connect();
    await admin.query(
      "INSERT INTO audit_checkpoints (org_id, seq, hash, at, key_id, signature) VALUES ($1,1,$2,now(),'audit-checkpoint:1',$3), ($1,3,$4,now(),'audit-checkpoint:1',$3)",
      [a, Buffer.alloc(32, 1), Buffer.alloc(64, 9), Buffer.alloc(32, 3)],
    );
    await admin.query(
      `INSERT INTO audit_verify_runs (org_id, mode, started_at, finished_at, ok, events, checkpoints)
       VALUES ($1,'db','2031-01-01T00:00:00Z','2031-01-01T00:00:01Z',true,3,2),
              ($1,'dir','2031-01-02T00:00:00Z','2031-01-02T00:00:01Z',false,3,2)`,
      [a],
    );
    await admin.query(
      "UPDATE audit_verify_runs SET broken_seq = 2, break_kind = 'hash' WHERE org_id = $1 AND mode = 'dir'",
      [a],
    );
    await admin.end();
    const s = (await http.get("/v1/audit/status").set(DEV_ORG, a).expect(200)).body;
    expect(s.head_seq).toBe(3);
    expect(s.latest_checkpoint).toMatchObject({ seq: 3, digest: "03".repeat(32), key_id: "audit-checkpoint:1" });
    expect(Object.keys(s.latest_checkpoint).sort()).toEqual(["at", "digest", "key_id", "seq"]);
    expect(s.latest_verify).toMatchObject({
      mode: "dir",
      ok: false,
      events: 3,
      checkpoints: 2,
      broken_seq: 2,
      break_kind: "hash",
    });
    expect("truncated_at" in s.latest_verify).toBe(false);
    expect((await http.get("/v1/audit/status").set(DEV_ORG, b).expect(200)).body).toEqual({ head_seq: 0 });
    await app.close();
  });
});
