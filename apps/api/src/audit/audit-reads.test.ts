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
import { CORE_CLIENT } from "../core/core.tokens.js";
import { AUDIT_SINK } from "./audit-sink.js";
import { AuditReadsModule } from "./audit.module.js";

// Task 6.5 slice: the audit read paths against a real Postgres as the app role (row-level security applies).
const MIGRATIONS = ["0001_roles.sql", "0002_tenancy_schema.sql", "0008_audit_ledger.sql", "0011_users.sql"];
const DEV_ORG = "x-locksmith-dev-org";

let container: StartedTestContainer;
let db: Database;
let adminUrl: string;
let app: INestApplication;

@Global()
@Module({
  providers: [
    { provide: KYSELY, useFactory: () => db },
    { provide: CORE_CLIENT, useValue: {} },
    { provide: AUDIT_SINK, useValue: { append: async () => {}, appendAdmin: async () => {} } },
  ],
  exports: [KYSELY, AUDIT_SINK, CORE_CLIENT],
})
class TestDbModule {}

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
  for (const name of MIGRATIONS)
    await admin.query(
      readFileSync(
        fileURLToPath(new URL(`../../../../services/control-plane/migrations/${name}`, import.meta.url)),
        "utf8",
      ),
    );
  await admin.end();
  db = createKysely(`postgres://locksmith_app:locksmith-app-dev-only@${hostPort}/postgres`, 4);
  process.env["LOCKSMITH_DEV_AUTH"] = "1";
  @Module({
    imports: [TestDbModule, TenantModule, OrgsModule, AuditReadsModule],
    providers: [{ provide: APP_FILTER, useClass: ProblemFilter }],
  })
  class M {}
  app = (await Test.createTestingModule({ imports: [M] }).compile()).createNestApplication({ logger: false });
  await app.init();
}, 180_000);

afterAll(async () => {
  await app?.close();
  await db?.destroy();
  await container?.stop();
});

const hex = (n: number) => n.toString(16).padStart(2, "0").repeat(32);

/** Seeds `n` chained events (and optionally a checkpoint and verify runs) for `org` as the admin role. */
async function seed(org: string, n: number, opts: { checkpoint?: boolean; verify?: boolean } = {}) {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    let prev = "00".repeat(32);
    for (let seq = 1; seq <= n; seq++) {
      const h = hex(seq);
      await admin.query(
        `insert into audit_events (org_id, seq, id, at, kind, actor, target, outcome, attrs, prev_hash, hash)
         values ($1, $2, gen_random_uuid(), now(), 'agent.created', 'user:u1', $3, 'ok', '{"k":"v"}', decode($4,'hex'), decode($5,'hex'))`,
        [org, seq, seq % 2 ? `agent:${seq}` : null, prev, h],
      );
      prev = h;
    }
    if (n > 0)
      await admin.query("insert into audit_heads (org_id, seq, hash) values ($1,$2,decode($3,'hex'))", [org, n, prev]);
    if (opts.checkpoint)
      await admin.query(
        "insert into audit_checkpoints (org_id, seq, hash, at, key_id, signature) values ($1,$2,decode($3,'hex'),now(),'audit-checkpoint:1',decode(repeat('00',64),'hex'))",
        [org, n, prev],
      );
    if (opts.verify) {
      await admin.query(
        "insert into audit_verify_runs (org_id, mode, started_at, finished_at, ok, events, checkpoints) values ($1,'db',now()-interval '2 min',now()-interval '1 min',true,1,0)",
        [org],
      );
      await admin.query(
        "insert into audit_verify_runs (org_id, mode, started_at, finished_at, ok, events, checkpoints, broken_seq, break_kind, truncated_at) values ($1,'dir',now()-interval '1 min',now(),false,5,1,3,'hash',4)",
        [org],
      );
    }
  } finally {
    await admin.end();
  }
}

async function newOrg(name: string): Promise<string> {
  return (await request(app.getHttpServer()).post("/v1/orgs").send({ name }).expect(201)).body.id;
}

describe("audit reads", () => {
  it("pages events newest first, shapes each row, and shows an org only its own ledger", async () => {
    const http = request(app.getHttpServer());
    const a = await newOrg("A");
    const b = await newOrg("B");
    await seed(a, 5);
    await seed(b, 2);

    const p1 = (await http.get("/v1/audit/events?limit=2").set(DEV_ORG, a).expect(200)).body;
    expect(p1.items.map((e: { seq: number }) => e.seq)).toEqual([5, 4]);
    expect(typeof p1.next).toBe("string");
    expect(Object.keys(p1.items[0]).sort()).toEqual(
      ["actor", "at", "attrs", "digest", "id", "kind", "outcome", "prev_digest", "seq", "target"].sort(),
    );
    expect(p1.items[0]).toMatchObject({
      seq: 5,
      target: "agent:5",
      attrs: { k: "v" },
      digest: hex(5),
      prev_digest: hex(4),
    });
    expect("target" in p1.items[1]).toBe(false); // seq 4 has no target: the key is absent, like Rust

    const p2 = (await http.get(`/v1/audit/events?limit=2&cursor=${p1.next}`).set(DEV_ORG, a).expect(200)).body;
    expect(p2.items.map((e: { seq: number }) => e.seq)).toEqual([3, 2]);
    const p3 = (await http.get(`/v1/audit/events?limit=2&cursor=${p2.next}`).set(DEV_ORG, a).expect(200)).body;
    expect(p3.items.map((e: { seq: number }) => e.seq)).toEqual([1]);
    expect(p3.next).toBeUndefined();
    expect(p1.items[0].prev_digest).not.toBe("0".repeat(64));
    expect(p3.items[0].prev_digest).toBe("0".repeat(64));

    const other = (await http.get("/v1/audit/events").set(DEV_ORG, b).expect(200)).body;
    expect(other.items.map((e: { seq: number }) => e.seq)).toEqual([2, 1]);
    const st = (await http.get("/v1/audit/status").set(DEV_ORG, b).expect(200)).body;
    expect(st.head_seq).toBe(2);
  });

  it("rejects a bad limit, cursor or query like the Rust API, and an unbound request", async () => {
    const http = request(app.getHttpServer());
    const a = await newOrg("C");
    for (const q of [
      "limit=0",
      "limit=101",
      "limit=x",
      "cursor=!!",
      "cursor=AAAAAAAAAAA",
      "cursor=AAAAAAAAAAA%3D",
      "extra=1",
    ])
      expect((await http.get(`/v1/audit/events?${q}`).set(DEV_ORG, a)).status, q).toBe(400);
    // seq 0 and negative cursors are not valid
    const zero = Buffer.alloc(8).toString("base64url");
    await http.get(`/v1/audit/events?cursor=${zero}`).set(DEV_ORG, a).expect(400);
    // i64::MAX is a valid cursor: a normal empty-or-full page, not an overflow
    const max = Buffer.from("7fffffffffffffff", "hex").toString("base64url");
    await http.get(`/v1/audit/events?cursor=${max}`).set(DEV_ORG, a).expect(200);
    await http.get("/v1/audit/events").expect(401);
    await http.get("/v1/audit/status").expect(401);
  });

  it("reports an empty ledger, then the newest checkpoint and verify run", async () => {
    const http = request(app.getHttpServer());
    const empty = await newOrg("D");
    expect((await http.get("/v1/audit/status").set(DEV_ORG, empty).expect(200)).body).toEqual({ head_seq: 0 });
    expect((await http.get("/v1/audit/events").set(DEV_ORG, empty).expect(200)).body).toEqual({ items: [] });

    const full = await newOrg("E");
    await seed(full, 3, { checkpoint: true, verify: true });
    const st = (await http.get("/v1/audit/status").set(DEV_ORG, full).expect(200)).body;
    expect(st.head_seq).toBe(3);
    expect(st.latest_checkpoint).toMatchObject({ seq: 3, digest: hex(3), key_id: "audit-checkpoint:1" });
    expect(st.latest_verify).toMatchObject({
      mode: "dir",
      ok: false,
      events: 5,
      checkpoints: 1,
      broken_seq: 3,
      break_kind: "hash",
      truncated_at: 4,
    });
  });
});
