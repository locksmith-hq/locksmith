import "reflect-metadata";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ServiceUnavailableException } from "@nestjs/common";
import pg from "pg";
import { GenericContainer, Wait, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { FailClosedAuditSink, issuerHost, type AuditSink, type AuthAuditEvent } from "../audit/audit-sink.js";
import type { HumanIdentity } from "../auth/human-auth.js";
import { createKysely, type Database } from "../db/db.module.js";
import { SessionController } from "./session.controller.js";
import { UsersService } from "./users.service.js";

// Task 4.2: user and personal-org creation and the sign-in and sign-out audit events, against a
// real Postgres as the app role (row-level security applies). Mirrors the Rust `users` tests.
const MIGRATIONS = ["0001_roles.sql", "0002_tenancy_schema.sql", "0011_users.sql"];
const ADMIN_PASSWORD = "admin-test-only";
const ISS = "https://id.example.test/realms/acme";

let container: StartedTestContainer;
let adminUrl: string;
let db: Database;

class Recorder implements AuditSink {
  events: AuthAuditEvent[] = [];
  async append(e: AuthAuditEvent) {
    this.events.push(e);
  }
  async appendAdmin() {}
}

const ident = (subject: string, o: Partial<HumanIdentity> = {}): HumanIdentity => ({
  issuer: ISS,
  subject,
  email: `${subject}@acme.test`,
  emailVerified: true,
  ...o,
});

beforeAll(async () => {
  container = await new GenericContainer("postgres:18.7")
    .withEnvironment({ POSTGRES_PASSWORD: ADMIN_PASSWORD })
    .withExposedPorts(5432)
    .withWaitStrategy(Wait.forLogMessage(/database system is ready to accept connections/, 2))
    .start();
  const hostPort = `${container.getHost()}:${container.getMappedPort(5432)}`;
  adminUrl = `postgres://postgres:${ADMIN_PASSWORD}@${hostPort}/postgres`;
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

async function counts(): Promise<{ users: number; orgs: number }> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  const u = await admin.query("select count(*)::int as n from users");
  const o = await admin.query("select count(*)::int as n from orgs");
  await admin.end();
  return { users: u.rows[0].n, orgs: o.rows[0].n };
}

beforeEach(async () => {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  await admin.query("truncate users cascade; truncate orgs cascade");
  await admin.end();
});

describe("users.resolve", () => {
  it("creates the user and a personal org on first sign-in, and audits the org", async () => {
    const audit = new Recorder();
    const svc = new UsersService(db, audit);
    const r = await svc.resolve(ident("u1"));
    expect(r).toMatchObject({ created: true, orgCreated: true });
    expect(await counts()).toEqual({ users: 1, orgs: 1 });
    expect(audit.events).toEqual([
      { kind: "org.personal_created", userId: r.userId, orgId: r.orgId, issuerHost: "id.example.test", outcome: "ok" },
    ]);
  });

  it("only reads on a repeat sign-in", async () => {
    const audit = new Recorder();
    const svc = new UsersService(db, audit);
    const first = await svc.resolve(ident("u1"));
    const again = await svc.resolve(ident("u1"));
    expect(again).toEqual({ userId: first.userId, orgId: first.orgId, created: false, orgCreated: false });
    expect(await counts()).toEqual({ users: 1, orgs: 1 });
    expect(audit.events).toHaveLength(1);
  });

  it("creates exactly one user and org for concurrent first sign-ins", async () => {
    const svc = new UsersService(db, new Recorder());
    const rs = await Promise.all([1, 2, 3, 4].map(() => svc.resolve(ident("race"))));
    expect(new Set(rs.map((r) => r.userId)).size).toBe(1);
    expect(await counts()).toEqual({ users: 1, orgs: 1 });
  });

  it("links a new identity with the same verified email to the existing personal org", async () => {
    const audit = new Recorder();
    const svc = new UsersService(db, audit);
    const a = await svc.resolve(ident("a", { email: "Shared@acme.test" }));
    const b = await svc.resolve(ident("b", { email: "shared@ACME.test" }));
    expect(b.orgId).toBe(a.orgId);
    expect(b).toMatchObject({ created: true, orgCreated: false });
    expect(b.userId).not.toBe(a.userId);
    expect(await counts()).toEqual({ users: 2, orgs: 1 });
    expect(audit.events).toHaveLength(1);
  });

  it("refuses an unverified identity with 403 and writes nothing", async () => {
    const svc = new UsersService(db, new Recorder());
    await expect(svc.resolve(ident("x", { emailVerified: false }))).rejects.toMatchObject({
      kind: "email-verification-required",
    });
    expect(await counts()).toEqual({ users: 0, orgs: 0 });
  });

  it("fails closed: a failing audit append rolls back the user and org", async () => {
    const svc = new UsersService(db, new FailClosedAuditSink());
    await expect(svc.resolve(ident("u9"))).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(await counts()).toEqual({ users: 0, orgs: 0 });
  });
});

describe("session controller", () => {
  const req = (identity: HumanIdentity) => ({ identity }) as never;

  it("records auth.sign_in and auth.sign_out with the user, org and issuer host only", async () => {
    const audit = new Recorder();
    const ctl = new SessionController(new UsersService(db, audit), audit);
    const id = ident("u2");
    await ctl.signIn(req(id));
    await ctl.signOut(req(id));
    const kinds = audit.events.map((e) => e.kind);
    expect(kinds).toEqual(["org.personal_created", "auth.sign_in", "auth.sign_out"]);
    const signIn = audit.events[1]!;
    expect(signIn).toMatchObject({ issuerHost: "id.example.test", outcome: "ok" });
    expect(JSON.stringify(audit.events)).not.toContain("@acme.test");
  });

  it("fails closed when the audit sink is down", async () => {
    const sink = new FailClosedAuditSink();
    const ctl = new SessionController(new UsersService(db, sink), sink);
    await expect(ctl.signIn(req(ident("u3")))).rejects.toBeInstanceOf(ServiceUnavailableException);
  });
});

describe("issuerHost", () => {
  it("keeps the host and drops everything else", () => {
    expect(issuerHost("https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Pool123")).toBe(
      "cognito-idp.eu-west-1.amazonaws.com",
    );
    expect(issuerHost("not a url")).toBeUndefined();
  });
});
