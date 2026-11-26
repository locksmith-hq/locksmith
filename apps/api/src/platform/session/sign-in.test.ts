import "reflect-metadata";
import { readFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { ConfigModule } from "@nestjs/config";
import { Controller, Get, Logger, type INestApplication } from "@nestjs/common";
import { APP_FILTER, APP_GUARD } from "@nestjs/core";
import { Test } from "@nestjs/testing";
import pg from "pg";
import request from "supertest";
import { GenericContainer, Wait, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DbModule } from "../../db/db.module.js";
import { AuthGuard, TOKEN_VERIFIER } from "../auth/auth.guard.js";
import { TokenRefused, type HumanIdentity } from "../auth/token-verifier.js";
import { ProblemFilter } from "../problem/problem.filter.js";
import { AUDIT_SINK, AuditSink, AuditSinkError, type AuditEventInput } from "./audit-sink.js";
import { CoreAuditSink } from "./core-audit-sink.js";
import { SessionController } from "./session.controller.js";
import { issuerHost, SessionService } from "./session.service.js";
import { UsersService } from "./users.service.js";

// Tasks 2.1/2.2 of b6-api-auth: sign-in and sign-out on a real Postgres, as the app role.
const MIGRATIONS = [
  "0001_roles.sql",
  "0002_tenancy_schema.sql",
  "0003_secret_versions.sql",
  "0004_gateway_audit.sql",
  "0005_gateway_audit_version_caller.sql",
  "0006_agents.sql",
  "0007_gateway_audit_agent.sql",
  "0008_audit_ledger.sql",
  "0009_gateway_audit_read_only.sql",
  "0010_audit_checkpoint_jobs.sql",
  "0011_users.sql",
];
const ADMIN_PASSWORD = "admin-test-only";
const ISSUER = "https://Issuer.Example.com/realms/acme";
// Fake bearer values: each maps to an identity in the stub verifier below.
const BEARER_PREFIX = "fake-bearer-";

let container: StartedTestContainer;
let admin: pg.Client;
let appUrl: string;

const migration = (name: string) =>
  readFileSync(
    fileURLToPath(new URL(`../../../../../services/control-plane/migrations/${name}`, import.meta.url)),
    "utf8",
  );

class FakeSink extends AuditSink {
  events: AuditEventInput[] = [];
  async append(e: AuditEventInput): Promise<void> {
    this.events.push(e);
  }
  kinds = () => this.events.map((e) => e.kind);
}

const identities = new Map<string, HumanIdentity>();
let counter = 0;
function login(over: Partial<HumanIdentity> = {}): { token: string; identity: HumanIdentity } {
  const n = ++counter;
  const identity: HumanIdentity = {
    issuer: ISSUER,
    subject: `sub-${n}-${Math.random().toString(36).slice(2)}`,
    email: `user${n}-${Math.random().toString(36).slice(2)}@acme.test`,
    emailVerified: true,
    clientId: null,
    authTime: null,
    ...over,
  };
  const token = `${BEARER_PREFIX}${n}`;
  identities.set(token, identity);
  return { token, identity };
}
const stubVerifier = {
  async verify(token: string): Promise<HumanIdentity> {
    const id = identities.get(token);
    if (!id) throw new TokenRefused("invalid");
    return id;
  },
};

// Never routes: only here so the module wiring matches the app's global guard and filter.
@Controller("noop")
class Noop {
  @Get()
  get() {
    return {};
  }
}

async function makeApp(sink: AuditSink | null): Promise<INestApplication> {
  const mod = await Test.createTestingModule({
    imports: [
      ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true, load: [() => ({ DATABASE_URL: appUrl })] }),
      DbModule,
    ],
    controllers: [SessionController, Noop],
    providers: [
      UsersService,
      SessionService,
      { provide: AUDIT_SINK, useValue: sink },
      { provide: TOKEN_VERIFIER, useValue: stubVerifier },
      { provide: APP_GUARD, useClass: AuthGuard },
      { provide: APP_FILTER, useClass: ProblemFilter },
    ],
  }).compile();
  const app = mod.createNestApplication();
  await app.init();
  return app;
}

const count = async (table: "users" | "orgs") =>
  Number((await admin.query(`select count(*)::int as n from ${table}`)).rows[0].n);

beforeAll(async () => {
  container = await new GenericContainer("postgres:18.7")
    .withEnvironment({ POSTGRES_PASSWORD: ADMIN_PASSWORD })
    .withExposedPorts(5432)
    .withWaitStrategy(Wait.forLogMessage(/database system is ready to accept connections/, 2))
    .start();
  const hostPort = `${container.getHost()}:${container.getMappedPort(5432)}`;
  appUrl = `postgres://locksmith_app:locksmith-app-dev-only@${hostPort}/postgres`;
  admin = new pg.Client({ connectionString: `postgres://postgres:${ADMIN_PASSWORD}@${hostPort}/postgres` });
  await admin.connect();
  for (const name of MIGRATIONS) await admin.query(migration(name));
}, 180_000);

afterAll(async () => {
  await admin?.end();
  await container?.stop();
});

describe("POST /v1/auth/sign-in", () => {
  it("first sign-in creates one user and one org; the second creates none", async () => {
    const sink = new FakeSink();
    const app = await makeApp(sink);
    const { token, identity } = login();
    const [users0, orgs0] = [await count("users"), await count("orgs")];

    const first = await request(app.getHttpServer()).post("/v1/auth/sign-in").set("authorization", `Bearer ${token}`);
    expect(first.status).toBe(204);
    expect(first.text).toBe("");
    expect([await count("users"), await count("orgs")]).toEqual([users0 + 1, orgs0 + 1]);
    expect(sink.kinds()).toEqual(["org.personal_created", "auth.sign_in"]);

    const row = (await admin.query("select id, personal_org_id from users where subject = $1", [identity.subject]))
      .rows[0];
    const org = (await admin.query("select name from orgs where id = $1", [row.personal_org_id])).rows[0];
    expect(org.name).toBe("Personal");
    for (const e of sink.events) {
      expect(e).toMatchObject({ orgId: row.personal_org_id, actorUserId: row.id, issuerHost: "issuer.example.com" });
    }

    sink.events = [];
    const second = await request(app.getHttpServer()).post("/v1/auth/sign-in").set("authorization", `Bearer ${token}`);
    expect(second.status).toBe(204);
    expect([await count("users"), await count("orgs")]).toEqual([users0 + 1, orgs0 + 1]);
    expect(sink.kinds()).toEqual(["auth.sign_in"]);
    await app.close();
  });

  it("an issuer with no usable host is a 401 before any user or org is created", async () => {
    const sink = new FakeSink();
    const app = await makeApp(sink);
    const { token } = login({ issuer: "not a url" });
    const [users0, orgs0] = [await count("users"), await count("orgs")];
    const res = await request(app.getHttpServer()).post("/v1/auth/sign-in").set("authorization", `Bearer ${token}`);
    expect(res.status).toBe(401);
    expect([await count("users"), await count("orgs")]).toEqual([users0, orgs0]);
    expect(sink.events).toEqual([]);
    await app.close();
  });

  it("two concurrent first sign-ins create one user and one org", async () => {
    const sink = new FakeSink();
    const app = await makeApp(sink);
    const { token } = login();
    const [users0, orgs0] = [await count("users"), await count("orgs")];
    const rs = await Promise.all(
      [1, 2].map(() => request(app.getHttpServer()).post("/v1/auth/sign-in").set("authorization", `Bearer ${token}`)),
    );
    expect(rs.map((r) => r.status)).toEqual([204, 204]);
    expect([await count("users"), await count("orgs")]).toEqual([users0 + 1, orgs0 + 1]);
    expect(sink.kinds().filter((k) => k === "org.personal_created")).toHaveLength(1);
    expect(sink.kinds().filter((k) => k === "auth.sign_in")).toHaveLength(2);
    await app.close();
  });

  it("links a second subject with the same verified email to the first personal org", async () => {
    const sink = new FakeSink();
    const app = await makeApp(sink);
    const a = login({ email: "Shared@Acme.test" });
    const b = login({ email: "shared@acme.test" });
    await request(app.getHttpServer()).post("/v1/auth/sign-in").set("authorization", `Bearer ${a.token}`).expect(204);
    const [users0, orgs0] = [await count("users"), await count("orgs")];
    sink.events = [];
    await request(app.getHttpServer()).post("/v1/auth/sign-in").set("authorization", `Bearer ${b.token}`).expect(204);
    expect([await count("users"), await count("orgs")]).toEqual([users0 + 1, orgs0]);
    const rows = (
      await admin.query("select personal_org_id from users where subject = any($1)", [
        [a.identity.subject, b.identity.subject],
      ])
    ).rows;
    expect(new Set(rows.map((r) => r.personal_org_id)).size).toBe(1);
    expect(sink.kinds()).toEqual(["auth.sign_in"]);
    await app.close();
  });

  it("refuses an unverified email with 403 and writes nothing", async () => {
    const sink = new FakeSink();
    const app = await makeApp(sink);
    const { token } = login({ emailVerified: false });
    const [users0, orgs0] = [await count("users"), await count("orgs")];
    const res = await request(app.getHttpServer()).post("/v1/auth/sign-in").set("authorization", `Bearer ${token}`);
    expect(res.status).toBe(403);
    expect(res.body.type).toBe("urn:locksmith:problem:email-verification-required");
    expect([await count("users"), await count("orgs")]).toEqual([users0, orgs0]);
    expect(sink.events).toEqual([]);
    await app.close();
  });

  it("refreshes a changed email on a known user", async () => {
    const app = await makeApp(new FakeSink());
    const { token, identity } = login();
    await request(app.getHttpServer()).post("/v1/auth/sign-in").set("authorization", `Bearer ${token}`).expect(204);
    identities.set(token, { ...identity, email: "new-address@acme.test" });
    await request(app.getHttpServer()).post("/v1/auth/sign-in").set("authorization", `Bearer ${token}`).expect(204);
    const row = (await admin.query("select email from users where subject = $1", [identity.subject])).rows[0];
    expect(row.email).toBe("new-address@acme.test");
    await app.close();
  });

  it("requires a bearer token", async () => {
    const app = await makeApp(new FakeSink());
    await request(app.getHttpServer()).post("/v1/auth/sign-in").expect(401);
    await request(app.getHttpServer()).post("/v1/auth/sign-out").set("authorization", "Bearer nope").expect(401);
    await app.close();
  });

  it("answers 503 problem-details when no audit sink is configured, and creates nothing", async () => {
    const app = await makeApp(null);
    const { token } = login();
    const [users0, orgs0] = [await count("users"), await count("orgs")];
    for (const path of ["/v1/auth/sign-in", "/v1/auth/sign-out"]) {
      const res = await request(app.getHttpServer()).post(path).set("authorization", `Bearer ${token}`);
      expect(res.status).toBe(503);
      expect(res.body.type).toBe("urn:locksmith:problem:unavailable");
    }
    expect([await count("users"), await count("orgs")]).toEqual([users0, orgs0]);
    await app.close();
  });

  it("answers 503 when the sink fails", async () => {
    const failing = new (class extends AuditSink {
      async append(): Promise<void> {
        throw new AuditSinkError("unreachable");
      }
    })();
    const app = await makeApp(failing);
    const { token } = login();
    await request(app.getHttpServer()).post("/v1/auth/sign-in").set("authorization", `Bearer ${token}`).expect(503);
    await app.close();
  });
});

describe("POST /v1/auth/sign-out", () => {
  it("appends auth.sign_out for a known user and creates nothing", async () => {
    const sink = new FakeSink();
    const app = await makeApp(sink);
    const { token } = login();
    await request(app.getHttpServer()).post("/v1/auth/sign-in").set("authorization", `Bearer ${token}`).expect(204);
    const [users0, orgs0] = [await count("users"), await count("orgs")];
    sink.events = [];
    const res = await request(app.getHttpServer()).post("/v1/auth/sign-out").set("authorization", `Bearer ${token}`);
    expect(res.status).toBe(204);
    expect(sink.kinds()).toEqual(["auth.sign_out"]);
    expect([await count("users"), await count("orgs")]).toEqual([users0, orgs0]);
    await app.close();
  });
});

describe("no secrets leak", () => {
  it("keeps the bearer out of sink payloads and logs", async () => {
    const lines: string[] = [];
    const methods = ["log", "warn", "error"] as const;
    const orig = methods.map((m) => Logger.prototype[m]);
    for (const m of methods) Logger.prototype[m] = (...a: unknown[]) => void lines.push(JSON.stringify(a));
    const sink = new FakeSink();
    try {
      const app = await makeApp(sink);
      const { token } = login();
      await request(app.getHttpServer()).post("/v1/auth/sign-in").set("authorization", `Bearer ${token}`).expect(204);
      await request(app.getHttpServer()).post("/v1/auth/sign-out").set("authorization", `Bearer ${token}`).expect(204);
      await request(app.getHttpServer()).post("/v1/auth/sign-in").set("authorization", "Bearer nope").expect(401);
      await app.close();
      expect(JSON.stringify(sink.events)).not.toContain(BEARER_PREFIX);
      expect(lines.join("\n")).not.toContain(BEARER_PREFIX);
      expect(lines.join("\n")).not.toContain("nope");
    } finally {
      methods.forEach((m, i) => (Logger.prototype[m] = orig[i] as never));
    }
  });
});

describe("issuerHost", () => {
  it("lowercases the host and drops port, user and path", () => {
    expect(issuerHost("https://Issuer.Example.com/realms/x")).toBe("issuer.example.com");
    expect(issuerHost("http://localhost:8080/realms/ls")).toBe("localhost");
    expect(issuerHost("https://user@idp.example:8443/x?y#z")).toBe("idp.example");
    expect(issuerHost("not a url")).toBeUndefined();
    expect(issuerHost("")).toBeUndefined();
    expect(issuerHost("http://[::1]:8080/x")).toBe("[::1]");
  });
});

describe("CoreAuditSink", () => {
  it("POSTs the contract body with the bearer header and maps failures", async () => {
    const seen: {
      url: string | undefined;
      method: string | undefined;
      auth: string | undefined;
      org: string | undefined;
      ctype: string | undefined;
      body: string;
    }[] = [];
    let status = 200;
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        seen.push({
          url: req.url,
          method: req.method,
          auth: req.headers.authorization,
          org: req.headers["x-locksmith-org"] as string | undefined,
          ctype: req.headers["content-type"],
          body,
        });
        res.writeHead(status).end("{}");
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    try {
      const sink = new CoreAuditSink(base, "test-core-token");
      const orgId = "0192f3a0-0000-7000-8000-00000000000a";
      const userId = "0192f3a0-0000-7000-8000-00000000000b";
      await sink.append({ orgId, kind: "auth.sign_in", actorUserId: userId, issuerHost: "issuer.example.com" });
      await sink.append({ orgId, kind: "auth.sign_out", actorUserId: userId });
      expect(seen[0]).toMatchObject({
        url: "/internal/v1/audit/human-events",
        method: "POST",
        auth: "Bearer test-core-token",
        org: orgId,
        ctype: "application/json",
      });
      expect(JSON.parse(seen[0]!.body!)).toEqual({
        kind: "auth.sign_in",
        user_id: userId,
        issuer: "issuer.example.com",
      });
      expect(JSON.parse(seen[1]!.body!)).toEqual({ kind: "auth.sign_out", user_id: userId });
      status = 500;
      await expect(sink.append({ orgId, kind: "auth.sign_in", actorUserId: userId })).rejects.toMatchObject({
        reason: "rejected",
      });
    } finally {
      await new Promise((r) => server.close(r));
    }
    await expect(
      new CoreAuditSink("http://127.0.0.1:1", "test-core-token").append({ orgId: "x", kind: "k", actorUserId: "y" }),
    ).rejects.toMatchObject({ reason: "unreachable" });
  });
});
