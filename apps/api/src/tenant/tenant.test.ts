import "reflect-metadata";
import { Controller, Get, Inject, Injectable, Module, UseGuards, type CanActivate } from "@nestjs/common";
import { APP_INTERCEPTOR } from "@nestjs/core";
import { Test } from "@nestjs/testing";
import { DummyDriver, Kysely, PostgresAdapter, PostgresIntrospector, PostgresQueryCompiler } from "kysely";
import { ClsModule } from "nestjs-cls";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { KYSELY, type Database } from "../db/db.module.js";
import { TenantInterceptor } from "./tenant.interceptor.js";
import { TenantService } from "./tenant.service.js";

const ORG = "0192f3a0-0000-7000-8000-000000000001";

/** A driver that records transaction control and every executed statement, with no database. */
class RecordingDriver extends DummyDriver {
  constructor(private readonly log: string[]) {
    super();
  }
  override async acquireConnection() {
    const log = this.log;
    return {
      async executeQuery(q: { sql: string }) {
        log.push(q.sql);
        return { rows: [] };
      },
      async *streamQuery() {},
    };
  }
  override async beginTransaction() {
    this.log.push("begin");
  }
  override async commitTransaction() {
    this.log.push("commit");
  }
  override async rollbackTransaction() {
    this.log.push("rollback");
  }
}

function fakeDb(log: string[]): Database {
  return new Kysely({
    dialect: {
      createAdapter: () => new PostgresAdapter(),
      createDriver: () => new RecordingDriver(log),
      createIntrospector: (db) => new PostgresIntrospector(db),
      createQueryCompiler: () => new PostgresQueryCompiler(),
    },
  }) as Database;
}

@Injectable()
class OrgGuard implements CanActivate {
  constructor(@Inject(TenantService) private readonly tenant: TenantService) {}
  canActivate(ctx: import("@nestjs/common").ExecutionContext): boolean {
    const org = ctx.switchToHttp().getRequest().headers["x-test-org"];
    if (typeof org === "string") this.tenant.setOrgId(org);
    return true;
  }
}

@Controller("t")
@UseGuards(OrgGuard)
class TController {
  constructor(@Inject(TenantService) private readonly tenant: TenantService) {}
  @Get("scoped")
  async scoped() {
    await this.tenant.tx().selectFrom("orgs").select("id").execute();
    return { ok: true };
  }
  @Get("open")
  open() {
    return { ok: true };
  }
  @Get("boom")
  async boom() {
    await this.tenant.tx().selectFrom("orgs").select("id").execute();
    throw new Error("boom");
  }
}

async function app(log: string[]) {
  @Module({
    imports: [ClsModule.forRoot({ global: true, middleware: { mount: true } })],
    controllers: [TController],
    providers: [
      OrgGuard,
      TenantService,
      { provide: KYSELY, useValue: fakeDb(log) },
      { provide: APP_INTERCEPTOR, useClass: TenantInterceptor },
    ],
  })
  class M {}
  const mod = await Test.createTestingModule({ imports: [M] }).compile();
  const a = mod.createNestApplication({ logger: false });
  await a.init();
  return a;
}

describe("tenant interceptor", () => {
  it("sets app.org_id transaction-locally before any query, in one transaction", async () => {
    const log: string[] = [];
    const a = await app(log);
    await request(a.getHttpServer()).get("/t/scoped").set("x-test-org", ORG).expect(200);
    expect(log).toEqual([
      "begin",
      "select set_config('app.org_id', $1, true)",
      'select "id" from "orgs"',
      "commit",
    ]);
    await a.close();
  });

  it("opens no transaction for requests without an org", async () => {
    const log: string[] = [];
    const a = await app(log);
    await request(a.getHttpServer()).get("/t/open").expect(200);
    expect(log).toEqual([]);
    await a.close();
  });

  it("rolls back when the handler throws", async () => {
    const log: string[] = [];
    const a = await app(log);
    await request(a.getHttpServer()).get("/t/boom").set("x-test-org", ORG).expect(500);
    expect(log.at(-1)).toBe("rollback");
    await a.close();
  });

  it("refuses a malformed org id before touching the database", async () => {
    const log: string[] = [];
    const a = await app(log);
    await request(a.getHttpServer()).get("/t/scoped").set("x-test-org", "1'; drop table orgs;--").expect(500);
    expect(log).toEqual([]);
    await a.close();
  });

  it("does not expose a transaction outside a tenant request", async () => {
    const log: string[] = [];
    const a = await app(log);
    const svc = a.get(TenantService);
    expect(() => svc.tx()).toThrow("no tenant transaction");
    await a.close();
  });
});
