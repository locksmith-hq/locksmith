import "reflect-metadata";
import { Global, Module } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { KYSELY } from "../../db/db.module.js";
import { TenantModule } from "../../tenant/tenant.module.js";
import { NotificationsModule } from "./notifications.module.js";
import { NotifyKind, notificationRoutes } from "./notification.schemas.js";

/** The inbox routes are not called here, so the database handle is never used. */
@Global()
@Module({ providers: [{ provide: KYSELY, useValue: {} }], exports: [KYSELY] })
class StubDb {}

describe("notifications contract stubs", () => {
  it("answers 501 on every declared route that is not the inbox", async () => {
    const app = (
      await Test.createTestingModule({ imports: [StubDb, TenantModule, NotificationsModule] }).compile()
    ).createNestApplication();
    await app.init();
    for (const r of notificationRoutes.filter((r) => !r.path.startsWith("/v1/notifications"))) {
      const path = r.path.replace("{id}", "0190a000-0000-7000-8000-0000000000a1");
      const res = await request(app.getHttpServer())[r.method.toLowerCase() as "get"](path);
      expect(res.status, `${r.method} ${path}`).toBe(501);
    }
    await app.close();
  });

  it("keeps the kind enum closed", () => {
    expect(NotifyKind.options).toEqual([
      "relay.denied",
      "git.denied",
      "grant.revoked",
      "agent.deleted",
      "honey.triggered",
    ]);
  });
});
