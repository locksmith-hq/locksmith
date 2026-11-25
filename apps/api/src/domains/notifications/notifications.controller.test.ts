import "reflect-metadata";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { NotificationsModule } from "./notifications.module.js";
import { NotifyKind, notificationRoutes } from "./notification.schemas.js";

describe("notifications contract stubs", () => {
  it("answers 501 on every declared route", async () => {
    const app = (await Test.createTestingModule({ imports: [NotificationsModule] }).compile()).createNestApplication();
    await app.init();
    for (const r of notificationRoutes) {
      const path = r.path.replace("{id}", "0190a000-0000-7000-8000-0000000000a1");
      const res = await request(app.getHttpServer())[r.method.toLowerCase() as "get"](path);
      expect(res.status, `${r.method} ${path}`).toBe(501);
    }
    await app.close();
  });

  it("keeps the kind enum closed", () => {
    expect(NotifyKind.options).toEqual(["relay.denied", "git.denied", "grant.revoked", "agent.deleted"]);
  });
});
