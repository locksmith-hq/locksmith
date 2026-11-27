import "reflect-metadata";
import { Controller, Get, INestApplication, Post, UseGuards } from "@nestjs/common";
import { APP_FILTER } from "@nestjs/core";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { z } from "zod";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { OrgBoundGuard } from "../auth/org-bound.guard.js";
import { ProblemException, ProblemFilter, PROBLEM_JSON } from "./problem.js";
import { TenantService } from "../tenant/tenant.service.js";

@Controller("t")
class Probe {
  @Get("400") bad() {
    return z.object({ name: z.string() }).parse({ name: 7 });
  }
  @Get("401") unauth(): never {
    throw new ProblemException("unauthenticated");
  }
  @Get("403") forbid(): never {
    throw new ProblemException("email-verification-required");
  }
  @Get("404") missing(): never {
    throw new ProblemException("not-found");
  }
  @Post("409") conflict(): never {
    throw new ProblemException("conflict", "a resource with that name already exists in this parent");
  }
  @Get("422") refused(): never {
    throw new ProblemException("unprocessable", "workload policy is not pinned");
  }
  @Get("500") boom(): never {
    throw new Error("secret-ish message FAKE-LEAK-123");
  }
  @Get("org") @UseGuards(OrgBoundGuard) org() {
    return { ok: true };
  }
}

let app: INestApplication;
let orgId: string | undefined;

beforeAll(async () => {
  const mod = await Test.createTestingModule({
    controllers: [Probe],
    providers: [
      { provide: APP_FILTER, useClass: ProblemFilter },
      OrgBoundGuard,
      { provide: TenantService, useValue: { orgId: () => orgId } },
    ],
  }).compile();
  app = mod.createNestApplication();
  await app.init();
});
afterAll(() => app.close());

const CASES: [string, "get" | "post", number, string][] = [
  ["/t/400", "get", 400, "validation"],
  ["/t/401", "get", 401, "unauthenticated"],
  ["/t/403", "get", 403, "email-verification-required"],
  ["/t/404", "get", 404, "not-found"],
  ["/t/409", "post", 409, "conflict"],
  ["/t/422", "get", 422, "unprocessable"],
  ["/t/500", "get", 500, "internal"],
  ["/t/none", "get", 404, "not-found"],
];

describe("problem details", () => {
  it.each(CASES)("%s answers problem+json (%s %i %s)", async (path, method, status, slug) => {
    const res = await request(app.getHttpServer())[method](path);
    expect(res.status).toBe(status);
    expect(res.headers["content-type"]).toContain(PROBLEM_JSON);
    expect(res.body.type).toBe(`urn:locksmith:problem:${slug}`);
    expect(res.body.status).toBe(status);
    expect(typeof res.body.title).toBe("string");
  });

  it("names the offending field and never echoes the value", async () => {
    const res = await request(app.getHttpServer()).get("/t/400");
    expect(res.body.detail).toBe("invalid field: name");
    expect(JSON.stringify(res.body)).not.toContain("7");
  });

  it("malformed JSON is a 400 problem, not a 500", async () => {
    const res = await request(app.getHttpServer()).post("/t/409").set("content-type", "application/json").send("{bad");
    expect(res.status).toBe(400);
    expect(res.body.type).toBe("urn:locksmith:problem:validation");
  });

  it("a bare 500 never leaks the error message", async () => {
    const res = await request(app.getHttpServer()).get("/t/500");
    expect(JSON.stringify(res.body)).not.toContain("FAKE-LEAK-123");
    expect(res.body.detail).toBeUndefined();
  });
});

describe("org-bound guard", () => {
  it.each([
    ["human bound to an org", "11111111-1111-4111-8111-111111111111", 200],
    ["principal with no bound org", undefined, 403],
  ])("%s -> %i", async (_name, org, status) => {
    orgId = org;
    const res = await request(app.getHttpServer()).get("/t/org");
    expect(res.status).toBe(status);
    if (status === 403) expect(res.body.type).toBe("urn:locksmith:problem:forbidden");
  });
});
