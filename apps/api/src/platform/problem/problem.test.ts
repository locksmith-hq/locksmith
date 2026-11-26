import "reflect-metadata";
import { BadRequestException, Controller, Get, INestApplication, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { KINDS, ProblemException, type Kind } from "./problem.js";
import { ProblemModule } from "./problem.module.js";

@Controller("t")
class TestController {
  @Get("400") bad() { throw new BadRequestException("secret-in-body hunter2"); }
  @Get("401") unauth() { throw new UnauthorizedException(); }
  @Get("403") forbidden() { throw new ProblemException("forbidden"); }
  @Get("403v") unverified() { throw new ProblemException("email-verification-required"); }
  @Get("404") missing() { throw new NotFoundException(); }
  @Get("409") conflict() { throw new ProblemException("conflict", "a resource with that name already exists in this parent"); }
  @Get("422") refused() { throw new ProblemException("unprocessable", "workload policy is not pinned"); }
  @Get("500") boom() { throw new Error("db password=hunter2"); }
}

let app: INestApplication;
beforeAll(async () => {
  const mod = await Test.createTestingModule({ imports: [ProblemModule], controllers: [TestController] }).compile();
  app = mod.createNestApplication({ logger: false });
  await app.init();
});
afterAll(() => app.close());

// Bodies as the Rust ApiError produces them (problem.rs).
const cases: [string, number, Kind, string | undefined][] = [
  ["400", 400, "validation", undefined],
  ["401", 401, "unauthenticated", undefined],
  ["403", 403, "forbidden", undefined],
  ["403v", 403, "email-verification-required", undefined],
  ["404", 404, "not-found", undefined],
  ["409", 409, "conflict", "a resource with that name already exists in this parent"],
  ["422", 422, "unprocessable", "workload policy is not pinned"],
  ["500", 500, "internal", undefined],
];

describe("problem details", () => {
  it.each(cases)("%s -> problem+json with the Rust body", async (path, status, kind, detail) => {
    const res = await request(app.getHttpServer()).get(`/t/${path}`);
    expect(res.status).toBe(status);
    expect(res.headers["content-type"]).toBe("application/problem+json");
    expect(JSON.parse(res.text)).toEqual({
      type: `urn:locksmith:problem:${kind}`,
      title: KINDS[kind].title,
      status,
      ...(detail ? { detail } : {}),
    });
  });

  it("never echoes framework or error messages", async () => {
    for (const p of ["400", "500"]) expect((await request(app.getHttpServer()).get(`/t/${p}`)).text).not.toContain("hunter2");
  });

  it("answers an unknown route with a 404 problem", async () => {
    const res = await request(app.getHttpServer()).get("/nope");
    expect(res.status).toBe(404);
    expect(res.headers["content-type"]).toBe("application/problem+json");
    expect(JSON.parse(res.text).type).toBe("urn:locksmith:problem:not-found");
  });
});
