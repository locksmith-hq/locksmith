import { type INestApplication } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { OrgBoundGuard } from "../../platform/permissions/org-bound.guard.js";
import type { Principal, RequestWithPrincipal } from "../../platform/permissions/principal.js";
import { ProblemFilter } from "../../platform/problem/problem.filter.js";
import { HoneyTokensController } from "./honey-tokens.controller.js";
import { HoneyTokensService } from "./honey-tokens.service.js";
import { honeyTokenRoutes } from "./honey-token.schemas.js";

describe("honey tokens contract", () => {
  it("registers list, create, disable and delete under an environment", () => {
    expect(honeyTokenRoutes.map((r) => `${r.method} ${r.path}`)).toEqual([
      "GET /v1/projects/{project_id}/environments/{environment_id}/honey-tokens",
      "POST /v1/projects/{project_id}/environments/{environment_id}/honey-tokens",
      "POST /v1/projects/{project_id}/environments/{environment_id}/honey-tokens/{id}/disable",
      "DELETE /v1/projects/{project_id}/environments/{environment_id}/honey-tokens/{id}",
    ]);
  });

  it("never describes a value in a response", () => {
    const text = JSON.stringify(honeyTokenRoutes.map((r) => Object.keys(r.responses)));
    expect(text).not.toContain("value");
  });
});

describe("honey tokens controller", () => {
  const ORG = "0192f3a0-0000-7000-8000-0000000000a1";
  const PROJ = "0192f3a0-0000-7000-8000-0000000000a3";
  const ENVI = "0192f3a0-0000-7000-8000-0000000000a4";
  const TOKEN = "0192f3a0-0000-7000-8000-0000000000a5";
  const base = `/v1/projects/${PROJ}/environments/${ENVI}/honey-tokens`;
  const view = { id: TOKEN, name: "n", template: "slack_token", created_at: "t", disabled_at: null, last_triggered_at: null };
  const calls: unknown[][] = [];
  const service = {
    list: async (...a: unknown[]) => (calls.push(["list", ...a]), []),
    create: async (...a: unknown[]) => (calls.push(["create", ...a]), view),
    disable: async (...a: unknown[]) => (calls.push(["disable", ...a]), view),
    remove: async (...a: unknown[]) => void calls.push(["remove", ...a]),
  };
  let principal: Principal | undefined;
  let app: INestApplication;

  beforeAll(async () => {
    const mod = await Test.createTestingModule({
      controllers: [HoneyTokensController],
      providers: [
        { provide: HoneyTokensService, useValue: service },
        { provide: APP_GUARD, useClass: OrgBoundGuard },
      ],
    }).compile();
    app = mod.createNestApplication();
    app.use((req: RequestWithPrincipal, _res: unknown, next: () => void) => {
      if (principal) req.principal = principal;
      next();
    });
    app.useGlobalFilters(new ProblemFilter());
    await app.init();
  });
  afterAll(() => app.close());
  beforeEach(() => {
    principal = { kind: "human", orgId: ORG };
    calls.length = 0;
  });

  it("refuses an agent, a service, an unbound human and no principal on every route", async () => {
    const routes = [
      () => request(app.getHttpServer()).get(base),
      () => request(app.getHttpServer()).post(base).send({ name: "n", template: "slack_token" }),
      () => request(app.getHttpServer()).post(`${base}/${TOKEN}/disable`),
      () => request(app.getHttpServer()).delete(`${base}/${TOKEN}`),
    ];
    for (const p of [{ kind: "agent", orgId: ORG }, { kind: "service", orgId: ORG }, { kind: "human", orgId: null }, undefined] as const) {
      principal = p;
      for (const r of routes) expect((await r()).status).toBe(403);
    }
    expect(calls).toEqual([]);
  });

  it("scopes every call to the principal's org, never a path or body value", async () => {
    expect((await request(app.getHttpServer()).get(base)).body).toEqual({ items: [] });
    const created = await request(app.getHttpServer()).post(base).send({ name: "n", template: "slack_token", org_id: "x" });
    expect(created.status).toBe(201);
    expect((await request(app.getHttpServer()).post(`${base}/${TOKEN}/disable`)).status).toBe(200);
    expect((await request(app.getHttpServer()).delete(`${base}/${TOKEN}`)).status).toBe(204);
    const s = { orgId: ORG, projectId: PROJ, environmentId: ENVI };
    expect(calls).toEqual([
      ["list", s],
      ["create", s, { name: "n", template: "slack_token" }],
      ["disable", s, TOKEN],
      ["remove", s, TOKEN],
    ]);
  });

  it("answers 422 for a bad body and 404 for an id that is not a uuid", async () => {
    for (const body of [{}, { name: "", template: "slack_token" }, { name: "n", template: "nope" }]) {
      expect((await request(app.getHttpServer()).post(base).send(body)).status).toBe(422);
    }
    expect((await request(app.getHttpServer()).delete(`${base}/not-a-uuid`)).status).toBe(404);
    expect((await request(app.getHttpServer()).get(`/v1/projects/x/environments/${ENVI}/honey-tokens`)).status).toBe(404);
    expect(calls).toEqual([]);
  });
});
