import type { Scenario } from "../scenario.ts";

const none = { "x-locksmith-dev-org": "not-a-uuid" };

export const scenarios: Scenario[] = [
  {
    id: "health",
    covers: ["GET /healthz", "GET /readyz", "GET /.well-known/jwks.json"],
    async run(ctx) {
      await ctx.expect("healthz", 200, { method: "GET", path: "/healthz" });
      await ctx.expect("readyz", 200, { method: "GET", path: "/readyz" });
      await ctx.expect("jwks", 200, { method: "GET", path: "/.well-known/jwks.json" });
    },
  },
  {
    id: "orgs",
    covers: ["POST /v1/orgs", "GET /v1/orgs/current", "GET /v1/orgs/{org_id}"],
    async run(ctx) {
      const { a, b } = ctx.seed;
      await ctx.expect("create ok", 201, { method: "POST", path: "/v1/orgs", body: { name: `orgs-${ctx.seed.run}` } });
      await ctx.expect("create missing name", 400, { method: "POST", path: "/v1/orgs", body: {} });
      await ctx.expect("create empty name", 400, { method: "POST", path: "/v1/orgs", body: { name: "" } });
      await ctx.expect("current ok", 200, { method: "GET", path: "/v1/orgs/current", headers: a.auth });
      await ctx.expect("current no token", 401, { method: "GET", path: "/v1/orgs/current" });
      await ctx.expect("current bad binding", 401, { method: "GET", path: "/v1/orgs/current", headers: none });
      await ctx.expect("get own", 200, { method: "GET", path: `/v1/orgs/${a.orgId}`, headers: a.auth });
      await ctx.expect("get no token", 401, { method: "GET", path: `/v1/orgs/${a.orgId}` });
      await ctx.expect("get cross-tenant", 404, { method: "GET", path: `/v1/orgs/${b.orgId}`, headers: a.auth });
      await ctx.expect("get malformed id", 404, { method: "GET", path: "/v1/orgs/not-a-uuid", headers: a.auth });
    },
  },
  {
    id: "auth",
    // Dev auth never accepts the dev header here: a verified bearer token is required, so only the
    // refusals are recorded; the success path is covered by `just auth-e2e` (design decision 4).
    covers: ["POST /v1/auth/sign-in", "POST /v1/auth/sign-out"],
    async run(ctx) {
      const { a } = ctx.seed;
      await ctx.expect("sign-in no token", 401, { method: "POST", path: "/v1/auth/sign-in" });
      await ctx.expect("sign-in dev header only", 401, { method: "POST", path: "/v1/auth/sign-in", headers: a.auth });
      await ctx.expect("sign-in bad bearer", 401, {
        method: "POST",
        path: "/v1/auth/sign-in",
        headers: { authorization: "Bearer not-a-token" },
      });
      await ctx.expect("sign-out no token", 401, { method: "POST", path: "/v1/auth/sign-out" });
      await ctx.expect("sign-out dev header only", 401, { method: "POST", path: "/v1/auth/sign-out", headers: a.auth });
    },
  },
];
