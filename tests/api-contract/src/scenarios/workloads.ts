import type { Scenario } from "../scenario.ts";

const missing = "00000000-0000-4000-8000-000000000000";

export const scenarios: Scenario[] = [
  {
    id: "workloads",
    covers: [
      "GET /v1/workload-identities",
      "POST /v1/workload-identities",
      "GET /v1/workload-identities/{id}",
      "DELETE /v1/workload-identities/{id}",
      "POST /v1/workload-tokens",
      "GET /v1/bindings",
    ],
    async run(ctx) {
      const { a, b } = ctx.seed;
      const agent = await ctx.expect("agent", 201, {
        method: "POST",
        path: "/v1/agents",
        headers: a.auth,
        body: { name: `wl-${ctx.seed.run}` },
      });
      const agentId = (agent.body as { agent: { id: string } }).agent.id;
      const policy = {
        name: `policy-${ctx.seed.run}`,
        issuer_kind: "github",
        audience: "locksmith",
        agent_id: agentId,
        conditions: [{ claim: "repository", pattern: "contract-org/contract-repo" }],
      };
      const base = "/v1/workload-identities";
      const created = await ctx.expect("create", 201, { method: "POST", path: base, headers: a.auth, body: policy });
      const { id, handle } = created.body as { id: string; handle: string };
      await ctx.expect("create no token", 401, { method: "POST", path: base, body: policy });
      await ctx.expect("create missing fields", 400, { method: "POST", path: base, headers: a.auth, body: {} });
      await ctx.expect("create duplicate", 409, { method: "POST", path: base, headers: a.auth, body: policy });
      await ctx.expect("create no subject pin", 422, {
        method: "POST",
        path: base,
        headers: a.auth,
        body: { ...policy, name: `pin-${ctx.seed.run}`, conditions: [{ claim: "ref", pattern: "refs/heads/main" }] },
      });
      await ctx.expect("create bare wildcard", 422, {
        method: "POST",
        path: base,
        headers: a.auth,
        body: { ...policy, name: `wild-${ctx.seed.run}`, conditions: [{ claim: "repository", pattern: "*" }] },
      });
      await ctx.expect("create unknown agent", 404, {
        method: "POST",
        path: base,
        headers: a.auth,
        body: { ...policy, name: `unk-${ctx.seed.run}`, agent_id: missing },
      });
      await ctx.expect("create cross-tenant agent", 404, {
        method: "POST",
        path: base,
        headers: b.auth,
        body: { ...policy, name: `x-${ctx.seed.run}` },
      });
      await ctx.expect("list", 200, { method: "GET", path: base, headers: a.auth });
      await ctx.expect("list bad limit", 400, { method: "GET", path: `${base}?limit=0`, headers: a.auth });
      await ctx.expect("list no token", 401, { method: "GET", path: base });
      await ctx.expect("list other tenant", 200, { method: "GET", path: base, headers: b.auth });
      await ctx.expect("get", 200, { method: "GET", path: `${base}/${id}`, headers: a.auth });
      await ctx.expect("get no token", 401, { method: "GET", path: `${base}/${id}` });
      await ctx.expect("get cross-tenant", 404, { method: "GET", path: `${base}/${id}`, headers: b.auth });
      await ctx.expect("get missing", 404, { method: "GET", path: `${base}/${missing}`, headers: a.auth });
      // The exchange needs a token from a real external issuer; only the refusals are scriptable.
      await ctx.expect("token garbage", 401, {
        method: "POST",
        path: "/v1/workload-tokens",
        body: { policy: handle, token: "not-a-jwt" },
      });
      await ctx.expect("token unknown policy", 401, {
        method: "POST",
        path: "/v1/workload-tokens",
        body: { policy: "lsw_unknown", token: "not-a-jwt" },
      });
      await ctx.expect("token missing fields", 400, { method: "POST", path: "/v1/workload-tokens", body: {} });
      await ctx.expect("bindings", 200, { method: "GET", path: "/v1/bindings", headers: a.auth });
      await ctx.expect("bindings no token", 401, { method: "GET", path: "/v1/bindings" });
      await ctx.expect("delete no token", 401, { method: "DELETE", path: `${base}/${id}` });
      await ctx.expect("delete cross-tenant", 404, { method: "DELETE", path: `${base}/${id}`, headers: b.auth });
      await ctx.expect("delete", 204, { method: "DELETE", path: `${base}/${id}`, headers: a.auth });
      await ctx.expect("get deleted", 404, { method: "GET", path: `${base}/${id}`, headers: a.auth });
    },
  },
];
