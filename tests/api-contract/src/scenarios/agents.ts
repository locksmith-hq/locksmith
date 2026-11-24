import type { Ctx, Scenario } from "../scenario.ts";

const missing = "00000000-0000-4000-8000-000000000000";

interface Created {
  agent: { id: string };
  enrollment_secret: string;
}

async function secretId(ctx: Ctx, label: string): Promise<string> {
  const { a } = ctx.seed;
  const auth = a.auth;
  const p = await ctx.expect(`${label}: project`, 201, {
    method: "POST",
    path: "/v1/projects",
    headers: auth,
    body: { name: `ag-${label}-${ctx.seed.run}` },
  });
  const pid = (p.body as { id: string }).id;
  const e = await ctx.expect(`${label}: environment`, 201, {
    method: "POST",
    path: `/v1/projects/${pid}/environments`,
    headers: auth,
    body: { name: "dev" },
  });
  const eid = (e.body as { id: string }).id;
  const s = await ctx.expect(`${label}: secret`, 201, {
    method: "POST",
    path: `/v1/projects/${pid}/environments/${eid}/secrets`,
    headers: auth,
    body: { name: "GRANTED" },
  });
  return (s.body as { id: string }).id;
}

export const scenarios: Scenario[] = [
  {
    id: "agents",
    covers: [
      "GET /v1/agents",
      "POST /v1/agents",
      "GET /v1/agents/{agent_id}",
      "DELETE /v1/agents/{agent_id}",
      "POST /v1/agents/{agent_id}/enrollment-secret",
      "POST /v1/agent-tokens",
    ],
    async run(ctx) {
      const { a, b } = ctx.seed;
      const created = await ctx.expect("create", 201, {
        method: "POST",
        path: "/v1/agents",
        headers: a.auth,
        body: { name: `agent-${ctx.seed.run}`, description: "d" },
      });
      const { agent, enrollment_secret: secret } = created.body as unknown as Created;
      const id = agent.id;
      await ctx.expect("create no token", 401, { method: "POST", path: "/v1/agents", body: { name: "x" } });
      await ctx.expect("create missing name", 400, { method: "POST", path: "/v1/agents", headers: a.auth, body: {} });
      await ctx.expect("create duplicate", 409, {
        method: "POST",
        path: "/v1/agents",
        headers: a.auth,
        body: { name: `agent-${ctx.seed.run}` },
      });
      await ctx.expect("list", 200, { method: "GET", path: "/v1/agents", headers: a.auth });
      await ctx.expect("list bad limit", 400, { method: "GET", path: "/v1/agents?limit=0", headers: a.auth });
      await ctx.expect("list no token", 401, { method: "GET", path: "/v1/agents" });
      await ctx.expect("list other tenant", 200, { method: "GET", path: "/v1/agents", headers: b.auth });
      await ctx.expect("get", 200, { method: "GET", path: `/v1/agents/${id}`, headers: a.auth });
      await ctx.expect("get no token", 401, { method: "GET", path: `/v1/agents/${id}` });
      await ctx.expect("get cross-tenant", 404, { method: "GET", path: `/v1/agents/${id}`, headers: b.auth });
      await ctx.expect("get missing", 404, { method: "GET", path: `/v1/agents/${missing}`, headers: a.auth });
      await ctx.expect("token ok", 200, {
        method: "POST",
        path: "/v1/agent-tokens",
        body: { enrollment_secret: secret },
      });
      await ctx.expect("token wrong secret", 401, {
        method: "POST",
        path: "/v1/agent-tokens",
        body: { enrollment_secret: "lsa_wrong" },
      });
      await ctx.expect("token missing secret", 400, { method: "POST", path: "/v1/agent-tokens", body: {} });
      const rotated = await ctx.expect("rotate", 200, {
        method: "POST",
        path: `/v1/agents/${id}/enrollment-secret`,
        headers: a.auth,
      });
      await ctx.expect("rotate no token", 401, { method: "POST", path: `/v1/agents/${id}/enrollment-secret` });
      await ctx.expect("rotate cross-tenant", 404, {
        method: "POST",
        path: `/v1/agents/${id}/enrollment-secret`,
        headers: b.auth,
      });
      await ctx.expect("token old secret after rotate", 401, {
        method: "POST",
        path: "/v1/agent-tokens",
        body: { enrollment_secret: secret },
      });
      await ctx.expect("token rotated secret", 200, {
        method: "POST",
        path: "/v1/agent-tokens",
        body: { enrollment_secret: (rotated.body as { enrollment_secret: string }).enrollment_secret },
      });
      await ctx.expect("delete no token", 401, { method: "DELETE", path: `/v1/agents/${id}` });
      await ctx.expect("delete cross-tenant", 404, { method: "DELETE", path: `/v1/agents/${id}`, headers: b.auth });
      await ctx.expect("delete", 204, { method: "DELETE", path: `/v1/agents/${id}`, headers: a.auth });
      await ctx.expect("get deleted", 404, { method: "GET", path: `/v1/agents/${id}`, headers: a.auth });
      await ctx.expect("token deleted agent", 401, {
        method: "POST",
        path: "/v1/agent-tokens",
        body: { enrollment_secret: secret },
      });
    },
  },
  {
    id: "grants",
    covers: [
      "GET /v1/agents/{agent_id}/grants",
      "POST /v1/agents/{agent_id}/grants",
      "DELETE /v1/agents/{agent_id}/grants/{grant_id}",
    ],
    async run(ctx) {
      const { a, b } = ctx.seed;
      const sid = await secretId(ctx, "grant");
      const created = await ctx.expect("agent", 201, {
        method: "POST",
        path: "/v1/agents",
        headers: a.auth,
        body: { name: `granted-${ctx.seed.run}` },
      });
      const id = (created.body as unknown as Created).agent.id;
      const base = `/v1/agents/${id}/grants`;
      const grant = await ctx.expect("create relay", 201, {
        method: "POST",
        path: base,
        headers: a.auth,
        body: { secret_id: sid },
      });
      const gid = (grant.body as { id: string }).id;
      await ctx.expect("create delegate", 201, {
        method: "POST",
        path: base,
        headers: a.auth,
        body: {
          secret_id: sid,
          mode: "delegate",
          scope: { actions: ["s3:GetObject"], resources: ["arn:aws:s3:::contract/*"], max_duration_secs: 900 },
        },
      });
      await ctx.expect("create delegate without scope", 400, {
        method: "POST",
        path: base,
        headers: a.auth,
        body: { secret_id: sid, mode: "delegate" },
      });
      await ctx.expect("create relay with scope", 400, {
        method: "POST",
        path: base,
        headers: a.auth,
        body: { secret_id: sid, scope: { actions: ["s3:GetObject"], resources: [] } },
      });
      await ctx.expect("create missing secret_id", 400, { method: "POST", path: base, headers: a.auth, body: {} });
      await ctx.expect("create unknown secret", 404, {
        method: "POST",
        path: base,
        headers: a.auth,
        body: { secret_id: missing },
      });
      await ctx.expect("create no token", 401, { method: "POST", path: base, body: { secret_id: sid } });
      await ctx.expect("create cross-tenant", 404, {
        method: "POST",
        path: base,
        headers: b.auth,
        body: { secret_id: sid },
      });
      await ctx.expect("list", 200, { method: "GET", path: base, headers: a.auth });
      await ctx.expect("list bad limit", 400, { method: "GET", path: `${base}?limit=0`, headers: a.auth });
      await ctx.expect("list no token", 401, { method: "GET", path: base });
      await ctx.expect("list cross-tenant", 404, { method: "GET", path: base, headers: b.auth });
      await ctx.expect("delete no token", 401, { method: "DELETE", path: `${base}/${gid}` });
      await ctx.expect("delete cross-tenant", 404, { method: "DELETE", path: `${base}/${gid}`, headers: b.auth });
      await ctx.expect("delete", 204, { method: "DELETE", path: `${base}/${gid}`, headers: a.auth });
      await ctx.expect("delete again", 404, { method: "DELETE", path: `${base}/${gid}`, headers: a.auth });
    },
  },
];
