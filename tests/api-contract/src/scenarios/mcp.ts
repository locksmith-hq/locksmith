import { internalAuth } from "../client.ts";
import type { Scenario } from "../scenario.ts";

const missing = "00000000-0000-4000-8000-000000000000";

export const scenarios: Scenario[] = [
  {
    id: "mcp",
    covers: [
      "GET /v1/mcp/clients",
      "POST /v1/mcp/clients/{client_row_id}/revoke",
      "GET /v1/mcp/tools",
      "PUT /v1/mcp/tools/{layer}/{tool}",
    ],
    async run(ctx) {
      const { a, b } = ctx.seed;
      // An agent MCP client row is made the way the gateway makes it: through the internal route.
      const agent = await ctx.expect("agent", 201, {
        method: "POST",
        path: "/v1/agents",
        headers: a.auth,
        body: { name: `mcp-${ctx.seed.run}` },
      });
      const agentId = (agent.body as { agent: { id: string } }).agent.id;
      await ctx.expect("register client", 200, {
        method: "POST",
        path: "/internal/v1/mcp/agent-clients",
        headers: internalAuth(a.orgId),
        body: { agent_id: agentId, client_name: "contract-client" },
      });
      await ctx.expect("clients", 200, { method: "GET", path: "/v1/mcp/clients", headers: a.auth });
      const list = await ctx.rec.call("clients raw", { method: "GET", path: "/v1/mcp/clients", headers: a.auth });
      const row = (list.body as { items: { id: string }[] }).items[0]?.id ?? missing;
      await ctx.expect("clients bad limit", 400, { method: "GET", path: "/v1/mcp/clients?limit=0", headers: a.auth });
      await ctx.expect("clients no token", 401, { method: "GET", path: "/v1/mcp/clients" });
      await ctx.expect("clients other tenant", 200, { method: "GET", path: "/v1/mcp/clients", headers: b.auth });
      await ctx.expect("revoke no token", 401, { method: "POST", path: `/v1/mcp/clients/${row}/revoke` });
      await ctx.expect("revoke cross-tenant", 404, {
        method: "POST",
        path: `/v1/mcp/clients/${row}/revoke`,
        headers: b.auth,
      });
      await ctx.expect("revoke missing", 404, {
        method: "POST",
        path: `/v1/mcp/clients/${missing}/revoke`,
        headers: a.auth,
      });
      await ctx.expect("revoke", 200, { method: "POST", path: `/v1/mcp/clients/${row}/revoke`, headers: a.auth });
      await ctx.expect("clients after revoke", 200, { method: "GET", path: "/v1/mcp/clients", headers: a.auth });
      await ctx.expect("tools", 200, { method: "GET", path: "/v1/mcp/tools", headers: a.auth });
      await ctx.expect("tools no token", 401, { method: "GET", path: "/v1/mcp/tools" });
      const off = { method: "PUT", path: "/v1/mcp/tools/hub/list_projects" };
      await ctx.expect("tool switch off", 200, { ...off, headers: a.auth, body: { enabled: false } });
      await ctx.expect("tools after switch", 200, { method: "GET", path: "/v1/mcp/tools", headers: a.auth });
      await ctx.expect("tool switch other tenant unchanged", 200, {
        method: "GET",
        path: "/v1/mcp/tools",
        headers: b.auth,
      });
      await ctx.expect("tool switch on", 200, { ...off, headers: a.auth, body: { enabled: true } });
      await ctx.expect("tool switch bad body", 400, { ...off, headers: a.auth, body: {} });
      await ctx.expect("tool switch no token", 401, { ...off, body: { enabled: true } });
      await ctx.expect("tool switch unknown tool", 404, {
        method: "PUT",
        path: "/v1/mcp/tools/hub/no_such_tool",
        headers: a.auth,
        body: { enabled: true },
      });
      await ctx.expect("tool switch unknown layer", 404, {
        method: "PUT",
        path: "/v1/mcp/tools/nope/list_projects",
        headers: a.auth,
        body: { enabled: true },
      });
    },
  },
  {
    id: "audit",
    covers: ["GET /v1/audit/events", "GET /v1/audit/status"],
    async run(ctx) {
      const { a, b } = ctx.seed;
      await ctx.expect("events", 200, { method: "GET", path: "/v1/audit/events", headers: a.auth });
      await ctx.expect("events limit", 200, { method: "GET", path: "/v1/audit/events?limit=1", headers: a.auth });
      await ctx.expect("events bad limit", 400, { method: "GET", path: "/v1/audit/events?limit=0", headers: a.auth });
      await ctx.expect("events bad cursor", 400, {
        method: "GET",
        path: "/v1/audit/events?cursor=zzz",
        headers: a.auth,
      });
      await ctx.expect("events no token", 401, { method: "GET", path: "/v1/audit/events" });
      await ctx.expect("events other tenant", 200, { method: "GET", path: "/v1/audit/events", headers: b.auth });
      await ctx.expect("status", 200, { method: "GET", path: "/v1/audit/status", headers: a.auth });
      await ctx.expect("status no token", 401, { method: "GET", path: "/v1/audit/status" });
    },
  },
];
