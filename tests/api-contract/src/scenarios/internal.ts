import { internalAuth } from "../client.ts";
import type { Ctx, Scenario } from "../scenario.ts";

const missing = "00000000-0000-4000-8000-000000000000";

/** The gateway's credential, and the same call with none, for one internal route. */
async function both(
  ctx: Ctx,
  label: string,
  ok: number,
  call: { method: string; path: string; body?: never },
  body?: object,
) {
  const org = ctx.seed.a.orgId;
  const withBody = body === undefined ? {} : { body: body as never };
  const res = await ctx.expect(label, ok, { ...call, ...withBody, headers: internalAuth(org) });
  await ctx.expect(`${label}: no credential`, 401, { ...call, ...withBody, headers: { "x-locksmith-org": org } });
  await ctx.expect(`${label}: user token is not accepted`, 401, { ...call, ...withBody, headers: ctx.seed.a.auth });
  return res;
}

export const scenarios: Scenario[] = [
  {
    id: "internal",
    covers: [
      "GET /internal/v1/agents/{agent_id}/grants",
      "POST /internal/v1/audit/events",
      "POST /internal/v1/audit/human-events",
      "PUT /internal/v1/gateway/bindings",
      "POST /internal/v1/mcp/agent-calls",
      "POST /internal/v1/mcp/agent-clients",
      "POST /internal/v1/mcp/upstream-calls",
      "GET /internal/v1/mcp/agent-tool-settings",
      "GET /internal/v1/mcp/revoked-agent-clients",
      "GET /internal/v1/secrets/{secret_id}/versions/{version}/material",
    ],
    async run(ctx) {
      const { a } = ctx.seed;
      const org = a.orgId;
      const p = await ctx.expect("project", 201, {
        method: "POST",
        path: "/v1/projects",
        headers: a.auth,
        body: { name: `int-${ctx.seed.run}` },
      });
      const pid = (p.body as { id: string }).id;
      const e = await ctx.expect("environment", 201, {
        method: "POST",
        path: `/v1/projects/${pid}/environments`,
        headers: a.auth,
        body: { name: "dev" },
      });
      const sBase = `/v1/projects/${pid}/environments/${(e.body as { id: string }).id}/secrets`;
      const s = await ctx.expect("secret", 201, {
        method: "POST",
        path: sBase,
        headers: a.auth,
        body: { name: "INTERNAL" },
      });
      const sid = (s.body as { id: string }).id;
      const value = process.env.API_CONTRACT_CANARY;
      if (!value) throw new Error("API_CONTRACT_CANARY is not set; run through scripts/api-contract.sh");
      await ctx.expect("version", 201, {
        method: "POST",
        path: `${sBase}/${sid}/versions`,
        headers: a.auth,
        body: { value },
      });
      const ag = await ctx.expect("agent", 201, {
        method: "POST",
        path: "/v1/agents",
        headers: a.auth,
        body: { name: `int-${ctx.seed.run}` },
      });
      const agentId = (ag.body as { agent: { id: string } }).agent.id;
      await ctx.expect("grant", 201, {
        method: "POST",
        path: `/v1/agents/${agentId}/grants`,
        headers: a.auth,
        body: { secret_id: sid },
      });

      await both(ctx, "grants", 200, { method: "GET", path: `/internal/v1/agents/${agentId}/grants` });
      await ctx.expect("grants unknown agent", 404, {
        method: "GET",
        path: `/internal/v1/agents/${missing}/grants`,
        headers: internalAuth(org),
      });

      // The material is ciphertext and a wrapped key only; the normaliser replaces both blobs.
      await both(ctx, "material", 200, { method: "GET", path: `/internal/v1/secrets/${sid}/versions/1/material` });
      await ctx.expect("material unknown version", 404, {
        method: "GET",
        path: `/internal/v1/secrets/${sid}/versions/99/material`,
        headers: internalAuth(org),
      });
      await ctx.expect("material unknown secret", 404, {
        method: "GET",
        path: `/internal/v1/secrets/${missing}/versions/1/material`,
        headers: internalAuth(org),
      });

      const attempt = {
        kind: "relay.attempt",
        outcome: "pending",
        agent_id: agentId,
        secret_id: sid,
        host: "upstream.test",
        method: "GET",
      };
      await both(ctx, "audit event", 201, { method: "POST", path: "/internal/v1/audit/events" }, attempt);
      await ctx.expect("audit event invalid", 400, {
        method: "POST",
        path: "/internal/v1/audit/events",
        headers: internalAuth(org),
        body: {},
      });

      const human = { kind: "auth.sign_in", user_id: "00000000-0000-7000-8000-0000000000b8", issuer: "idp.test" };
      await both(ctx, "human audit event", 201, { method: "POST", path: "/internal/v1/audit/human-events" }, human);
      await ctx.expect("human audit event invalid issuer", 400, {
        method: "POST",
        path: "/internal/v1/audit/human-events",
        headers: internalAuth(org),
        body: { ...human, issuer: "idp.test:8443" },
      });

      const snapshot = {
        items: [
          { kind: "http", name: "https://upstream.test", origin: "https://upstream.test", header: "authorization" },
        ],
      };
      await both(ctx, "bindings publish", 204, { method: "PUT", path: "/internal/v1/gateway/bindings" }, snapshot);
      await ctx.expect("bindings invalid", 400, {
        method: "PUT",
        path: "/internal/v1/gateway/bindings",
        headers: internalAuth(org),
        body: {},
      });
      await ctx.expect("bindings visible", 200, { method: "GET", path: "/v1/bindings", headers: a.auth });

      await both(
        ctx,
        "agent client",
        200,
        { method: "POST", path: "/internal/v1/mcp/agent-clients" },
        { agent_id: agentId, client_name: "gateway" },
      );
      await ctx.expect("agent client unknown agent", 404, {
        method: "POST",
        path: "/internal/v1/mcp/agent-clients",
        headers: internalAuth(org),
        body: { agent_id: missing, client_name: "x" },
      });
      await ctx.expect("agent client invalid", 400, {
        method: "POST",
        path: "/internal/v1/mcp/agent-clients",
        headers: internalAuth(org),
        body: {},
      });

      await both(
        ctx,
        "agent call",
        201,
        { method: "POST", path: "/internal/v1/mcp/agent-calls" },
        { agent_id: agentId, tool: "list_projects", outcome: "ok" },
      );
      await ctx.expect("agent call invalid", 400, {
        method: "POST",
        path: "/internal/v1/mcp/agent-calls",
        headers: internalAuth(org),
        body: {},
      });

      await both(
        ctx,
        "upstream call",
        201,
        { method: "POST", path: "/internal/v1/mcp/upstream-calls" },
        {
          phase: "call",
          agent_id: agentId,
          upstream: "github",
          tool: "list_issues",
          decision: "allow",
          outcome: "pending",
        },
      );
      await ctx.expect("upstream call invalid", 400, {
        method: "POST",
        path: "/internal/v1/mcp/upstream-calls",
        headers: internalAuth(org),
        body: {},
      });

      await both(ctx, "tool settings", 200, { method: "GET", path: "/internal/v1/mcp/agent-tool-settings" });
      await both(ctx, "revoked clients", 200, { method: "GET", path: "/internal/v1/mcp/revoked-agent-clients" });
    },
  },
];
