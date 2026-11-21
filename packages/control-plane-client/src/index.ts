// Control-plane client for agents and grants. Types and transport come from @locksmith/sdk.
// Nothing here logs or persists a response body: the enrollment secret only ever lives in
// the object returned to the caller.
import { createLocksmith, LocksmithError, paginate, unwrap, type components } from "@locksmith/sdk";

export type Agent = components["schemas"]["Agent"];
export type AgentEnrollment = components["schemas"]["AgentEnrollment"];
export type AgentGrant = components["schemas"]["AgentGrant"];
export type NewAgent = components["schemas"]["NewAgent"];
export type NewAgentGrant = components["schemas"]["NewAgentGrant"];
export type AuditEvent = components["schemas"]["AuditEvent"];
export type AuditEventPage = components["schemas"]["AuditEventPage"];
export type AuditStatus = components["schemas"]["AuditStatus"];
export type McpLayer = components["schemas"]["McpLayer"];
export type McpToolSetting = components["schemas"]["McpToolSetting"];
export type McpClient = components["schemas"]["McpClient"];
export type Problem = components["schemas"]["Problem"];

/** The audit views' outcome filter: denials (any denied outcome or a `relay.denied` event) or redaction failures. */
export type AuditOutcomeFilter = "all" | "denied" | "redaction_failed";
export const auditOutcomeMatches = (e: AuditEvent, f: AuditOutcomeFilter): boolean =>
  f === "all" || (f === "denied" ? e.outcome === "denied" || e.kind === "relay.denied" : e.outcome === "redaction_failed");

export class ApiError extends LocksmithError {
  constructor(status: number, message: string) {
    super(status, { detail: message });
    this.name = "ApiError";
  }
}

export interface Client {
  listAgents(): Promise<Agent[]>;
  createAgent(body: NewAgent): Promise<AgentEnrollment>;
  deleteAgent(id: string): Promise<void>;
  rotateEnrollment(id: string): Promise<AgentEnrollment>;
  listGrants(agentId: string): Promise<AgentGrant[]>;
  createGrant(agentId: string, body: NewAgentGrant): Promise<AgentGrant>;
  revokeGrant(agentId: string, grantId: string): Promise<void>;
  /** One page of audit events, newest first. Pass the previous page's `next` as `cursor`. */
  listAuditEvents(opts?: { cursor?: string | null; limit?: number }): Promise<AuditEventPage>;
  auditStatus(): Promise<AuditStatus>;
  /** Every MCP tool of both layers with its default and the org's switch. */
  listMcpTools(): Promise<McpToolSetting[]>;
  /** Turn one MCP tool on or off. Enforced server-side: a client cannot list or call an off tool. */
  setMcpTool(layer: McpLayer, tool: string, enabled: boolean): Promise<McpToolSetting>;
  /** MCP clients that signed in, revoked ones included. */
  listMcpClients(): Promise<McpClient[]>;
  /** Revoke a client by its row `id` (not the OAuth `client_id`). Idempotent. */
  revokeMcpClient(id: string): Promise<McpClient>;
}

/**
 * `getToken` supplies the human bearer token (read per request, so a renewed token is used).
 * With a token the dev org header is not sent: the control plane takes the org from the token.
 */
export function createClient(orgId: string, baseUrl = "", getToken?: () => string | undefined): Client {
  // openapi-fetch builds a Request, which needs an absolute URL: use a placeholder origin for a
  // relative base and strip it again, so the app still fetches `/v1/...` on its own origin.
  const origin = "http://relative.invalid";
  const c = createLocksmith({
    baseUrl: baseUrl || origin,
    token: () => getToken?.(),
    // Read the global at call time; never cache a response in the browser.
    fetch: async (input) => {
      const r = input as Request; // openapi-fetch always passes a Request
      const body = (await r.text()) || undefined;
      return globalThis.fetch(baseUrl ? r.url : r.url.slice(origin.length), {
        method: r.method,
        headers: Object.fromEntries(r.headers),
        body,
        cache: "no-store",
      });
    },
  });
  c.use({
    onRequest({ request }) {
      if (!getToken?.()) request.headers.set("x-locksmith-dev-org", orgId);
      return request;
    },
  });

  // Convert the SDK's error into the ApiError the apps already handle.
  async function run<T>(p: Promise<{ data?: T; error?: unknown; response: Response }>): Promise<T> {
    const r = await p;
    if (r.response.ok && r.response.status === 204) return undefined as T;
    try {
      return unwrap(r);
    } catch (e) {
      if (e instanceof LocksmithError) throw new ApiError(e.status, e.message);
      throw e;
    }
  }

  async function all<T>(page: (cursor: string | null) => Promise<{ items: T[]; next?: string | null }>): Promise<T[]> {
    const out: T[] = [];
    for await (const p of paginate(page)) out.push(...p.items);
    return out;
  }

  const q = (cursor: string | null) => (cursor ? { cursor } : {});
  return {
    listAgents: () => all((cursor) => run(c.GET("/v1/agents", { params: { query: q(cursor) } }))),
    createAgent: (body) => run(c.POST("/v1/agents", { body })),
    deleteAgent: (agent_id) => run(c.DELETE("/v1/agents/{agent_id}", { params: { path: { agent_id } } })),
    rotateEnrollment: (agent_id) => run(c.POST("/v1/agents/{agent_id}/enrollment-secret", { params: { path: { agent_id } } })),
    listGrants: (agent_id) =>
      all((cursor) => run(c.GET("/v1/agents/{agent_id}/grants", { params: { path: { agent_id }, query: q(cursor) } }))),
    createGrant: (agent_id, body) => run(c.POST("/v1/agents/{agent_id}/grants", { params: { path: { agent_id } }, body })),
    revokeGrant: (agent_id, grant_id) =>
      run(c.DELETE("/v1/agents/{agent_id}/grants/{grant_id}", { params: { path: { agent_id, grant_id } } })),
    listAuditEvents: ({ cursor, limit } = {}) =>
      run(c.GET("/v1/audit/events", { params: { query: { ...(limit ? { limit } : {}), ...q(cursor ?? null) } } })),
    auditStatus: () => run(c.GET("/v1/audit/status")),
    listMcpTools: async () => (await run(c.GET("/v1/mcp/tools"))).items,
    setMcpTool: (layer, tool, enabled) =>
      run(c.PUT("/v1/mcp/tools/{layer}/{tool}", { params: { path: { layer, tool } }, body: { enabled } })),
    listMcpClients: () => all((cursor) => run(c.GET("/v1/mcp/clients", { params: { query: q(cursor) } }))),
    revokeMcpClient: (client_row_id) =>
      run(c.POST("/v1/mcp/clients/{client_row_id}/revoke", { params: { path: { client_row_id } } })),
  };
}
