// Control-plane client for agents and grants. Types come from the generated schema.
// Nothing here logs or persists a response body: the enrollment secret only ever lives in
// the object returned to the caller.
import type { components } from "./schema";

export type Agent = components["schemas"]["Agent"];
export type AgentEnrollment = components["schemas"]["AgentEnrollment"];
export type AgentGrant = components["schemas"]["AgentGrant"];
export type NewAgent = components["schemas"]["NewAgent"];
export type NewAgentGrant = components["schemas"]["NewAgentGrant"];
export type AuditEvent = components["schemas"]["AuditEvent"];
export type AuditEventPage = components["schemas"]["AuditEventPage"];
export type AuditStatus = components["schemas"]["AuditStatus"];
export type Org = components["schemas"]["Org"];
export type Project = components["schemas"]["Project"];
export type NewProject = components["schemas"]["NewProject"];
export type Environment = components["schemas"]["Environment"];
export type NewEnvironment = components["schemas"]["NewEnvironment"];
export type Secret = components["schemas"]["Secret"];
export type SecretVersion = components["schemas"]["SecretVersion"];
export type Patch = components["schemas"]["Patch"];
export type McpLayer = components["schemas"]["McpLayer"];
export type McpToolSetting = components["schemas"]["McpToolSetting"];
export type McpClient = components["schemas"]["McpClient"];
export type Problem = components["schemas"]["Problem"];

/** The audit views' outcome filter: denials (any denied outcome or a `relay.denied` event) or redaction failures. */
export type AuditOutcomeFilter = "all" | "denied" | "redaction_failed";
export const auditOutcomeMatches = (e: AuditEvent, f: AuditOutcomeFilter): boolean =>
  f === "all" || (f === "denied" ? e.outcome === "denied" || e.kind === "relay.denied" : e.outcome === "redaction_failed");

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
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
  getOrg(id: string): Promise<Org>;
  listProjects(): Promise<Project[]>;
  createProject(body: NewProject): Promise<Project>;
  updateProject(id: string, body: Patch): Promise<Project>;
  deleteProject(id: string): Promise<void>;
  listEnvironments(projectId: string): Promise<Environment[]>;
  createEnvironment(projectId: string, body: NewEnvironment): Promise<Environment>;
  updateEnvironment(projectId: string, envId: string, body: Patch): Promise<Environment>;
  deleteEnvironment(projectId: string, envId: string): Promise<void>;
  /** Secret metadata only. The client has no method that reads, writes or fetches a secret value or its material. */
  listSecrets(projectId: string, envId: string): Promise<Secret[]>;
  getSecret(projectId: string, envId: string, secretId: string): Promise<Secret>;
  listSecretVersions(projectId: string, envId: string, secretId: string): Promise<SecretVersion[]>;
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
  async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const token = getToken?.();
    const headers: Record<string, string> = token ? { authorization: `Bearer ${token}` } : { "x-locksmith-dev-org": orgId };
    if (body !== undefined) headers["content-type"] = "application/json";
    const res = await fetch(`${baseUrl}${path}`, {
      method,
      headers,
      cache: "no-store",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) {
      let msg = `request failed (${res.status})`;
      try {
        const p = (await res.json()) as Partial<Problem>;
        if (p.detail || p.title) msg = String(p.detail ?? p.title);
      } catch { /* no problem body */ }
      throw new ApiError(res.status, msg);
    }
    return res.status === 204 ? (undefined as T) : ((await res.json()) as T);
  }

  async function all<T>(path: string): Promise<T[]> {
    const out: T[] = [];
    let cursor: string | null | undefined;
    do {
      const q = cursor ? `?cursor=${encodeURIComponent(cursor)}` : "";
      const page = await req<{ items: T[]; next?: string | null }>("GET", path + q);
      out.push(...page.items);
      cursor = page.next;
    } while (cursor);
    return out;
  }

  const e = encodeURIComponent;
  const p = (id: string) => `/v1/projects/${e(id)}`;
  const env = (pid: string, eid: string) => `${p(pid)}/environments/${e(eid)}`;
  const sec = (pid: string, eid: string, sid: string) => `${env(pid, eid)}/secrets/${e(sid)}`;
  const a = (id: string) => `/v1/agents/${encodeURIComponent(id)}`;
  return {
    listAgents: () => all<Agent>("/v1/agents"),
    createAgent: (b) => req("POST", "/v1/agents", b),
    deleteAgent: (id) => req("DELETE", a(id)),
    rotateEnrollment: (id) => req("POST", `${a(id)}/enrollment-secret`),
    listGrants: (id) => all<AgentGrant>(`${a(id)}/grants`),
    createGrant: (id, b) => req("POST", `${a(id)}/grants`, b),
    listAuditEvents: ({ cursor, limit } = {}) => {
      const q = new URLSearchParams();
      if (limit) q.set("limit", String(limit));
      if (cursor) q.set("cursor", cursor);
      const qs = q.toString();
      return req("GET", `/v1/audit/events${qs ? `?${qs}` : ""}`);
    },
    auditStatus: () => req("GET", "/v1/audit/status"),
    getOrg: (id) => req("GET", `/v1/orgs/${e(id)}`),
    listProjects: () => all<Project>("/v1/projects"),
    createProject: (b) => req("POST", "/v1/projects", b),
    updateProject: (id, b) => req("PATCH", p(id), b),
    deleteProject: (id) => req("DELETE", p(id)),
    listEnvironments: (pid) => all<Environment>(`${p(pid)}/environments`),
    createEnvironment: (pid, b) => req("POST", `${p(pid)}/environments`, b),
    updateEnvironment: (pid, eid, b) => req("PATCH", env(pid, eid), b),
    deleteEnvironment: (pid, eid) => req("DELETE", env(pid, eid)),
    listSecrets: (pid, eid) => all<Secret>(`${env(pid, eid)}/secrets`),
    getSecret: (pid, eid, sid) => req("GET", sec(pid, eid, sid)),
    listSecretVersions: async (pid, eid, sid) => (await req<{ items: SecretVersion[] }>("GET", `${sec(pid, eid, sid)}/versions`)).items,
    listMcpTools: async () => (await req<{ items: McpToolSetting[] }>("GET", "/v1/mcp/tools")).items,
    setMcpTool: (layer, tool, enabled) =>
      req("PUT", `/v1/mcp/tools/${layer}/${encodeURIComponent(tool)}`, { enabled }),
    listMcpClients: () => all<McpClient>("/v1/mcp/clients"),
    revokeMcpClient: (id) => req("POST", `/v1/mcp/clients/${encodeURIComponent(id)}/revoke`),
    revokeGrant: (id, g) => req("DELETE", `${a(id)}/grants/${encodeURIComponent(g)}`),
  };
}
