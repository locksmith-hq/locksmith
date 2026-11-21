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
export type WorkloadIdentity = components["schemas"]["WorkloadIdentity"];
export type NewWorkloadIdentity = components["schemas"]["NewWorkloadIdentity"];
export type WorkloadCondition = components["schemas"]["ConditionView"];
export type McpLayer = components["schemas"]["McpLayer"];
export type McpToolSetting = components["schemas"]["McpToolSetting"];
export type McpClient = components["schemas"]["McpClient"];
export type Problem = components["schemas"]["Problem"];

/** The audit views' outcome filter: denials (any denied outcome or a `relay.denied` event) or redaction failures. */
export type AuditOutcomeFilter = "all" | "denied" | "redaction_failed";
export const auditOutcomeMatches = (e: AuditEvent, f: AuditOutcomeFilter): boolean =>
  f === "all" || (f === "denied" ? e.outcome === "denied" || e.kind === "relay.denied" : e.outcome === "redaction_failed");

/** True when a condition value is a trailing-`*` prefix match (broader than an exact match). */
export const isPrefixPattern = (c: WorkloadCondition): boolean => c.pattern.endsWith("*");
export const hasPrefixCondition = (conditions: readonly WorkloadCondition[]): boolean => conditions.some(isPrefixPattern);

export type WorkloadPreset = "github" | "kubernetes";
export interface WorkloadForm {
  name: string;
  agentId: string;
  audience: string;
  preset: WorkloadPreset;
  /** Kubernetes only: the cluster's https issuer URL. */
  issuer?: string;
  /** GitHub: owner/repo (pinned subject). */
  repository?: string;
  ref?: string;
  environment?: string;
  /** Kubernetes: compiled to `sub` = `system:serviceaccount:<namespace>:<serviceaccount>`. */
  namespace?: string;
  serviceaccount?: string;
}

/** Builds the create request from a preset form. Carries no token or secret field by construction. */
export function buildWorkloadIdentity(f: WorkloadForm): NewWorkloadIdentity {
  const conditions: WorkloadCondition[] = [];
  const add = (claim: string, pattern?: string) => { const v = pattern?.trim(); if (v) conditions.push({ claim, pattern: v }); };
  if (f.preset === "github") {
    add("repository", f.repository); add("ref", f.ref); add("environment", f.environment);
    return { name: f.name.trim(), agent_id: f.agentId, audience: f.audience.trim(), issuer_kind: "github", conditions };
  }
  const ns = f.namespace?.trim(), sa = f.serviceaccount?.trim();
  if (ns && sa) add("sub", `system:serviceaccount:${ns}:${sa}`);
  return { name: f.name.trim(), agent_id: f.agentId, audience: f.audience.trim(), issuer_kind: "oidc", issuer: f.issuer?.trim(), conditions };
}

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
  listWorkloadIdentities(): Promise<WorkloadIdentity[]>;
  createWorkloadIdentity(body: NewWorkloadIdentity): Promise<WorkloadIdentity>;
  deleteWorkloadIdentity(id: string): Promise<void>;
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
    listWorkloadIdentities: () => all<WorkloadIdentity>("/v1/workload-identities"),
    createWorkloadIdentity: (b) => req("POST", "/v1/workload-identities", b),
    deleteWorkloadIdentity: (id) => req("DELETE", `/v1/workload-identities/${encodeURIComponent(id)}`),
    listMcpTools: async () => (await req<{ items: McpToolSetting[] }>("GET", "/v1/mcp/tools")).items,
    setMcpTool: (layer, tool, enabled) =>
      req("PUT", `/v1/mcp/tools/${layer}/${encodeURIComponent(tool)}`, { enabled }),
    listMcpClients: () => all<McpClient>("/v1/mcp/clients"),
    revokeMcpClient: (id) => req("POST", `/v1/mcp/clients/${encodeURIComponent(id)}/revoke`),
    revokeGrant: (id, g) => req("DELETE", `${a(id)}/grants/${encodeURIComponent(g)}`),
  };
}
