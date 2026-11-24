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
export type Org = components["schemas"]["Org"];
export type Project = components["schemas"]["Project"];
export type NewProject = components["schemas"]["NewProject"];
export type Environment = components["schemas"]["Environment"];
export type NewEnvironment = components["schemas"]["NewEnvironment"];
export type Secret = components["schemas"]["Secret"];
export type SecretVersion = components["schemas"]["SecretVersion"];
export type Patch = components["schemas"]["Patch"];
export type WorkloadIdentity = components["schemas"]["WorkloadIdentity"];
export type NewWorkloadIdentity = components["schemas"]["NewWorkloadIdentity"];
export type WorkloadCondition = components["schemas"]["ConditionView"];
export type McpLayer = components["schemas"]["McpLayer"];
export type McpToolSetting = components["schemas"]["McpToolSetting"];
export type McpClient = components["schemas"]["McpClient"];
/** One gateway binding, non-secret fields only (never a password, template, secret id or key). */
export type BindingSummary = components["schemas"]["BindingSummary"];
export type BindingKind = components["schemas"]["BindingKind"];
export type Problem = components["schemas"]["Problem"];
export * from "./oauth";

/** Non-secret fields of a binding as label/value pairs for display, in a fixed order per kind; unset fields are skipped. */
export function bindingDetails(b: BindingSummary): Array<[label: string, value: string]> {
  const rows: Array<[string, string | number | boolean | null | undefined]> =
    b.kind === "pg"
      ? [
          ["Host", b.host],
          ["Port", b.port],
          ["User", b.user],
          ["Database", b.database],
          ["TLS", b.tls],
        ]
      : b.kind === "http"
        ? [
            ["Origin", b.origin],
            ["Header", b.header],
          ]
        : b.kind === "git"
          ? [
              ["Host", b.host],
              ["Repo", b.repo],
            ]
          : [
              ["Role", b.role],
              ["Region", b.region],
              ["Vend credentials", b.vend == null ? null : b.vend ? "yes" : "no"],
              ["Max duration", b.max_duration_secs == null ? null : `${b.max_duration_secs}s`],
              ["Allowed actions", b.allowed_actions == null ? null : b.allowed_actions.join(", ") || "none"],
            ];
  return rows
    .filter((r): r is [string, string | number | boolean] => r[1] != null && r[1] !== "")
    .map(([l, v]) => [l, String(v)]);
}

/** The audit views' outcome filter: denials (any denied outcome or a `relay.denied` event) or redaction failures. */
export type AuditOutcomeFilter = "all" | "denied" | "redaction_failed";
export const auditOutcomeMatches = (e: AuditEvent, f: AuditOutcomeFilter): boolean =>
  f === "all" ||
  (f === "denied" ? e.outcome === "denied" || e.kind === "relay.denied" : e.outcome === "redaction_failed");

/** True when a condition value is a trailing-`*` prefix match (broader than an exact match). */
export const isPrefixPattern = (c: WorkloadCondition): boolean => c.pattern.endsWith("*");
export const hasPrefixCondition = (conditions: readonly WorkloadCondition[]): boolean =>
  conditions.some(isPrefixPattern);

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
  const add = (claim: string, pattern?: string) => {
    const v = pattern?.trim();
    if (v) conditions.push({ claim, pattern: v });
  };
  if (f.preset === "github") {
    add("repository", f.repository);
    add("ref", f.ref);
    add("environment", f.environment);
    return { name: f.name.trim(), agent_id: f.agentId, audience: f.audience.trim(), issuer_kind: "github", conditions };
  }
  const ns = f.namespace?.trim(),
    sa = f.serviceaccount?.trim();
  if (ns && sa) add("sub", `system:serviceaccount:${ns}:${sa}`);
  return {
    name: f.name.trim(),
    agent_id: f.agentId,
    audience: f.audience.trim(),
    issuer_kind: "oidc",
    issuer: f.issuer?.trim(),
    conditions,
  };
}

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
  listWorkloadIdentities(): Promise<WorkloadIdentity[]>;
  createWorkloadIdentity(body: NewWorkloadIdentity): Promise<WorkloadIdentity>;
  deleteWorkloadIdentity(id: string): Promise<void>;
  /** Every MCP tool of both layers with its default and the org's switch. */
  listMcpTools(): Promise<McpToolSetting[]>;
  /** Turn one MCP tool on or off. Enforced server-side: a client cannot list or call an off tool. */
  setMcpTool(layer: McpLayer, tool: string, enabled: boolean): Promise<McpToolSetting>;
  /** MCP clients that signed in, revoked ones included. */
  listMcpClients(): Promise<McpClient[]>;
  /** The gateway's bindings for the org, non-secret fields only. */
  listBindings(): Promise<BindingSummary[]>;
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
        signal: r.signal,
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
    rotateEnrollment: (agent_id) =>
      run(c.POST("/v1/agents/{agent_id}/enrollment-secret", { params: { path: { agent_id } } })),
    listGrants: (agent_id) =>
      all((cursor) => run(c.GET("/v1/agents/{agent_id}/grants", { params: { path: { agent_id }, query: q(cursor) } }))),
    createGrant: (agent_id, body) =>
      run(c.POST("/v1/agents/{agent_id}/grants", { params: { path: { agent_id } }, body })),
    revokeGrant: (agent_id, grant_id) =>
      run(c.DELETE("/v1/agents/{agent_id}/grants/{grant_id}", { params: { path: { agent_id, grant_id } } })),
    listAuditEvents: ({ cursor, limit } = {}) =>
      run(c.GET("/v1/audit/events", { params: { query: { ...(limit ? { limit } : {}), ...q(cursor ?? null) } } })),
    auditStatus: () => run(c.GET("/v1/audit/status")),
    getOrg: (org_id) => run(c.GET("/v1/orgs/{org_id}", { params: { path: { org_id } } })),
    listProjects: () => all((cursor) => run(c.GET("/v1/projects", { params: { query: q(cursor) } }))),
    createProject: (body) => run(c.POST("/v1/projects", { body })),
    updateProject: (project_id, body) =>
      run(c.PATCH("/v1/projects/{project_id}", { params: { path: { project_id } }, body })),
    deleteProject: (project_id) => run(c.DELETE("/v1/projects/{project_id}", { params: { path: { project_id } } })),
    listEnvironments: (project_id) =>
      all((cursor) =>
        run(c.GET("/v1/projects/{project_id}/environments", { params: { path: { project_id }, query: q(cursor) } })),
      ),
    createEnvironment: (project_id, body) =>
      run(c.POST("/v1/projects/{project_id}/environments", { params: { path: { project_id } }, body })),
    updateEnvironment: (project_id, environment_id, body) =>
      run(
        c.PATCH("/v1/projects/{project_id}/environments/{environment_id}", {
          params: { path: { project_id, environment_id } },
          body,
        }),
      ),
    deleteEnvironment: (project_id, environment_id) =>
      run(
        c.DELETE("/v1/projects/{project_id}/environments/{environment_id}", {
          params: { path: { project_id, environment_id } },
        }),
      ),
    listSecrets: (project_id, environment_id) =>
      all((cursor) =>
        run(
          c.GET("/v1/projects/{project_id}/environments/{environment_id}/secrets", {
            params: { path: { project_id, environment_id }, query: q(cursor) },
          }),
        ),
      ),
    getSecret: (project_id, environment_id, secret_id) =>
      run(
        c.GET("/v1/projects/{project_id}/environments/{environment_id}/secrets/{secret_id}", {
          params: { path: { project_id, environment_id, secret_id } },
        }),
      ),
    listSecretVersions: async (project_id, environment_id, secret_id) =>
      (
        await run(
          c.GET("/v1/projects/{project_id}/environments/{environment_id}/secrets/{secret_id}/versions", {
            params: { path: { project_id, environment_id, secret_id } },
          }),
        )
      ).items,
    listMcpTools: async () => (await run(c.GET("/v1/mcp/tools"))).items,
    listWorkloadIdentities: () =>
      all((cursor) => run(c.GET("/v1/workload-identities", { params: { query: q(cursor) } }))),
    createWorkloadIdentity: (body) => run(c.POST("/v1/workload-identities", { body })),
    deleteWorkloadIdentity: (id) => run(c.DELETE("/v1/workload-identities/{id}", { params: { path: { id } } })),
    setMcpTool: (layer, tool, enabled) =>
      run(c.PUT("/v1/mcp/tools/{layer}/{tool}", { params: { path: { layer, tool } }, body: { enabled } })),
    listBindings: async () => (await run(c.GET("/v1/bindings"))).items,
    listMcpClients: () => all((cursor) => run(c.GET("/v1/mcp/clients", { params: { query: q(cursor) } }))),
    revokeMcpClient: (client_row_id) =>
      run(c.POST("/v1/mcp/clients/{client_row_id}/revoke", { params: { path: { client_row_id } } })),
  };
}
