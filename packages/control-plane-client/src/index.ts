// Control-plane client for agents and grants. Types come from the generated schema.
// Nothing here logs or persists a response body: the enrollment secret only ever lives in
// the object returned to the caller.
import type { components } from "./schema";

export type Agent = components["schemas"]["Agent"];
export type AgentEnrollment = components["schemas"]["AgentEnrollment"];
export type AgentGrant = components["schemas"]["AgentGrant"];
export type NewAgent = components["schemas"]["NewAgent"];
export type NewAgentGrant = components["schemas"]["NewAgentGrant"];
export type Problem = components["schemas"]["Problem"];

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
}

export function createClient(orgId: string, baseUrl = ""): Client {
  async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { "x-locksmith-dev-org": orgId };
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
    revokeGrant: (id, g) => req("DELETE", `${a(id)}/grants/${encodeURIComponent(g)}`),
  };
}
