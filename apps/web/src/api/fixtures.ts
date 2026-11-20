// In-memory fixture backend for every route the console calls. Tests install it with
// `installFixtureFetch()`; it holds ids, names and counts only, never a secret value or material.
import { vi } from "vitest";

const now = "2026-11-20T00:00:00Z";
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

export interface FixtureOptions {
  /** Force a status for any request whose "METHOD path" matches (e.g. `{ "POST /v1/projects": 409 }`). */
  fail?: Record<string, number>;
  empty?: boolean;
}

export function createFixtures(opts: FixtureOptions = {}) {
  const projects = opts.empty ? [] : [{ id: id(1), name: "payments", description: "", created_at: now, updated_at: now }];
  const envs = opts.empty ? [] : [{ id: id(10), project_id: id(1), name: "dev", description: "", created_at: now, updated_at: now }];
  const secrets = opts.empty
    ? []
    : [{ id: id(20), project_id: id(1), environment_id: id(10), name: "STRIPE_KEY", description: "", version_count: 2, created_at: now, updated_at: now }];
  const requests: string[] = [];
  let seq = 100;

  const reply = (body: unknown, status = 200) =>
    status === 204 ? new Response(null, { status }) : new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const problem = (status: number) => reply({ type: "about:blank", title: `status ${status}`, detail: `fixture ${status}`, status }, status);

  async function handle(input: string, init: RequestInit = {}): Promise<Response> {
    const method = init.method ?? "GET";
    const url = new URL(input, "http://fixture");
    const path = url.pathname;
    const key = `${method} ${path}`;
    requests.push(key);
    if (opts.fail?.[key]) return problem(opts.fail[key]!);
    const body = init.body ? (JSON.parse(String(init.body)) as Record<string, string>) : {};
    const page = (items: unknown[]) => reply({ items, next: null });
    let m: RegExpMatchArray | null;
    if (path === "/v1/projects") {
      if (method === "GET") return page(projects);
      const p = { id: id(seq++), name: body.name!, description: body.description ?? "", created_at: now, updated_at: now };
      if (projects.some((x) => x.name === p.name)) return problem(409);
      projects.push(p);
      return reply(p, 201);
    }
    if ((m = path.match(/^\/v1\/projects\/([^/]+)$/))) {
      const i = projects.findIndex((x) => x.id === m![1]);
      if (i < 0) return problem(404);
      if (method === "DELETE") return projects.splice(i, 1), reply(null, 204);
      if (method === "PATCH") return Object.assign(projects[i]!, body.name ? { name: body.name } : {}), reply(projects[i]);
      return reply(projects[i]);
    }
    if ((m = path.match(/^\/v1\/projects\/([^/]+)\/environments$/))) {
      if (method === "GET") return page(envs.filter((e) => e.project_id === m![1]));
      const e = { id: id(seq++), project_id: m[1]!, name: body.name!, description: body.description ?? "", created_at: now, updated_at: now };
      envs.push(e);
      return reply(e, 201);
    }
    if ((m = path.match(/^\/v1\/projects\/([^/]+)\/environments\/([^/]+)$/))) {
      const i = envs.findIndex((x) => x.id === m![2]);
      if (i < 0) return problem(404);
      if (method === "DELETE") return envs.splice(i, 1), reply(null, 204);
      if (method === "PATCH") return Object.assign(envs[i]!, body.name ? { name: body.name } : {}), reply(envs[i]);
      return reply(envs[i]);
    }
    if ((m = path.match(/^\/v1\/projects\/([^/]+)\/environments\/([^/]+)\/secrets$/))) return page(secrets.filter((s) => s.environment_id === m![2]));
    if ((m = path.match(/^\/v1\/projects\/[^/]+\/environments\/[^/]+\/secrets\/([^/]+)$/))) {
      const s = secrets.find((x) => x.id === m![1]);
      return s ? reply(s) : problem(404);
    }
    if ((m = path.match(/^\/v1\/projects\/[^/]+\/environments\/[^/]+\/secrets\/([^/]+)\/versions$/))) {
      const s = secrets.find((x) => x.id === m![1]);
      if (!s) return problem(404);
      return reply({ items: Array.from({ length: s.version_count }, (_, n) => ({ secret_id: s.id, version: n + 1, key_id: "gateway:v1", created_at: now })) });
    }
    if (path === "/v1/agents" || /^\/v1\/agents\/[^/]+\/grants$/.test(path)) return page([]);
    if (path === "/v1/audit/events") return page([]);
    if (path === "/v1/audit/status") return reply({ status: "ok" });
    return problem(404);
  }
  return { handle, requests, projects, envs, secrets };
}

/** Replaces global `fetch` with the fixture backend; returns it so tests can assert on `requests`. */
export function installFixtureFetch(opts?: FixtureOptions) {
  const fx = createFixtures(opts);
  vi.stubGlobal("fetch", vi.fn((input: string, init?: RequestInit) => fx.handle(String(input), init)));
  return fx;
}
