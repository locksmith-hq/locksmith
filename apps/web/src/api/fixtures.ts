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

function createFixtures(opts: FixtureOptions = {}) {
  const projects = opts.empty
    ? []
    : [{ id: id(1), name: "payments", description: "", created_at: now, updated_at: now }];
  const envs = opts.empty
    ? []
    : [{ id: id(10), project_id: id(1), name: "dev", description: "", created_at: now, updated_at: now }];
  const secrets = opts.empty
    ? []
    : [
        {
          id: id(20),
          project_id: id(1),
          environment_id: id(10),
          name: "STRIPE_KEY",
          description: "",
          version_count: 2,
          created_at: now,
          updated_at: now,
        },
      ];
  const agents: { id: string; name: string; created_at: string }[] = [];
  const grants: ({ id: string; agent_id: string; created_at: string } & Record<string, unknown>)[] = [];
  const mcpTools = opts.empty ? [] : [{ layer: "hub", tool: "list_secrets", default_enabled: true, enabled: true }];
  const mcpClients: { id: string; client_id: string; name: string; revoked_at: string | null }[] = opts.empty
    ? []
    : [{ id: id(30), client_id: "fixture-client", name: "Fixture MCP client", revoked_at: null }];
  const inbox = opts.empty
    ? []
    : [
        {
          id: id(40),
          kind: "relay.denied",
          payload: {
            kind: "relay.denied",
            actor: { id: "a1", name: "ci-agent" },
            object_name: "stripe",
            occurred_at: now,
            link: "/activity",
          },
          created_at: now,
          read_at: null as string | null,
        },
        {
          id: id(41),
          kind: "git.denied",
          payload: { kind: "git.denied", actor: null, object_name: "app", occurred_at: now, link: "/activity" },
          created_at: now,
          read_at: now as string | null,
        },
      ];
  let rules: { kind: string; channel: string; audience: string; audience_user_id: null }[] = [
    { kind: "relay.denied", channel: "inbox", audience: "owner", audience_user_id: null },
  ];
  const honey: Record<string, unknown>[] = opts.empty
    ? []
    : [
        {
          id: id(50),
          name: "prod-aws-decoy",
          template: "aws_access_key",
          created_at: now,
          disabled_at: null,
          last_triggered_at: "2026-11-19T02:15:00Z",
        },
        {
          id: id(51),
          name: "ci-github-decoy",
          template: "github_pat",
          created_at: now,
          disabled_at: null,
          last_triggered_at: null,
        },
      ];
  const chan = { email: { enabled: false }, slack: { configured: false } };
  const requests: string[] = [];
  let seq = 100;

  const reply = (body: unknown, status = 200) =>
    status === 204
      ? new Response(null, { status })
      : new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const problem = (status: number) =>
    reply({ type: "about:blank", title: `status ${status}`, detail: `fixture ${status}`, status }, status);

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
      const p = {
        id: id(seq++),
        name: body.name!,
        description: body.description ?? "",
        created_at: now,
        updated_at: now,
      };
      if (projects.some((x) => x.name === p.name)) return problem(409);
      projects.push(p);
      return reply(p, 201);
    }
    if ((m = path.match(/^\/v1\/projects\/([^/]+)$/))) {
      const i = projects.findIndex((x) => x.id === m![1]);
      if (i < 0) return problem(404);
      if (method === "DELETE") return (projects.splice(i, 1), reply(null, 204));
      if (method === "PATCH")
        return (Object.assign(projects[i]!, body.name ? { name: body.name } : {}), reply(projects[i]));
      return reply(projects[i]);
    }
    if ((m = path.match(/^\/v1\/projects\/([^/]+)\/environments$/))) {
      if (method === "GET") return page(envs.filter((e) => e.project_id === m![1]));
      const e = {
        id: id(seq++),
        project_id: m[1]!,
        name: body.name!,
        description: body.description ?? "",
        created_at: now,
        updated_at: now,
      };
      envs.push(e);
      return reply(e, 201);
    }
    if ((m = path.match(/^\/v1\/projects\/([^/]+)\/environments\/([^/]+)$/))) {
      const i = envs.findIndex((x) => x.id === m![2]);
      if (i < 0) return problem(404);
      if (method === "DELETE") return (envs.splice(i, 1), reply(null, 204));
      if (method === "PATCH") return (Object.assign(envs[i]!, body.name ? { name: body.name } : {}), reply(envs[i]));
      return reply(envs[i]);
    }
    if ((m = path.match(/^\/v1\/projects\/([^/]+)\/environments\/([^/]+)\/secrets$/)))
      return page(secrets.filter((s) => s.environment_id === m![2]));
    if ((m = path.match(/^\/v1\/projects\/[^/]+\/environments\/[^/]+\/secrets\/([^/]+)$/))) {
      const s = secrets.find((x) => x.id === m![1]);
      return s ? reply(s) : problem(404);
    }
    if ((m = path.match(/^\/v1\/projects\/[^/]+\/environments\/[^/]+\/secrets\/([^/]+)\/versions$/))) {
      const s = secrets.find((x) => x.id === m![1]);
      if (!s) return problem(404);
      return reply({
        items: Array.from({ length: s.version_count }, (_, n) => ({
          secret_id: s.id,
          version: n + 1,
          key_id: "gateway:v1",
          created_at: now,
        })),
      });
    }
    if (path === "/v1/agents") {
      if (method === "GET") return page(agents);
      const a = { id: id(seq++), name: body.name ?? "agent", created_at: now };
      agents.push(a);
      return reply({ agent: a, enrollment_secret: "fixture-enrollment-secret" }, 201);
    }
    if ((m = path.match(/^\/v1\/agents\/([^/]+)$/))) {
      const i = agents.findIndex((x) => x.id === m![1]);
      if (i < 0 || method !== "DELETE") return problem(404);
      return (agents.splice(i, 1), reply(null, 204));
    }
    if ((m = path.match(/^\/v1\/agents\/([^/]+)\/enrollment-secret$/))) {
      return agents.some((x) => x.id === m![1])
        ? reply({ agent: agents.find((x) => x.id === m![1]), enrollment_secret: "fixture-enrollment-secret" }, 201)
        : problem(404);
    }
    if ((m = path.match(/^\/v1\/agents\/([^/]+)\/grants$/))) {
      if (method === "GET") return page(grants.filter((g) => g.agent_id === m![1]));
      const g = { id: id(seq++), agent_id: m[1]!, ...body, created_at: now };
      grants.push(g);
      return reply(g, 201);
    }
    if ((m = path.match(/^\/v1\/agents\/([^/]+)\/grants\/([^/]+)$/))) {
      const i = grants.findIndex((x) => x.id === m![2]);
      if (i < 0) return problem(404);
      return (grants.splice(i, 1), reply(null, 204));
    }
    if (path === "/v1/mcp/tools") return reply({ items: mcpTools });
    if ((m = path.match(/^\/v1\/mcp\/tools\/([^/]+)\/([^/]+)$/))) {
      const t = mcpTools.find((x) => x.layer === m![1] && x.tool === decodeURIComponent(m![2]!));
      if (!t) return problem(404);
      return (Object.assign(t, { enabled: (body as unknown as { enabled: boolean }).enabled }), reply(t));
    }
    if (path === "/v1/bindings")
      return reply({
        items: opts.empty
          ? []
          : [
              {
                kind: "pg",
                name: "appdb",
                host: "db.internal.example.com",
                port: 5432,
                user: "app",
                database: "appdb",
                tls: "verify-full",
              },
              {
                kind: "http",
                name: "https://api.example.com",
                origin: "https://api.example.com",
                header: "Authorization",
              },
              {
                kind: "aws",
                name: "arn:aws:iam::123456789012:role/deploy",
                role: "arn:aws:iam::123456789012:role/deploy",
                region: "eu-west-1",
                vend: true,
                max_duration_secs: 900,
                allowed_actions: ["s3:GetObject", "s3:PutObject"],
              },
              {
                kind: "mcp",
                name: "github",
                origin: "https://api.githubcopilot.com/mcp/",
                header: "Authorization",
                default_decision: "hide",
                tools: [
                  { name: "create_issue", decision: "hold" },
                  { name: "delete_repository", decision: "deny" },
                  { name: "list_issues", decision: "allow" },
                ],
              },
            ],
        next: null,
      });
    if (path === "/v1/notifications")
      return reply({ items: inbox, unread_count: inbox.filter((n) => !n.read_at).length });
    if (path === "/v1/notifications/read-all") return (inbox.forEach((n) => (n.read_at ??= now)), reply(null, 204));
    if ((m = path.match(/^\/v1\/notifications\/([^/]+)\/read$/))) {
      const n = inbox.find((x) => x.id === m![1]);
      return n ? ((n.read_at ??= now), reply(null, 204)) : problem(404);
    }
    if (path === "/v1/notification-rules") {
      if (method === "PUT") rules = (body as unknown as { rules: typeof rules }).rules;
      return reply({ rules });
    }
    if (path === "/v1/notification-channels") {
      if (method === "PUT") chan.email.enabled = (body as unknown as { email: { enabled: boolean } }).email.enabled;
      return reply(chan);
    }
    if ((m = path.match(/^\/v1\/projects\/[^/]+\/environments\/[^/]+\/honey-tokens(?:\/([^/]+?)(\/disable)?)?$/))) {
      if (!m[1]) {
        if (method === "GET") return reply({ items: honey });
        const t = {
          id: id(seq++),
          name: body.name!,
          template: body.template!,
          created_at: now,
          disabled_at: null,
          last_triggered_at: null,
        };
        honey.push(t);
        return reply(t, 201);
      }
      const i = honey.findIndex((x) => x.id === m![1]);
      if (i < 0) return problem(404);
      if (method === "DELETE") return (honey.splice(i, 1), reply(null, 204));
      return ((honey[i]!.disabled_at ??= now), reply(honey[i]));
    }
    if (path === "/v1/mcp/clients") return reply({ items: mcpClients });
    if ((m = path.match(/^\/v1\/mcp\/clients\/([^/]+)\/revoke$/))) {
      const c = mcpClients.find((x) => x.id === decodeURIComponent(m![1]!));
      return c ? (Object.assign(c, { revoked_at: now }), reply(c)) : problem(404);
    }
    if ((m = path.match(/^\/v1\/orgs\/([^/]+)$/)))
      return reply({ id: decodeURIComponent(m[1]!), name: "Fixture org", created_at: now });
    if (path === "/v1/audit/events") return page([]);
    if (path === "/v1/audit/status") return reply({ status: "ok" });
    return problem(404);
  }
  return { handle, requests, projects, envs, secrets };
}

/** Replaces global `fetch` with the fixture backend; returns it so tests can assert on `requests`. */
export function installFixtureFetch(opts?: FixtureOptions) {
  const fx = createFixtures(opts);
  vi.stubGlobal(
    "fetch",
    vi.fn((input: string, init?: RequestInit) => fx.handle(String(input), init)),
  );
  return fx;
}
