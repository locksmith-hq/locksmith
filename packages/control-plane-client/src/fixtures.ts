// Fixture data for the MCP tool switches and clients, shaped like the control-plane responses.
// Test and story data only: ids and names, never a token or a secret value.
import type { paths } from "@locksmith/sdk";
import type { BindingSummary, McpClient, McpToolSetting } from "./index";

type Ok<P extends keyof paths, M extends keyof paths[P]> = paths[P][M] extends {
  responses: { 200: { content: { "application/json": infer B } } };
}
  ? B
  : never;

export const mcpToolSettings: McpToolSetting[] = [
  {
    layer: "hub",
    tool: "list_projects",
    description: "Projects in your org.",
    default_enabled: true,
    enabled: true,
    overridden: false,
  },
  {
    layer: "hub",
    tool: "revoke_grant",
    description: "Revoke an agent grant.",
    default_enabled: false,
    enabled: true,
    overridden: true,
  },
  {
    layer: "agent",
    tool: "relay_http_request",
    description: "Relay an HTTP request.",
    default_enabled: true,
    enabled: true,
    overridden: false,
  },
  {
    layer: "agent",
    tool: "issue_short_lived_credential",
    description: "Issue a short-lived credential.",
    default_enabled: false,
    enabled: false,
    overridden: false,
  },
];

export const mcpClients: McpClient[] = [
  {
    id: "0192f0a0-0000-7000-8000-000000000001",
    layer: "hub",
    client_id: "claude-desktop",
    principal: "user-1",
    client_name: "Claude",
    first_seen_at: "2026-01-01T00:00:00Z",
    last_seen_at: "2026-01-02T00:00:00Z",
  },
  {
    id: "0192f0a0-0000-7000-8000-000000000002",
    layer: "agent",
    client_id: "0192f0a0-0000-7000-8000-0000000000a1",
    principal: "0192f0a0-0000-7000-8000-0000000000a1",
    client_name: "",
    first_seen_at: "2026-01-01T00:00:00Z",
    last_seen_at: "2026-01-01T00:00:00Z",
    revoked_at: "2026-01-03T00:00:00Z",
  },
];

/** One binding of every kind, shaped like `GET /v1/bindings`. Non-secret fields only. */
export const bindingSummaries: BindingSummary[] = [
  { kind: "http", name: "https://api.example.com", origin: "https://api.example.com", header: "Authorization" },
  { kind: "git", name: "github.com/acme", host: "github.com", repo: "acme" },
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
];

// N1 notifications. Payloads carry the allow-listed fields only: never a secret value.
const owner = "0190a000-0000-7000-8000-000000000001";
const payload = (kind: "relay.denied" | "git.denied" | "grant.revoked", object_name: string, occurred_at: string) => ({
  kind,
  actor: { id: "agent-ci", name: "ci-agent" },
  object_name,
  occurred_at,
  link: "/audit",
});

/** An inbox of three with one unread. */
export const notificationInbox: Ok<"/v1/notifications", "get"> = {
  unread_count: 1,
  items: [
    {
      id: "0190a000-0000-7000-8000-0000000000a3",
      kind: "relay.denied",
      payload: payload("relay.denied", "stripe", "2026-11-25T09:00:00Z"),
      created_at: "2026-11-25T09:00:01Z",
      read_at: null,
    },
    {
      id: "0190a000-0000-7000-8000-0000000000a2",
      kind: "git.denied",
      payload: payload("git.denied", "locksmith-hq/app", "2026-11-24T16:00:00Z"),
      created_at: "2026-11-24T16:00:01Z",
      read_at: "2026-11-24T17:00:00Z",
    },
    {
      id: "0190a000-0000-7000-8000-0000000000a1",
      kind: "grant.revoked",
      payload: payload("grant.revoked", "prod-db", "2026-11-23T08:00:00Z"),
      created_at: "2026-11-23T08:00:01Z",
      read_at: "2026-11-23T09:00:00Z",
    },
  ],
};

/** The default rules matrix: every kind to the org owner's inbox. */
export const notificationRules: Ok<"/v1/notification-rules", "get"> = {
  rules: (["relay.denied", "git.denied", "grant.revoked", "agent.deleted"] as const).map((kind) => ({
    kind,
    channel: "inbox" as const,
    audience: "owner" as const,
    audience_user_id: null,
  })),
};

/** Email off with no failed delivery, Slack not configured. */
export const notificationChannels: Ok<"/v1/notification-channels", "get"> = {
  email: { enabled: false, delivery_failed: false },
  slack: { configured: false },
};

/** A 403 problem body, as a non-owner gets on the rules and channels routes. */
export const notificationForbidden = {
  type: "about:blank",
  title: "Forbidden",
  status: 403,
  detail: "only an org owner can change notification rules",
};
