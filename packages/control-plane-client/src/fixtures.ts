// Fixture data for the MCP tool switches and clients, shaped like the control-plane responses.
// Test and story data only: ids and names, never a token or a secret value.
import type { BindingSummary, McpClient, McpToolSetting } from "./index";

export const mcpToolSettings: McpToolSetting[] = [
  { layer: "hub", tool: "list_projects", description: "Projects in your org.", default_enabled: true, enabled: true, overridden: false },
  { layer: "hub", tool: "revoke_grant", description: "Revoke an agent grant.", default_enabled: false, enabled: true, overridden: true },
  { layer: "agent", tool: "relay_http_request", description: "Relay an HTTP request.", default_enabled: true, enabled: true, overridden: false },
  { layer: "agent", tool: "issue_short_lived_credential", description: "Issue a short-lived credential.", default_enabled: false, enabled: false, overridden: false },
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
  { kind: "pg", name: "appdb", host: "db.internal.example.com", port: 5432, user: "app", database: "appdb", tls: "verify-full" },
  { kind: "aws", name: "arn:aws:iam::123456789012:role/deploy", role: "arn:aws:iam::123456789012:role/deploy", region: "eu-west-1", vend: true, max_duration_secs: 900, allowed_actions: ["s3:GetObject", "s3:PutObject"] },
];
