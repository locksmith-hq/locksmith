// Fixture data for the MCP tool switches and clients, shaped like the control-plane responses.
// Test and story data only: ids and names, never a token or a secret value.
import type { AgentSession, AgentsPauseState, McpClient, McpToolSetting } from "./index";

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

// Live agent sessions: ids, a kind, a binding slug and times only (never a token, its jti or an address).
export const agentSessions: AgentSession[] = [
  {
    id: "0192f0b0-0000-7000-8000-000000000001",
    agent_id: "0192f0a0-0000-7000-8000-0000000000a1",
    kind: "http",
    slug: "github-api",
    started_at: "2026-01-01T00:00:00Z",
    last_seen_at: "2026-01-01T00:05:00Z",
    live: true,
  },
  {
    id: "0192f0b0-0000-7000-8000-000000000002",
    agent_id: "0192f0a0-0000-7000-8000-0000000000a2",
    kind: "pg",
    slug: "orders-db",
    started_at: "2026-01-01T00:00:00Z",
    last_seen_at: "2026-01-01T00:00:30Z",
    live: false,
  },
  {
    id: "0192f0b0-0000-7000-8000-000000000003",
    agent_id: "0192f0a0-0000-7000-8000-0000000000a1",
    kind: "mcp",
    slug: "",
    started_at: "2026-01-01T00:01:00Z",
    last_seen_at: "2026-01-01T00:05:00Z",
    live: true,
  },
];

export const agentsPaused: AgentsPauseState = { agents_paused: true };
export const agentsResumed: AgentsPauseState = { agents_paused: false };
