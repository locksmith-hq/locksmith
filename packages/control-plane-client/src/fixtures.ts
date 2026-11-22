// Fixture data for the MCP tool switches and clients, shaped like the control-plane responses.
// Test and story data only: ids and names, never a token or a secret value.
import type { Invite, Member, MemberList, MyOrg, McpClient, McpToolSetting } from "./index";

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

// T6: two orgs (the caller owns the personal one and is a plain member of the other), members of
// two roles and one pending invite. The invite token is a placeholder, not a working link.
export const myOrgs: MyOrg[] = [
  { id: "0192f0a0-0000-7000-8000-0000000000b1", name: "Personal", region: "eu", personal: true, role: "owner", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
  { id: "0192f0a0-0000-7000-8000-0000000000b2", name: "Acme", region: "eu", personal: false, role: "member", created_at: "2026-01-02T00:00:00Z", updated_at: "2026-01-02T00:00:00Z" },
];

export const members: Member[] = [
  { user_id: "0192f0a0-0000-7000-8000-0000000000c1", email: "owner@example.test", role: "owner", created_at: "2026-01-01T00:00:00Z" },
  { user_id: "0192f0a0-0000-7000-8000-0000000000c2", email: "dev@example.test", role: "member", created_at: "2026-01-03T00:00:00Z" },
];

export const memberList: MemberList = { caller_role: "owner", items: members };

export const invites: Invite[] = [
  {
    id: "0192f0a0-0000-7000-8000-0000000000d1",
    email: "new@example.test",
    role: "admin",
    invited_by: "0192f0a0-0000-7000-8000-0000000000c1",
    expires_at: "2026-01-10T00:00:00Z",
  },
];
