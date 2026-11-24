// OAuth fixtures shaped like the gateway responses; the github, connection, grant and error
// entries equal `crates/ls-oauth/fixtures/` (checked by oauth.test.ts). Ids and names only.
import type {
  ConnectionGrant,
  ConnectionGrantListing,
  ConnectionSummary,
  ConnectRequest,
  ConnectResponse,
  OAuthErrorBody,
  ProviderSummary,
} from "./oauth";

export const oauthProviders: ProviderSummary[] = [
  { provider: "github", name: "GitHub", scopes: ["contents:read"], revoke_supported: true },
  { provider: "google", name: "Google", scopes: ["openid", "email"], revoke_supported: true },
  { provider: "slack", name: "Slack", scopes: ["chat:write"], revoke_supported: true },
  { provider: "linear", name: "Linear", scopes: ["read"], revoke_supported: true },
  { provider: "atlassian", name: "Atlassian", scopes: ["read:me", "offline_access"], revoke_supported: false },
];

export const oauthConnection: ConnectionSummary = {
  id: "0194a3c0-1111-7000-8000-000000000001",
  provider: "github",
  account_login: "alice-dev",
  account_id: "4242",
  scopes: ["contents:read"],
  status: "connected",
  connected_at: "2026-11-24T10:00:00Z",
  expires_at: "2026-11-24T18:00:00Z",
  last_refreshed_at: "2026-11-24T10:00:00Z",
};

export const oauthConnectionRefreshFailed: ConnectionSummary = {
  id: "0194a3c0-1111-7000-8000-000000000002",
  provider: "slack",
  account_login: "alice",
  account_id: "U123",
  scopes: ["chat:write"],
  status: "refresh_failed",
  connected_at: "2026-11-20T09:00:00Z",
  last_error_code: "invalid_grant",
};

export const oauthConnections: ConnectionSummary[] = [oauthConnection, oauthConnectionRefreshFailed];

export const oauthConnectionGrant: ConnectionGrant = {
  id: "0194a3c0-2222-7000-8000-000000000001",
  agent_id: "0194a3c0-3333-7000-8000-000000000001",
  connection_id: "0194a3c0-1111-7000-8000-000000000001",
  expires_at: "2026-12-01T00:00:00Z",
  created_by: "0194a3c0-4444-7000-8000-000000000001",
  created_at: "2026-11-24T10:05:00Z",
};

export const oauthGrantListing: ConnectionGrantListing = {
  connection_id: "0194a3c0-1111-7000-8000-000000000001",
  provider: "github",
  person_name: "Alice",
  expires_at: "2026-12-01T00:00:00Z",
};

export const oauthConnectRequest: ConnectRequest = {
  provider: "github",
  return_to: "http://localhost:5173/settings/connections",
};

export const oauthConnectResponse: ConnectResponse = {
  flow_id: "0194a3c0-5555-7000-8000-000000000001",
  authorize_url:
    "https://github.com/login/oauth/authorize?client_id=x&state=y&code_challenge=z&code_challenge_method=S256",
};

export const oauthWrongPerson: OAuthErrorBody = { error: "wrong_person" };
export const oauthHostNotAllowed: OAuthErrorBody = { error: "host_not_allowed" };
