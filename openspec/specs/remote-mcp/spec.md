# remote-mcp Specification

## Purpose

Remote MCP servers for the hub (a person's assistant) and the gateway (an enrolled agent), with a server-enforced switch per tool and the rule that no tool returns a stored secret value.

## Requirements

### Requirement: No tool returns a stored secret value
No Hub MCP or Agent MCP tool input, output, resource or error SHALL carry a stored secret value or key material. The only credential a tool may return is a short-lived, scoped one from `issue_short_lived_credential`.

#### Scenario: Schema carries no value field
- **WHEN** the tool registry of either server is serialized
- **THEN** no tool input or output schema has a field that can hold a secret value, and a test fails if one is added

#### Scenario: Relay returns the upstream response
- **WHEN** an agent calls the relay tool for a key it holds a grant for
- **THEN** the result is the upstream response with any injected credential redacted, never the key

### Requirement: Hub MCP signs in as a person
The Hub MCP SHALL accept only an OIDC access token for the person (OAuth 2.1 with PKCE), verified through JWKS, and SHALL authorize every call as that person in their org.

#### Scenario: Unauthenticated request
- **WHEN** a request reaches `/mcp` on the control plane without a valid token
- **THEN** it is answered `401` with a `WWW-Authenticate` challenge and no tool runs

#### Scenario: Person's permissions apply
- **WHEN** a person who cannot read a project's activity calls the activity tool
- **THEN** the call is denied exactly as the same console action would be

### Requirement: Agent MCP signs in as an agent
The Agent MCP SHALL accept only a valid agent token with audience `gateway` and SHALL only use grants of that agent.

#### Scenario: Expired agent token
- **WHEN** an agent calls `/mcp` on the gateway with an expired or wrong-audience token
- **THEN** the call is answered `401` and nothing is relayed

### Requirement: One switch per tool, enforced on the server
Each tool SHALL have an enabled flag per org and layer. A tool that is off SHALL NOT appear in the tool list and SHALL NOT be callable. Read tools default on; tools that change state, and `issue_short_lived_credential`, default off.

#### Scenario: Off tool is hidden and refused
- **WHEN** a tool is off and a client lists tools, then calls that tool by name
- **THEN** it is absent from the list and the call returns a tool-disabled error without side effects

#### Scenario: Switching takes effect immediately
- **WHEN** an admin turns a tool on
- **THEN** the next `tools/list` from any connected client includes it

### Requirement: Short-lived credential is the only exception
`issue_short_lived_credential` SHALL create a credential valid for minutes, scoped to one job, and SHALL record an audit event for every issue.

#### Scenario: Issue is audited and expires
- **WHEN** the tool is on and an agent calls it
- **THEN** the credential expires within the configured minutes and one audit event names the agent, scope and expiry but not the credential

### Requirement: MCP calls are audited
Every tool call SHALL append one event to the audit ledger with the layer, tool name, principal and outcome, and no tool arguments that could carry a value.

#### Scenario: Denied call is recorded
- **WHEN** a call is denied
- **THEN** the ledger has an event with outcome `denied` for that call

### Requirement: Clients can be listed and revoked
The console SHALL list connected MCP clients and let an admin revoke one. Revoke SHALL bind to the OAuth `client_id` (Hub) or the agent (Agent MCP), not to a transport session, so that a revoked client cannot return by starting a new session.

#### Scenario: Revoke a client
- **WHEN** an admin revokes a client and that client calls a tool
- **THEN** the call is refused with `401`

#### Scenario: Revoked client re-initializes
- **WHEN** a revoked client sends a fresh `initialize` with the same token
- **THEN** it is refused with `401` and no new session or `mcp_clients` row is created

#### Scenario: Refreshed token after revoke
- **WHEN** a revoked Hub client refreshes its token after the revoke and calls a tool
- **THEN** the refresh is refused at the issuer, or the new token's `auth_time` is before `revoked_at` and the call is refused with `401`

#### Scenario: Person signs in again after revoke
- **WHEN** the person signs in again and grants consent to the client after the revoke
- **THEN** the new token's `auth_time` is after `revoked_at` and calls are accepted

### Requirement: MCP helpers have a single implementation shared by hub and gateway
The cache bound on revocation-relevant reads, the `mcp_clients` upsert and `mcp_tool_settings` reads, the tool definition to MCP tool conversion, the tool-error status reader, the audit append call and the bearer challenge SHALL each have one implementation, used by every Hub MCP and Agent MCP code path that needs it. Sharing SHALL NOT change any observable behaviour: revoke checks, fail-closed paths, audit events and reason codes, response bodies and headers stay as they were.

#### Scenario: Cache bound is one value
- **WHEN** a gateway cache for grants, tool switches or revoked clients is built with a TTL above 10 s
- **THEN** it serves an entry for at most 10 s, an error read is never cached, and a zero TTL disables caching, as before

#### Scenario: Revoke still takes effect within the bound
- **WHEN** a client is revoked while the gateway holds a cached revoked set
- **THEN** the next request after the cache expires is refused, and an unreadable registry still counts as revoked (fail closed)

#### Scenario: Client upsert is the same for both layers
- **WHEN** a hub client or an agent client is recorded twice with different names
- **THEN** one row exists with the latest name capped at 200 characters, `last_seen_at` refreshed and `revoked_at` untouched

#### Scenario: Audit outcome is unchanged
- **WHEN** a tool call finishes with `ok`, a `401` or `403` tool error, another tool error, or a protocol error, on the hub or on the gateway
- **THEN** the `mcp.call` outcome and reason are the same as before the change on each side

#### Scenario: Challenge header is byte-identical
- **WHEN** a request reaches `/mcp` on the hub or the gateway without a token, or with an invalid one
- **THEN** it is answered `401` with the same `WWW-Authenticate` value as before

#### Scenario: Existing tests pass unchanged
- **WHEN** the gateway MCP tests (`services/gateway/src/relay/tests/mcp*.rs`) and the control-plane MCP tests (`tests/mcp.rs`, `tests/mcp_auth.rs`, `tests/mcp_tools.rs`) run after the change
- **THEN** they pass with no assertion edited
