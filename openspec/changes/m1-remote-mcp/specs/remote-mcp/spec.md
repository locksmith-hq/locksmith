# Spec Delta

## Purpose
Remote MCP servers for the hub (a person's assistant) and the gateway (an enrolled agent), with a server-enforced switch per tool and the rule that no tool returns a stored secret value.

## ADDED Requirements

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
