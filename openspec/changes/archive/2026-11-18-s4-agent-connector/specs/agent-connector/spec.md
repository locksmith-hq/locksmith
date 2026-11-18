# Spec Delta

## Purpose
An agent has an identity and a short-lived token, sees which secrets it may use, and calls upstreams through the gateway without ever receiving a secret value.

## ADDED Requirements

### Requirement: Agents have org-scoped identities and grants
The control plane SHALL let an authorized caller register an agent and grant it relay use of a secret binding, optionally with an expiry. Agents and grants SHALL be isolated per org by row-level security.

#### Scenario: Cross-org isolation
- **WHEN** org B lists agents or grants
- **THEN** none of org A's rows are visible

### Requirement: Short-lived agent tokens
The control plane SHALL mint a signed token (default 15 minutes, audience `gateway`) for a registered agent. The token SHALL carry only agent id, org id and expiry, and the gateway SHALL verify it through the published JWKS.

#### Scenario: Expired or forged token
- **WHEN** a relay call uses an expired, wrongly signed or wrong-audience token
- **THEN** the gateway returns 401 and makes no KMS call

### Requirement: Gateway enforces grants before unwrap
The gateway SHALL relay a secret only when the token's agent holds an unexpired grant for it. A missing or expired grant SHALL be refused before any key unwrap, and the audit row SHALL record the agent id.

#### Scenario: No grant
- **WHEN** a valid agent without a grant relays a request for a secret
- **THEN** the gateway returns 403, makes no decrypt call and audits the denial

### Requirement: Agent-visible surfaces never carry values
`smith grants`, `GET /v1/grants`, the MCP tool `list_grants` and every error path SHALL return secret names, allowed hosts and modes only. `relay_request` SHALL return the redacted upstream response.

#### Scenario: Transcript leak scan
- **WHEN** a headless Claude Code session uses the connector to call the mock upstream
- **THEN** `just leak-scan` over the transcript, logs, traces and database finds no canary
