# Proposal: S4 agent connector

## Why
S3 proves a secret can be used without the caller holding it, but the relay is guarded by one static token and nothing lets a coding agent reach it. S4 gives an agent an identity, a short-lived token, and the tools (`smith`, `locksmith-mcp`) to list what it may use and route calls through the gateway. This is the first demo: Claude Code calls a real API with no key on the laptop.

## What Changes
- **Agent identity** in the control plane: `agents` and `agent_grants` tables (org-scoped, RLS), API to register an agent and grant it a secret binding. A grant names the secret, usage mode `relay` only, and an optional expiry.
- **Short-lived agent token**: the control plane mints a signed JWT (EdDSA, 15 min default, audience `gateway`) for an agent; the gateway verifies it through the control-plane JWKS. It replaces the S3 static caller token. The token carries agent id and org id, never a secret.
- **Gateway** checks the token and the grant before any key unwrap, and records the agent id in `gateway_audit`.
- **`GET /v1/grants`** on the gateway: lists the caller's grants as names, allowed hosts and modes, never values.
- **`smith` and `locksmith-mcp`**: `smith login --agent`, `smith grants`, `smith relay`; MCP tools `list_grants` and `relay_request` that call the gateway with the agent token. Existing local-vault paths stay untouched.
- Minimal console and desktop surface: agents and grants list page, so `just apps-build` stays green and the grant is visible to a human.
- Live demo: a headless `claude -p` run calls a real API through the connector.

## Capabilities
### New Capabilities
- `agent-connector`: agent identity, short-lived token, grants, and the CLI/MCP surface that routes calls through the gateway.

### Modified Capabilities
- `gateway-http-relay` (from S3): caller auth changes from a static token to the agent token plus grant check.

## Out of scope
Human sign-in (T1), policy engine and ABAC (T2), human approval of access requests (T4), delegate and inject modes (D1-D3), hash-chained audit (S5), adversarial suite (S6), workload identity (D4).

## Depends on
`s3-gateway-http`.

## Impact
`services/control-plane`, `services/gateway`, `crates/smith-cli`, `crates/locksmith-mcp`, `apps/web`, `tests/e2e`, `openapi.json`.
