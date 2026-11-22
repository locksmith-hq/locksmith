# Proposal: T8 live sessions, revoke and pause

## Why
An admin can revoke a single grant or an agent's MCP client, but cannot see what agents are connected right now, and has no one-click way to cut access during an incident. The gateway already re-checks grants every cache TTL (10 s) and closes Postgres relay sessions on revocation (d3), so the enforcement exists; the visibility and the big red buttons do not.

## What Changes
- Control plane: an `agent_sessions` view of live sessions (agent, kind http/pg/mcp, target slug, started, last seen), fed by the gateway through an internal endpoint; no values, tokens or hostnames beyond binding slugs.
- API: list sessions, revoke one session (marks its agent token family revoked), revoke all of an org's sessions, and pause or resume every agent of an org (an org-level `agents_paused` flag). Each action writes a ledger event (`session.revoked`, `agents.paused`, `agents.resumed`).
- Gateway: refuses new requests and closes live sessions for a revoked session or a paused org within one grant-cache TTL (10 s), before any decrypt.
- Console (`apps/web`) and desktop: a Sessions page with per-row Revoke, "Revoke all" and a Pause agents toggle with confirm dialogs; states for loading, empty, error and `403`.
- `smith doctor` reports a paused org with a clear message.

## Capabilities
### New Capabilities
- `agent-sessions`: listing live agent sessions, revoking one or all, pausing every agent, and the seconds-level enforcement guarantee.

### Modified Capabilities
<!-- none: gateway grant enforcement keeps its existing requirement; the pause flag is checked inside the same check order and is specified in the new capability -->

## Impact
`services/control-plane` (migration, routes, OpenAPI, audit kinds), `services/gateway` (session reporting, pause and revoke checks), `crates/ls-audit` (event kinds), `packages/control-plane-client`, `apps/web`, `apps/desktop`, `crates/smith-cli` (doctor), `tests/adversarial` (revoked and paused cases).

## Out of scope
Per-agent pause (revoke its grants instead), session recording or replay, notifications on revoke (N1), secret value entry (T7).

## Depends on
`t3-console-mvp` (shell, routed pages, shared client); `d3-db-relay` watcher is reused for Postgres sessions.
