# Design: T8 live sessions, revoke and pause

## Context
The gateway caches grants (`GrantCache`, TTL = max grant TTL, 10 s) and d3's Postgres watcher closes sessions when a grant disappears. Agent tokens are short-lived. MCP clients can already be revoked per agent (`mcp_clients.revoked_at`). See proposal.md for motivation.

## Goals / Non-Goals
**Goals:** one visibility surface and two org-wide controls that take effect within one cache TTL; reuse the existing refresh path.
**Non-Goals:** instant (sub-second) kill; per-agent pause; recording sessions.

## Decisions and evidence
| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | **Sessions come from the gateway, not the ledger.** The gateway posts `session opened/heartbeat/closed` to an internal `/internal/v1` endpoint (same auth as the other internal routes) into `agent_sessions` (id, org_id, agent_id, `token_jti`, kind, slug, started_at, last_seen_at, revoked_at). `token_jti` is the agent token's `jti` claim, the key between a session and the token the gateway sees. Heartbeat every 5 s; a session whose `last_seen_at` is older than 15 s (three heartbeats) is not live. | Deriving from ledger events: opened-without-closed is ambiguous after a crash. | d3 design decision 8 (gateway already tracks sessions); `crates/ls-audit` ledger schema. |
| 2 | **Revocation rides the grant refresh.** The grant-set response the gateway already fetches gains `revoked_jtis` and `agents_paused`. Check order per request: TLS, token verify, **paused or `jti` revoked (refuse)**, binding exists, grant, address guard, decrypt. Paused and revoked are checked right after token verification so no further work is done. Live sessions are closed by the d3 watcher on the same refresh. | Push over websocket: new infrastructure for no gain inside the 10 s budget. | d3 design decisions 4 and 8; `GrantCache` TTL in `services/gateway/src/grants.rs`. |
| 3 | **Pause is an org flag** (`orgs.agents_paused boolean`), changed only through the authenticated org API with a ledger event; one toggle covers all agents, including new ones. | Per-agent pause state: more to manage during an incident. | Proposal (incident use case). |
| 4 | **Fail closed.** If the refresh fails past the TTL the gateway denies (current cache behaviour; a test pins it). | Fail open on refresh errors. | AGENTS.md security rules. |
| 5 | **Authorization.** No org-admin role exists today (the human-auth spec defines none), so these routes use the same authorization as the existing revoke-grant and revoke-MCP-client routes: a signed-in human member of the org; others get `403`. A distinct admin role is out of scope and would be its own change. | Inventing a role here: unspecified storage and checks. | `openspec/specs/human-auth/spec.md`; `services/control-plane/src/api/mcp.rs` revoke route. |
| 6 | **Agent tokens gain a `jti`.** `AgentClaims` (`services/control-plane/src/agent_token.rs`) has only sub/org/aud/iat/exp, so issuance adds a unique `jti` (UUID) and the gateway reads it; revoke-one is per `jti`, not per token family. | Keying on agent id: would revoke every session of the agent. | `AgentClaims` today; RFC 7519 section 4.1.7. |

## OSS used
None new. Everything uses crates and packages already in the repo (axum, sqlx, tokio, serde, the existing web and desktop stacks), so there is nothing to licence-check or AGPL-check. Nothing is built in-house that a maintained package already does: the session list is a plain table and the revoke path reuses the existing grant refresh.

## How an agent debugs this
`just up`, `just api`, `just gateway`. Tables: `agent_sessions`, `orgs.agents_paused` (Postgres MCP). Ledger: `GET /v1/audit/events` for `session.revoked`, `agents.paused`, `agents.resumed`, then `just audit-verify`. `just leak-scan` for canaries. Gateway and control-plane spans and logs through the Grafana MCP (Tempo and Loki). `smith doctor` shows the paused-org message.

## Risks / Trade-offs
- Up to 10 s after revoke, in-flight requests may complete → documented in the spec and UI copy ("takes effect within 10 seconds").
- Heartbeat load grows with sessions → one small upsert per 5 s per session; batched per gateway tick.
- Wrong pause is an outage for agents → confirm dialog naming the org, ledger event, one-click resume.

## Migration Plan
Additive migration (`agent_sessions`, `orgs.agents_paused default false`); gateway and control plane deploy in either order because the new fields default to "not revoked, not paused". Rollback: drop the routes; the columns are harmless.
