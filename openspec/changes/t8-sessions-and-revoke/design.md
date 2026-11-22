# Design: T8 live sessions, revoke and pause

## Context
The gateway caches grants (`GrantCache`, TTL = max grant TTL, 10 s) and d3's Postgres watcher closes sessions when a grant disappears. Agent tokens are short-lived. MCP clients can already be revoked per agent (`mcp_clients.revoked_at`). See proposal.md for motivation.

## Goals / Non-Goals
**Goals:** one visibility surface and two org-wide controls that take effect within one cache TTL; reuse the existing refresh path.
**Non-Goals:** instant (sub-second) kill; per-agent pause; recording sessions.

## Decisions
1. **Sessions come from the gateway, not the ledger.** The gateway posts `session opened/heartbeat/closed` to an internal endpoint (same auth as the other `/internal/v1` routes) into `agent_sessions` (id, org_id, agent_id, kind, slug, started_at, last_seen_at, revoked_at). Alternative, deriving from ledger events: rejected, since opened-without-closed is ambiguous after a crash. Heartbeat every 5 s; rows older than 15 s are not live.
2. **Revocation rides the grant refresh.** The grant-set response the gateway already fetches gains `revoked_session_ids` and `agents_paused`; the gateway checks both before decrypt (after binding, before the address guard order stays as decision 4 of d3: paused/revoked is checked first so no work is done). Alternative, push over websocket: rejected as new infrastructure for no gain inside the 10 s budget.
3. **Pause is an org flag** (`orgs.agents_paused boolean`), changed only through the admin API with a ledger event, not a per-agent state, so one toggle covers all agents including new ones.
4. **Fail closed.** If the refresh fails past the TTL the gateway denies (already the cache behaviour; a test pins it).
5. **Roles.** Reuse the existing admin check from the human-auth capability; the console hides the buttons for non-admins but the API enforces.
6. **No new OSS.** Everything uses crates and packages already in the repo; OSS used: none new.

## Risks / Trade-offs
- Up to 10 s after revoke, in-flight requests may complete → documented in the spec and UI copy ("takes effect within 10 seconds").
- Heartbeat load grows with sessions → one small upsert per 5 s per session; batched per gateway tick.
- Wrong pause is an outage for agents → confirm dialog naming the org, ledger event, one-click resume.

## Migration Plan
Additive migration (`agent_sessions`, `orgs.agents_paused default false`); gateway and control plane deploy in either order because the new fields default to "not revoked, not paused". Rollback: drop the routes; the columns are harmless.
