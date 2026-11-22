# Tasks: T8 live sessions, revoke and pause

## 1. Contract [sonnet]
- [x] 1.0 Add a unique `jti` claim to `AgentClaims` at issuance and expose it in the verified claims the gateway reads. Verify: `cargo nextest run -p ls-control-plane agent_token`.
- [x] 1.1 Add the migration (`agent_sessions`, `orgs.agents_paused`), OpenAPI paths for list, revoke-one, revoke-all, pause and resume, and the `session.revoked`, `agents.paused`, `agents.resumed` ledger kinds in `ls-audit`; mock data and TS client methods in `packages/control-plane-client`. Verify: `cargo nextest run -p ls-control-plane openapi` and `npm test --workspace packages/control-plane-client`.

## 2. Control plane [sonnet]
- [x] 2.1 Internal session report endpoint (open, heartbeat, close) and the list endpoint with the 15 s liveness rule; no token or address in any response. Verify: `cargo nextest run -p ls-control-plane sessions` including a canary leak assertion.
- [x] 2.2 Revoke-one, revoke-all, pause and resume, authorized as the existing revoke routes (org member, `403` otherwise), each with its ledger event; extend the grant-set response with `revoked_jtis` and `agents_paused`. Verify: `cargo nextest run -p ls-control-plane sessions_admin` (403 for a non-member, events present, `just audit-verify`).

## 3. Gateway [sonnet]
- [ ] 3.1 Report sessions (http, pg, mcp) with a 5 s heartbeat; check revoked and paused before decrypt; close live sessions (reuse the d3 watcher) and deny on refresh failure. Verify: `cargo nextest run -p ls-gateway sessions_revoke` showing no decrypt call after pause and a close within one TTL.
- [ ] 3.2 Adversarial cases: revoked token replay and request during pause. Verify: `bash tests/adversarial/run.sh gateway` and `just leak-scan`.

## 4. Console, desktop and CLI [sonnet]
- [ ] 4.1 Sessions page in `apps/web` (list, Revoke, Revoke all, Pause toggle, confirms, empty/error/`403` states) with Vitest tests. Verify: `npm test --workspace apps/web`.
- [ ] 4.2 Desktop Sessions view and `smith doctor` paused-org message. Verify: `npm test --workspace apps/desktop` and `cargo nextest run -p smith-cli doctor`.

## 5. Local verification [sonnet]
- [ ] 5.1 End to end: `just up`, open a real session, revoke it and pause the org through the API, assert refusal within 10 s and the ledger events. Verify: new `tests/e2e` test via `cargo nextest run -p ls-e2e sessions_revoke`; `just apps-build`, then `just quick`.
