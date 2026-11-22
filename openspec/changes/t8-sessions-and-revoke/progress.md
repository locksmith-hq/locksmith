## 2026-11-22 worker
- Task: planning review fixes - done
- Verified: openspec validate t8-sessions-and-revoke -> valid; just quick -> clean
- Notes for next session: spec/design/tasks now agree on 15 s liveness and `token_jti` key.

## 2026-11-22 worker
- Task: planning review fixes - done
- Verified: openspec validate t8-sessions-and-revoke -> valid; just quick -> clean
- Notes for next session: added jti task 1.0; no admin role exists, so authorization narrowed to org member like existing revoke routes. All 6 threads resolved; review reruns on push.

## 2026-11-22 worker
- Task: 1.0 jti claim on AgentClaims - done
- Verified: cargo nextest run -p ls-control-plane agent_token workload_exchange -> 10 passed; ls-gateway builds; just quick (below)
- Notes for next session: branched from main (not t3, merge conflicted in control-plane-client index.ts); 1.1 touches that client, so rebase-free merge main first.

## 2026-11-22 worker
- Task: 1.1 sessions contract (migration 0014, 5 OpenAPI paths as documented 501 stubs, ledger kinds, TS client + fixtures) - done
- Verified: cargo nextest run -p ls-control-plane openapi -> 3 passed; cargo test -p ls-control-plane --test tenancy (real Postgres) -> 9 passed; npm test --workspace packages/control-plane-client -> 14 passed; just quick clean. Evaluator PASS after one fix (0014 was not registered in migrate.rs).
- Notes for next session: handlers in services/control-plane/src/api/sessions.rs return 501 until 2.1/2.2; `revoked_jtis`/`agents_paused` still to add to the grant-set response (2.2). Postgres tests run locally with `cargo test -p ls-control-plane --test <name>` (nextest default filter excludes them).

## 2026-11-22 worker
- Task: 2.1 internal session report (open, heartbeat, close) and GET /v1/sessions with the 15 s liveness rule - done
- Verified: cargo nextest run -p ls-control-plane sessions -> 9 passed (5 Postgres-backed, canary jti leak assertions, org isolation); openapi tests passed; just quick clean. Evaluator PASS.
- Notes for next session: close sets last_seen_at 1 min in the past (app role can only update last_seen_at, revoked_at). List omits agent name (spec says id and name): add with the web task 4.1 or 2.2. A heartbeat after close revives a session; gateway must stop heartbeating on close (3.1). 2.2 next.

## 2026-11-22 worker
- Task: 2.2 revoke-one, revoke-all, pause, resume + grant-set `revoked_jtis`/`agents_paused` - done
- Verified: cargo nextest run -p ls-control-plane sessions -> 15 passed (incl. sessions_admin, canary, org isolation, idempotency); openapi 3 passed; control-plane-client 14 passed; ls-gateway builds; just quick clean. Evaluator PASS. `just audit-verify` not run (needs `just up`).
- Notes for next session: 403 comes only from OrgBinding's unverified-email check (same as existing revoke routes); actor is DEV_AUTH_ACTOR. revoke_all revokes every unrevoked row, so its count can include stale rows (description says "live"): tidy in 4.1 or reword. revoked_jtis window 30 min (token TTL 15 min). Next: 3.1 gateway enforcement.
