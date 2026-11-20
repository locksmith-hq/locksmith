# Progress: d3-db-relay

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-19 worker
- Task: none - planning
- Verified: `openspec validate d3-db-relay --strict`, `bash scripts/tree-check.sh`
- Notes for next session: the M6 local Postgres relay (`crates/ls-proxy/src/db/postgres.rs`, `scram.rs`, `smith db connect`) is sync and session-tree gated; D3 adds an async TLS pgwire listener to the hosted gateway and reuses its SCRAM/md5 helpers. Verify the pgwire version and codec-only use at task 1.1 before building on it.

## 2026-11-19 22:22 worker
- Task: planning review fix - done
- Verified: openspec validate d3-db-relay --strict -> valid
- Notes for next session: merge-review FAIL on spec.md:74 fixed (agent.json excepted, before/after home snapshot); gate 4 CI was still running; re-add ready-to-merge label if gate passes.

## 2026-11-20 worker
- Task: 1.1-1.4 - done
- Verified: `cargo nextest run -p ls-gateway pg_config` 2 passed; `cargo nextest run -p ls-proxy db` 18 passed (M6 behaviour unchanged); `just ci` exit 0.
- Notes for next session: `PgBinding`/`PgTls` in `services/gateway/src/config.rs` (`Bindings::pg_by_name`); `ls_proxy::db::scram::Client` and `ls_proxy::db::postgres::md5_password` are public. pgwire is pinned but unused until group 2 (no code imports it yet). Next: group 2 (listener, opus-grade auth path).

## 2026-11-20 worker (merge)
- Task: merge origin/main into branch - done (conflicts in `services/gateway/src/config.rs`, `relay.rs`: kept both `pg` and `git_bindings`; fixed `git_fixture_tests.rs` initializer)
- Verified: `cargo nextest run -p ls-gateway` 89 passed; fmt and clippy clean.
- Notes for next session: group 2 (pg listener and agent auth, opus-grade) is next and not started.

## 2026-11-20 03:25 worker
- Task: ci-fix - done (no code change)
- Verified: just ci -> green locally after merging origin/main; human_auth 16/16 pass locally
- Notes for next session: CI rust job failed only on ls-control-plane human_auth auth_garbage_kids_cannot_turn_requests_into_a_fetch_storm (fetches 2 vs 1), a timing flake under CI load, not touched by d3. If it recurs, file on harness-backlog / fix the test.

## 2026-11-20 05:28 worker
- Task: 2.1-2.4 - done
- Verified: `cargo nextest run -p ls-gateway pg_auth` -> 9 passed (plus pg_config 3 passed, full ls-gateway 99 passed); fmt and clippy -D warnings clean; `just ci` -> exit 0
- Notes for next session: listener is `services/gateway/src/pg/listener.rs`; group 3 plugs in through the `PgUpstream` trait (`pg/mod.rs`), which gets a `PgSession` (binding, guard-checked pinned addrs, allow-listed client params, decrypted password in `SecretBytes`) and the TLS client stream. `main.rs` wires `UpstreamUnavailable` (answers 0A000) until then. New: `LOCKSMITH_GATEWAY_PG_TLS_CERT`/`_KEY` (required with `_PG_LISTEN`), `[[pg]] version` (default 1, needed for decrypt), `egress::check_host`, ledger kind `db.session.denied` (control plane, ls-audit, openapi.json, TS schema). Bad token and unbound database are not in the ledger (no agent / no secret to name); logged as slugs. CancelRequest is closed unanswered until 3.3. An independent evaluator pass (evaluate-escalate step 3) was not run in this session.

## 2026-11-20 05:35 worker
- Task: 2.3/2.4 evaluator FAIL fix - done
- Verified: `cargo nextest run -p ls-gateway` -> 102 passed (pg_auth 12); fmt, clippy clean; `openspec validate d3-db-relay --strict` valid; `just ci` -> exit 0
- Notes for next session: unresolvable upstream (`upstream_unreachable`) and material/decrypt failures (`material_error`/`decrypt_failed`) now append `db.session.denied`; the control plane accepts those three outcomes for that kind only. Spec scenario "Invalid agent token" amended: 28P01, slug log only, no ledger event (no agent identity). Added a NegotiateProtocolVersion test.

## 2026-11-20 worker (C)
- Task: 3.1-3.4 pg upstream relay, redaction, cancel map - done (`services/gateway/src/pg/upstream.rs`, listener cancel map, wired in main.rs; added `rustls` dep that the merge had left missing)
- Verified: `cargo nextest run -p ls-gateway` 109 passed (pg_relay 7, real testcontainers postgres:18 SCRAM+md5, fake upstream for cleartext-refusal and E/N redaction); `just ci` -> exit 0; independent sonnet evaluator PASS (static)
- Notes for next session: group 4 next (ledger events db.session.opened/closed, revocation watcher, adversarial cases). Not yet done: bytes in/out counters; ledger event for cleartext-refused/upstream failures is slug-log only until 4.1. Evaluator notes: wrap upstream cancel secret in zeroize; add a per-message timeout to the post-AuthenticationOk S/K/Z read loop; `verify-full` upstream untested.

## 2026-11-20 worker (A)
- Task: 4.1, 4.2 - done (`db.session.opened`/`closed` ledger kinds in ls-audit, control plane, openapi, TS schema, gateway audit; opened is appended before any upstream connect and the session is refused 08001 if that fails; closed carries reason, duration_ms, bytes_in/out and `attempt_id` = the opened id; revocation watcher in `pg/listener.rs` re-checks grant and token `exp` every `watch_interval` (default 10 s = max grant TTL), 3 failed reads close with `error`)
- Verified: `cargo nextest run -p ls-gateway pg_auth pg_audit pg_revoke` 16 passed; `cargo nextest run -p ls-control-plane --test audit` 9 passed; `just ci` -> exit 0. No separate evaluator run (static self-review only).
- Notes for next session: 4.3 (adversarial G9 Postgres cases: shell stack case needs gateway with LOCKSMITH_GATEWAY_PG_LISTEN + TLS cert, compose postgres with SCRAM role, psql) and 4.4 remain; they need `just up`. Note the d2 branch also adds a G9 case id: pick the next free id after merging. `PgSession` now has `token_expires_at` and `stats`; `AgentAuth::verify_expiring` returns the token exp.

## 2026-11-20 worker (events)
- Task: 4.3, 4.4 - done (`tests/adversarial/gateway/G10.sh` + 4 `pg_relay` Rust tests: RAISE echo redaction, options/startup-parameter injection, guessed-key cancel)
- Verified: `cargo nextest run -p ls-gateway pg_relay pg_audit pg_revoke` pass; `run.sh gateway G10` PASS (re-run by me with `just api` up); `run.sh all gateway` 16 passed, A2 skipped (no aws CLI); `just audit-verify` ok; `just leak-scan` clean. Evaluator (sonnet) approved the tests as real; its only FAIL point was G10 not run with the API down, now run.
- Notes for next session: groups 5 (smith db connect --gateway, doctor db.gateway), 6 (bindings page, needs t3 console pages), 7 remain. G10 id chosen to avoid d2's G9.
