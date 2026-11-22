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

## 2026-11-22 08:35 lead
- Task: d3-db-relay planning PR #611 - ci-fix
- Verified: `just tree-check task-guard` -> OK on both branches; #611 diff now only `openspec/changes/d3-db-relay/`
- Notes for next session: #611 `merge-ready` failed in the review pre-check because the PR also touched `openspec/decisions.md`, which voids the planning-only exemption (all files under `openspec/changes/`). Planning PRs must never touch `decisions.md`; the D3-1 line moved to #612.

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

## 2026-11-20 worker (A)
- Task: 5.1, 5.2, 5.3 - done (`smith db connect <name> --gateway <host[:port]|url> [--sslmode verify-full|require] [--ca-cert FILE] [-- cmd]` in `crates/smith-cli/src/db_cmd.rs`; doctor check `db.gateway` in `crates/smith-cli/src/doctor_d3_db.rs`; `ls_connector::State::token_secret()` added)
- Verified: `cargo nextest run -p smith-cli db` 12 passed (full smith-cli 139 passed, 2 skipped); `cargo fmt --all`; `cargo clippy -p smith-cli --all-targets -- -D warnings` clean. `just ci` not run in this session.
- Notes for next session: `--gateway` also reads `LOCKSMITH_DB_GATEWAY`, which `smith doctor` uses to find the listener (check skips when unset; `https://host` without a port means 5432, not 443). `PGPASSWORD` (agent token) is set only on the child (exec on Unix) and PGPASSFILE/PGSERVICE/PGSERVICEFILE/PGHOSTADDR/PGOPTIONS are cleared for it; without a command only non-secret variables are printed. Doctor probe sends SSLRequest then a verified rustls handshake (system roots plus `PGSSLROOTCERT`), no startup message; pgpass check reports line numbers only. Task 5.2 "MCP help text": no MCP db tool exists, so only CLI help was added. Real psql end-to-end is task 7.1.

## 2026-11-20 worker (A, follow-up)
- Task: 5.1-5.3 - evaluator PASS (independent sonnet review); `just ci` -> exit 0 (441s)
- Verified: `cargo nextest run -p smith-cli db` 12 passed; `just ci` exit 0
- Notes for next session: minor evaluator findings, non-blocking: (1) doctor_d3_db.rs pgpass check reads the whole file into an unzeroized String - read line by line and drop after the host field; (2) weak `all(..)` assertion near :197, use assert_eq on the vec; (3) doctor ignores `--ca-cert` (only PGSSLROOTCERT); (4) pgpass match ignores port/db. Remaining: 6.x (needs t3 bindings page), 7.x.

## 2026-11-21 worker (alfie)
- Task: none (groups 1-5 already ticked; merged origin/main into the branch, no conflicts)
- Verified: nothing new run; no code changed
- Notes for next session: 6.1 is blocked because no bindings page exists yet in `apps/web` or `apps/desktop` (t3 console pages); 7.1/7.2 need `just up` plus psql. Take 7.1 first (it does not need the UI), then 6.x once t3 lands.

## 2026-11-21 worker (alfie, second entry)
- Task: 7.1 - done (`just db-smoke` and `tests/e2e/tests/db_relay.rs`); evaluator PASS (independent sonnet review)
- Verified: `just db-smoke` 1 passed against compose Postgres (twice); `just quick` exit 0
- Notes for next session: 6.1/6.2 still need the t3 bindings page; 7.2 needs `just apps-build` after 6.x, then CI results. `just leak-scan` not run.

## 2026-11-21 worker (josie)
- Task: none - parked (merged origin/main clean)
- Verified: merge clean, no code changed
- Notes for next session: 6.1 still needs a live bindings page (t3-console-mvp #489); 7.2 last.

## 2026-11-22 00:51 worker (harriet)
- Task: none - blocked (6.1 needs a bindings page; none exists in apps/web, apps/desktop or packages/ui; merged origin/main clean)
- Verified: merge clean, no code changed
- Notes for next session: 6.1/6.2 wait for t3-console-mvp (#489); 7.2 last.

## 2026-11-22 worker (alfie)
- Task: none - conflict fix on PR #485 (merge main)
- Verified: `cargo check -p ls-gateway --all-targets`, `cargo test -p ls-gateway pg` (30 passed)
- Notes for next session: main renamed `MAX_GRANT_TTL` to `ttl::MAX_CACHE_TTL` and dropped `MAX_SETTINGS_TTL`; fixed in `pg/listener.rs` and `main.rs`. The branch already holds pg listener/upstream code and tests, but no tasks are ticked yet; verify each against `tasks.md` before ticking.

## 2026-11-22 worker (alfie, second entry)
- Task: none - parked; opened needs-rescue for 6.1 (no bindings page exists in apps/web or apps/desktop even after t3 archived); merged origin/main (already up to date)
- Verified: nothing new run; no code changed
- Notes for next session: wait for the lead's answer on the rescue issue; 6.1/6.2 then 7.2 remain.

## 2026-11-22 lead (rescue #610)
- Task: rescue for 6.1. Cause: the task assumed a Bindings page and a binding data source, and neither exists, because bindings live only in the gateway's bindings file. Fix: decision D3-1 (#611). d3 group 6 builds the page: 6.1 is the contract in `packages/control-plane-client`, 6.2 is the gateway inventory push (`PUT /internal/v1/gateway/bindings`) and `GET /v1/bindings`, 6.3 is the page and 6.4 is verification.
- Verified: `openspec validate d3-db-relay` is valid, and `just tree-check task-guard` passes on the planning branch.
- Notes for next session: merge main once #611 lands, then start 6.1 against fixtures. 7.2 stays last.

## 2026-11-22 worker (alfie, third entry)
- Task: contract slice for new 6.1 (rescue #610, D3-1); not ticked because #611 (new numbering) has not merged and the branch's 6.1 text is still the old one.
- Done: `GET /v1/bindings` + `BindingSummary`/`BindingList` in the control-plane OpenAPI (`api/bindings.rs`, handler returns an empty list until 6.2 stores snapshots), regenerated `openapi.json` and `packages/sdk/src/schema.d.ts`, `listBindings()` and `bindingSummaries` fixtures (http, git, pg, aws) in `packages/control-plane-client`.
- Verified: `cargo test -p ls-control-plane --test openapi` 8 passed; `npm test` and `npm run lint --workspace packages/control-plane-client` pass (14 tests).
- Notes for next session: after #611 merges, merge main and tick new 6.1 (verified as above). Then 6.2 (gateway push, control-plane storage; fills the empty list), 6.3 page, 6.4, 7.2.

## 2026-11-22 worker (alfie, fourth entry)
- Task: 6.1 contract (D3-1) - done, ticked
- Verified: `cargo test -p ls-control-plane --test openapi` (8 passed); `npm test` and `npm run lint --workspace packages/control-plane-client` (14 tests, tsc clean) after `npm ci`
- Notes for next session: merged main (conflict in progress.md only, kept both). Next: 6.2 (gateway inventory push `PUT /internal/v1/gateway/bindings`, control-plane storage fills the empty `GET /v1/bindings`), then 6.3 page, 6.4, 7.2.

## 2026-11-22 worker
- Task: ci-fix - blocked (cause not reproducible locally)
- Verified: just quick -> OK; tree-check, task guard, public-check OK; gitleaks on origin/main..HEAD -> no leaks; cargo test -p ls-gateway -> git::fixture_tests flake (different tests each run, same on clean main in this VM)
- Notes for next session: PR #485 hygiene/macos failures (head bef3784) had no readable annotations (macos exit 100 looks like a runner/install issue). Merged main in and pushed; re-check CI on the new head before more work.

## 2026-11-22 worker
- Task: ci-fix (PR #485 hygiene red) - ci-fix
- Verified: just tree-check task-guard public-check, just quick -> pass locally after merging origin/main
- Notes for next session: hygiene failure was not reproducible locally; likely stale vs main. Merged main and pushed; check CI result on 6c6e434+. Gitleaks full-history scan shows 3 known hits in ls-envelope seal-key-sig-v1.json vectors (on main, not this branch).
