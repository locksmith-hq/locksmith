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
