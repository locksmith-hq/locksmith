# Progress: d3-db-relay

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-19 worker
- Task: none - planning
- Verified: `openspec validate d3-db-relay --strict`, `bash scripts/tree-check.sh`
- Notes for next session: the M6 local Postgres relay (`crates/ls-proxy/src/db/postgres.rs`, `scram.rs`, `smith db connect`) is sync and session-tree gated; D3 adds an async TLS pgwire listener to the hosted gateway and reuses its SCRAM/md5 helpers. Verify the pgwire version and codec-only use at task 1.1 before building on it.
