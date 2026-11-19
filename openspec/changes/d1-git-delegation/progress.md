# Progress: d1-git-delegation

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-19 worker
- Task: none - planning
- Verified: `openspec validate d1-git-delegation --strict`, `bash scripts/tree-check.sh`
- Notes for next session: the local M5 Git forwarder (`crates/ls-proxy/src/github.rs`, `smith git`) already exists; D1 adds the hosted gateway route with streaming bodies (relay.rs buffers `Bytes`). Reuse `ls-proxy::github` credential and App-token code. Verify reqwest streaming feature and `git http-backend` availability at apply.

## 2026-11-19 worker (c)
- Task: 1.1, 1.2 - done
- Verified: `cargo nextest run -p ls-gateway git_binding` -> 6 passed; `just ci` -> exit 0; Sonnet evaluator PASS (follow-ups applied: duplicate git secret_id rejected, extra bypass cases tested)
- Notes for next session: `services/gateway/src/git.rs` has `GitBinding::authorize` (pure path/host/repo/service check; run it before any decrypt) and `Bindings::git_for_secret`. `allow_private_hosts` is parsed but not yet enforced: task 2.1/2.2 must use it for the egress check. Owner casing is case-insensitive in `covers`; normalise when building the upstream URL. Next: group 2 (streaming route, `services/gateway/src/git.rs` plus an `app.rs` route).
