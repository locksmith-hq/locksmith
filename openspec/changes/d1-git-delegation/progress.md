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

## 2026-11-19 worker
- Task: 2.1, 2.2, 2.3, 2.4 - done
- Verified: `cargo nextest run -p ls-gateway git` -> 12 passed (clone, push, unbound repo 403 with no decrypt, fetch-only cannot push, redirect not followed, App token minted once); `cargo deny check` ok; `just ci` -> exit 0 (701 tests); Sonnet evaluator PASS
- Notes for next session: GitBinding gained optional `version`, `port`, `plain_http` (the last two only with `allow_private_hosts`); fold into the design.md contract section. Group 3 next: audit events `git.fetch`/`git.push`/denials are not emitted yet, and upstream error bodies and response headers are not redacted yet (response headers are an allow-list; body streamed raw). No request body size cap: group 5 asserts memory.

## 2026-11-19 worker
- Task: 3.1, 3.2, 3.3 - done
- Verified: `cargo nextest run -p ls-gateway git_redact` -> 7 passed; `just adversarial-gate` PASS (G7 added); `just audit-verify` ok; `just lint` ok; `just test-rust` 718/719 (only `ls-ipc foreign_peer_is_closed...` fails: root VM cannot setuid to nobody, unrelated); Sonnet evaluator PASS
- Notes for next session: one `git.fetch`/`git.push`/`git.denied` event per call (new closed kinds in ls-audit, control-plane internal API, OpenAPI and TS schema); fold into design.md. 2xx `application/x-git-*` streams are relayed raw (headers scanned only), a documented limit. Plain `cargo test -p ls-gateway git_` is flaky in a shared process (passes under nextest or --test-threads=1); check whether pre-existing. Group 4 next (`smith git setup`).

## 2026-11-19 worker
- Task: 4.1 `smith git setup --gateway <url>` (insteadOf include + `gateway-credential` helper returning the agent token), teardown removes it, `git.gateway` doctor check.
- Verified: `cargo nextest run -p smith-cli git` (8 pass), clippy on smith-cli and ls-connector clean. Full `just ci` not run this slice.
- Notes for next session: 4.2 (console/desktop bindings page with Vitest), 4.3, then groups 5 and 6.

## 2026-11-20 worker
- Task: 5.1, 5.2 - done (4.2 blocked: see notes)
- Verified: `cargo nextest run -p ls-gateway git_large` -> 1 passed (50 MB push, slow upstream, RSS growth bound 20 MB, all bytes + credential seen upstream, one git.push event); clippy -D warnings clean; `just ci` -> exit 0. No independent evaluator run (test-only slice).
- Notes for next session: merged main (G7 name clash: main's human-token case kept G7, our Git case renamed to G8.sh with README row and comment refs updated). Task 4.2 is blocked: no bindings page exists in apps/web or apps/desktop (only mockups/Relays) and no API lists Git bindings (they live only in gateway `[[git_binding]]` TOML), so it needs a control-plane/gateway read endpoint first; needs-rescue/lead decision. Task 4.3 follows it. 6.1 (`just git-smoke`) still open.

## 2026-11-20 lead (rescue #482)
- Task: 4.2 decision - moved to `t3-console-mvp` (design.md decision 6, planning PR #483).
- Cause: no bindings page in `apps/web`/`apps/desktop` and no API lists Git bindings (gateway TOML only); T3 owns the console on the real API.
- Verified: `openspec validate d1-git-delegation --strict` valid; `just tree-check task-guard` ok.
- Notes for next session: once #483 is on main, merge origin/main here; tasks.md conflicts on the adjacent 4.1/4.2 lines: keep this branch's ticks and main's 4.2/4.3 text. Then 4.3 (`cargo nextest run -p smith-cli git`) and 6.1.
