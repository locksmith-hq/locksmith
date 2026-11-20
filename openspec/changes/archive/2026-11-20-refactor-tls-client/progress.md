# Progress: refactor-tls-client

<!-- append-only session log -->

## 2026-11-20 · lead · planned
- Planned from the lead review of the d1 (#429) and t1 (#395) merges. The TLS client builder is copied 4 times, and their `rustls` feature declarations already differ.

## 2026-11-20 · worker · slices 1–3.1 done
- Added `crates/ls-http` (`tls_config`, `builder`, `blocking_builder`) with redirect and proxy tests; migrated ls-envelope, ls-connector, gateway and control-plane; dropped now-unused `rustls`/`rustls-platform-verifier` deps. `just ci` and `cargo deny` green; grep for `with_platform_verifier` outside ls-http is empty.
- Left: 3.2 (`just up`/`just api`, `just adversarial-gate`, `just apps-build`) not run this session; change is not complete, so no archive.

## 2026-11-20 · worker · 3.2 done, change complete
- Task 3.2 verified: `just up`, `just api`, `just adversarial-gate` (PASS), `just apps-build` (built), `just ci` (exit 0).
- Archived the change in this PR.
## 2026-11-20 worker
- Task: 1.1,1.2,2.1,2.2,2.3,3.1 - done
- Verified: `just ci` + `cargo deny check` -> green; evaluator PASS
- Notes for next session: 3.2 left (just up/api, adversarial-gate, apps-build), then archive. PR #507.
