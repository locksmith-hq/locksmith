# Progress: h1-test-recipes

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-18 08:30 pm
- Task: planning (proposal, spec, design, tasks) - done
- Verified: `openspec validate h1-test-recipes --strict`
- Notes for next session: no dependencies; docs and tooling only, Sonnet tier. AGENTS.md is protected, so link docs/testing.md from the non-protected indexes. Directory names differ from Cargo package names (control-plane -> ls-control-plane); resolve with cargo metadata.

## 2026-11-18 worker
Fixed review finding: apps/web has no test script; spec, tasks and design now treat it as covered-by `just test-web`.

## 2026-11-18 worker
- Tasks: 1.1-1.4, 2.1-2.2, 3.1 done.
- Verified: `docs/testing.md` has 35 rows; ran `just test <name>` for every row, all pass (e2e needs `just up` and `just api`; desktop needed the Linux GTK/webkit dev packages, installed with apt on this VM). `bash scripts/test-recipes-check.test.sh` passes; `just tree-check` fails with a planted `crates/ls-planted`; `just test no-such-thing` exits 1 and lists names; `just apps-build` and `just ci` green.
- Notes: apps/web now has a `test` script (S4), so its row runs `npm test --workspace apps/web`. Rows with no tests of their own resolve to their covering row. The VM disk filled during `just ci` (target/debug/build ~18G); deleted `build/ls-control-plane` and `build/ls-gateway`.
