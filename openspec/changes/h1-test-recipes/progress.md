# Progress: h1-test-recipes

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-18 08:30 pm
- Task: planning (proposal, spec, design, tasks) - done
- Verified: `openspec validate h1-test-recipes --strict`
- Notes for next session: no dependencies; docs and tooling only, Sonnet tier. AGENTS.md is protected, so link docs/testing.md from the non-protected indexes. Directory names differ from Cargo package names (control-plane -> ls-control-plane); resolve with cargo metadata.

## 2026-11-18 worker
Fixed review finding: apps/web has no test script; spec, tasks and design now treat it as covered-by `just test-web`.
