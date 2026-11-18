# Progress: s6-adversarial-gate-1

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-18 18:49 worker
- Task: none - planning
- Verified: `openspec validate s6-adversarial-gate-1 --strict`, `bash scripts/tree-check.sh`, `bash scripts/check-task-edits.sh`
- Notes for next session: depends on s5-audit-ledger (ledger events, audit API and export are G2/G5/G6 surfaces and evidence). Groups 1-6 are [opus]. Do group 1 (oracle) before group 4 (redactor) so the judge always sees more than the redactor. Gateway cases live in `tests/adversarial/gateway/` and run via `run.sh gateway`; `run.sh all` must stay unchanged because the weekly `adversarial.yml` runs it without a stack (agents cannot edit workflows). No new Actions job (AGENTS.md CI policy): "green in CI" = fast tier in `just ci` plus `just adversarial-gate` in Local verification. Re-check wiremock release date at apply. Owner open questions: create the nightly routine; ANTHROPIC_API_KEY in the VM for live mode.
