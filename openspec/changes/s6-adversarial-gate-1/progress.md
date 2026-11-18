# Progress: s6-adversarial-gate-1

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-18 18:49 worker
- Task: none - planning
- Verified: `openspec validate s6-adversarial-gate-1 --strict`, `bash scripts/tree-check.sh`, `bash scripts/check-task-edits.sh`
- Notes for next session: depends on s5-audit-ledger (ledger events, audit API and export are G2/G5/G6 surfaces and evidence). Groups 1-6 are [opus]. Do group 1 (oracle) before group 4 (redactor) so the judge always sees more than the redactor. Gateway cases live in `tests/adversarial/gateway/` and run via `run.sh gateway`; `run.sh all` must stay unchanged because the weekly `adversarial.yml` runs it without a stack (agents cannot edit workflows). No new Actions job (AGENTS.md CI policy): "green in CI" = fast tier in `just ci` plus `just adversarial-gate` in Local verification. Re-check wiremock release date at apply. Owner open questions: create the nightly routine; ANTHROPIC_API_KEY in the VM for live mode.

## 2026-11-18 worker (josie)
- Task: 1.1 - failed (2 attempts, evaluator FAIL both; WIP, not ticked)
- Verified: `bash tests/adversarial/run.sh selftest` -> pass; `bash tests/kit/leak_scan_test.sh` -> pass
- Notes for next session: oracle.py has all new forms (commit 33bdad9, WIP follow-up has gzip fail-closed fix). Remaining evaluator blockers: (1) `tests/adversarial/run.sh` ~line 79 calls `oracle.py scan` via positional path (`scan_paths`, strict=False), so "gzip budget exhausted" is only a stderr notice and exits 0 -> repro: GZIP_MAGIC*4096 + gzip(canary) (~12KB) reports clean. Make `rep.incomplete` strict in scan_paths (also the >50MB skip) or use `--dir` in run.sh. (2) perf: GZIP_MAX_ATTEMPTS=4096 makes repeated-magic input ~14x slower (44s at 16MB); decompress only the first ~64KB per offset, or cap total gzip input bytes and mark incomplete. Then re-evaluate and tick 1.1/1.2.
