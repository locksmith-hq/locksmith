# Progress: B4 API contract suite

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-24 (PM, planning)
- Split out of `b1-nestjs-api` tasks 1.4 to 1.6 so a second worker builds the contract suite while B1's worker builds the NestJS skeleton (#674). Every Phase 2 row now needs `b1-nestjs-api:contract`, which this completes. Nothing implemented.

## 2026-11-24 (worker-b, group 1)
- Built `tests/api-contract` (workspace, AGPL-3.0-only): normaliser (ids, timestamps, tokens, numbered by first appearance), recorder, dev-auth seeding of two orgs, `diff`, scenario loader, `run.ts` CLI. Node 22 type stripping runs it, so no build step (`.ts` import extensions, `erasableSyntaxOnly`).
- `scripts/api-contract.sh <url>` / `--diff <a> <b>` / `--diff-files <a.json> <b.json>`, `just api-contract`, `scripts/api-contract.test.sh` (planted transcripts). Docs: `docs/testing.md` row, `knip.json`, `test-recipes-check.sh`.
- Coverage test: every `openapi.json` operation needs a scenario or a row in `src/exclusions.ts`; all 54 operations start excluded as "pending: task 2.x/3.x". Each scenario task deletes its rows (the test fails on a stale row).
- Verified: 1.4 commands (11 unit tests, shell test), tsc, oxlint, oxfmt, knip, test-recipes-check. Scenarios (groups 2-3) need `just up`/`just api` and are not started.

## 2026-11-24 (worker-b, group 2)
- Scenarios: `health`, `orgs`, `auth` (tenancy.ts), `projects`, `environments` (projects.ts), `secrets`, `secret-versions` (secrets.ts); 98 exchanges. Verified against `just up-lite` + `just api`: `--diff` of the server with itself matches (transcript deterministic); `just leak-scan` clean; the runner exports a `just canary` canary that is sent, never recorded.
- Sign-in and sign-out success need a verified bearer token (dev header is refused), so only the 401 cases are recorded; success stays with `just auth-e2e` (design decision 4).
- Normaliser additions found by the self-diff: per-run seed suffix (`<run>`), JWKS `kid`/`x`.
- Next: group 3 (agents, workloads, MCP, audit, internal).
