# Progress: B3 TypeScript tooling

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-23 (PM, planning)
- Split out of `b1-nestjs-api` group 3 (tasks 3.1 to 3.5) so another worker can take it while B1's NestJS foundation is in progress (#653, #670). Baseline and configs are in `docs/research/nestjs-typescript7.md` (B1 spike 1.2). Nothing implemented.

## 2026-11-23 (worker-a)
- Groups 1 to 4 done on `claude/change-b3-ts-tooling`. oxlint 1.94.0, oxfmt 0.79.0, knip 6.47.0 pinned at the root; per-package scripts pass `-c ../../.oxlintrc.json` (oxfmt and oxlint only read the config from the cwd). The old `tsc --noEmit` `lint` scripts are now `typecheck`; `just lint` runs `turbo run lint format:check knip typecheck`; `just quick` runs the same when a TS file changed.
- oxfmt formats TOML and YAML by default, so `.oxfmtrc.json` ignores them (it would have rewritten Cargo.toml). The format commit is listed in `.git-blame-ignore-revs`.
- knip fixes: removed 19 unused exports and types (knip --fix), dropped the unused `openapi-typescript` devDependency of `control-plane-client`, added `typescript` where `tsc` is called and `react` as a `packages/ui` peer dependency. `packages/eslint-config` removed (no leftovers).
- Planted-export check: an unused file in `packages/sdk` made `//:knip` fail naming it; removed, green.
- Not done: 5.1 (`just up` and `just apps-build`); the CI workflow needs no edit because it calls `just lint`.

## 2026-11-23 worker
- Task: 1.1-4.3 - done; PR #689 open, 5.1 left
- Verified: `npx turbo run lint format:check knip typecheck` -> 19/19 green; evaluator PASS
- Notes for next session: do 5.1 (`just up`, `just apps-build`, `just quick`), tick it, then finish the PR with auto-merge. d2-aws-sts archive is PR #688 (auto-merge on).

## 2026-11-23 worker (ci-fix)
- Task: ci-fix + 5.1 - done
- Verified: `just quick` green; `just apps-build` exit 0; test-recipes-check and tree-check OK
- Notes for next session: hygiene failed because the TypeScript gates table in docs/testing.md used `lint`/`knip`/`typecheck` as first-column names, which test-recipes-check read as component rows (now `npm run <gate>`). The desktop api-types diff failed because ts-rs output is unformatted; `just api-types` now runs oxfmt@0.79.0 over it. `just up` not run (no service touched).
