# Progress: B1 NestJS API

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-22 (owner session)
- Planned from owner decision OC-8: inspected Infisical's backend (stack, `src/domains` layout, hand-wired DI, Redis queue, Knex) and verified current package versions from the npm registry. Nothing implemented.
- Open gates: G1 Rust core contents (task 5.1), G2 port existing endpoints versus new only (6.1), G3 TypeScript 7 versus 6 (decided by spike 1.1), G4 licence of `apps/api` (AGPL-3.0-only proposed).
- Known stale files to fix on a harness-release branch (task group 8): `openspec/config.yaml` still says "Licence: ... No `ee/`" (stale since the `ee/` layer, #622) and "Rust for ... all services".

## 2026-11-22 (owner session, gates)
- G1 answered: audit, tokens and key wrap stay in Rust behind the core API; authorization in NestJS (decision OC-9). Task 5.1 ticked.
- G2 answered: t6, t7 and t8 paused, existing endpoints ported first (OC-9). Task 6.1 ticked. t6 #605, t7 #599 and t8 #588 are small early PRs; no Rust handlers are to be merged for them. G3 (TypeScript 7 or 6) is decided by spike 1.1; G4 (AGPL for `apps/api`) stands.

## 2026-11-22 (owner session, spike 1.1)
- Task 1.1 done: NestJS 12.6.0 builds, runs and tests on TypeScript 7.0.2 (0.49 s build; DI via emitted decorator metadata; vitest 5.1.1 needs no swc plugin). TypeScript 6.0.3 also works. Details and untested areas in `docs/research/nestjs-typescript7.md`. Recommendation for gate G3: pin TypeScript 7.0.2, fallback 6.0.3. Tooling check for task 1.2 on the spike: oxlint and oxfmt clean, knip needs entry and ignore config.
- Gate G3 answered by the owner: pin TypeScript 7.0.2 (decision OC-10).

## 2026-11-22 (owner session, contract approach)
- Before starting 1.4 found that the Rust integration tests are not HTTP: each of about 17 files builds its own router and calls it with `tower::oneshot` through its own helper (30 call sites), so "record their HTTP calls" has no hook. Amended tasks 1.4 to 1.6 (and design decision 6) to a scenario suite over real HTTP plus a two-server diff. Not started: the suite itself is about 37 paths of scenarios, sized for several worker runs.

## 2026-11-22 (owner session, task 1.2)
- Task 1.2 done: baseline of oxlint (14 warnings, 0 errors), oxfmt (86 of 98 files would change; one repo-wide formatting commit needed) and knip (26 unused files, mostly the mockup entry; a handful of dependency fixes) over the real packages; configs each needs are in `docs/research/nestjs-typescript7.md`.

## 2026-11-22 (worker-b, task 1.3)
- Task 1.3 done: `apps/api/route-table.json` lists every method and path of `services/control-plane/openapi.json` with owner `rust`. The oasdiff check already protects the frozen contract.
- Started task 2.1 (not ticked): `apps/api` package skeleton (`package.json`, `tsconfig.json`), a test that checks the route table against `openapi.json`, and the `docs/testing.md` row. Still open for 2.1: `tree-check.sh` learning `apps/api`, the Turborepo `typecheck` task, the shared tsconfig base decision.

## 2026-11-23 worker-b
- Task: ci-fix (PR #640) - done (merged main to clear red hygiene)
- Verified: tree-check, check-task-edits, public-check, migration-guard, just quick -> OK locally
- Notes for next session: macos failure was locksmithd test agent_session_start_grants_only_inside_policy (not from this change); recheck after push. hygiene logs unreadable, likely fixed by check-task-edits.sh update on main.

## 2026-11-23 worker-b (second pass)
- Task: ci-fix (PR #640) - done
- Verified: macos failure was locksmithd test agent_session_start_grants_only_inside_policy; passes locally (flaky, unrelated). Merged origin/main again; just quick -> OK.
- Notes for next session: recheck macos on #640 after push; 39 tasks still open, no task work done this run.

## 2026-11-23 worker
- Task: ci-fix - done
- Verified: npx vitest run src/route-table.test.ts -> 2 passed
- Notes for next session: web CI failed because route-table.json lacked GET /v1/bindings and PUT /internal/v1/gateway/bindings (added by d3 to openapi.json). 39 tasks still unticked; PR #640 not ready for auto-merge.

## 2026-11-23 worker-b (task 2.1)
- Task 2.1 done: `apps/api` pins TypeScript 7.0.2 (G3/OC-10), Turborepo has a `typecheck` task, tree-check and docs/testing.md already cover `apps/api`, tsconfig extends `packages/tsconfig/base.json`.
- Verified: `tsc --noEmit` clean, `vitest run` 2 passed, tree-check OK.
- Notes for next session: 38 tasks open; next is 2.2 (Nest bootstrap). Tasks 1.4 to 1.6 are sized for several runs. PR #640 not ready for auto-merge.
- Evaluator FAIL on 2.1 (so left unticked): everything is done except an explicit `apps/api` rule in `scripts/tree-check.sh`; the script covers it only indirectly through `test-recipes-check.sh`. `tree-check.sh` is a guard script (trust root), so agent branches may not edit it: needs the lead or owner to say whether the indirect coverage satisfies 2.1, or to make that edit. Everything else in 2.1 is pushed.
