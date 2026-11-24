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

## 2026-11-23 (PM, split for parallel work)
- Workers were idle with an empty ready queue (#670) while this 44-task change is held by one worker (#653). Group 3 (TypeScript tooling) is now also planned as `b3-ts-tooling`, and tasks 5.2 and 5.3 (core API contract and Rust service) as `b2-rust-core`; both have no deps, so two more workers can start today. This change's task text is unchanged: when one of those changes merges, run the matching verify task here (3.5, or the 5.2/5.3 outputs) and tick it only if it passes. Task 5.4 calls `packages/core-client` from `b2-rust-core`. The lead may drop the duplicated task lines on a planning branch (#653).

## 2026-11-24 (PM, split for parallel work)
- T2, T6, T7, T8 and N1 now need only `b1-nestjs-api:contract` (this change's group 1), not the whole port. Tasks 1.4 to 1.6 (scenario suite, runner, verify) are also planned as `b4-api-contract-suite` (no deps) for a second worker; when it merges, run 1.6 here and tick 1.4 to 1.6 only if it passes. Task text unchanged. Landing 1.3 (route table, #674) on main also counts: `change-status.sh` reads B1 ticks from main or `claude/change-b1-nestjs-api`, not the `-r2` branch.
