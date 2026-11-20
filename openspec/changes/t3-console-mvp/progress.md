# Progress: T3 web console MVP (append-only)

- 2026-11-20 · planning only: proposal, spec, design and tasks written by a worker; no code. `x-depends_on` empty because t1-human-auth is archived on main. Task 5.4 is an owner gate (layout approval), placed last.
- 2026-11-20 · plan revised after review: desktop surface added as group 5, so the owner gate is now task 6.4 (not 5.4).
- 2026-11-20 · worker: group 1 done on claude/change-t3-console-mvp. Client gained org, project, environment, secret-metadata and version-list methods (no value or material method); vitest added to control-plane-client; 401 wrapper and in-memory fixtures in apps/web/src/api. msw not added (design.md updated). Groups 2-7 remain.

## 2026-11-20 worker
- Task: 1.1-1.4 - done
- Verified: just ci -> green; npm test (web, control-plane-client) -> pass; evaluator PASS
- Notes for next session: fixtures.ts imports vitest, so only tests may import it. Groups 2-7 remain; 6.4 is an owner gate.

## 2026-11-20 worker
- Task: 2.1-2.4 - done (tokens and kit moved to packages/ui, Shell and routes, QueryState)
- Verified: just ci -> green; npm test (web 31, desktop 25) and web build -> pass; evaluator PASS
- Notes for next session: org header shows the user's email because the console has no org id for getOrg after OIDC sign-in; task 3.1 (Overview with org name) needs that. Shell and App import each other (temporary until group 4). Groups 3-7 remain; 6.4 is an owner gate.

## 2026-11-20 worker
- Task: 3.1-3.4 - done (Overview with counts, recent activity and dismissible checklist; Projects list/create/rename/delete with confirm; Environments inside a project; Shell now provides the QueryClient)
- Verified: `npm test --workspace apps/web` -> 37 passed (incl. 409, 403-with-retry, empty); tsc clean; just ci -> exit 0
- Notes for next session: Overview shows no org name (still no org id after OIDC sign-in). Group 4 next: Secrets, then move Agents/Grants/Audit sections out of App.tsx (Shell and App still import each other). No independent evaluator run (self-checked).
