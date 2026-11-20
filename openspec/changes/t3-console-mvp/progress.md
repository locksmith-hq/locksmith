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
- Notes for next session: Overview shows no org name (still no org id after OIDC sign-in). Group 4 next: Secrets, then move Agents/Grants/Audit sections out of App.tsx (Shell and App still import each other). Evaluator PASS (sonnet); gaps: no test for 403/409 on mutations or env rename; org name on Overview deferred.

## 2026-11-20 worker
- Task: 4.1-4.5 - done (Secrets list/detail with versions, metadata only; Agents, Grants and Activity moved to routed pages in apps/web/src/pages; App/Shell import cycle gone)
- Verified: `npm test --workspace apps/web` -> 38 passed; tsc clean; just ci -> exit 0; evaluator PASS (sonnet)
- Notes for next session: gap: no test that the enrollment secret is absent from the react-query cache (structurally safe: Agents uses useState). Group 5 (desktop) next; 6.4 is an owner gate.

## 2026-11-20 worker
- Task: 5.1-5.3 - done (desktop Projects/Environments views with create/rename/confirm-delete; Overview project+agent counts; Secrets metadata view; no value or material routes)
- Verified: `npm test --workspace apps/desktop` -> 33 passed; tsc clean; `just apps-build` -> ok; just ci -> exit 0; evaluator PASS (sonnet)
- Notes for next session: Overview has no secrets count (would need per-env listing). Group 6 (Playwright e2e, `just web-e2e`) next; 6.4 is an owner gate (layout approval), so 6.1-6.3 can proceed but 6.4+ park on it.

## 2026-11-20 worker
- Task: 6.1 - blocked (not started)
- Verified: none; tasks 1-5 already on branch, merge of main is current
- Notes for next session: 6.1-6.3 need a Playwright `just web-e2e` recipe against `just up` (auth profile); 6.4 is an owner gate (live console layout approval, no approval recorded in openspec/decisions.md or issues). Do 6.1-6.3 next, then ask the lead for the layout decision.

## 2026-11-20 worker
- Task: 6.2 - done; 6.1 partial (not ticked)
- Verified: `just up`, `just api`, `just web-e2e` -> 1 passed (one earlier run failed while `just ci` compiled in parallel; rerun green); just ci -> exit 0
- Notes for next session: Playwright e2e in apps/web/e2e (sign in as seeded alice, project, environment, agent, leak check on all /v1 and /internal requests). 6.1 still needs grant create/revoke on a real secret: the control plane has no secret-create route, so the spec only asserts the error alert for an unknown secret id; seed a secret (DB or new route) then extend. 6.3 waits on 6.1. 6.4 is an owner gate. Run with `PW_CHROMIUM=/opt/pw-browsers/chromium just web-e2e` on the cloud VM. vitest now excludes e2e/.

## 2026-11-20 worker
- Task: 6.1 - blocked (no code change this run)
- Verified: none; branch merged with main (already current); main CI green
- Notes for next session: 6.1 grant create/revoke on a real secret still needs a seeded secret. Control plane has no secret-create route; seed via SQL (secrets row + secret_versions, see services/control-plane/tests/internal.rs ~l.178) from e2e global setup, or add the route. Needs `just up` (auth profile) + `just api` (cold build is long). 6.4 is an owner gate after 6.3.
