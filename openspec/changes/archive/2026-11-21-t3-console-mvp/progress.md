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

## 2026-11-20 worker
- Task: 6.1, 6.3 - done (e2e seeds a secret via the existing POST .../secrets route with the console's own bearer, then creates and revokes a grant in the UI; leak check unchanged)
- Verified: `just up`, `just api`, `just web-e2e` -> 1 passed; just ci -> exit 0
- Notes for next session: the earlier note "no secret-create route" was wrong (secrets::create exists). Remaining: 6.4 is an owner gate (no layout approval recorded); 6.5-6.6, 7.x follow it. Lead: needs the live console layout decision for 6.4.
- Evaluator PASS (sonnet); caveats: bearer taken from first request without /v1 filter, ids set in async handler without wait, Activity asserts only the region.

## 2026-11-20 07:05 lead
- Task: 6.4 - blocked (owner gate raised)
- Verified: `just up`, `just api`, `just web-e2e` -> 1 passed; live screenshots taken for the owner brief
- Notes for next session: rescue #509 closed in favour of needs-owner #510 (layout options A/B/C; lead recommends B: the mockup frame on the live pages, which needs a styling task group before 6.5). On approval the lead records it in decisions.md and adjusts tasks on claude/planning-t3-console-mvp-tasks. Until then 6.5+ stay parked.

## 2026-11-20 worker
- Task: 6.4 gate ticked (owner approved option B on #510); 6.4.1 code done but NOT ticked
- Verified: `npm test` in apps/web -> 38 passed, tsc clean; guard OK; evaluator PASS (sonnet)
- Notes for next session: sidebar grouped (Home; Secret Management: Projects/Environments/Secrets; Agent Gateway: Agents/Grants; Activity) with user card at the bottom; Environments is a placeholder route pointing to Projects; org switcher is a static label in the sidebar (no workspace API yet). Task lines 6.4.1-6.4.3 exist only on planning PR #524 (not merged: merge-gate rejects agent-app-authored PRs "not opened by the owner"), so tasks.md here is main's version and the task-guard fails if they are merged in. Once #524 is on main, merge main, tick 6.4.1, then do 6.4.2 (style pages with packages/ui kit) and 6.4.3 (e2e + screenshots). Also note: `just ci` was not run to green here because of that guard; the other recipes passed before task-guard.

## 2026-11-21 12:10 worker
- Task: merge main into the change branch (conflict resolution) - done
- Verified: `npm test` in packages/control-plane-client, apps/web, apps/desktop + `tsc --noEmit` -> pass (9, 45, 36 tests)
- Notes for next session: conflicts came from m1 MCP Tools/Clients pages landing in the old single-file web App. They now live in `apps/web/src/pages/McpTools.tsx`, `McpClients.tsx` (routes `tools`, `clients` in Shell). Desktop and control-plane-client keep both sides. Tasks 6.4.1-6.4.3 restored from main as unticked; 6.4.1 code is on the branch but not yet verified (`just web-e2e`), so left unticked.

## 2026-11-21 worker (alfie)
- Task: group 1 (1.1-1.4) verified and ticked; design.md "OSS used" now records the pinned versions (react-query 5.108.1, react-router 8.5.2; msw not used, in-memory fixtures).
- Verified: `npm test` in packages/control-plane-client (9), apps/web (45), apps/desktop (36) pass; `npm run build --workspace apps/web` OK.
- Notes for next session: groups 2-5 have code and tests on this branch but are not yet audited against each task line, so they are unticked. 6.4.1-6.4.3 and group 6 need `just up && just web-e2e` (docker, Keycloak); not run this session.
- 2026-11-21 · evaluator first failed 1.3 (fixtures lacked agent/grant writes, MCP and org routes); fixed in `apps/web/src/api/fixtures.ts` with a test, re-evaluated PASS (apps/web 46 tests). Unexercised handlers: updateProject/deleteProject/environment writes/audit events.

## 2026-11-21 worker (josie)
- Task: groups 2, 3, 4 (2.1-4.5) audited against their task lines by an independent Sonnet evaluator and ticked; the only FAIL (4.2: no test that the enrollment secret stays out of the query cache) was fixed with a new test in `apps/web/src/App.test.tsx`.
- Verified: `npm test --workspace apps/web` (47 passed), `npm run build --workspace apps/web` OK, main merged in (`.gitignore` kept both sides).
- Notes for next session: group 5 (desktop) and 6.4.1+ remain. 6.4.1 code is on the branch but needs `just up && just web-e2e` to verify; Activity page heading still says "Audit"; Agents page does not use `QueryState`; grant mode is hardcoded "relay" in `Grants.tsx:36`; `/grants` route has no dedicated test.

## 2026-11-21 worker (josie, later)
- Task: group 5 (5.1-5.3) audited by an independent Sonnet evaluator (PASS) and ticked.
- Verified: `npm test --workspace apps/desktop` (36 passed), `just apps-build` exit 0.
- Notes for next session: remaining 6.1-6.3, 6.4.1-6.4.3, 6.5-6.6, 7.x need `just up && just web-e2e` (docker/Keycloak). Weak spot: the desktop 5.2 `fetch` assertion is near-vacuous (client mocked); the method allow-list is the real check.

## 2026-11-21 worker (josie, run 3)
- Task: t3 PR #489 conflicts - done (merged origin/main; vitest 4 from main kept, package-lock regenerated with npm i).
- Verified: npm test in control-plane-client (9), apps/web (47), apps/desktop (36); web build OK; `just quick` OK.
- Notes for next session: remaining 6.1-6.3, 6.4.1-6.4.3, 6.5-6.6, 7.x need `just up && just web-e2e` (docker/Keycloak); not attempted this run.

## 2026-11-21 worker (josie, run 4)
- Task: 6.2 and 6.3 audited by an independent Sonnet evaluator (PASS) and ticked; 6.1 left unticked.
- Verified: `just up` + `just api` + `just web-e2e` (1 test passed, with `PW_CHROMIUM=/opt/pw-browsers/chromium`); main merged in.
- Notes for next session: 6.1 caveats: the "see activity" step only asserts the Audit region is visible (should assert a grant create/revoke row), and the `web-e2e` recipe does not start `just up` itself (task text says it does). Remaining: 6.1, 6.4.1-6.4.3, 6.5-6.6, 7.x. Docker image pull for `just up` takes ~10 min cold; cargo build of `just api` ~5 min.

## 2026-11-21 worker (alfie)
- Task: 6.4.1 shell frame done and ticked: org switcher (button + menu, top right), user card holds sign-out, Environments opens the viewed project (else first, else /projects), with tests.
- Verified: `npm test --workspace apps/web` (49 passed), tsc clean. Evaluator: Sonnet FAIL and Opus FAIL on earlier attempts (static switcher; selected-project test could not fail), fixed; third review (Opus) PASS, plus a mutation check that the test fails when `selected` is ignored.
- Notes for next session: org switcher is single-org (no API lists orgs yet); `selected` is not cleared if its project is deleted; org menu has no Escape/outside-click close (do in 6.4.2). Remaining: 6.1, 6.4.2, 6.4.3 (needs `just up && just web-e2e`), 6.5-6.6, 7.x.

## 2026-11-21 worker (josie, run 5)
- Task: 6.4.2 restyle done and ticked: web imports the shared desktop styles, fonts (deps added to apps/web) and new `@locksmith/ui/kit.css` (crumbs, plain, inline-form, panel.form, switch moved out of the mockup CSS); all pages use kit classes (btn, panel, grid, list, state) and `Head`; org menu closes on Escape and outside click (test added).
- Verified: tsc clean, `npm test --workspace apps/web` (50), web build OK. Evaluator: Sonnet FAIL (dead classes, fixed), then PASS.
- Notes for next session: not yet seen in a browser; 6.4.3 (needs `just up && just web-e2e`, screenshots) and 6.1 caveats remain, then 6.5-6.6, 7.x.

## 2026-11-21 worker (josie, run 6)
- Task: 6.4.3 - done (ticked). Live screenshots in `openspec/changes/t3-console-mvp/screenshots/`: `live-overview.png` and `live-projects.png` vs `mockup-overview.png` (the mockup is the Home product-card page; live Overview has the same frame: grouped sidebar, org switcher, user card; the Home card grid is not built).
- Verified: `npm test --workspace apps/web` (50 passed), `npm run build --workspace apps/web` OK, `just up` + `just api` + `just web-e2e` (1 passed, leak check included).
- Notes for next session: independent Sonnet evaluator PASS (re-ran tests, build, e2e). Live Overview uses plain bullet lists and default-blue links (Get started, Recent activity), unlike the mockup. Remaining: 6.1 caveats, 6.5-6.6, 7.x.

## 2026-11-21 worker (harriet)
- Task: 6.1, 6.5, 6.6 - done (ticked). The e2e now asserts the Audit table shows this run's `grant.created` and `grant.revoked` rows; `just web-e2e` starts `just up` and the API itself when `/healthz` is down and passes extra args through; `apps/web/e2e/screenshots.spec.ts` locks Linux baselines for Overview, Projects and Activity (data regions hidden by `shot.css` so runs are deterministic; update with `just web-e2e --update-snapshots`).
- Verified: `just up` + `just api` + `just web-e2e` (2 passed, three consecutive runs stable, leak check included).
- Notes for next session: remaining 7.1 (`just up`, `just web-e2e`, `just apps-build`, then CI) and 7.2 (manual `ci-platforms` run if last of its phase). Baselines are `-linux` only; macOS CI does not run web-e2e.

## 2026-11-21 worker (harriet, run 2)
- Task: t3 PR #489 conflicts with main - done (merged origin/main; kept both sides: Projects/Secrets tabs plus workload identities; main's inline web Console dropped, workload identities ported to `apps/web/src/pages/WorkloadIdentities.tsx` and routed in Shell).
- Verified: npm test control-plane-client (9), apps/web (51), apps/desktop (37); web build OK; `just quick` OK.
- Notes for next session: remaining 7.1 (`just up`, `just web-e2e`, `just apps-build`) and 7.2. Web-e2e snapshots were not rerun after this merge; rerun before ticking 7.1.

## 2026-11-21 worker (alfie, run 2)
- Task: 7.1 - done (ticked). After merging main in: `just up` + `just web-e2e` (2 passed, snapshots unchanged) and `just apps-build` OK; the full `just ci` is left to the PR's required checks.
- Verified: `PW_CHROMIUM=/opt/pw-browsers/chromium just web-e2e && just apps-build` -> exit 0.
- Notes for next session: only 7.2 remains (manual `ci-platforms` run; record the result), then archive the change (`archive-change`) in this PR.

## 2026-11-21 worker (josie)
- Task: 7.2 - not applicable: T3 is not the last change of phase 2 (T4, T6, T7, T8, N1 still open), so ci-platforms was not run manually; the PR runs it anyway.
- Verified: all required checks green on the branch head; main CI green.
- Notes: change archived in this PR.

## 2026-11-21 worker
- Task: review findings on #489 - done
- Verified: npm test --workspace apps/web -> 55 passed; tsc clean
- Notes for next session: Agents and Grants now use useQuery + QueryState, Activity has Retry, with a 5xx test per page; Copy button on the enrollment secret. API gap logged for the lead: no endpoint returns the caller's org id (no /v1/me, and the token is not assumed to carry it), so the Overview and org switcher cannot show the personal org name; the spec scenario was amended to match. Follow-up: add `/v1/me` (or an org claim) and call `client.getOrg`.
