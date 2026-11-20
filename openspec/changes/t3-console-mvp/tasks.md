# Tasks: T3 web console MVP

## 1. Contract and foundations [sonnet]
- [x] 1.1 Add `@tanstack/react-query` and `react-router` (and `msw` if 1.3 uses it), pinned; re-check licence and release date and record them in design.md "OSS used"; run `npm i` in `apps/web`.
- [x] 1.2 Extend `createClient` in `packages/control-plane-client` with orgs, projects, environments, secrets and versions methods (web and desktop both get them), with unit tests in that package; `apps/web` maps `401` to sign-out in its wrapper; Vitest with a mocked fetch.
- [x] 1.3 Fixture data (MSW or in-memory handlers) for every route the console calls, in `apps/web/src/api/fixtures.ts`.
- [x] 1.4 Verify: `npm test --workspace apps/web`.

## 2. Tokens and shell [sonnet]
- [x] 2.1 Move design tokens and kit components from `mockup/kit.tsx` and the CSS into `packages/ui`; the mockup imports them; no visual change.
- [x] 2.2 Keep the existing `AuthGate`; add `Shell` (sidebar, org header, sign-out) and routes with empty pages; signed-out and expired-session tests.
- [x] 2.3 Shared `QueryState` component: loading, empty, error with retry; tests.
- [x] 2.4 Verify: `npm test --workspace apps/web && npm run build --workspace apps/web`.

## 3. Overview, projects and environments [sonnet]
- [x] 3.1 Overview page with counts, recent activity and the dismissible "Get started" checklist.
- [x] 3.2 Projects list, create, rename, delete with confirm dialog; API errors shown.
- [x] 3.3 Environments list and manage inside a project.
- [x] 3.4 Verify: `npm test --workspace apps/web` (fixtures cover `403`, `409`, empty, error).

## 4. Secrets, agents, grants and activity [sonnet]
- [x] 4.1 Secrets list and detail with versions; a test asserts no request to a value or material route.
- [x] 4.2 Move the existing Agents section to its routed page (keep its tests); the enrollment secret is shown once, kept out of the query cache, storage and logs, and cleared on close, with a test for each.
- [x] 4.3 Move the existing Grants section to its routed page (keep its tests) with mode, target, expiry.
- [x] 4.4 Move the existing Audit section to the Activity page (keep paging, outcome filter and ledger status tests).
- [x] 4.5 Verify: `npm test --workspace apps/web`.

## 5. Desktop surface [sonnet]
- [x] 5.1 Desktop Projects and Environments views in `apps/desktop/src` using the shared client methods from 1.2; Vitest tests including `403`, `409` and empty states.
- [x] 5.2 Desktop Overview counts and Secrets metadata view (no value routes); Vitest test that no value or material request is made.
- [x] 5.3 Verify: `npm test --workspace apps/desktop && just apps-build`.

## 6. End-to-end [sonnet]
- [ ] 6.1 Playwright setup, `just web-e2e` recipe (starts `just up` with the auth profile): sign in as a test user, create a project and environment, register an agent, create and revoke a grant, see activity.
- [ ] 6.2 Add a leak check: the e2e records all requests and fails on any value or material route.
- [ ] 6.3 Verify: `just up && just web-e2e`.
- [ ] 6.4 Gate: confirm the owner approved the live console layout (design.md Open Questions); otherwise stop and report to the lead.
- [ ] 6.5 Lock the Playwright screenshot baselines for Overview, Projects and Activity.
- [ ] 6.6 Verify: `just web-e2e` passes against the locked baselines.

## 7. Local verification [sonnet]
- [ ] 7.1 `just up`, `just web-e2e`, `just apps-build`, then `just ci`.
- [ ] 7.2 Run the manual `ci-platforms` workflow if this is the last change of its phase and record the result in progress.md.
