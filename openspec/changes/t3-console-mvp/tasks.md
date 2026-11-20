# Tasks: T3 web console MVP

## 1. Contract and foundations [sonnet]
- [ ] 1.1 Add `@tanstack/react-query` and `react-router`, pinned; re-check licence and release date and record them in design.md "OSS used"; run `npm i` in `apps/web`.
- [ ] 1.2 `apps/web/src/api/client.ts`: bearer-token client over `@locksmith/control-plane-client`, `401` -> sign-out, problem+json -> typed error; Vitest with a mocked fetch.
- [ ] 1.3 Fixture data (MSW or in-memory handlers) for every route the console calls, in `apps/web/src/api/fixtures.ts`.
- [ ] 1.4 Verify: `npm test --workspace apps/web`.

## 2. Tokens and shell [sonnet]
- [ ] 2.1 Move design tokens and kit components from `mockup/kit.tsx` and the CSS into `packages/ui`; the mockup imports them; no visual change.
- [ ] 2.2 `AuthGate`, `Shell` (sidebar, org header, sign-out) and routes with empty pages; signed-out and expired-session tests.
- [ ] 2.3 Shared `QueryState` component: loading, empty, error with retry; tests.
- [ ] 2.4 Verify: `npm test --workspace apps/web && npm run build --workspace apps/web`.

## 3. Overview, projects and environments [sonnet]
- [ ] 3.1 Overview page with counts, recent activity and the dismissible "Get started" checklist.
- [ ] 3.2 Projects list, create, rename, delete with confirm dialog; API errors shown.
- [ ] 3.3 Environments list and manage inside a project.
- [ ] 3.4 Verify: `npm test --workspace apps/web` (fixtures cover `403`, `409`, empty, error).

## 4. Secrets, agents, grants and activity [sonnet]
- [ ] 4.1 Secrets list and detail with versions; a test asserts no request to a value or material route.
- [ ] 4.2 Agents list, register, revoke.
- [ ] 4.3 Grants list, create, revoke with mode, target, expiry.
- [ ] 4.4 Activity page with paging and ledger status.
- [ ] 4.5 Verify: `npm test --workspace apps/web`.

## 5. End-to-end [sonnet]
- [ ] 5.1 Playwright setup, `just web-e2e` recipe (starts `just up` with the auth profile): sign in as a test user, create a project and environment, register an agent, create and revoke a grant, see activity.
- [ ] 5.2 Add a leak check: the e2e records all requests and fails on any value or material route.
- [ ] 5.3 Verify: `just up && just web-e2e`.
- [ ] 5.4 Gate: confirm the owner approved the live console layout (design.md Open Questions); otherwise stop and report to the lead.
- [ ] 5.5 Lock the Playwright screenshot baselines for Overview, Projects and Activity.

## 6. Local verification [sonnet]
- [ ] 6.1 `just up`, `just web-e2e`, `just apps-build`, then `just ci`.
- [ ] 6.2 Run the manual `ci-platforms` workflow if this is the last change of its phase and record the result in progress.md.
