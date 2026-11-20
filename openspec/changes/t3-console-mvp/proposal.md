# Proposal: T3 web console MVP

## Why
`apps/web` today has a sign-in `AuthGate` and one single-page `Console` in `App.tsx` with Agents (including the one-time enrollment secret), Grants and Audit sections on the real API, with tests. It has no navigation, no projects, environments or secrets views, no Overview, and shares no styling with the mockup. The control-plane API already manages projects, environments, secret names and versions, agents, grants and audit events, but nothing a person can click uses it. The console mockup (`apps/web/src/mockup`) is static fake data. This change makes the first thing a person can use in the browser, so the cloud dev environment (P1) has something to show.

## What Changes
- A React console shell in `apps/web` on the real API through `@locksmith/control-plane-client`. It migrates the existing Agents, Grants and Audit sections into routed pages (behaviour and tests carry over) and adds the hub Overview (with the T1-1 "Get started" checklist), Projects, Environments and Secrets (names and version metadata only), with Activity as the renamed Audit page.
- Create, rename and delete projects and environments; register and revoke agents; create and revoke grants. Every action is an existing API call; no new server behaviour.
- Design tokens and the shared kit move from the mockup into `packages/ui`; the mockup keeps importing them from there.
- Loading, empty, error and signed-out states for every page; a read-only role notice when the API returns `403`.
- Desktop views for Overview, Projects, Environments and Secrets (read and manage, no values) in `apps/desktop`, on the same shared client methods, with Vitest tests, as the apps rule requires.
- Playwright end-to-end test against `just up` (Keycloak sign-in, create project, see it listed).
- No secret value entry or display anywhere (that is T7).

## Capabilities
### New Capabilities
- `web-console`: the signed-in console shell and its read/manage pages over the control-plane API, and the rule that it never shows or handles a secret value.

### Modified Capabilities
<!-- none -->

## Impact
`apps/web` (new routes, pages, tests), `apps/desktop` (Overview, Projects, Environments and Secrets views, tests), `packages/ui` (tokens, kit), `packages/control-plane-client` (new methods on the shared `createClient`; schema unchanged), `tests/e2e` (Playwright), `justfile` (`web-e2e`). No Rust, schema or migration changes. If an API gap is found, it is logged on the change's `progress.md` and raised to the lead, not patched here.

## Out of scope
Secret value entry (T7), live sessions and revoke-all (T8), organization members and invites (T6), policy (T2), access requests (T4), notifications (N1), billing and settings mockup pages, hosting the static console in AWS (P1).

## Depends on
`t1-human-auth` (archived, on main): the console signs in through its OIDC client and sends the bearer token.
