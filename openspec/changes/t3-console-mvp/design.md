# Design: T3 web console MVP

## Context
`apps/web` has `App.tsx`, `auth.ts` (OIDC via `oidc-client-ts`, from T1) and a large static mockup under `src/mockup` with its own CSS and fake data. The API surface comes from `packages/control-plane-client` (generated `schema.d.ts`): orgs, projects, environments, secrets and versions, agents, grants, audit events and status. Decisions: H1-1 (values are sealed in the browser later, T7), T1-1 (first-run Overview and checklist, mockup tokens).

## Decisions and evidence
| Decision | Alternatives rejected | Evidence |
|---|---|---|
| Extend the existing shared `createClient` in `packages/control-plane-client` (bearer token, problem+json to `ApiError`, cursor paging; already used by `apps/web` and `apps/desktop`) with project, environment, secret and org methods, wrapped by `@tanstack/react-query` hooks | A second `openapi-fetch` client in `apps/web` (two clients would drift); Redux | The shared client and generated schema already exist; TanStack Query is the maintained standard for server state (https://tanstack.com/query) |
| `react-router` v7 data-less routes | Custom hash router; Next.js | Static SPA hosting is the P1 plan (S3 + CloudFront); no SSR needed |
| Tokens and kit move to `packages/ui`, mockup imports them | Copy the CSS | One source avoids drift; the mockup stays as the design reference |
| No value routes called from the console | Reveal-on-click | Security rule; T7 owns entry; checked by a test on recorded requests |
| Playwright against `just up` | Cypress; jsdom-only | Playwright and Chromium are already installed in agent VMs |
| Roles shown as API outcomes (`403` notice), not computed client-side | Client role checks | Server is the authority; T6 adds members later |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| @tanstack/react-query | MIT | 5.108.1 (pinned) | 2026-11-19, maintained | Server-state cache, retry, invalidation | permissive, fine |
| react-router | MIT | 8.5.2 (pinned) | 2026-11-18, maintained | Routing | permissive, fine |
| msw (if used for fixtures) | MIT | not added: fixtures are an in-memory fetch stub (`apps/web/src/api/fixtures.ts`) | n/a | API mocks in tests | permissive, fine |
| @playwright/test | Apache-2.0 | match installed Playwright | 2026 | e2e | permissive, fine |
Versions and dates are re-checked when added (task 1.1) and recorded here.

## Built in-house
Page components and the shared kit, because the mockup defines the look; searched for a component library first and rejected adding one so the mockup tokens stay the only styling source.

## Architecture
`App` -> `AuthGate` (T1 auth) -> `Shell` (sidebar, org header) -> pages. Each page uses `useQuery`/`useMutation` hooks in `src/api/`; a single `apiClient` adds the bearer token and maps `401` to sign-out and problem+json to a typed error. Dismissed-checklist state is stored per user in `localStorage`.

## How an agent debugs this
`just up` starts the stack with the Keycloak profile; `just dev web` runs vite; control-plane logs via the Grafana/Loki MCP and `docker compose logs control-plane`; traces for each API call in Tempo; DB tables `projects`, `environments`, `secrets`, `agent_grants`, `audit_events` through the postgres MCP (read-only); Playwright traces with `--trace on` on failure.

## Open questions
- Does the owner want the mockup's sidebar layout unchanged for the live console? Assumed yes (mockup is the approved direction under T1-1); a `Gate:` task near the end (6.4) confirms before the e2e snapshot baseline is locked.
- API gaps (for example org-wide activity filters) are logged, not patched here.
