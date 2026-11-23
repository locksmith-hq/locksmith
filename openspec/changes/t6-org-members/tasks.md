# Tasks: T6 organizations and members

## 1. Contract [sonnet]
- [x] 1.1 Add the `OrgRole` enum and the orgs, members and invites request and response types to the OpenAPI schema (utoipa) and regenerate `packages/control-plane-client`; stubs return `501`.
- [x] 1.2 Fixture data for every new route in `apps/web/src/api/fixtures.ts` (members of two roles, a pending invite, an org list of two).
- [x] 1.3 Verify: `cargo nextest run -p ls-control-plane openapi` and `npm test --workspace packages/control-plane-client`.

## 2. Schema and tenancy [sonnet]
- [x] 2.1 Migration `0014_memberships.sql`: `memberships` and `invites` with forced RLS and grants as in design.md; backfill one `owner` membership per existing user.
- [x] 2.2 Cover both tables in `ls-tenant-lint`; a migration test proves the backfill and cross-org isolation.
- [x] 2.3 Verify: `cargo nextest run -p ls-control-plane tenancy` and `cargo nextest run -p ls-tenant-lint`.

## 3. Org selection and orgs [opus]
- [x] 3.1 `OrgBinding` honours `X-Locksmith-Org` after a membership check in the binding transaction; default is the personal org; exposes the caller's role. A miss is `404`.
- [x] 3.2 `GET/POST /v1/orgs`, `PATCH`, `DELETE` (owner only, `409` while secrets exist), with ledger events.
- [x] 3.3 Verify: `cargo nextest run -p ls-control-plane org_select orgs`: non-member `404`, old user default, removed member refused.

## 4. Members and invites [sonnet]
- [x] 4.1 Invite create, list and revoke: random token, SHA-256 stored, link returned once, role rules, 7-day expiry.
- [x] 4.2 `POST /v1/invites/accept`: verified-email match, single use, uniform `404`, ledger event.
- [x] 4.3 Member list, role change, remove and leave with the last-owner lock; concurrent test with two owners.
- [x] 4.4 Add the invite and membership cases (guess a token, reuse, other email, cross-org `404`) to `tests/adversarial/`.
- [ ] 4.5 Verify: `cargo nextest run -p ls-control-plane members invites`, `bash tests/adversarial/run.sh`, `just leak-scan`, `just audit-verify`.

## 5. Web console [sonnet]
- [ ] 5.1 Org switcher from `GET /v1/orgs` that sets `X-Locksmith-Org` for the shared client and remembers the choice per browser.
- [ ] 5.2 Members page: list, invite (link shown once, kept out of the query cache and storage), change role, remove, leave; buttons hidden by role, server errors shown.
- [ ] 5.3 Accept-invite route (token read from the URL fragment, posted in the body, cleared from history) and a "Create organization" dialog.
- [ ] 5.4 Verify: `npm test --workspace apps/web` (fixtures cover `403`, `404`, `409`, empty).

## 6. Desktop surface [sonnet]
- [ ] 6.1 Desktop org switcher and Members view in `apps/desktop/src` using the shared client; Vitest tests including `403` and `409`.
- [ ] 6.2 Verify: `npm test --workspace apps/desktop` and `just apps-build`.

## 7. Local verification [sonnet]
- [ ] 7.1 `just org-smoke` and `tests/e2e/tests/org_members.rs`: user A creates an org and an invite, user B (second Keycloak user) accepts and acts in the org, A removes B, B is refused.
- [ ] 7.2 `just up`, `just org-smoke`, `just apps-build`, then `just quick`.
