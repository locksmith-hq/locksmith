# Progress: t6-org-members

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-22 worker
- Task: none - planning
- Verified: `openspec validate t6-org-members --strict`
- Notes for next session: groups 1 to 4 need only the archived T1; 5 to 6 stack on t3-console-mvp (#489). `just psql` exists; there is no `just tenant-lint`, use the ls-tenant-lint crate tests.

## 2026-11-22 worker (harriet)
- Task: group 1 (contract) 1.1-1.3.
- Done: `OrgRole` and the org/member/invite types, routes and `501` stubs (`services/control-plane/src/api/members.rs`, new `Kind::NotImplemented`), `openapi.json` and `packages/sdk` schema regenerated, client methods plus fixtures in `packages/control-plane-client` (there is no `apps/web/src/api/fixtures.ts`; fixtures live in the client package). `POST /v1/orgs` stays the dev-only create until group 3.
- Verified: `cargo test -p ls-control-plane --test openapi`, `npm test --workspace packages/control-plane-client`.
- Notes for next session: the openapi secret-field test now allows `InviteCreated.token` (shown once). `members.rs` has a module `allow(dead_code)`: remove it when groups 3 and 4 read the fields. Next: group 2 (migration 0014, ls-tenant-lint).

## 2026-11-22 worker (harriet)
- Task: group 2 (schema and tenancy) 2.1-2.3.
- Done: migration `0014_memberships.sql` (registered in `migrate.rs`): `memberships`, `invites`, forced RLS, `app.login_user` and `app.invite_hash` slices, one owner membership backfilled per user (backfill runs before RLS on the new tables; `users` FORCE is lifted and restored in the same transaction). New `tests/memberships.rs` (backfill via `run_to(13)`, cross-org isolation, invite-hash accept slice); lint test in `tests/tenant_lint.rs`; `tests/tenancy.rs` counts updated (14 migrations, 19 `tenant_isolation` policies).
- Verified: `cargo test -p ls-control-plane --test tenancy --test memberships --test tenant_lint --test openapi --test users --test api`, `cargo test -p ls-tenant-lint` (`cargo nextest ... tenancy` filters by test name and matched none; ran the binaries instead).
- Notes for next session: group 3. `orgs` RLS is by `id = current_org_id()`, so `GET /v1/orgs` needs a `login_user`-style read path for the caller's orgs; `users` RLS is by personal org, so the member list needs emails of other members (same slice problem). Add the policy or a join through a narrowly scoped setting in migration 0015, not by loosening 0014.
