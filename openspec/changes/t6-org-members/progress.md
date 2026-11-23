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

## 2026-11-22 worker (harriet, run end)
- Task: 1.1-1.3, 2.1-2.3 - done
- Verified: `cargo test` openapi/tenancy/memberships/tenant_lint, `npm test --workspace packages/control-plane-client`, `just quick` -> pass
- Notes for next session: group 3 is `[opus]`; start there. See the group 2 note about `orgs` and `users` read slices.

## 2026-11-22 08:53 worker
- Task: PR #605 conflict + red macos - ci-fix
- Verified: vitest + tsc in packages/control-plane-client, just quick -> pass
- Notes for next session: merged main (index.test.ts conflict: kept main's describe/it plus T6 tests). macos job failed with exit 100 before; no annotation detail, check whether it recurs on the new head.

## 2026-11-22 worker (group 3)
- Task: 3.1-3.3 (org selection and orgs) - implemented, not ticked (pending review).
- Done: `OrgBinding` now carries `role` and `user`; a human's `X-Locksmith-Org` is checked against `memberships` in the binding (login) transaction via `app.login_user` before the org is bound (`users::bind`, span `org.select`); miss or malformed id = `404`. New users get an owner membership of their personal org. `OrgRole` moved to `auth.rs` (re-exported from `members.rs`). `GET/POST /v1/orgs`, `PATCH`/`DELETE /v1/orgs/{id}` built; new `Kind::Forbidden` (`403`), ledger kinds `org.created`/`org.renamed`/`org.deleted`. Migration `0015_org_member_read.sql` adds a SELECT-only `orgs` policy for the caller's member orgs.
- Deviation: DELETE ends every membership and revokes open invites but keeps the `orgs` row and its ledger (append-only ledger; app has no DELETE on `orgs`); personal orgs are `409`. PATCH/DELETE require `{org_id}` to be the bound org (send `X-Locksmith-Org`).
- Verified: `cargo nextest run -p ls-control-plane org_select orgs` (tests in `tests/orgs.rs`), `cargo nextest run -p ls-control-plane -p ls-audit -p ls-tenant-lint` (304 passed).

## 2026-11-22 worker (harriet) - group 3 verified
- Evaluator (Opus) PASS on tasks 3.1-3.3; `cargo nextest run -p ls-control-plane org_select orgs` 11 passed.
- Note: delete_org keeps the `orgs` row (ledger is append-only); it ends memberships and revokes invites. Differs from design.md "explicit deletes".
- Follow-ups for later: revoke grants/disable workload identities and mcp clients on org delete; add explicit `org_id = $1` to the invites/secrets statements in delete_org.
- Next: group 4 (members and invites), sonnet. macOS job on #605 failed with exit 100 earlier (could not rerun: 403); the push reruns CI.

## 2026-11-22 worker (harriet) ci-fix
- Task: PR #605 red `rust` job - ci-fix
- Verified: `cargo deny check advisories` -> ok, `just quick` -> pass
- Notes for next session: failure was cargo-deny RUSTSEC-2026-0592 (`url` 2.5.8), not macOS; bumped to 2.5.9 in Cargo.lock. Main has the same advisory, so other PRs will hit it until this merges. Group 4 (members and invites) is next.

## 2026-11-22 worker (harriet)
- Task: 4.1-4.3 (invites, accept, members) - done, ticked after Sonnet evaluator PASS.
- Verified: `cargo test -p ls-control-plane --test members` (8 passed), tenancy/tenant_lint/orgs/users/openapi/memberships, `just quick` -> pass. Migration 0016 adds SELECT-only `org_member_read` on `users`.
- Deviation: accept returns 401 (no auth) / 403 (unverified email) before looking at the token, not the uniform 404 the spec lists for "unverified"; leaks nothing about token validity. Amend spec text or map to 404.
- Notes for next session: 4.4 (adversarial cases) and 4.5 remain. Possible deadlock (500) when two admins act on each other at once (lock order owners, caller, target); add test/fix lock ordering. Missing tests: admin removes admin. npm tests for packages/sdk and control-plane-client not run here (node_modules stale); regenerated `packages/sdk/src/schema.d.ts` (Location header) is unverified.

## 2026-11-22 worker
- Task: ci-fix (macos exit 100 on #605) - done
- Verified: just quick -> ok; merged main, pushed to rerun checks
- Notes for next session: check #605 macos result; no code change was made

## 2026-11-23 worker-c
- Task: ci-fix (macos on #605) - done
- Cause: the new Postgres-backed binaries `members`, `memberships`, `orgs` were not in the nextest `portable` skip filter, so they panicked on the Docker-less macOS runner (`ls-pg-test` start). Added them to `.config/nextest.toml`.
- Verified: `just quick` -> pass; pushed once to rerun checks.
- Next: 4.4 and 4.5, then groups 5-7. PR #605 not auto-merge armed (tasks unticked).

## 2026-11-23 worker-c
- Task: 4.4 - done. Added `members_abuse_cross_org_and_token_probes_are_uniform_404` (members.rs) and adversarial case `tests/adversarial/cases/T6.sh` (README documented).
- Verified: `cargo test -p ls-control-plane --test members --test memberships` (11 passed), `bash tests/adversarial/run.sh T6` PASS, merged main (hygiene scripts pass), `just quick`.
- Not done: 4.5 stays open: `just leak-scan` and `just audit-verify` need the local stack (`just up`), not run here. Groups 5-7 (web, desktop, e2e) remain.
- Earlier red `hygiene` on #605 cleared by merging main (task-edit guard changed on main).
