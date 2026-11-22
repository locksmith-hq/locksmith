# Design: T6 organizations and members

## Context
`users` is keyed by `(issuer, subject)` and points at one `personal_org_id` (migration 0011); `OrgBinding` (`services/control-plane/src/auth.rs`) resolves the verified user to that org and sets `app.org_id` per transaction (A0-4, A0-5). Tenant tables use `org_id`, forced RLS and `current_org_id()`. T6 adds membership without changing that shape.

## Decisions and evidence
| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | **`memberships(org_id, user_id, role)`** with `UNIQUE (org_id, user_id)`; `personal_org_id` stays as the default org. Migration backfills an `owner` row per existing user. | Replace `personal_org_id` (breaks T1 linking and the login-time RLS settings); roles on `users` (one role per user, not per org). | Migration 0011 comments; A0-4. |
| 2 | **Org is selected per request by `X-Locksmith-Org`**, validated against memberships inside the same transaction that binds `app.org_id`. No org claim in the token. | Org id in the JWT (needs issuer config, stale after removal; rejected by T3-2); URL prefix on every route (breaks the current API and client). | Decision T3-2; OWASP ASVS V4 (server-side authorisation, never trust client-supplied tenant). |
| 3 | **Invite = 32 random bytes (base64url), SHA-256 stored**, single-use, 7-day expiry, bound to a lower-cased invited email; accept requires a verified email match. Uniform `404` on every failure. | Emailing a signed link (no mail service until N1); storing the token (a DB read would leak working links). | OWASP Forgot Password Cheat Sheet (high-entropy single-use hashed tokens, uniform responses). |
| 4 | **No email sent in T6.** The inviter copies the link; N1 later delivers it. | Adding SMTP here (new secret, new service, out of a thin slice). | Roadmap row N1 `Needs` t3 only; AGENTS.md "start small". |
| 5 | **Last-owner rule** enforced in SQL: demote/remove/leave run in one transaction that locks the org's owner rows (`SELECT ... FOR UPDATE`) and aborts if it would leave zero. | Check in application code only (races between two owners). | PostgreSQL docs, explicit locking. |
| 6 | **Roles are data, not policy.** T6 enforces only member management; everything else stays "any member acts" until T2, which reads `OrgRole` from this change. `OrgRole` is a shared type in the contract group. | Building RBAC here (T2 is `[opus]`, Cedar). | Roadmap T2 row. |
| 7 | **Lookup of a user's orgs** uses a transaction-local `app.login_user` setting (like `app.login_issuer`) so a `memberships` row is visible to its own user across orgs, in addition to the org policy. | A `BYPASSRLS` helper role (rejected by A0-4). | Migration 0011 login settings pattern. |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| none new | - | - | - | `sha2`, `rand`, `base64`, `sqlx`, `axum` are already workspace dependencies | n/a |

Nothing is built that a maintained package provides; a hosted invite or membership service was not searched for because it would put org membership outside our RLS boundary.

## Data model
- `memberships(id uuid v7, org_id, user_id, role text CHECK in (owner,admin,member), created_at)`; FK `(org_id)` and `(user_id)`; RLS `org_id = current_org_id() OR user_id = login_user`; app role may SELECT, INSERT, UPDATE(role), DELETE.
- `invites(id, org_id, email lower-cased, role, token_hash bytea UNIQUE, invited_by, expires_at, accepted_at, revoked_at)`; RLS by org; token lookup at accept binds a transaction-local `app.invite_hash` so exactly that row is visible to the accepting user.
- Org delete: refused while any `secrets` row exists; otherwise soft state is not needed (rows cascade by explicit deletes in one transaction).

## API (contract group)
`GET /v1/orgs` (mine), `POST /v1/orgs`, `PATCH /v1/orgs/{id}`, `DELETE /v1/orgs/{id}`, `GET /v1/orgs/current/members`, `PATCH .../members/{user_id}` (role), `DELETE .../members/{user_id}` (remove or leave when it is the caller), `POST .../invites`, `GET .../invites`, `DELETE .../invites/{id}`, `POST /v1/invites/accept` with the token in the body (never a query string, so it stays out of access logs).

## Risks
- Header selection must never fall back to another org on a miss: a miss is `404`, tested.
- Removing a member does not revoke an already-issued agent grant they created; grants belong to the org (documented, T2 decides more).

## Open questions
None blocking. Assumed and recorded: invite expiry 7 days, no email delivery in T6.

## How an agent debugs this
- DB: `just psql` then `select * from memberships;` / `invites` (token_hash only); with the postgres MCP server read-only.
- Logs and traces: control-plane logs `org.*` and `member.*` event names only; trace spans `org.select` and `invite.accept` in the local OTel stack.
- Ledger: `just audit-verify`, and `GET /v1/audit` filtered by the event names above.
- Tests: `cargo nextest run -p ls-control-plane org_members`; leak check `just leak-scan`.
