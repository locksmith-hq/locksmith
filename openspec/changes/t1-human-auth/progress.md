# Progress: T1 human authentication (append-only)

- 2026-11-19 · planning only: proposal, spec, design and tasks written by a worker; no code. Next: obtain owner approval for the sign-in UX direction before task 6.0.

## 2026-11-19 11:52 worker
- Task: planning - done
- Verified: openspec validate t1-human-auth -> valid; tree-check OK
- Notes for next session: task 6.0 is gated on owner approval of sign-in UX; verify OSS versions at apply.

## 2026-11-19 16:15 worker
- Task: 1.1-1.4 JWT verification (jsonwebtoken kept; JWKS cache, OrgBinding, forged/none/aud/exp/rotation tests) - done
- Verified: just ci -> green; nextest -p ls-control-plane auth -> pass; independent evaluator PASS
- Notes for next session: personal_org_id is an interim UUIDv5(issuer,sub) until 3.2 creates real personal orgs; no RS256 signing round-trip test (ES256 only); telemetry_export test updated since a bearer is no longer downgraded to the dev header; 2.x next (dev_auth gating), 6.0 gated on owner UX approval.

## 2026-11-19 18:00 worker
- Task: 2.1, 2.2 - done
- Verified: `cargo nextest run -p ls-control-plane config` -> 15 passed; `just ci` -> exit 0; Sonnet evaluator PASS
- Notes for next session: `dev_auth` was already default off; added `LOCKSMITH_ALLOW_DEV_AUTH` override check (release builds only, unit-tested via a bool) and `just api` sets it. Group 3 (users, personal orgs) next; 6.0 still gated on owner UX approval (recorded T1-1 approved in decisions).

## 2026-11-19 worker (b)
- Task: 3.1-3.4 - done
- Verified: `cargo nextest run -p ls-control-plane users` (8) and `-p ls-tenant-lint` (5) pass; `just ci` exit 0 (725 tests); Sonnet evaluator PASS
- Notes for next session: `users.resolve` runs in `Database::with_login` (advisory lock per identity; users RLS admits the bound login identity and verified email). Open risk: two different identities with the same verified email signing in concurrently for the first time can each create an org (add an email-keyed lock if it matters). Every human request does a DB read in the extractor (no cache). 3.3 exemption for resend-verification/sign-out routes is needed when those routes exist. Next: 4.x (Keycloak) and 5.x; 6.1+ web.

## 2026-11-19 worker (a)
- Task: 4.1, 4.2, 4.3 - done
- Verified: `just up` (Keycloak keycloak/keycloak:26.0.8 from Docker Hub, quay.io is blocked; mailpit v1.21.8), `just api` in background, `just auth-e2e` -> all checks passed (re-run by the worker after the implementer); `just ci` -> exit 0; Sonnet evaluator PASS
- Deviation: 4.2 social flows only test the `kc_idp_hint` redirect up to the provider authorize URL with a placeholder client id (no mock IdP); device grant is started, not approved; unverified-user 403 is covered by unit tests, as Keycloak issues no token to unverified users.
- Notes for next session: 5.x (ledger auth events, G7 adversarial case), then 6.1-6.4 web/desktop/CLI. `just up` now starts the `auth` profile; `just up-lite` skips it. Stack: `just up && just api`.

## 2026-11-19 worker (c)
- Task: 5.1 - done
- Verified: `cargo nextest run -p ls-control-plane` (131 passed, 4 new in tests/human_auth.rs), clippy clean, `just ci` -> exit 0 (729 tests); Sonnet evaluator PASS
- Deviation: `auth.verify_failed` is ledgered only for a known user with an unverified email (the ledger chain is per org; a forged or unknown token has no trustworthy org, and a global sink would invite flooding). `auth.sign_in`/`auth.sign_out` are new `POST /v1/auth/sign-in` and `/sign-out` routes (204, human bearer only), since a per-request event would serialize on the org head lock; sign-out is stateless. `org.personal_created` is appended in the first-login transaction. Event attrs: issuer host and static reason only.
- Notes for next session: 5.2 (G7 case in the adversarial gate) and 5.3 next, then 6.1-6.4 and 7.1. If bad-token failures must be ledgered, it needs a system-level chain decision (lead).
