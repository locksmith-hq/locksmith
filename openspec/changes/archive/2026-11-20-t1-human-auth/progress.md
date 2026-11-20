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

## 2026-11-19 worker (events)
- Task: 5.2, 5.3 - done
- Verified: `bash tests/adversarial/run.sh gateway G7` PASS (real Keycloak token; forged, dev-header-off, agent/internal routes all 401); `just leak-scan` clean; `just audit-verify` ok; `just ci` exit 0 (first run had one load-induced timeout in smith-cli http test, passes alone and on rerun)
- Notes for next session: expired-but-signed token not testable from a case (unit-covered); sign-out replay not asserted (stateless by design). Next: 6.1-6.4 web/desktop/CLI, then 7.1.

## 2026-11-19 worker (b, run 2)
- Task: 6.1 - done
- Verified: `npm test --workspace apps/web` 19 passed (10 new); `just ci` exit 0; Sonnet evaluator PASS
- Deviation: oidc-client-ts 3.5.0 with InMemoryWebStorage; only PKCE state (no tokens) uses sessionStorage. Overview landing and "Get started" checklist not built yet; dev Org id input removed (org comes from the bearer).
- Notes for next session: 6.2 desktop (loopback + keyring), 6.3 `smith login --user` (device grant), 6.4, then 7.1. Follow-up: Overview landing page and checklist from decision 9.

## 2026-11-19 worker (c)
- Task: 6.2 - done
- Verified: `cargo test` desktop crate 23 passed, clippy -D warnings clean; `just ci` exit 0 (first run failed on stale node_modules, `npm ci` fixed it); Sonnet evaluator PASS
- Deviation: keyring pinned 3.6.3 (4.x changes the store API); real keyring store has no unit test (no secret service on the VM); no webview UI wiring yet (Rust commands sign_in/sign_out/auth_status only). Evaluator nits fixed: manual Debug on Callback, fixed error text, no partial keystore writes.
- Notes for next session: 6.3 `smith login --user` (device grant, keystore), 6.4, then 7.1. Follow-ups: desktop webview sign-in button; Overview landing and checklist.

## 2026-11-19 worker (event, #477)
- Task: 6.3 - done
- Verified: `cargo nextest run -p smith-cli` 129 passed; clippy -D warnings clean; `just ci` exit 0 (after `npm ci` for stale node_modules); Sonnet evaluator PASS
- Deviation: oauth2 5.0.0 (ureq) with a ~35-line SyncHttpClient wrapper, because stock ureq 2 maps 4xx to errors and hides authorization_pending/access_denied. deny.toml ignores RUSTSEC-2026-0543 (chrono unmaintained via oauth2). Real keyring store untested (no secret service on VM). Evaluator nit: transient non-zeroized String copy of the access token before SecretString.
- Notes for next session: 6.4 (web lint/test, smith-cli tests, `just apps-build`), then 7.1. Realm needs a `locksmith-cli` client with the device grant enabled.

## 2026-11-19 worker (b, run 3)
- Task: 6.4 - done
- Verified: `npm run lint`, `npm test --workspace apps/web`, `cargo nextest run -p smith-cli` (129), `just apps-build` all exit 0 after merging main in (resolved the App.tsx import conflict, keeping both sides)
- Notes for next session: only 7.1 remains (`just up`, `auth-e2e`, `adversarial-gate`, `leak-scan`, `audit-verify`, `apps-build`, `just ci`), then archive and mark the PR ready. Run `npm ci` after checking out the branch, not before.

## 2026-11-20 worker (c)
- Task: 7.1 - done
- Verified: `just up`, `just auth-e2e` all checks passed, `just adversarial-gate` PASS (incl. leak-scan), `just audit-verify` ok, `just apps-build`, `just ci` exit 0 (746 tests)
- Fix: G5's coverage sweep required a valid call for the new human-only `auth_sign_in`/`auth_sign_out`; G5 now probes them with no auth, dev header and agent token (all 401) in mode `human-refused`; the real human-token path is G7's.
- Notes for next session: change complete; archived in the same PR. VM disk allowance fills after a cold `just ci` plus the stack (~15 GB target); `rm -rf target` frees it.

## 2026-11-20 lead (rescue #491)
- Cause: `auth_garbage_kids_cannot_turn_requests_into_a_fetch_storm` ran 30 requests inside a 300 ms JWKS refresh window; on a loaded runner the loop outlasted it and a second fetch fired (2 vs 1). The rotation test had the same race on its 5 in-window requests. The cache uses `std::time::Instant`, so tokio paused time cannot help.
- Fix: test-only. `Issuer::app_with_refresh`; the garbage-kids test uses a 3600 s interval; the shared test interval is 1 s (was 300 ms), so the rotation test keeps proving rate limiting and a refresh after the interval.
- Verified: under CPU load (3x nproc busy loops, load ~14-17) the old code failed `cargo nextest run -p ls-control-plane --test human_auth --retries 0` 5/5 runs, the new code passed 6/6; `just ci` exit 0 (770 tests); Sonnet evaluator PASS.
- Note: `auth_verify_span_has_no_token_content` fails under plain `cargo test` (shared process; tracing callsite interest cached by another test), before and after this fix. nextest isolates tests, so CI is unaffected.
