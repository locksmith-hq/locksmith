# Tasks: T1 human authentication

## 1. JWT verification [sonnet]
- [ ] 1.1 Re-check `jsonwebtoken` against `openidconnect` and `axum-oidc` (maintenance, licence) and record the result in design.md "OSS used"; add the chosen dependency.
- [ ] 1.2 JWKS cache (single-flight refresh, minimum interval, `kid` lookup) with unit tests against a local mock issuer.
- [ ] 1.3 `OrgBinding` extractor verifies issuer, audience, expiry and the algorithm allow-list; uniform `401` without a reason; spans `verify_jwt` without token content.
- [ ] 1.4 Verify: `cargo nextest run -p ls-control-plane auth` including forged, `none`, wrong-audience, expired and rotated-key tokens.

## 2. Dev header gating [sonnet]
- [ ] 2.1 `dev_auth` config default off; release builds refuse to start with it on without `LOCKSMITH_ALLOW_DEV_AUTH`; update existing tests and `just api` to opt in.
- [ ] 2.2 Verify: `cargo nextest run -p ls-control-plane` passes; a request with only the dev header gets `401` when `dev_auth` is off.

## 3. Users and personal orgs [sonnet]
- [ ] 3.1 Migration `0011_users.sql`: `users (id, issuer, subject, email, email_verified, created_at)` with a unique `(issuer, subject)`, RLS per A0-4/A0-5; extend `ls-tenant-lint`.
- [ ] 3.2 First-login transaction creating the user and personal org idempotently; concurrency test.
- [ ] 3.3 Email-verified gate (`403` problem type) and verified-email-only identity linking.
- [ ] 3.4 Verify: `cargo nextest run -p ls-control-plane users` and `cargo nextest run -p ls-tenant-lint`.

## 4. Local issuer [sonnet]
- [ ] 4.1 Keycloak in `infra/compose` (profile `auth`), realm JSON with the `locksmith-web`, `locksmith-desktop` and `smith-cli` clients, test users, a mail catcher for verification and reset mails, and Google/GitHub identity-provider stubs with placeholder client ids (no secrets).
- [ ] 4.2 `just auth-e2e` script: password sign-up, verify, sign-in, reset, token call to the API; social flows use Keycloak's mock IdP.
- [ ] 4.3 Verify: `just up && just auth-e2e`.

## 5. Audit and leak safety [sonnet]
- [ ] 5.1 Ledger events `auth.sign_in`, `auth.sign_out`, `auth.verify_failed`, `org.personal_created` without credentials.
- [ ] 5.2 Add a G7 case to the adversarial gate (forged and replayed human tokens, dev header, human token at agent and internal routes).
- [ ] 5.3 Verify: `just leak-scan`, `just audit-verify`, `bash tests/adversarial/run.sh gateway G7`.

## 6. Console, desktop and CLI [sonnet]
- [x] 6.0 Gate: confirm the owner approved the sign-in and onboarding UX direction (design.md Open Questions); otherwise stop here and report to the lead.
- [ ] 6.1 `apps/web`: sign-in redirect with PKCE, callback, return-to, in-memory tokens, signed-in header, sign-out, expiry handling; Vitest tests.
- [ ] 6.2 `apps/desktop`: system-browser flow with loopback redirect; tokens in the OS keystore.
- [ ] 6.3 `smith login --user` with the device grant; token in the keystore.
- [ ] 6.4 Verify: `npm run lint`, `npm test --workspace apps/web`, `cargo nextest run -p smith-cli`, `just apps-build`.

## 7. Local verification
- [ ] 7.1 `just up`, `just auth-e2e`, `just adversarial-gate`, `just leak-scan`, `just audit-verify`, `just apps-build`, then `just ci`.
