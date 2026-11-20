# Design: T1 human authentication

## Context
- `services/control-plane/src/auth.rs` exposes `OrgBinding` (dev header) and `ServiceOrgBinding` (gateway static token). Handlers depend only on `OrgBinding`, so T1 replaces the extractor and no handler changes.
- Binding decisions: A0-4 and A0-5 (RLS tenancy), A0-11 (ledger), A0-14 (Keycloak as the local OIDC stand-in), A0-15 (Cognito in cloud, any OIDC for self-host, JWKS-verified JWTs only, no Cognito SDK on the request path).
- `jsonwebtoken` is already in the lockfile (transitive). Compose has no Keycloak yet.
- Agents are unchanged: agent tokens (S4) are a separate credential type and a human token is never accepted at agent or gateway routes.

## Goals / Non-Goals
**Goals:** verified human identity on every control-plane request; sign-up and sign-in on web, desktop and CLI against a local issuer; personal org on first login.
**Non-Goals:** org members and roles (T6), policy (T2), enterprise SSO, real Cognito (P1), brand design.

## Decisions and evidence
| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | **Verify JWTs in the control plane with `jsonwebtoken` plus a small cached JWKS client** (RS256/ES256 allow-list, 60 s leeway, one rate-limited refresh on unknown `kid`). | A full OIDC client crate in the resource server (not needed: it only verifies); an auth proxy sidecar (extra moving part, hides identity from RLS binding). | A0-15; RFC 8725 (JWT best practices); `jsonwebtoken` already in the lockfile. **[verify version and last release at apply]** |
| 2 | **Keycloak (realm JSON imported at start) is the local issuer** in `just up`, pinned to a Docker Hub-reachable image (`quay.io` and `ghcr.io` may be blocked in the agent VM: pick the mirror that resolves at apply and record it). | Dex (no password store or email verification), Authentik/ZITADEL (heavier, less parity with Cognito flows), moto's Cognito (no browser flow). | A0-14 names Keycloak. Verified at apply 2026-11-19: `keycloak/keycloak:26.0.8` from Docker Hub (`docker manifest inspect`), Apache-2.0; `quay.io` is blocked in the agent VM. Mail catcher `axllent/mailpit:v1.21.8` (MIT). |
| 3 | **GitHub is brokered by the issuer.** Keycloak has a built-in GitHub identity provider; Cognito reaches GitHub through an OIDC-compatible wrapper or a Lambda shim decided in P1. Services only see an OIDC token. | Speaking GitHub OAuth in our service (duplicates provider logic, leaks the second protocol into the resource server). | Keycloak server docs, "Identity Brokering"; GitHub OAuth is OAuth 2.0 only (no `id_token`). **[verify Cognito path at P1]** |
| 4 | **Authorization code + PKCE for web and desktop; device grant (RFC 8628) for `smith login --user`.** | Implicit flow (deprecated, RFC 9700); password grant (removed in OAuth 2.1). | OAuth 2.0 Security BCP (RFC 9700). |
| 5 | **Tokens live in memory (web) and the OS keystore (desktop, via the `keyring` crate); refresh via a refresh token rotation handled by the issuer.** Never `localStorage`. | `localStorage` (XSS-readable); cookies with a BFF (more infrastructure than a first slice needs; revisit for hosted). | OWASP HTML5 Security cheat sheet; `keyring` (MIT/Apache-2.0) **[verify]**. |
| 6 | **Users table keyed by `(issuer, subject)`; personal org created in one transaction with `INSERT ... ON CONFLICT`.** Identity linking only by verified email. | Keying by email (account takeover on unverified email); creating orgs lazily on the first org call (races). | Account-takeover class documented in OIDC Core §5.7 (`sub` is the stable key). |
| 7 | **Dev header off by default; release build refuses to start if on.** | Keeping it on in dev images (it would ship). | Current `auth.rs` header comment. |
| 8 | **Claims used:** `iss`, `aud`, `exp`, `sub`, `email`, `email_verified`. No role claims (T6/T2 own roles). | Trusting issuer-supplied groups now (couples policy to an issuer). | A0-15. |
| 9 | **Sign-in UX is option C (owner-approved, [#397](https://github.com/locksmith-hq/locksmith/issues/397)):** our own first screen offers "Continue with GitHub / Google / email"; GitHub and Google go straight to that provider through the issuer's hint parameter (`kc_idp_hint` for Keycloak, `identity_provider` for Cognito); email goes to the issuer's hosted page with our theme. A self-hoster's own OIDC issuer gets one "Continue" button. First run: land on the hub Overview, personal org created automatically with no setup form, and a dismissible "Get started" checklist (`smith login --user`, desktop app, first agent). Visual style uses the existing desktop and hub mockup tokens. | A: hosted page only (issuer's layout, weaker first impression). B: our own password pages via the issuer API (passwords through our code, needs a non-PKCE flow that contradicts decision 4, rebuilds MFA, reset and lockout; 2 to 3x the work). | Owner reply "Approved C" on #397 (2026-11-19); brief https://claude.ai/artifact/4H2DZtpZTEufP1euDYBQeY. Keeps credentials, MFA and recovery with the issuer (decision 4, A0-15). |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| jsonwebtoken | MIT | 12.0.0 (lockfile; `rust_crypto` backend) | 2026-11-13 | JWT verification | not AGPL |
| reqwest | MIT OR Apache-2.0 | 0.13.5 (lockfile; rustls, no default features) | 2026-09-08 | JWKS fetch | not AGPL |
| keyring | MIT/Apache-2.0 | **[verify]** | **[verify]** | desktop token storage | not AGPL |
| Keycloak | Apache-2.0 | 26.0.8 (image `keycloak/keycloak:26.0.8`, Docker Hub; `quay.io` is blocked in the agent VM) | 26.0.8 (26.0.x line) | local issuer, compose only (`start-dev`), not shipped | not AGPL |
| oidc-client-ts (web) | Apache-2.0 | 3.5.0 (pinned in `apps/web/package.json`; depends only on `jwt-decode`) | 2026-03-13 | PKCE flow in `apps/web`; `InMemoryWebStorage` user store, so tokens never reach web storage (only the transient PKCE state, which holds no token, uses `sessionStorage`) | not AGPL |

Built in-house: the JWKS cache and the `OrgBinding` extractor (about 200 lines). Searched first: `openidconnect`, `axum-oidc` and `jwks-client` crates; they bundle a client flow or an unmaintained cache. The choice between them and the small in-house cache is re-checked at task 1.1.

## Risks / Trade-offs
- [Algorithm confusion or `none` tokens] → algorithm allow-list per key type, tests with forged tokens (also added to the S6 gate as a G7 case).
- [JWKS fetch becomes a DoS lever] → cache with a single-flight refresh and a minimum refresh interval.
- [Keycloak adds startup time and RAM to `just up`] → profile it behind a compose profile `auth`; `just up` starts it, `just up-lite` skips it.
- [Email linking enables takeover] → link only on `email_verified=true` from a trusted issuer; otherwise create a separate user.
- [Looks and flows drift from the approved direction] → pages follow decision 9 (option C, #397) and the existing mockup tokens.

## How an agent debugs this
- `just up` (with Keycloak), `just api`; `curl` the realm at `http://localhost:<port>/realms/locksmith/.well-known/openid-configuration`.
- Postgres MCP: `select id, issuer, subject, email_verified from users`, `select * from audit_events where kind like 'auth.%' order by at desc limit 50`.
- Grafana/Tempo spans `verify_jwt` (attributes: issuer, outcome, never the token); Loki `{service="control-plane"} |= "auth"`.
- `just auth-e2e` runs the flows; `just leak-scan` and `just audit-verify` afterwards.

## Open Questions
- ~~Owner approval needed before building pages~~ **Resolved 2026-11-19:** the owner approved option C for sign-in and the shared first run ([#397](https://github.com/locksmith-hq/locksmith/issues/397)); see decision 9 and `openspec/decisions.md` T1-1. Tasks 6.x may start once groups 1 to 5 are done.
- Cognito's GitHub path (decision 3) is deferred to P1; no AWS action in T1.
- Whether the hosted console should use a BFF cookie session instead of in-memory tokens (decision 5).
