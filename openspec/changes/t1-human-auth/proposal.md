# Proposal: T1 human authentication

## Why
Every control-plane call is still bound to an org by the dev-only `X-Locksmith-Dev-Org` header (`services/control-plane/src/auth.rs`). There are no human users, so the console and desktop app cannot sign anyone in and a hosted or self-hosted deployment cannot be exposed. A0-15 fixed the approach: Cognito in our cloud, Keycloak locally, any OIDC issuer for self-hosters, and services that only verify JWTs through JWKS. T1 delivers that first human identity slice.

## What Changes
- **JWT verification in the control plane.** `OrgBinding` verifies a bearer access token against the issuer's JWKS (issuer, audience, expiry, algorithm allow-list, key rotation with cached JWKS) and resolves the user and their org. The dev header stays available only when `dev_auth` is on and is refused by default in release builds.
- **Users and personal orgs.** A `users` table (issuer + subject, email, verified flag) and a first-login hook that creates a personal org with the user as owner. Tenant isolation follows A0-4 and A0-5 (RLS); `ls-tenant-lint` covers the new tables.
- **Sign-up and sign-in** with email and password (verified email, password reset), Google and GitHub, all through the OIDC authorization-code flow with PKCE. Keycloak in `just up` is the local issuer, with a realm file checked in. Cognito appears only as configuration (issuer URL, client id) and an OpenTofu stub for P1.
- **GitHub is OAuth 2.0, not OIDC.** The design picks the brokering: Keycloak and Cognito federate GitHub; services never speak GitHub OAuth.
- **Console and desktop surfaces:** a sign-in page and callback in `apps/web`, the same flow in `apps/desktop` through the system browser and a loopback redirect, a signed-in header with sign-out, and session expiry handling. The `smith` CLI gets `smith login --user` using the device authorization grant so a human can link a terminal.
- **Audit:** sign-in, sign-out, failed verification and personal-org creation are ledger events (no tokens or passwords in them).

## Out of scope
- Organization members, invites and roles beyond a single owner (T6).
- Policy engine, RBAC and ABAC (T2); every authenticated user is the owner of their personal org for now.
- Agent identity and agent tokens (S4, unchanged); agents never use human tokens.
- Enterprise SSO (SAML, SCIM), MFA enrolment UX beyond what the issuer offers, passkeys.
- The real Cognito user pool and any AWS change (P1; owner approval for AWS spend remains required).
- Visual design of the sign-in pages beyond a plain functional layout: brand and look need owner approval before they are built on (owner decision 2026-11-18); see Open Questions in design.md.

## Depends on
`s6-adversarial-gate-1` (the gate must be green before a new public auth surface is added; T1 adds its own cases to it).

## Usable outcome
A person can sign up with email and password or with Google or GitHub, sign in to the web console and the desktop app against the local stack, and every API call is attributed to a verified user in a personal org. Nobody can call the API with the dev header unless dev auth is explicitly on.
