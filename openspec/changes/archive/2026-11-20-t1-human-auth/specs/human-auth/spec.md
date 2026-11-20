# Spec Delta

## Purpose
Human sign-up, sign-in and request authentication for the control plane, console and desktop app, using generic OIDC.

## ADDED Requirements

### Requirement: Requests are authenticated by verified JWTs
The control plane SHALL bind a request to a user and org only after verifying a bearer access token's signature against the configured issuer's JWKS, its issuer, audience and expiry, and an algorithm allow-list that excludes `none` and symmetric algorithms. It SHALL NOT call any issuer-specific SDK on the request path.

#### Scenario: Valid token
- **WHEN** a request carries a valid token for a known user
- **THEN** the handler sees that user's personal org binding

#### Scenario: Invalid token
- **WHEN** the token is expired, has the wrong issuer or audience, is unsigned, uses an unlisted algorithm or an unknown `kid` after a JWKS refresh
- **THEN** the response is `401` problem details that do not say why

#### Scenario: Key rotation
- **WHEN** the issuer publishes a new key and signs with it
- **THEN** the next request refreshes the JWKS once (rate limited) and succeeds

### Requirement: The dev org header is off by default
The `X-Locksmith-Dev-Org` header SHALL be honoured only when `dev_auth` is explicitly enabled, and release builds SHALL refuse to start with it enabled unless an explicit override flag is set.

#### Scenario: Header with dev auth off
- **WHEN** a request sends only the dev header
- **THEN** it receives `401`

### Requirement: First sign-in creates a user and a personal org
A first successful sign-in SHALL create a user keyed by issuer and subject and a personal org owned by that user, atomically and idempotently.

#### Scenario: Concurrent first requests
- **WHEN** two requests with the same new subject arrive together
- **THEN** exactly one user and one org exist afterwards

### Requirement: Unverified email cannot use the API
A user whose email is not verified SHALL receive `403` from every route except those that resend verification or sign out.

#### Scenario: Unverified user
- **WHEN** a password sign-up has not confirmed its email
- **THEN** API calls return `403` with a problem type naming "email verification required"

### Requirement: Sign-in methods
The local issuer SHALL offer email and password with verification and reset, Google, and GitHub, via authorization code with PKCE. Self-hosters MAY point the services at any OIDC issuer by configuration only.

#### Scenario: Social login linked by verified email
- **WHEN** a user signs in with Google and later GitHub using the same verified email
- **THEN** both identities resolve to one user, and an unverified email is never linked automatically

### Requirement: Auth events are audited without credentials
Sign-in, sign-out, failed verification and personal-org creation SHALL be appended to the audit ledger. No event, log line or trace SHALL contain a token, authorization code, password or client secret.

#### Scenario: Leak scan after sign-in flows
- **WHEN** the e2e sign-in flows have run
- **THEN** `just leak-scan` finds no canary token or password in the database, logs or traces

### Requirement: Console, desktop and CLI sign-in
The web console SHALL sign in with the browser redirect flow, the desktop app through the system browser and a loopback redirect, and `smith login --user` through the device authorization grant. Tokens SHALL be kept in memory or the OS keystore, never in `localStorage`.

#### Scenario: Signed-out console
- **WHEN** an unauthenticated visitor opens the console
- **THEN** they are sent to sign in, and after signing in return to the page they asked for
