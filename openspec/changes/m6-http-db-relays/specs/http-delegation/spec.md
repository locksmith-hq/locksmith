# Spec Delta

## Purpose

Lets programs run by agents call third-party HTTP APIs using placeholder tokens, while real API keys are attached only inside Locksmith.

## ADDED Requirements

### Requirement: Opaque token substitution
Requests through the relay carrying a valid opaque token in its configured placement SHALL be forwarded upstream with the real credential in that placement.

#### Scenario: Stripe call
- **WHEN** an app in the session calls the relay with `Authorization: Bearer lsk_…` bound to `STRIPE_KEY`
- **THEN** Stripe receives the real key and the app receives Stripe's response

### Requirement: Host allowlist enforcement
The relay SHALL refuse to attach a credential for a host outside that token's allowlist.

#### Scenario: Exfiltration attempt
- **WHEN** a request carries the Stripe opaque token toward `evil.example`
- **THEN** the relay returns 403 without contacting the host and audits BLOCKED

### Requirement: Response cleansing
Any occurrence of the real credential in upstream response headers or bodies, including compressed bodies, SHALL be masked before reaching the client.

#### Scenario: Key echoed by API
- **WHEN** an upstream response body echoes the real key
- **THEN** the client receives the body with the key masked

### Requirement: Name-constrained local CA
When the user enables explicit-proxy mode, the generated certificate authority SHALL be technically constrained to the enabled API hosts, and SHALL be removable with one command.

#### Scenario: Out-of-scope host
- **WHEN** the CA is used to sign a certificate for a host not enabled
- **THEN** clients reject the certificate due to name constraints
