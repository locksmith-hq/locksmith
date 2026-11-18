# Spec Delta

## Purpose
The gateway authenticates callers as agents (short-lived token plus grant) instead of one static token.

## MODIFIED Requirements

### Requirement: Only the gateway can decrypt
The gateway SHALL be the only component holding the KMS decrypt credential. The control-plane material endpoint SHALL return only ciphertext, the wrapped DEK and the key id, and SHALL require the gateway service token. `/v1/relay` SHALL require a valid agent token (signature, audience, expiry) and an unexpired grant for the requested secret.

#### Scenario: Material endpoint carries no plaintext
- **WHEN** the material endpoint is called with a valid service token
- **THEN** the body contains ciphertext and wrapped DEK only, and a request without the token gets 401

#### Scenario: Caller authentication
- **WHEN** `/v1/relay` is called without a valid agent token
- **THEN** it returns 401 and performs no fetch, unwrap or upstream call

#### Scenario: Caller without a grant
- **WHEN** `/v1/relay` is called with a valid agent token but no unexpired grant for the secret
- **THEN** it returns 403 and performs no fetch, unwrap or upstream call
