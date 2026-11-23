# Spec Delta

## Purpose

Defines the internal Rust core that the NestJS API calls for audit integrity, token mint and verify, and key wrap, so the API never holds key bytes.

## ADDED Requirements

### Requirement: The core owns key and audit operations
The core SHALL expose audit append and checkpoint signing, agent-token and workload-token mint and verify, and DEK wrap and unwrap through KMS, and SHALL return only ids, ciphertext, tokens and verdicts, never key bytes or plaintext secret values.

#### Scenario: Wrap and unwrap round trip
- **WHEN** a caller wraps a DEK and then unwraps the result
- **THEN** the core returns the wrapped DEK and later the same DEK handle, and no key bytes appear in the core's logs or traces (`just leak-scan`)

#### Scenario: Audit append is chained
- **WHEN** a caller appends two audit events for an org
- **THEN** the second event's hash chains to the first and `just audit-verify` passes

### Requirement: Only authenticated internal callers
The core SHALL refuse any request without valid caller authentication.

#### Scenario: Unauthenticated caller
- **WHEN** a request reaches the core without caller credentials
- **THEN** it returns 401 and performs no operation
