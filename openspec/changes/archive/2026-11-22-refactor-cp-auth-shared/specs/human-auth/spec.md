## ADDED Requirements

### Requirement: Token verification rules have a single implementation
The token size cap, the accepted algorithms, the clock leeway, the rule that the signing key (not the token header) fixes the algorithm, and the capped read of issuer documents SHALL each have one implementation in the control plane, used by both human-token and workload-token verification. Sharing SHALL NOT change any observable behaviour: refusal reasons, span fields, audit attributes and fetch limits stay as they were.

#### Scenario: Algorithm rules are shared
- **WHEN** a human token or a workload token names `none`, `HS256`, or an algorithm different from its key's
- **THEN** both are refused with reason `algorithm`, as before

#### Scenario: Oversized token is refused before parsing
- **WHEN** a human or workload token is longer than 8 KiB
- **THEN** it is refused with reason `too_large` before any key lookup or fetch

#### Scenario: Oversized issuer document is refused
- **WHEN** an issuer's JWKS or discovery document exceeds its byte cap, with or without a `Content-Length` header
- **THEN** the fetch fails with the same error as before and nothing is cached

#### Scenario: Existing tests pass unchanged
- **WHEN** `tests/human_auth.rs`, `tests/workload_verify.rs`, `tests/workload_exchange.rs` and the `jwks` and `issuers` unit tests run after the change
- **THEN** they pass with no assertion edited
