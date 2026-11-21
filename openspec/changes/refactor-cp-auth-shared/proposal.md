# Proposal: refactor-cp-auth-shared

## Why

The lead review of the merged d4-workload-identity change (#530) found the control plane's token-verification and issuer-fetch code written twice. The duplicated part is the security-critical algorithm pinning, so a later change to one copy (for example allowing EdDSA, or a new size cap) can silently miss the other.

| # | Duplicated code | Locations (origin/main at c8ea55e) |
|---|---|---|
| a | `LEEWAY_SECS`, `MAX_TOKEN_BYTES`, `ALLOWED` declared twice; the same pre-decode sequence (size cap, `decode_header`, `ALLOWED`, `kid`, key lookup, `key.alg != header.alg`) and `Validation` setup | `services/control-plane/src/auth/human.rs:20-24`, `:109-137`; `auth/external.rs:31-38`, `:132-168` |
| b | Capped HTTP body read (`content_length` check plus `chunk()` loop with a byte cap) | `auth/jwks.rs:173-187`; `auth/issuers.rs:262-288` `fetch_capped` |
| c | The same three attribute blocks (`AGENT_ID`, `issuer_host`, `claims_text`) copied into each workload audit builder | `src/audit.rs` `workload_identity_created`, `workload_identity_exchanged`, `workload_identity_denied` |

## What Changes

- `auth`: a new `auth/jwt.rs` owns `LEEWAY_SECS`, `MAX_TOKEN_BYTES`, `ALLOWED`, `pre_check(token) -> Result<(Header, &str kid), Refused>` and `validation(key_alg, issuer, audience, required_claims) -> Validation`, plus `pin_alg(key, header)`. `human.rs` and `external.rs` call them; each keeps its own key source, claim type and post-decode checks (`check_lifetime`, the unverified-issuer shortcut). `Refused` labels stay the same.
- `ls-http`: gains `read_capped(response, max) -> Result<Vec<u8>, CapError>` (`TooLarge`, `Transport`), with the `content_length` pre-check. `jwks.rs` and `issuers.rs` map `CapError` to their existing labels and errors.
- `audit.rs`: one private `workload_attrs(agent_id, issuer, claims) -> Attrs` used by the three workload builders.
- No behaviour change: refusal labels, span fields, audit attributes, HTTP limits and error mapping stay as they are.

Out of scope:
- The gateway and `ls-envelope` capped reads (`services/gateway/src/auth.rs`, `decrypt.rs`, `crates/ls-envelope/src/openbao.rs`): they may adopt `read_capped` later, not here.
- Adding or removing an algorithm, changing leeway or caps.
- `config.rs` numeric env parsing styles.

Depends on: none (d4-workload-identity is merged).

Usable outcome: the next change to accepted JWT algorithms, token size, leeway or fetch caps edits one function, and both human and workload tokens follow.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
- `human-auth`: one added requirement, that human and workload token verification share one pre-decode and validation implementation with unchanged behaviour.

## Impact

- `services/control-plane` (new `src/auth/jwt.rs`; edits in `auth.rs`, `auth/human.rs`, `auth/external.rs`, `auth/jwks.rs`, `auth/issuers.rs`, `audit.rs`), `crates/ls-http` (new function; `reqwest` is already its dependency).
- No API, data, schema, config or `Cargo.lock` changes.
