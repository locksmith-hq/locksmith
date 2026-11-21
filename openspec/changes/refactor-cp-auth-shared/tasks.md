# Tasks: refactor-cp-auth-shared

## 1. Shared JWT pre-checks [sonnet]
- [ ] 1.1 Add `services/control-plane/src/auth/jwt.rs` with `LEEWAY_SECS`, `MAX_TOKEN_BYTES`, `ALLOWED`, `pre_check`, `pin_alg` and `validation` (design decisions 1, 2); register it in `auth.rs`. Unit tests: oversized, malformed, `none`/`HS256`, missing `kid`, key/header alg mismatch, each with today's label.
- [ ] 1.2 Switch `auth/human.rs` `verify_inner` to the shared functions; remove its three constants (re-export from `jwt` if other code imports them).
- [ ] 1.3 Switch `auth/external.rs` `verify_inner`, keeping the unverified-issuer check before the key fetch and `check_lifetime` after decode; remove its duplicated constants.
- [ ] 1.4 Verify: `cargo nextest run -p ls-control-plane -E 'binary(human_auth) | binary(workload_verify) | binary(workload_exchange) | test(jwt)'`; `rg -n 'const (LEEWAY_SECS|MAX_TOKEN_BYTES|ALLOWED)' services/control-plane/src` lists only `auth/jwt.rs`.

## 2. Capped read in ls-http [sonnet]
- [ ] 2.1 Add `read_capped(response, max) -> Result<Vec<u8>, CapError>` to `crates/ls-http` with tests (under cap, over cap with and without `Content-Length`, exact cap) against a local `wiremock` server (design decision 3).
- [ ] 2.2 Use it in `auth/jwks.rs` and `auth/issuers.rs` `fetch_capped`, mapping errors to today's labels and `IssuerError` values.
- [ ] 2.3 Verify: `cargo nextest run -p ls-http -p ls-control-plane -E 'test(jwks) | test(issuers) | test(capped)'`.

## 3. Workload audit attributes [haiku]
- [ ] 3.1 Add private `workload_attrs` in `services/control-plane/src/audit.rs` and use it in the three workload builders (design decision 4).
- [ ] 3.2 Verify: `cargo nextest run -p ls-control-plane -E 'binary(audit) | binary(workload_exchange) | binary(workload_identities)'`.

## 4. Local verification [haiku]
- [ ] 4.1 `git diff origin/main --stat -- ':!openspec'` touches only the files in the proposal's Impact, and `git diff origin/main -- services/control-plane/tests` shows no changed `assert`.
- [ ] 4.2 `cargo nextest run -p ls-control-plane -p ls-http`, then `just quick`.
