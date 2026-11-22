# Design: refactor-cp-auth-shared

## Decisions

1. **Share the pre-decode steps, not the whole verifier.** Human and external verification differ in key source (one `JwksCache` vs per-issuer registry), required claims (`iat` only for workloads), claim type (struct vs `Map`) and post-checks (`check_lifetime`, the unverified-issuer shortcut before any fetch). A single `verify` would need many parameters; sharing `pre_check`, `pin_alg` and `validation` removes every duplicated security rule while each verifier stays readable. The order of checks must not change: the external verifier still rejects a foreign `iss` before fetching a key.
2. **`Refused` labels are unchanged.** `pre_check` returns the same static labels (`too_large`, `malformed`, `algorithm`, `no_kid`); tests in `tests/human_auth.rs` and `tests/workload_verify.rs` assert them and must pass without edits.
3. **`read_capped` lives in `ls-http`.** It is the crate that already builds every outbound client; the error type is generic (`TooLarge`, `Transport`) and each caller maps it, so `jwks.rs` keeps `"too_large"` / `"transport"` and `issuers.rs` keeps `IssuerError::Unavailable`. Status checks stay in the callers (they map statuses differently).
4. **Audit helper is private.** `workload_attrs` builds only the shared prefix; each builder still adds its own outcome and reason attributes.
