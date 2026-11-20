# Proposal: refactor-tls-client

## Why

Four places build the same locked-down outbound HTTPS client by hand. Each one uses rustls with the ring provider, the OS trust store through `rustls-platform-verifier`, no redirects, no proxy from the environment, and fixed timeouts:

| Copy | Location |
|---|---|
| control plane, JWKS fetch | `services/control-plane/src/auth/jwks.rs` `default_client` |
| OpenBao client | `crates/ls-envelope/src/openbao.rs` `default_client` |
| `smith` connector (blocking) | `crates/ls-connector/src/lib.rs` `client` |
| gateway | `services/gateway/src/http_client.rs` `tls` and `build_with_idle` |

They already declare their `rustls` features differently. The control plane lists no `tls12` and gets it only through feature unification from `ls-envelope`. Comments in the copies point at each other ("same setup as ls-envelope") instead of at one place.

The TLS policy is a security default, so it should change in exactly one place. Found by the lead review of the d1 and t1 merges on 2026-11-20.

## What Changes

- Add a small crate `crates/ls-http` that owns the TLS policy:
  - `tls_config()`: ring provider, safe default protocol versions with TLS 1.2 and 1.3, platform verifier, no client auth.
  - `builder()`: a `reqwest::ClientBuilder` with that TLS config, `redirect::Policy::none()` and `no_proxy()`.
  - `blocking_builder()`, behind a `blocking` feature: the same for `reqwest::blocking`.
  - Callers keep setting their own timeouts, pinning and pool options.
- Replace the four copies with calls into `ls-http`. Each caller keeps its own error type.
- There is no behaviour change.

Out of scope:
- Changing timeouts, pinning (gateway `resolve_to_addrs`) or any other per-caller option.
- New HTTP clients, and any change to `ls-proxy`'s hyper-based forwarding.
- Windows-specific work (#320).

Depends on: none.

Usable outcome: whoever next changes the TLS policy, for example to add a custom CA bundle for self-hosters, edits one function, and every outbound client follows.

## Capabilities

### New Capabilities
None. This is a pure refactor (`skip_specs: true`).

### Modified Capabilities
None.

## Impact

- New crate `crates/ls-http`, which depends on `reqwest`, `rustls` and `rustls-platform-verifier`. All three are already in `Cargo.lock` at the versions the callers use.
- `ls-envelope`, `ls-connector`, `ls-gateway` and `ls-control-plane` drop their direct `rustls-platform-verifier` dependency, and drop `rustls` where nothing else uses it.
- There are no API, data or config changes.
