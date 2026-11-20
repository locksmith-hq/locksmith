# Design: refactor-tls-client

## Context

See proposal.md, "Why". All four copies use `reqwest` 0.13.5 with `rustls-no-provider`, `rustls` 0.23.46 and `rustls-platform-verifier` 0.7.1. Only `ls-connector` uses the blocking client. Only the gateway adds address pinning, an idle timeout and `pool_max_idle_per_host(0)`.

## Goals / Non-Goals

**Goals:**
- One function owns the TLS policy (provider, protocol versions, verifier) and the no-redirect and no-proxy defaults.
- The callers' observable behaviour stays the same, except that JWKS fetches gain TLS 1.2.

**Non-Goals:**
- A general HTTP abstraction. Callers still use `reqwest` types directly.
- Moving timeouts into the shared crate.

## Decisions

### 1. A new leaf crate, not an existing one
`ls-envelope` and `ls-crypto` are about key material, and `ls-connector` is the CLI side. The gateway and the control plane both need the client, and neither should depend on the other's crate for it. A leaf crate `ls-http` that depends only on `reqwest` and `rustls` adds no new edges between existing crates.

### 2. Return a builder, not a finished client
The callers differ in timeouts, pinning (`resolve_to_addrs`), read timeout and pool size. If the shared function returned a builder, each caller would add its own options. A finished client with an options struct would grow a field per caller and reintroduce over-specific code.

### 3. Keep each caller's error type
`ls-http` returns a single opaque `BuildError`. Each caller maps it to the variant it already has (`JwksError::Client`, `WrapError::Client`, `ClientBuildError`, connector `fail`). Error messages and HTTP problem types do not change.

### 4. Enable `tls12` in one place
`ls-http` enables `rustls/tls12`. Cargo feature unification already turns it on for the control-plane binary when the gateway or envelope crates are in the same build, but not when the binary is built alone. Owning the feature in `ls-http` makes it explicit.

### Decisions and evidence

| Decision | Alternatives rejected | Evidence |
|---|---|---|
| Leaf crate `ls-http` | Put it in `ls-envelope` (wrong concern, and the gateway already avoids that edge); keep four copies | The four copies are listed in proposal.md, Why; lead review 2026-11-20 |
| Return a `ClientBuilder` | An options struct | Gateway `build_with_idle` needs `resolve_to_addrs`, `read_timeout` and `pool_max_idle_per_host`, which no other caller uses |
| TLS 1.2 + 1.3 | TLS 1.3 only | 3 of 4 clients already allow 1.2. Self-hosted OpenBao and Keycloak deployments may still serve 1.2 |

## OSS used

| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| reqwest | MIT/Apache-2.0 | 0.13.5 | already in tree | HTTP client used by all four callers | compatible |
| rustls | MIT/Apache-2.0/ISC | 0.23.46 | already in tree | TLS | compatible |
| rustls-platform-verifier | MIT/Apache-2.0 | 0.7.1 | already in tree | OS trust store | compatible |

Nothing new enters `Cargo.lock`. The wrapper is about 40 lines of glue. No crate packages "reqwest with a preconfigured rustls policy", and the policy is ours to own.

## Risks / Trade-offs

- [The gateway's adversarial tests rely on exact client behaviour (no redirects, pinning)] → The gateway keeps adding pinning itself. G-series cases and `cargo nextest run -p ls-gateway` must pass unchanged.
- [A forgotten fifth copy] → Task 3.1 greps for `with_platform_verifier` and `builder_with_provider` outside `crates/ls-http`, and the grep must find nothing.

## Migration Plan

Code only, with no deploy steps. Rollback is a revert.

## How an agent debugs this

- `cargo nextest run -p ls-http -p ls-envelope -p ls-connector -p ls-gateway -p ls-control-plane`
- JWKS: `services/control-plane/tests/human_auth.rs` (wiremock issuer).
- OpenBao: `just up`, then the `ls-envelope` integration tests. Gateway: `just api`, then `just adversarial-gate` (G1–G8).
- Logs: the control-plane and gateway `tracing` output in `just up` (Grafana/Loki MCP).
- No DB tables are involved.
