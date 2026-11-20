# Tasks: refactor-tls-client

## 1. Shared crate
- [ ] 1.1 Add `crates/ls-http` with `tls_config()`, `builder()` and, behind a `blocking` feature, `blocking_builder()` (design decisions 1, 2 and 4). Enable `rustls` features `ring`, `std` and `tls12`. Add unit tests asserting that a built client does not follow a 302 and does not use `HTTPS_PROXY` (wiremock).
- [ ] 1.2 Verify: `cargo nextest run -p ls-http` and `cargo clippy -p ls-http --all-targets -- -D warnings` pass, and `cargo deny check` is clean.

## 2. Callers
- [ ] 2.1 Replace `default_client` in `crates/ls-envelope/src/openbao.rs` and `client` in `crates/ls-connector/src/lib.rs` with `ls-http` calls, keeping their timeouts and error mapping (design decision 3). Drop direct `rustls-platform-verifier` deps that are no longer used. Verify: `cargo nextest run -p ls-envelope -p ls-connector`.
- [ ] 2.2 Replace `tls()` and the builder defaults in `services/gateway/src/http_client.rs` with `ls_http::builder()`, keeping pinning, the idle timeout and the pool setting. Verify: `cargo nextest run -p ls-gateway`.
- [ ] 2.3 Replace `default_client` in `services/control-plane/src/auth/jwks.rs` with `ls_http::builder()`. Verify: `cargo nextest run -p ls-control-plane -E 'test(jwks) | binary(human_auth)'`.

## 3. Local verification
- [ ] 3.1 `rg -n 'with_platform_verifier|builder_with_provider' crates services --glob '!crates/ls-http/**'` prints nothing.
- [ ] 3.2 `just up` and `just api`, then `just adversarial-gate`, `just apps-build` and `just ci`.
