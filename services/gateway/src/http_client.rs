//! The one way the gateway builds HTTP clients: rustls with the ring provider and the OS trust
//! store (same stack as `ls-envelope`), no redirects, no proxy from the environment.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// The client could not be built (TLS setup). Carries nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientBuildError;

impl std::fmt::Display for ClientBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("could not build the HTTP client")
    }
}

impl std::error::Error for ClientBuildError {}

fn tls() -> Result<rustls::ClientConfig, ClientBuildError> {
    use rustls_platform_verifier::BuilderVerifierExt as _;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| ClientBuildError)?
        .with_platform_verifier()
        .map_err(|_| ClientBuildError)?
        .with_no_client_auth())
}

/// A client that never follows redirects and ignores `HTTP(S)_PROXY`.
///
/// `pin`, when set, is `(host, addrs)`: the client connects only to those already-validated
/// addresses for `host` and never resolves it again (design decision 5, no DNS rebinding).
pub fn build(
    connect_timeout: Duration,
    timeout: Duration,
    pin: Option<(&str, &[SocketAddr])>,
) -> Result<reqwest::Client, ClientBuildError> {
    let mut b = reqwest::Client::builder()
        .tls_backend_preconfigured(tls()?)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(connect_timeout)
        .timeout(timeout)
        .pool_max_idle_per_host(0);
    if let Some((host, addrs)) = pin {
        b = b.resolve_to_addrs(host, addrs);
    }
    b.build().map_err(|_| ClientBuildError)
}
