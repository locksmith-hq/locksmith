//! The one way the gateway builds HTTP clients: rustls with the ring provider and the OS trust
//! store (same stack as `ls-envelope`), no redirects, no proxy from the environment.

use std::net::SocketAddr;
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

/// A client that never follows redirects and ignores `HTTP(S)_PROXY`.
///
/// `pin`, when set, is `(host, addrs)`: the client connects only to those already-validated
/// addresses for `host` and never resolves it again (design decision 5, no DNS rebinding).
pub fn build(
    connect_timeout: Duration,
    timeout: Duration,
    pin: Option<(&str, &[SocketAddr])>,
) -> Result<reqwest::Client, ClientBuildError> {
    build_with_idle(connect_timeout, timeout, None, pin)
}

/// As [`build`], plus an idle (per-read) timeout for streamed bodies (Git, D1): `timeout` caps
/// the whole exchange, `idle` caps the wait for the next chunk.
pub fn build_with_idle(
    connect_timeout: Duration,
    timeout: Duration,
    idle: Option<Duration>,
    pin: Option<(&str, &[SocketAddr])>,
) -> Result<reqwest::Client, ClientBuildError> {
    let mut b = ls_http::builder()
        .map_err(|_| ClientBuildError)?
        .connect_timeout(connect_timeout)
        .timeout(timeout)
        .pool_max_idle_per_host(0);
    if let Some(idle) = idle {
        b = b.read_timeout(idle);
    }
    if let Some((host, addrs)) = pin {
        b = b.resolve_to_addrs(host, addrs);
    }
    b.build().map_err(|_| ClientBuildError)
}
