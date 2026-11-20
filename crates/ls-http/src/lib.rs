//! The one way Locksmith builds outbound HTTPS clients: rustls with the ring provider and the OS
//! trust store, TLS 1.2 and 1.3, no redirects, no proxy from the environment. Callers add their own
//! timeouts, pinning and pool options to the returned builder.

use std::sync::Arc;

/// The client could not be set up (TLS configuration). Carries nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildError;

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("could not build the HTTP client")
    }
}

impl std::error::Error for BuildError {}

/// The shared rustls client configuration.
pub fn tls_config() -> Result<rustls::ClientConfig, BuildError> {
    use rustls_platform_verifier::BuilderVerifierExt as _;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| BuildError)?
        .with_platform_verifier()
        .map_err(|_| BuildError)?
        .with_no_client_auth())
}

/// An async client builder that never follows redirects and ignores `HTTP(S)_PROXY`.
pub fn builder() -> Result<reqwest::ClientBuilder, BuildError> {
    Ok(reqwest::Client::builder()
        .tls_backend_preconfigured(tls_config()?)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy())
}

/// As [`builder`], for the blocking client.
#[cfg(feature = "blocking")]
pub fn blocking_builder() -> Result<reqwest::blocking::ClientBuilder, BuildError> {
    Ok(reqwest::blocking::Client::builder()
        .tls_backend_preconfigured(tls_config()?)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn does_not_follow_redirects() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/a"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/b"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/b"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let client = builder().unwrap().build().unwrap();
        let resp = client
            .get(format!("{}/a", server.uri()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 302);
    }

    /// Runs in a child process that has `HTTP_PROXY` set (the workspace forbids `unsafe`, which
    /// `set_var` needs). Ignored so it only runs through the parent test.
    #[tokio::test]
    #[ignore]
    async fn proxy_child() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = builder().unwrap().build().unwrap();
        let resp = client.get(server.uri()).send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    #[test]
    fn ignores_proxy_environment() {
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args(["--exact", "tests::proxy_child", "--ignored"])
            .env("HTTP_PROXY", "http://127.0.0.1:9")
            .env("http_proxy", "http://127.0.0.1:9")
            .env("ALL_PROXY", "http://127.0.0.1:9")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
