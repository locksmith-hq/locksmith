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

/// Why [`read_capped`] stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    /// The body is larger than the cap (by `Content-Length` or by bytes read).
    TooLarge,
    /// The connection failed while reading the body.
    Transport,
}

/// Read a response body of at most `max` bytes. A `Content-Length` above the cap is refused
/// before reading; otherwise the body is read in chunks and refused as soon as it passes the
/// cap, so memory stays bounded for a server that lies about or omits the length. Status
/// checks stay with the caller.
pub async fn read_capped(mut response: reqwest::Response, max: usize) -> Result<Vec<u8>, CapError> {
    if response.content_length().is_some_and(|n| n > max as u64) {
        return Err(CapError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| CapError::Transport)? {
        if body.len().saturating_add(chunk.len()) > max {
            return Err(CapError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
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

    async fn get(server: &MockServer, body: Vec<u8>) -> reqwest::Response {
        Mock::given(method("GET"))
            .and(path("/body"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(server)
            .await;
        builder()
            .unwrap()
            .build()
            .unwrap()
            .get(format!("{}/body", server.uri()))
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn capped_read_under_and_exact_cap() {
        let server = MockServer::start().await;
        let resp = get(&server, vec![7; 10]).await;
        assert_eq!(read_capped(resp, 10).await.unwrap(), vec![7; 10]);
        let resp = get(&server, vec![7; 10]).await;
        assert_eq!(read_capped(resp, 100).await.unwrap().len(), 10);
    }

    #[tokio::test]
    async fn capped_read_over_cap_with_content_length() {
        let server = MockServer::start().await;
        let resp = get(&server, vec![7; 11]).await;
        assert!(resp.content_length().is_some());
        assert_eq!(read_capped(resp, 10).await, Err(CapError::TooLarge));
    }

    #[tokio::test]
    async fn capped_read_over_cap_without_content_length() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        // Chunked body, no Content-Length: only the byte count can stop it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                .await;
            for _ in 0..3 {
                let _ = sock.write_all(b"6\r\nabcdef\r\n").await;
            }
            let _ = sock.write_all(b"0\r\n\r\n").await;
        });
        let resp = builder()
            .unwrap()
            .build()
            .unwrap()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap();
        assert!(resp.content_length().is_none());
        assert_eq!(read_capped(resp, 10).await, Err(CapError::TooLarge));
    }
}
