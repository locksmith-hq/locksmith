//! Egress rules for relayed calls (S3 design decision 5), checked before any key is unwrapped:
//!
//! 1. The target's origin (`scheme://host:port`) must equal the binding's origin exactly.
//! 2. The host is resolved once. Every address must be public: loopback, RFC 1918, link-local,
//!    CGNAT, ULA, unspecified and multicast are refused unless the binding sets
//!    `allow_private_hosts` (the local mock upstream). Cloud metadata addresses are refused
//!    always. The address checks are `ls-proxy`'s network guard (`is_private`, `is_metadata`).
//! 3. The upstream client is pinned to exactly those addresses ([`EgressTarget::client`]), so a
//!    second DNS answer (rebinding) cannot move the connection, and it follows no redirects.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ls_proxy::forward::{is_metadata, is_private};
use url::{Host, Url};

use crate::config::Binding;
use crate::decrypt::BoxFuture;
use crate::http_client;

/// Why a target was refused. Carries no URL text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressError {
    /// The target's origin is not the binding's origin.
    HostNotAllowed,
    /// The host resolves to an address the gateway does not call.
    AddressNotAllowed,
    /// The host did not resolve.
    Unresolvable,
}

impl std::fmt::Display for EgressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::HostNotAllowed => "upstream host is not allowed for this secret",
            Self::AddressNotAllowed => {
                "upstream resolves to a private, loopback, link-local or metadata address"
            }
            Self::Unresolvable => "upstream host did not resolve",
        })
    }
}

impl std::error::Error for EgressError {}

/// Name resolution, injectable for tests (a rebinding stub).
pub trait Resolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>>;
}

/// The system resolver (`getaddrinfo` through tokio).
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, port)).await?.collect()) })
    }
}

/// Rule 1: the URL's origin equals the binding's, with no credentials in the URL.
pub fn check_origin(binding: &Binding, url: &Url) -> Result<(), EgressError> {
    let allowed = Url::parse(&binding.origin).map_err(|_| EgressError::HostNotAllowed)?;
    let ok = matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.host().is_some()
        && url.origin() == allowed.origin();
    if ok {
        Ok(())
    } else {
        Err(EgressError::HostNotAllowed)
    }
}

/// Whether the relay may connect to `ip`.
pub fn address_allowed(ip: IpAddr, allow_private: bool) -> bool {
    let ip = ip.to_canonical();
    if is_metadata(ip) || ip.is_multicast() || ip.is_unspecified() {
        return false;
    }
    allow_private || !is_private(ip)
}

/// A checked target: the URL plus the validated addresses its host is pinned to.
pub struct EgressTarget {
    url: Url,
    /// `(domain, addrs)` for a name; `None` for an IP literal (no resolution happens).
    pin: Option<(String, Vec<SocketAddr>)>,
}

impl EgressTarget {
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// A client that connects only to the validated addresses and follows no redirects.
    pub fn client(
        &self,
        connect_timeout: Duration,
        timeout: Duration,
    ) -> Result<reqwest::Client, http_client::ClientBuildError> {
        let pin = self.pin.as_ref().map(|(h, a)| (h.as_str(), a.as_slice()));
        http_client::build(connect_timeout, timeout, pin)
    }
}

/// Rules 1 and 2: check the origin, resolve once and check every address.
pub async fn check(
    binding: &Binding,
    url: &Url,
    resolver: &dyn Resolver,
) -> Result<EgressTarget, EgressError> {
    check_origin(binding, url)?;
    let port = url
        .port_or_known_default()
        .ok_or(EgressError::HostNotAllowed)?;
    let allow_private = binding.allow_private_hosts;
    let pin = match url.host().ok_or(EgressError::HostNotAllowed)? {
        Host::Ipv4(ip) => {
            literal(IpAddr::V4(ip), allow_private)?;
            None
        }
        Host::Ipv6(ip) => {
            literal(IpAddr::V6(ip), allow_private)?;
            None
        }
        Host::Domain(name) => {
            let addrs = resolver
                .resolve(name, port)
                .await
                .map_err(|_| EgressError::Unresolvable)?;
            if addrs.is_empty() {
                return Err(EgressError::Unresolvable);
            }
            // Every answer must pass: a name that also points at an internal address is refused
            // outright rather than filtered.
            if !addrs.iter().all(|a| address_allowed(a.ip(), allow_private)) {
                return Err(EgressError::AddressNotAllowed);
            }
            Some((name.to_owned(), addrs))
        }
    };
    Ok(EgressTarget {
        url: url.clone(),
        pin,
    })
}

fn literal(ip: IpAddr, allow_private: bool) -> Result<(), EgressError> {
    if address_allowed(ip, allow_private) {
        Ok(())
    } else {
        Err(EgressError::AddressNotAllowed)
    }
}

/// Test support: a resolver answering from a fixed table and counting lookups.
#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct StubResolver {
        pub answers: HashMap<String, Vec<IpAddr>>,
        pub lookups: Mutex<Vec<String>>,
    }

    impl StubResolver {
        pub fn with(entries: &[(&str, IpAddr)]) -> Self {
            let mut answers: HashMap<String, Vec<IpAddr>> = HashMap::new();
            for (h, ip) in entries {
                answers.entry((*h).to_owned()).or_default().push(*ip);
            }
            Self {
                answers,
                lookups: Mutex::new(Vec::new()),
            }
        }
    }

    impl Resolver for StubResolver {
        fn resolve<'a>(
            &'a self,
            host: &'a str,
            port: u16,
        ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
            self.lookups.lock().unwrap().push(host.to_owned());
            let out = self
                .answers
                .get(host)
                .map(|ips| ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such host"));
            Box::pin(async move { out })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::StubResolver;
    use super::*;
    use uuid::Uuid;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn binding(origin: &str, allow_private: bool) -> Binding {
        Binding {
            secret_id: Uuid::nil(),
            origin: origin.to_owned(),
            header: "Authorization".to_owned(),
            template: "Bearer {secret}".to_owned(),
            allow_private_hosts: allow_private,
        }
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn origin_must_match_exactly() {
        let b = binding("https://api.example.com", false);
        for ok in [
            "https://api.example.com/v1/x?q=1",
            "https://API.example.com/",
            "https://api.example.com:443/x",
        ] {
            assert_eq!(check_origin(&b, &url(ok)), Ok(()), "{ok}");
        }
        for bad in [
            "http://api.example.com/",
            "https://api.example.com:8443/",
            "https://evil.example.com/",
            "https://api.example.com.evil.test/",
            "https://user:pw@api.example.com/",
            "https://user@api.example.com/",
            "ftp://api.example.com/",
        ] {
            assert_eq!(
                check_origin(&b, &url(bad)),
                Err(EgressError::HostNotAllowed),
                "{bad}"
            );
        }
    }

    #[test]
    fn address_classes() {
        for p in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
        ] {
            let ip: IpAddr = p.parse().unwrap();
            assert!(!address_allowed(ip, false), "{p} must be refused");
            assert!(address_allowed(ip, true), "{p} allowed with allow_private");
        }
        for never in ["169.254.169.254", "0.0.0.0", "::", "224.0.0.1", "ff02::1"] {
            let ip: IpAddr = never.parse().unwrap();
            assert!(!address_allowed(ip, true), "{never} must always be refused");
        }
        assert!(address_allowed("93.184.215.14".parse().unwrap(), false));
        assert!(address_allowed("2606:4700::1111".parse().unwrap(), false));
    }

    #[tokio::test]
    async fn private_resolution_refused_unless_allowed() {
        let r = StubResolver::with(&[
            ("internal.test", "10.0.0.5".parse().unwrap()),
            ("public.test", "93.184.215.14".parse().unwrap()),
            ("mixed.test", "93.184.215.14".parse().unwrap()),
            ("mixed.test", "127.0.0.1".parse().unwrap()),
        ]);
        for (h, want) in [
            ("internal.test", Some(EgressError::AddressNotAllowed)),
            ("mixed.test", Some(EgressError::AddressNotAllowed)),
            ("nowhere.test", Some(EgressError::Unresolvable)),
            ("public.test", None),
        ] {
            let got = check(
                &binding(&format!("https://{h}"), false),
                &url(&format!("https://{h}/")),
                &r,
            )
            .await
            .err();
            assert_eq!(got, want, "{h}");
        }
        let ok = check(
            &binding("https://internal.test", true),
            &url("https://internal.test/"),
            &r,
        )
        .await;
        assert!(ok.is_ok());
        // IP literals are checked without a lookup.
        let before = r.lookups.lock().unwrap().len();
        let lit = check(
            &binding("http://127.0.0.1:8080", false),
            &url("http://127.0.0.1:8080/"),
            &r,
        )
        .await;
        assert_eq!(lit.err(), Some(EgressError::AddressNotAllowed));
        assert_eq!(r.lookups.lock().unwrap().len(), before);
    }

    #[tokio::test]
    async fn host_check_happens_before_any_lookup() {
        let r = StubResolver::with(&[("evil.test", "93.184.215.14".parse().unwrap())]);
        let e = check(
            &binding("https://api.example.com", false),
            &url("https://evil.test/"),
            &r,
        )
        .await;
        assert_eq!(e.err(), Some(EgressError::HostNotAllowed));
        assert!(r.lookups.lock().unwrap().is_empty());
    }

    /// The client connects to the pinned address: `pinned.test` exists only in the stub, so
    /// reaching the mock proves the system resolver was never asked.
    #[tokio::test]
    async fn client_is_pinned_and_does_not_follow_redirects() {
        let elsewhere = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&elsewhere)
            .await;
        let up = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/stolen", elsewhere.uri())),
            )
            .expect(1)
            .mount(&up)
            .await;
        let port = up.address().port();
        let r = StubResolver::with(&[("pinned.test", "127.0.0.1".parse().unwrap())]);
        let origin = format!("http://pinned.test:{port}");
        let t = check(&binding(&origin, true), &url(&format!("{origin}/x")), &r)
            .await
            .expect("allowed");
        let client = t
            .client(Duration::from_secs(2), Duration::from_secs(5))
            .unwrap();
        let resp = client.get(t.url().clone()).send().await.unwrap();
        assert_eq!(
            resp.status().as_u16(),
            302,
            "redirect returned, not followed"
        );
    }
}
