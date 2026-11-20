//! Per-issuer JWKS registry for workload identity (D4 design decision 3).
//!
//! Workload policies name their issuer; this registry turns a stored issuer URL into a
//! [`JwksCache`], created lazily and shared by every policy naming the same issuer. Rules:
//!
//! - **Issuer from the policy only.** Callers pass the issuer stored on a policy. Nothing from
//!   a presented token (`iss`, `jku`, `x5u`) is ever used to choose a URL.
//! - **OpenID discovery.** The JWKS location is read from
//!   `<issuer>/.well-known/openid-configuration`, whose `issuer` must equal the stored issuer
//!   exactly (OpenID Connect Discovery 1.0 section 4.3).
//! - **https only, address guarded.** Every fetch (discovery and JWKS) goes through a client
//!   that refuses plain http and whose resolver refuses any name with a loopback, private,
//!   link-local, CGNAT, ULA, multicast or unspecified answer (the gateway's egress rule, through
//!   `ls-proxy`'s network guard). IP literals are checked before any request. Cloud metadata
//!   addresses are refused always. [`IssuerAccess::allow_private_hosts`] (local development
//!   only) lifts the private-address and https rules so a stub issuer on localhost works.
//! - **Bounded.** Discovery documents are capped in size, every request has a timeout, a failed
//!   discovery is retried at most once per minimum refresh interval, and the JWKS cache keeps its
//!   own refresh rate limit and size cap. The number of cached issuers is capped too.
//!
//! Failures are static labels; no response body or URL is logged.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::jwks::{DEFAULT_MAX_AGE, DEFAULT_MIN_REFRESH, JwksCache, VerificationKey};

/// Largest discovery document accepted.
const MAX_DISCOVERY_BYTES: usize = 64 * 1024;
/// Most issuers held at once. Issuers come from stored policies only; the cap bounds memory if
/// many orgs name distinct issuers.
const MAX_ISSUERS: usize = 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

/// How far the control plane may reach for issuer keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IssuerAccess {
    /// Local development only: allow issuers on loopback and private addresses, over plain
    /// http as well. Metadata addresses stay refused.
    pub allow_private_hosts: bool,
}

/// Why no key could be produced. Static labels for spans; carries no URL or body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerError {
    /// The stored issuer or the discovered `jwks_uri` is not an allowed URL (scheme, host).
    UrlNotAllowed,
    /// The issuer's host is (or resolves to) an address the control plane does not call.
    AddressNotAllowed,
    /// Discovery failed (transport, status, size, document) or is rate limited after a failure.
    Unavailable,
    /// The JWKS client could not be built.
    Client,
}

impl IssuerError {
    pub fn label(self) -> &'static str {
        match self {
            Self::UrlNotAllowed => "issuer_url",
            Self::AddressNotAllowed => "issuer_address",
            Self::Unavailable => "issuer_unavailable",
            Self::Client => "issuer_client",
        }
    }
}

/// Lazily created [`JwksCache`]s, one per stored issuer URL.
pub struct IssuerRegistry {
    access: IssuerAccess,
    min_refresh: Duration,
    max_age: Duration,
    client: reqwest::Client,
    entries: Mutex<HashMap<String, Arc<Entry>>>,
}

struct Entry {
    /// Held across discovery (single flight); `None` until discovery succeeds.
    state: tokio::sync::Mutex<EntryState>,
}

struct EntryState {
    jwks: Option<Arc<JwksCache>>,
    last_attempt: Option<Instant>,
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

impl IssuerRegistry {
    pub fn new(access: IssuerAccess) -> Result<Self, IssuerError> {
        Self::with_refresh(access, DEFAULT_MIN_REFRESH, DEFAULT_MAX_AGE)
    }

    /// As [`Self::new`] with explicit refresh timing (tests). `min_refresh` also spaces out
    /// discovery retries after a failure.
    pub fn with_refresh(
        access: IssuerAccess,
        min_refresh: Duration,
        max_age: Duration,
    ) -> Result<Self, IssuerError> {
        Ok(Self {
            access,
            min_refresh,
            max_age,
            client: guarded_client(access)?,
            entries: Mutex::new(HashMap::new()),
        })
    }

    pub fn access(&self) -> IssuerAccess {
        self.access
    }

    /// The key published under `kid` by `issuer` (a stored policy's issuer URL). Discovers the
    /// issuer on first use, then defers to its [`JwksCache`] (one rate-limited refresh for an
    /// unknown `kid`).
    pub async fn key(
        &self,
        issuer: &str,
        kid: &str,
    ) -> Result<Option<Arc<VerificationKey>>, IssuerError> {
        let jwks = self.jwks(issuer).await?;
        Ok(jwks.key(kid).await)
    }

    async fn jwks(&self, issuer: &str) -> Result<Arc<JwksCache>, IssuerError> {
        // Checked on every call, before any network use, so a stored URL that is not allowed
        // under the current settings never reaches the client.
        check_url(issuer, self.access)?;
        let entry = self.entry(issuer);
        let mut state = entry.state.lock().await;
        if let Some(jwks) = &state.jwks {
            return Ok(jwks.clone());
        }
        if state
            .last_attempt
            .is_some_and(|t| t.elapsed() < self.min_refresh)
        {
            return Err(IssuerError::Unavailable);
        }
        state.last_attempt = Some(Instant::now());
        let jwks_uri = self.discover(issuer).await.inspect_err(|e| {
            tracing::warn!(reason = e.label(), "workload issuer discovery failed");
        })?;
        let jwks = Arc::new(JwksCache::with_client(
            jwks_uri,
            self.client.clone(),
            self.min_refresh,
            self.max_age,
        ));
        state.jwks = Some(jwks.clone());
        Ok(jwks)
    }

    fn entry(&self, issuer: &str) -> Arc<Entry> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = entries.get(issuer) {
            return e.clone();
        }
        if entries.len() >= MAX_ISSUERS {
            // Drop an arbitrary issuer: it is rediscovered on its next use.
            if let Some(k) = entries.keys().next().cloned() {
                entries.remove(&k);
            }
        }
        let e = Arc::new(Entry {
            state: tokio::sync::Mutex::new(EntryState {
                jwks: None,
                last_attempt: None,
            }),
        });
        entries.insert(issuer.to_owned(), e.clone());
        e
    }

    /// Fetch the discovery document and return its checked `jwks_uri`.
    async fn discover(&self, issuer: &str) -> Result<String, IssuerError> {
        let url = format!("{}{DISCOVERY_PATH}", issuer.trim_end_matches('/'));
        let body = fetch_capped(&self.client, &url, MAX_DISCOVERY_BYTES).await?;
        let doc: Discovery = serde_json::from_slice(&body).map_err(|_| IssuerError::Unavailable)?;
        if doc.issuer != issuer {
            return Err(IssuerError::Unavailable);
        }
        check_url(&doc.jwks_uri, self.access)?;
        Ok(doc.jwks_uri)
    }

    /// Create-time check for a policy's issuer: allowed URL and every resolved address allowed.
    /// Makes no HTTP request. A name that does not resolve is accepted (it fails closed later).
    pub async fn check_issuer_host(&self, issuer: &str) -> Result<(), IssuerError> {
        let host = check_url(issuer, self.access)?;
        let Host::Name(name) = host else {
            return Ok(());
        };
        let Ok(addrs) = tokio::net::lookup_host((name.as_str(), 443)).await else {
            return Ok(());
        };
        let addrs: Vec<SocketAddr> = addrs.collect();
        if addrs
            .iter()
            .all(|a| address_allowed(a.ip(), self.access.allow_private_hosts))
        {
            Ok(())
        } else {
            Err(IssuerError::AddressNotAllowed)
        }
    }
}

/// Whether the control plane may connect to `ip` for issuer keys. The gateway's egress rule.
pub fn address_allowed(ip: IpAddr, allow_private: bool) -> bool {
    use ls_proxy::forward::{is_metadata, is_private};
    let ip = ip.to_canonical();
    if is_metadata(ip) || ip.is_multicast() || ip.is_unspecified() {
        return false;
    }
    allow_private || !is_private(ip)
}

enum Host {
    Ip,
    Name(String),
}

/// A URL the registry may fetch: `https` (or `http` when private hosts are allowed), a host,
/// no credentials; an IP-literal host must be an allowed address.
fn check_url(raw: &str, access: IssuerAccess) -> Result<Host, IssuerError> {
    let uri: http::Uri = raw.parse().map_err(|_| IssuerError::UrlNotAllowed)?;
    let scheme_ok = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => access.allow_private_hosts,
        _ => false,
    };
    let authority = uri.authority().ok_or(IssuerError::UrlNotAllowed)?;
    if !scheme_ok || authority.as_str().contains('@') || uri.query().is_some() {
        return Err(IssuerError::UrlNotAllowed);
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if host.is_empty() {
        return Err(IssuerError::UrlNotAllowed);
    }
    match host.parse::<IpAddr>() {
        Ok(ip) if address_allowed(ip, access.allow_private_hosts) => Ok(Host::Ip),
        Ok(_) => Err(IssuerError::AddressNotAllowed),
        Err(_) => Ok(Host::Name(host.to_ascii_lowercase())),
    }
}

async fn fetch_capped(
    client: &reqwest::Client,
    url: &str,
    max: usize,
) -> Result<Vec<u8>, IssuerError> {
    let mut response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| IssuerError::Unavailable)?;
    if !response.status().is_success() {
        return Err(IssuerError::Unavailable);
    }
    if response.content_length().is_some_and(|n| n > max as u64) {
        return Err(IssuerError::Unavailable);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| IssuerError::Unavailable)?
    {
        if body.len() + chunk.len() > max {
            return Err(IssuerError::Unavailable);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The outbound client for discovery and JWKS fetches: the shared TLS policy (no redirects, no
/// proxy environment), https only unless private hosts are allowed, short timeouts, and a
/// resolver that refuses names with any disallowed answer. Checking at resolution time, on the
/// addresses actually connected to, leaves no gap for DNS rebinding.
fn guarded_client(access: IssuerAccess) -> Result<reqwest::Client, IssuerError> {
    ls_http::builder()
        .map_err(|_| IssuerError::Client)?
        .https_only(!access.allow_private_hosts)
        .dns_resolver(Arc::new(GuardedResolver {
            allow_private: access.allow_private_hosts,
        }))
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|_| IssuerError::Client)
}

struct GuardedResolver {
    allow_private: bool,
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow_private = self.allow_private;
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            // Every answer must pass: a name that also points inside is refused outright.
            if addrs.is_empty() || !addrs.iter().all(|a| address_allowed(a.ip(), allow_private)) {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "address not allowed",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC: IssuerAccess = IssuerAccess {
        allow_private_hosts: false,
    };
    const DEV: IssuerAccess = IssuerAccess {
        allow_private_hosts: true,
    };

    #[test]
    fn workload_issuer_urls_must_be_https_with_an_allowed_host() {
        assert!(check_url("https://token.actions.githubusercontent.com", PUBLIC).is_ok());
        assert!(check_url("https://k8s.example/path", PUBLIC).is_ok());
        assert!(check_url("https://8.8.8.8", PUBLIC).is_ok());
        for bad in [
            "http://k8s.example",
            "ftp://k8s.example",
            "k8s.example",
            "https://u:p@k8s.example",
            "https://k8s.example/?q=1",
            "",
        ] {
            assert_eq!(
                check_url(bad, PUBLIC).err(),
                Some(IssuerError::UrlNotAllowed),
                "{bad}"
            );
        }
        for private in [
            "https://127.0.0.1",
            "https://10.0.0.1:8443",
            "https://169.254.169.254",
            "https://[::1]",
            "https://[fd00::1]",
            "https://100.64.0.1",
            "https://0.0.0.0",
        ] {
            assert_eq!(
                check_url(private, PUBLIC).err(),
                Some(IssuerError::AddressNotAllowed),
                "{private}"
            );
        }
    }

    #[test]
    fn workload_issuer_dev_flag_allows_private_and_http_but_never_metadata() {
        assert!(check_url("http://127.0.0.1:8080", DEV).is_ok());
        assert!(check_url("https://10.1.2.3", DEV).is_ok());
        assert_eq!(
            check_url("http://169.254.169.254", DEV).err(),
            Some(IssuerError::AddressNotAllowed)
        );
        assert_eq!(
            check_url("http://[fd00:ec2::254]", DEV).err(),
            Some(IssuerError::AddressNotAllowed)
        );
    }

    #[tokio::test]
    async fn workload_issuer_create_check_resolves_names() {
        let reg = IssuerRegistry::new(PUBLIC).unwrap();
        assert_eq!(
            reg.check_issuer_host("https://localhost").await,
            Err(IssuerError::AddressNotAllowed)
        );
        assert_eq!(
            reg.check_issuer_host("https://127.0.0.1").await,
            Err(IssuerError::AddressNotAllowed)
        );
        let dev = IssuerRegistry::new(DEV).unwrap();
        assert_eq!(dev.check_issuer_host("http://localhost:1").await, Ok(()));
    }
}
