//! JWKS cache for human-token verification (T1 design decision 1).
//!
//! The issuer's key set is fetched over HTTP and kept in memory, indexed by `kid`. Three rules
//! keep the fetch from becoming a denial-of-service lever:
//!
//! - **Single flight:** concurrent lookups that need a refresh queue behind one gate; the
//!   first fetches, the others find the result (or the rate limit) when they get in.
//! - **Minimum refresh interval:** at most one fetch attempt per interval, successful or not,
//!   so a stream of tokens with random `kid`s causes at most one fetch per interval.
//! - **Bounded response:** the body is capped and the request has a timeout.
//!
//! Each key carries the one algorithm it may verify with, derived from its key type (RSA gives
//! RS256, P-256 gives ES256). The token header's `alg` is never used to choose it. Symmetric
//! (`oct`) and other key types are dropped, so HS* tokens cannot verify against a published key.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;

/// Default minimum time between fetch attempts.
pub const DEFAULT_MIN_REFRESH: Duration = Duration::from_secs(30);
/// Default age after which a cached set is refreshed even for a known `kid`, so revoked keys
/// disappear. A failed refresh keeps serving the old keys.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(3600);
/// Largest JWKS document accepted.
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Smallest accepted RSA modulus, in bytes (2048 bits).
const MIN_RSA_MODULUS_BYTES: usize = 256;

/// A public key and the single algorithm it may verify.
#[derive(Clone)]
pub struct VerificationKey {
    pub alg: Algorithm,
    pub key: DecodingKey,
}

/// Why a cache could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwksError {
    Client,
}

impl std::fmt::Display for JwksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("could not build the JWKS HTTP client")
    }
}

impl std::error::Error for JwksError {}

struct Snapshot {
    keys: HashMap<String, Arc<VerificationKey>>,
    /// When `keys` was last loaded successfully.
    loaded_at: Option<Instant>,
}

/// Cached JWKS of one issuer.
pub struct JwksCache {
    url: String,
    client: reqwest::Client,
    min_refresh: Duration,
    max_age: Duration,
    snapshot: RwLock<Snapshot>,
    last_attempt: Mutex<Option<Instant>>,
    /// Held across a fetch: this is what makes a refresh single flight.
    gate: tokio::sync::Mutex<()>,
}

impl JwksCache {
    pub fn new(url: String, min_refresh: Duration, max_age: Duration) -> Result<Self, JwksError> {
        Ok(Self::with_client(
            url,
            default_client()?,
            min_refresh,
            max_age,
        ))
    }

    /// As [`Self::new`] with a caller-built client, e.g. one whose resolver refuses private
    /// addresses (workload issuers, D4 decision 3). The client should carry its own timeouts.
    pub fn with_client(
        url: String,
        client: reqwest::Client,
        min_refresh: Duration,
        max_age: Duration,
    ) -> Self {
        Self {
            url,
            client,
            min_refresh,
            max_age,
            snapshot: RwLock::new(Snapshot {
                keys: HashMap::new(),
                loaded_at: None,
            }),
            last_attempt: Mutex::new(None),
            gate: tokio::sync::Mutex::new(()),
        }
    }

    /// The key published under `kid`, refreshing the set first when it is empty, stale, or does
    /// not hold `kid` (subject to the minimum refresh interval). `None` when no such key is
    /// known after that.
    pub async fn key(&self, kid: &str) -> Option<Arc<VerificationKey>> {
        let (hit, fresh) = self.lookup(kid);
        if fresh && hit.is_some() {
            return hit;
        }
        let _gate = self.gate.lock().await;
        // Someone ahead of us in the queue may already have refreshed.
        let (hit, fresh) = self.lookup(kid);
        if fresh && hit.is_some() {
            return hit;
        }
        if !self.may_attempt() {
            // Rate limited: a stale hit is still served, an unknown kid stays unknown.
            return hit;
        }
        self.refresh().await;
        self.lookup(kid).0
    }

    fn lookup(&self, kid: &str) -> (Option<Arc<VerificationKey>>, bool) {
        let snap = self.snapshot.read().unwrap_or_else(|e| e.into_inner());
        let fresh = snap.loaded_at.is_some_and(|t| t.elapsed() < self.max_age);
        (snap.keys.get(kid).cloned(), fresh)
    }

    /// Record an attempt now and report whether the minimum interval had passed.
    fn may_attempt(&self) -> bool {
        let mut last = self.last_attempt.lock().unwrap_or_else(|e| e.into_inner());
        if last.is_some_and(|t| t.elapsed() < self.min_refresh) {
            return false;
        }
        *last = Some(Instant::now());
        true
    }

    async fn refresh(&self) {
        match self.fetch().await {
            Ok(keys) => {
                tracing::debug!(keys = keys.len(), "jwks refreshed");
                let mut snap = self.snapshot.write().unwrap_or_else(|e| e.into_inner());
                snap.keys = keys;
                snap.loaded_at = Some(Instant::now());
            }
            // Keep serving the previous keys. Nothing from the response is logged.
            Err(kind) => tracing::warn!(kind, "jwks refresh failed"),
        }
    }

    async fn fetch(&self) -> Result<HashMap<String, Arc<VerificationKey>>, &'static str> {
        let mut response = self
            .client
            .get(&self.url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    "timeout"
                } else {
                    "transport"
                }
            })?;
        if !response.status().is_success() {
            return Err("status");
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_BODY_BYTES as u64)
        {
            return Err("too_large");
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| "transport")? {
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                return Err("too_large");
            }
            body.extend_from_slice(&chunk);
        }
        parse_jwks(&body).ok_or("malformed")
    }
}

#[derive(Deserialize)]
struct RawSet {
    keys: Vec<serde_json::Value>,
}

/// Parse a JWKS document into verification keys by `kid`. Keys that are unusable (no `kid`,
/// not for signatures, symmetric or unsupported type, declared algorithm that does not match the
/// key type, short RSA modulus) are skipped one by one; `None` only when the document itself is
/// not a JWKS. The first key wins on a duplicate `kid`.
pub fn parse_jwks(body: &[u8]) -> Option<HashMap<String, Arc<VerificationKey>>> {
    let raw: RawSet = serde_json::from_slice(body).ok()?;
    let mut keys = HashMap::new();
    for value in raw.keys {
        let Ok(jwk) = serde_json::from_value::<Jwk>(value) else {
            continue;
        };
        let (Some(kid), Some(key)) = (jwk.common.key_id.clone(), verification_key(&jwk)) else {
            continue;
        };
        keys.entry(kid).or_insert_with(|| Arc::new(key));
    }
    Some(keys)
}

/// The verification key for `jwk`, with its algorithm fixed by the key type.
fn verification_key(jwk: &Jwk) -> Option<VerificationKey> {
    if jwk
        .common
        .public_key_use
        .as_ref()
        .is_some_and(|u| *u != PublicKeyUse::Signature)
    {
        return None;
    }
    let (alg, declared) = match &jwk.algorithm {
        AlgorithmParameters::RSA(p) => {
            let n = URL_SAFE_NO_PAD.decode(p.n.trim_end_matches('=')).ok()?;
            // Leading zero bytes do not count towards the modulus size.
            let significant = n.iter().skip_while(|b| **b == 0).count();
            if significant < MIN_RSA_MODULUS_BYTES {
                return None;
            }
            (Algorithm::RS256, KeyAlgorithm::RS256)
        }
        AlgorithmParameters::EllipticCurve(p) if p.curve == EllipticCurve::P256 => {
            (Algorithm::ES256, KeyAlgorithm::ES256)
        }
        _ => return None,
    };
    // A key that declares an algorithm must declare the one its type implies.
    if jwk.common.key_algorithm.is_some_and(|a| a != declared) {
        return None;
    }
    Some(VerificationKey {
        alg,
        key: DecodingKey::from_jwk(jwk).ok()?,
    })
}

/// HTTP client for JWKS fetches: rustls with the ring provider and the OS trust store (the
/// same setup as the OpenBao client in `ls-envelope`), no redirects, no proxy environment,
/// short timeouts.
fn default_client() -> Result<reqwest::Client, JwksError> {
    ls_http::builder()
        .map_err(|_| JwksError::Client)?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| JwksError::Client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A P-256 public JWK with a fixed, throwaway test point (the generator point).
    fn ec_jwk(kid: &str) -> serde_json::Value {
        json!({
            "kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
            "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
            "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
        })
    }

    fn rsa_jwk(kid: &str, modulus_bytes: usize) -> serde_json::Value {
        // Not a real key: public-shaped bytes of the requested size.
        let mut n = vec![0xA5u8; modulus_bytes];
        n[0] |= 0x80;
        json!({"kty": "RSA", "kid": kid, "use": "sig", "n": URL_SAFE_NO_PAD.encode(n), "e": "AQAB"})
    }

    async fn serve(server: &MockServer, keys: Vec<serde_json::Value>) {
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": keys })))
            .mount(server)
            .await;
    }

    fn cache(server: &MockServer, min_refresh: Duration, max_age: Duration) -> JwksCache {
        JwksCache::new(format!("{}/jwks", server.uri()), min_refresh, max_age).unwrap()
    }

    async fn fetches(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    #[tokio::test]
    async fn auth_jwks_looks_up_a_key_by_kid_with_its_algorithm_from_the_key_type() {
        let server = MockServer::start().await;
        serve(&server, vec![ec_jwk("ec-1"), rsa_jwk("rsa-1", 256)]).await;
        let c = cache(&server, DEFAULT_MIN_REFRESH, DEFAULT_MAX_AGE);
        assert_eq!(c.key("ec-1").await.unwrap().alg, Algorithm::ES256);
        assert_eq!(c.key("rsa-1").await.unwrap().alg, Algorithm::RS256);
        assert!(c.key("nope").await.is_none());
    }

    #[tokio::test]
    async fn auth_jwks_known_kids_are_served_from_cache() {
        let server = MockServer::start().await;
        serve(&server, vec![ec_jwk("a")]).await;
        let c = cache(&server, DEFAULT_MIN_REFRESH, DEFAULT_MAX_AGE);
        for _ in 0..5 {
            assert!(c.key("a").await.is_some());
        }
        assert_eq!(fetches(&server).await, 1);
    }

    #[tokio::test]
    async fn auth_jwks_concurrent_first_lookups_fetch_once() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"keys": [ec_jwk("a")]}))
                    .set_delay(Duration::from_millis(150)),
            )
            .mount(&server)
            .await;
        let c = Arc::new(cache(&server, DEFAULT_MIN_REFRESH, DEFAULT_MAX_AGE));
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let c = c.clone();
                tokio::spawn(async move { c.key("a").await.is_some() })
            })
            .collect();
        for t in tasks {
            assert!(t.await.unwrap());
        }
        assert_eq!(fetches(&server).await, 1);
    }

    #[tokio::test]
    async fn auth_jwks_unknown_kid_refreshes_at_most_once_per_interval() {
        let server = MockServer::start().await;
        serve(&server, vec![ec_jwk("a")]).await;
        let c = cache(&server, Duration::from_millis(300), DEFAULT_MAX_AGE);
        assert!(c.key("a").await.is_some());
        assert_eq!(fetches(&server).await, 1);

        // A burst of unknown kids: the first is rate limited too (the load just happened).
        for i in 0..10 {
            assert!(c.key(&format!("unknown-{i}")).await.is_none());
        }
        assert_eq!(fetches(&server).await, 1);

        // After the interval exactly one more fetch, however many unknown kids arrive.
        tokio::time::sleep(Duration::from_millis(350)).await;
        for i in 0..10 {
            assert!(c.key(&format!("other-{i}")).await.is_none());
        }
        assert_eq!(fetches(&server).await, 2);
    }

    #[tokio::test]
    async fn auth_jwks_rotation_is_picked_up_after_the_interval() {
        let server = MockServer::start().await;
        serve(&server, vec![ec_jwk("old")]).await;
        let c = cache(&server, Duration::from_millis(200), DEFAULT_MAX_AGE);
        assert!(c.key("old").await.is_some());
        serve(&server, vec![ec_jwk("old"), ec_jwk("new")]).await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(c.key("new").await.is_some());
    }

    #[tokio::test]
    async fn auth_jwks_stale_set_is_refreshed_and_dropped_keys_disappear() {
        let server = MockServer::start().await;
        serve(&server, vec![ec_jwk("old")]).await;
        let c = cache(
            &server,
            Duration::from_millis(50),
            Duration::from_millis(200),
        );
        assert!(c.key("old").await.is_some());
        serve(&server, vec![ec_jwk("new")]).await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(c.key("old").await.is_none());
        assert!(c.key("new").await.is_some());
    }

    #[tokio::test]
    async fn auth_jwks_a_failed_refresh_keeps_the_previous_keys() {
        let server = MockServer::start().await;
        serve(&server, vec![ec_jwk("a")]).await;
        let c = cache(
            &server,
            Duration::from_millis(50),
            Duration::from_millis(100),
        );
        assert!(c.key("a").await.is_some());
        server.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(c.key("a").await.is_some(), "stale key still served");
    }

    #[tokio::test]
    async fn auth_jwks_unreachable_issuer_yields_no_key() {
        let c = JwksCache::new(
            "http://127.0.0.1:1/jwks".to_owned(),
            DEFAULT_MIN_REFRESH,
            DEFAULT_MAX_AGE,
        )
        .unwrap();
        assert!(c.key("a").await.is_none());
    }

    #[tokio::test]
    async fn auth_jwks_oversized_response_is_refused() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b' '; MAX_BODY_BYTES + 1]))
            .mount(&server)
            .await;
        let c = cache(&server, DEFAULT_MIN_REFRESH, DEFAULT_MAX_AGE);
        assert!(c.key("a").await.is_none());
    }

    #[test]
    fn auth_jwks_unusable_keys_are_skipped_not_fatal() {
        let doc = json!({"keys": [
            {"kty": "oct", "kid": "hmac", "k": "c2VjcmV0", "alg": "HS256"},
            ec_jwk("good"),
            {"kty": "EC", "crv": "P-384", "kid": "p384",
             "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
             "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"},
            {"kty": "OKP", "crv": "Ed25519", "kid": "ed", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
            rsa_jwk("short", 128),
            {"kty": "RSA", "kid": "enc", "use": "enc", "n": URL_SAFE_NO_PAD.encode([0xA5u8; 256]), "e": "AQAB"},
            {"kty": "EC", "crv": "P-256", "kid": "wrong-alg", "alg": "RS256",
             "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
             "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"},
            {"kty": "EC", "crv": "P-256",
             "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
             "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"},
            {"kty": "mystery", "kid": "mystery"}
        ]});
        let keys = parse_jwks(doc.to_string().as_bytes()).unwrap();
        let mut kids: Vec<_> = keys.keys().cloned().collect();
        kids.sort();
        assert_eq!(kids, ["good"]);
    }

    #[test]
    fn auth_jwks_a_non_jwks_document_is_rejected() {
        assert!(parse_jwks(b"not json").is_none());
        assert!(parse_jwks(br#"{"nokeys": []}"#).is_none());
    }
}
