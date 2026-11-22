//! Agent authentication (S4 task 2.1): every `/v1` call carries an agent token, an EdDSA JWT the
//! control plane mints (S4 design decision 1), verified here through the control plane's JWKS.
//!
//! - The bearer credential is parsed by [`ls_control_plane::auth::bearer`], the one bearer parser
//!   (scheme case-insensitive).
//! - Claims and validation come from [`ls_control_plane::agent_token`]: EdDSA only, audience
//!   `gateway`, `exp` enforced with its leeway. The token's `org` must be the org this gateway
//!   serves.
//! - Keys come from `GET /.well-known/jwks.json` and are cached by `kid`. The set is refetched
//!   when it is older than [`JwksSettings::refresh_after`], or when a token names an unknown
//!   `kid`, at most once per [`JwksSettings::min_refetch_interval`] (an attacker sending random
//!   `kid`s cannot turn the gateway into a JWKS flood). Concurrent refetches are coalesced.
//! - Rotation by `kid`: a key that disappears from the JWKS is kept for
//!   [`JwksSettings::retain_retired`] (default: token lifetime plus leeway), so tokens minted just
//!   before a rotation stay valid until they expire. The control plane publishes only its current
//!   key; this overlap is what keeps rotation seamless. Honest trade-off: a key removed because it
//!   leaked is also honoured for that window.
//! - A failed fetch keeps the cached keys (availability); it never empties the cache.
//!
//! Errors are an enum of reasons, never token text. Nothing here logs a token.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, header};
use jsonwebtoken::{Algorithm, DecodingKey};
use ls_control_plane::agent_token::{self, Jwk, VerifyError};
use serde::Deserialize;
use url::Url;
use uuid::Uuid;

use crate::decrypt::BoxFuture;
use crate::http_client;

/// Where the control plane publishes the agent-token keys, relative to its base URL.
pub const JWKS_PATH: &str = ".well-known/jwks.json";

/// Longest accepted token. A minted token is about 400 bytes.
const MAX_TOKEN_BYTES: usize = 4096;
/// Largest JWKS response read.
const MAX_JWKS_RESPONSE: usize = 64 * 1024;
/// Most keys kept at once (current, plus retired keys inside their overlap window).
const MAX_KEYS: usize = 32;

/// The verified caller: the agent and its org. Ids only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentIdentity {
    pub agent_id: Uuid,
    pub org_id: Uuid,
}

/// Why a caller was refused. Every variant is a `401`; none carries token text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// No `Authorization: Bearer` credential.
    Missing,
    /// Not a JWT, oversized, no `kid`, or claims of the wrong shape.
    Malformed,
    /// No key with the token's `kid` (after a refetch, if one was allowed).
    UnknownKey,
    BadSignature,
    Expired,
    WrongAudience,
    /// A valid token for an org this gateway does not serve.
    WrongOrg,
}

impl AuthError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::UnknownKey => "unknown_key",
            Self::BadSignature => "bad_signature",
            Self::Expired => "expired",
            Self::WrongAudience => "wrong_audience",
            Self::WrongOrg => "wrong_org",
        }
    }
}

/// The JWKS could not be fetched. Carries nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JwksError;

/// Fetches the published key set.
pub trait JwksSource: Send + Sync {
    fn fetch(&self) -> BoxFuture<'_, Result<Vec<Jwk>, JwksError>>;
}

/// The control plane's `/.well-known/jwks.json`, over the gateway's standard client.
pub struct HttpJwks {
    client: reqwest::Client,
    url: Url,
}

impl HttpJwks {
    /// `control_plane` is the control plane's base URL.
    pub fn new(control_plane: &Url) -> Result<Self, http_client::ClientBuildError> {
        let url = control_plane
            .join(JWKS_PATH)
            .map_err(|_| http_client::ClientBuildError)?;
        let client = http_client::build(Duration::from_secs(2), Duration::from_secs(5), None)?;
        Ok(Self { client, url })
    }

    async fn get(&self) -> Result<Vec<Jwk>, JwksError> {
        let resp = self
            .client
            .get(self.url.clone())
            .send()
            .await
            .map_err(|_| JwksError)?;
        if !resp.status().is_success() {
            return Err(JwksError);
        }
        let body = ls_http::read_capped(resp, MAX_JWKS_RESPONSE)
            .await
            .map_err(|_| JwksError)?;
        parse_jwks(&body)
    }
}

impl JwksSource for HttpJwks {
    fn fetch(&self) -> BoxFuture<'_, Result<Vec<Jwk>, JwksError>> {
        Box::pin(self.get())
    }
}

/// Parse a JWK set, skipping keys of other shapes (an RSA key next to ours is not an error).
pub fn parse_jwks(body: &[u8]) -> Result<Vec<Jwk>, JwksError> {
    #[derive(Deserialize)]
    struct RawSet {
        keys: Vec<serde_json::Value>,
    }
    let raw: RawSet = serde_json::from_slice(body).map_err(|_| JwksError)?;
    Ok(raw
        .keys
        .into_iter()
        .filter_map(|k| serde_json::from_value::<Jwk>(k).ok())
        .collect())
}

/// JWKS cache timing.
#[derive(Debug, Clone, Copy)]
pub struct JwksSettings {
    /// Refetch the set on the next request once it is this old.
    pub refresh_after: Duration,
    /// At most one fetch per this interval, whatever triggers it.
    pub min_refetch_interval: Duration,
    /// How long a key that left the JWKS is still honoured.
    pub retain_retired: Duration,
}

impl Default for JwksSettings {
    fn default() -> Self {
        Self {
            refresh_after: Duration::from_secs(5 * 60),
            min_refetch_interval: Duration::from_secs(10),
            retain_retired: agent_token::DEFAULT_TTL
                + Duration::from_secs(agent_token::LEEWAY_SECS),
        }
    }
}

struct CachedKey {
    key: Arc<DecodingKey>,
    /// When this key was first missing from a fetched set.
    retired_at: Option<Instant>,
}

#[derive(Default)]
struct KeyState {
    keys: HashMap<String, CachedKey>,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
}

impl KeyState {
    fn lookup(&self, kid: &str, now: Instant, retain: Duration) -> Option<Arc<DecodingKey>> {
        let k = self.keys.get(kid)?;
        match k.retired_at {
            Some(at) if now.saturating_duration_since(at) >= retain => None,
            _ => Some(k.key.clone()),
        }
    }

    fn stale(&self, now: Instant, refresh_after: Duration) -> bool {
        self.fetched_at
            .is_none_or(|at| now.saturating_duration_since(at) >= refresh_after)
    }

    /// Fold a fetched set in: its keys are current, missing ones start (or continue) their
    /// retirement, and keys past the overlap window are dropped.
    fn merge(&mut self, set: Vec<Jwk>, now: Instant, retain: Duration) {
        let mut current = HashMap::new();
        for jwk in set {
            let usable = jwk.alg == "EdDSA" && jwk.use_ == "sig" && !jwk.kid.is_empty();
            if let (true, Some(key)) = (usable, jwk.decoding_key()) {
                current.insert(jwk.kid, key);
            }
        }
        for (kid, cached) in &mut self.keys {
            if !current.contains_key(kid) && cached.retired_at.is_none() {
                cached.retired_at = Some(now);
            }
        }
        self.keys.retain(|_, k| {
            k.retired_at
                .is_none_or(|at| now.saturating_duration_since(at) < retain)
        });
        for (kid, key) in current {
            self.keys.insert(
                kid,
                CachedKey {
                    key: Arc::new(key),
                    retired_at: None,
                },
            );
        }
        // Bound memory: keep current keys first, then the most recently retired.
        if self.keys.len() > MAX_KEYS {
            let mut order: Vec<(String, Option<Instant>)> = self
                .keys
                .iter()
                .map(|(kid, k)| (kid.clone(), k.retired_at))
                .collect();
            order.sort_by(|a, b| match (a.1, b.1) {
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) => std::cmp::Ordering::Less,
                (Some(_), None) => std::cmp::Ordering::Greater,
                (Some(x), Some(y)) => y.cmp(&x),
            });
            for (kid, _) in order.into_iter().skip(MAX_KEYS) {
                self.keys.remove(&kid);
            }
        }
        self.fetched_at = Some(now);
    }
}

/// Verifies agent tokens for one org. No `Clone`; shared behind an `Arc`.
pub struct AgentAuth {
    org_id: Uuid,
    source: Arc<dyn JwksSource>,
    settings: JwksSettings,
    state: Mutex<KeyState>,
    /// Serialises fetches so concurrent misses share one.
    fetching: tokio::sync::Mutex<()>,
}

impl AgentAuth {
    pub fn new(org_id: Uuid, source: Arc<dyn JwksSource>, settings: JwksSettings) -> Self {
        Self {
            org_id,
            source,
            settings,
            state: Mutex::new(KeyState::default()),
            fetching: tokio::sync::Mutex::new(()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, KeyState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Authenticate a request by its `Authorization: Bearer` agent token.
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<AgentIdentity, AuthError> {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| ls_control_plane::auth::bearer(v.as_bytes()))
            .ok_or(AuthError::Missing)?;
        let token = std::str::from_utf8(token).map_err(|_| AuthError::Malformed)?;
        self.verify(token).await
    }

    /// Verify one token: header (`EdDSA`, a `kid`), key by `kid`, signature, audience, expiry,
    /// org.
    pub async fn verify(&self, token: &str) -> Result<AgentIdentity, AuthError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(AuthError::Malformed);
        }
        let header = jsonwebtoken::decode_header(token).map_err(|_| AuthError::Malformed)?;
        if header.alg != Algorithm::EdDSA {
            return Err(AuthError::BadSignature);
        }
        let kid = header
            .kid
            .filter(|k| !k.is_empty() && k.len() <= 128)
            .ok_or(AuthError::Malformed)?;
        let key = self.key_for(&kid).await?;
        let claims = agent_token::verify(token, &key).map_err(|e| match e {
            VerifyError::Expired => AuthError::Expired,
            VerifyError::WrongAudience => AuthError::WrongAudience,
            VerifyError::BadSignature => AuthError::BadSignature,
            VerifyError::Malformed => AuthError::Malformed,
        })?;
        if claims.org != self.org_id {
            return Err(AuthError::WrongOrg);
        }
        Ok(AgentIdentity {
            agent_id: claims.sub,
            org_id: claims.org,
        })
    }

    async fn key_for(&self, kid: &str) -> Result<Arc<DecodingKey>, AuthError> {
        let (cached, stale) = {
            let now = Instant::now();
            let s = self.lock();
            (
                s.lookup(kid, now, self.settings.retain_retired),
                s.stale(now, self.settings.refresh_after),
            )
        };
        if let (Some(key), false) = (&cached, stale) {
            return Ok(key.clone());
        }
        self.refresh().await;
        self.lock()
            .lookup(kid, Instant::now(), self.settings.retain_retired)
            .ok_or(AuthError::UnknownKey)
    }

    /// Fetch the JWKS unless a fetch was attempted within the rate-limit interval. A caller that
    /// waited behind another fetch sees its result instead of fetching again.
    pub async fn refresh(&self) {
        let _one_at_a_time = self.fetching.lock().await;
        {
            let now = Instant::now();
            let mut s = self.lock();
            if s.last_attempt.is_some_and(|at| {
                now.saturating_duration_since(at) < self.settings.min_refetch_interval
            }) {
                return;
            }
            s.last_attempt = Some(now);
        }
        match self.source.fetch().await {
            Ok(set) => {
                let mut s = self.lock();
                s.merge(set, Instant::now(), self.settings.retain_retired);
                tracing::debug!(keys = s.keys.len(), "agent-token JWKS refreshed");
            }
            Err(JwksError) => tracing::warn!("agent-token JWKS could not be fetched"),
        }
    }
}

#[cfg(test)]
pub mod testkit {
    //! A JWKS source the tests can switch between key sets, and a token signer.
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    pub struct StubJwks {
        pub set: Mutex<Option<Vec<Jwk>>>,
        pub fetches: AtomicUsize,
    }

    impl StubJwks {
        pub fn with(keys: Vec<Jwk>) -> Self {
            Self {
                set: Mutex::new(Some(keys)),
                fetches: AtomicUsize::new(0),
            }
        }

        /// `None` makes every fetch fail.
        pub fn replace(&self, keys: Option<Vec<Jwk>>) {
            *self.set.lock().unwrap() = keys;
        }

        pub fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    impl JwksSource for StubJwks {
        fn fetch(&self) -> BoxFuture<'_, Result<Vec<Jwk>, JwksError>> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            let r = self.set.lock().unwrap().clone().ok_or(JwksError);
            Box::pin(async move { r })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::StubJwks;
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ls_control_plane::agent_token::{AUDIENCE, AgentClaims, AgentTokenSigner};
    use time::OffsetDateTime;
    use zeroize::Zeroizing;

    const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a1);
    const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a2);

    fn signer(seed: u8) -> AgentTokenSigner {
        AgentTokenSigner::from_seed(Zeroizing::new([seed; 32])).unwrap()
    }

    fn claims(org: Uuid, aud: &str, exp_in: i64) -> AgentClaims {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        AgentClaims {
            sub: AGENT,
            org,
            aud: aud.to_owned(),
            iat: now,
            exp: now + exp_in,
        }
    }

    fn token(s: &AgentTokenSigner) -> String {
        s.mint(AGENT, ORG, OffsetDateTime::now_utc()).unwrap().token
    }

    fn auth(source: Arc<StubJwks>, settings: JwksSettings) -> AgentAuth {
        AgentAuth::new(ORG, source, settings)
    }

    fn bearer(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, value.parse().unwrap());
        h
    }

    #[tokio::test]
    async fn valid_token_authenticates_case_insensitive_scheme() {
        let s = signer(1);
        let a = auth(
            Arc::new(StubJwks::with(vec![s.jwk().clone()])),
            JwksSettings::default(),
        );
        let t = token(&s);
        for scheme in ["Bearer", "bearer", "BEARER"] {
            let id = a
                .authenticate(&bearer(&format!("{scheme} {t}")))
                .await
                .unwrap();
            assert_eq!(
                id,
                AgentIdentity {
                    agent_id: AGENT,
                    org_id: ORG
                }
            );
        }
        assert_eq!(
            a.authenticate(&HeaderMap::new()).await,
            Err(AuthError::Missing)
        );
        assert_eq!(
            a.authenticate(&bearer(&format!("Basic {t}"))).await,
            Err(AuthError::Missing)
        );
    }

    #[tokio::test]
    async fn forged_expired_wrong_audience_and_wrong_org_are_refused() {
        let s = signer(1);
        let a = auth(
            Arc::new(StubJwks::with(vec![s.jwk().clone()])),
            JwksSettings::default(),
        );
        // Signed by a key the JWKS does not publish.
        let other = signer(2);
        assert_eq!(a.verify(&token(&other)).await, Err(AuthError::UnknownKey));
        // Trusted kid, payload swapped (claims of another org): signature no longer matches.
        let good = token(&s);
        let parts: Vec<&str> = good.split('.').collect();
        let forged_payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims(ORG, AUDIENCE, 600)).unwrap());
        let tampered = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);
        assert_eq!(a.verify(&tampered).await, Err(AuthError::BadSignature));
        // `alg: none` and HS256 headers are refused before any key lookup: `none` is not a
        // JOSE algorithm the header parser accepts (malformed), HS256 is not EdDSA.
        for (alg, want) in [
            ("none", AuthError::Malformed),
            ("HS256", AuthError::BadSignature),
        ] {
            let h = URL_SAFE_NO_PAD.encode(format!(
                r#"{{"alg":"{alg}","typ":"JWT","kid":"{}"}}"#,
                s.jwk().kid
            ));
            let t = format!("{h}.{}.{}", parts[1], parts[2]);
            assert_eq!(a.verify(&t).await.err(), Some(want), "{alg}");
        }
        assert_eq!(
            a.verify(&s.sign(&claims(ORG, AUDIENCE, -120)).unwrap())
                .await,
            Err(AuthError::Expired)
        );
        assert_eq!(
            a.verify(&s.sign(&claims(ORG, "control-plane", 600)).unwrap())
                .await,
            Err(AuthError::WrongAudience)
        );
        assert_eq!(
            a.verify(&s.sign(&claims(Uuid::now_v7(), AUDIENCE, 600)).unwrap())
                .await,
            Err(AuthError::WrongOrg)
        );
        assert_eq!(a.verify("not-a-jwt").await, Err(AuthError::Malformed));
        assert_eq!(
            a.verify(&"a".repeat(MAX_TOKEN_BYTES + 1)).await,
            Err(AuthError::Malformed)
        );
        assert!(a.verify(&good).await.is_ok());
    }

    #[tokio::test]
    async fn rotation_by_kid_keeps_the_old_key_for_the_overlap_window() {
        let (old, new) = (signer(1), signer(2));
        let src = Arc::new(StubJwks::with(vec![old.jwk().clone()]));
        let a = auth(
            src.clone(),
            JwksSettings {
                min_refetch_interval: Duration::ZERO,
                ..JwksSettings::default()
            },
        );
        let old_token = token(&old);
        assert!(a.verify(&old_token).await.is_ok());
        assert_eq!(src.fetches(), 1);

        // The control plane rotates: only the new key is published.
        src.replace(Some(vec![new.jwk().clone()]));
        // A token with the new kid triggers a refetch and verifies.
        assert!(a.verify(&token(&new)).await.is_ok());
        assert_eq!(src.fetches(), 2);
        // Tokens minted before the rotation still verify inside the overlap window, from cache.
        assert!(a.verify(&old_token).await.is_ok());
        assert_eq!(src.fetches(), 2, "known kid needs no fetch");
    }

    #[tokio::test]
    async fn retired_key_is_refused_after_the_overlap_window() {
        let (old, new) = (signer(1), signer(2));
        let src = Arc::new(StubJwks::with(vec![old.jwk().clone()]));
        let a = auth(
            src.clone(),
            JwksSettings {
                min_refetch_interval: Duration::ZERO,
                retain_retired: Duration::ZERO,
                ..JwksSettings::default()
            },
        );
        let old_token = token(&old);
        assert!(a.verify(&old_token).await.is_ok());
        src.replace(Some(vec![new.jwk().clone()]));
        assert!(a.verify(&token(&new)).await.is_ok());
        assert_eq!(a.verify(&old_token).await, Err(AuthError::UnknownKey));
    }

    #[tokio::test]
    async fn unknown_kid_refetches_at_most_once_per_interval() {
        let s = signer(1);
        let src = Arc::new(StubJwks::with(vec![s.jwk().clone()]));
        let a = auth(src.clone(), JwksSettings::default());
        assert!(a.verify(&token(&s)).await.is_ok());
        assert_eq!(src.fetches(), 1);
        // A flood of tokens with unknown kids: no further fetch inside the interval.
        for seed in 2..12 {
            assert_eq!(
                a.verify(&token(&signer(seed))).await,
                Err(AuthError::UnknownKey)
            );
        }
        assert_eq!(src.fetches(), 1);
    }

    #[tokio::test]
    async fn concurrent_misses_share_one_fetch() {
        let s = signer(1);
        let src = Arc::new(StubJwks::with(vec![s.jwk().clone()]));
        let a = Arc::new(auth(src.clone(), JwksSettings::default()));
        let t = token(&s);
        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let (a, t) = (a.clone(), t.clone());
                tokio::spawn(async move { a.verify(&t).await })
            })
            .collect();
        for task in tasks {
            assert!(task.await.unwrap().is_ok());
        }
        assert_eq!(src.fetches(), 1);
    }

    #[tokio::test]
    async fn failed_refresh_keeps_cached_keys_and_no_keys_means_refused() {
        let s = signer(1);
        let src = Arc::new(StubJwks::with(vec![s.jwk().clone()]));
        let a = auth(
            src.clone(),
            JwksSettings {
                refresh_after: Duration::ZERO,
                min_refetch_interval: Duration::ZERO,
                ..JwksSettings::default()
            },
        );
        let t = token(&s);
        assert!(a.verify(&t).await.is_ok());
        src.replace(None);
        assert!(
            a.verify(&t).await.is_ok(),
            "stale but cached key still used"
        );
        assert!(src.fetches() >= 2, "a refresh was attempted");

        let empty = auth(Arc::new(StubJwks::default()), JwksSettings::default());
        assert_eq!(empty.verify(&t).await, Err(AuthError::UnknownKey));
    }

    #[tokio::test]
    async fn http_jwks_reads_the_control_plane_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let cp = MockServer::start().await;
        let s = signer(1);
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "keys": [s.jwk()] })),
            )
            .mount(&cp)
            .await;
        let src = HttpJwks::new(&cp.uri().parse().unwrap()).unwrap();
        assert_eq!(src.fetch().await.unwrap(), vec![s.jwk().clone()]);
        let a = AgentAuth::new(ORG, Arc::new(src), JwksSettings::default());
        assert!(a.verify(&token(&s)).await.is_ok());

        let down = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&down)
            .await;
        let src = HttpJwks::new(&down.uri().parse().unwrap()).unwrap();
        assert_eq!(src.fetch().await, Err(JwksError));

        // A JWKS body over the cap is refused, not parsed.
        let big = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(" ".repeat(MAX_JWKS_RESPONSE + 1)),
            )
            .mount(&big)
            .await;
        let src = HttpJwks::new(&big.uri().parse().unwrap()).unwrap();
        assert_eq!(src.fetch().await, Err(JwksError));
    }

    #[test]
    fn jwks_parsing_skips_foreign_keys() {
        let s = signer(1);
        let body = serde_json::json!({ "keys": [
            { "kty": "RSA", "n": "abc", "e": "AQAB", "kid": "rsa" },
            s.jwk(),
        ]});
        let keys = parse_jwks(body.to_string().as_bytes()).unwrap();
        assert_eq!(keys, vec![s.jwk().clone()]);
        assert_eq!(parse_jwks(b"{}"), Err(JwksError));
    }

    #[test]
    fn merge_ignores_unusable_keys_and_bounds_the_cache() {
        let mut state = KeyState::default();
        let now = Instant::now();
        let mut bad = signer(1).jwk().clone();
        bad.alg = "RS256".to_owned();
        state.merge(vec![bad], now, Duration::from_secs(60));
        assert!(state.keys.is_empty());
        for seed in 0..(MAX_KEYS as u8 + 8) {
            state.merge(
                vec![signer(seed).jwk().clone()],
                now,
                Duration::from_secs(60),
            );
        }
        assert_eq!(state.keys.len(), MAX_KEYS);
        let newest = signer(MAX_KEYS as u8 + 7).jwk().kid.clone();
        assert!(
            state
                .lookup(&newest, now, Duration::from_secs(60))
                .is_some()
        );
    }
}
