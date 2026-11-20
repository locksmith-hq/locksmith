//! The calling agent's grants (S4 task 2.1, design decision 4).
//!
//! [`GrantSource`] reads an agent's unexpired grants; [`ControlPlane`] serves them from the
//! internal grants endpoint with the gateway service token. `GET /v1/grants` returns them to the
//! agent with the origin each secret may be sent to through this gateway: ids, names, modes,
//! expiry and origins only, never a value.
//!
//! [`GrantCache`] keeps each agent's grants for at most [`MAX_GRANT_TTL`] (design decision 4), so
//! a revoked grant stops working within that time; `/v1/relay` checks [`allows_relay`] before any
//! material fetch or unwrap (S4 task 2.2).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::Instrument;
use uuid::Uuid;

use crate::decrypt::{BoxFuture, ControlPlane, Internal};
use crate::relay::{Relay, error};

/// Largest grants response read.
const MAX_GRANTS_RESPONSE: usize = 1024 * 1024;

/// One unexpired grant as the control plane reports it. Ids, a name and a mode.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Grant {
    pub grant_id: Uuid,
    pub secret_id: Uuid,
    pub secret_name: String,
    pub mode: String,
    /// The allow-list of a `delegate` grant (D2); `None` for `relay`.
    #[serde(default)]
    pub scope: Option<crate::aws_policy::AwsGrantScope>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

impl Grant {
    /// Unexpired at `now` (the control plane filters too; a cached copy must re-check).
    pub fn active_at(&self, now: OffsetDateTime) -> bool {
        self.expires_at.is_none_or(|e| e > now)
    }
}

/// The only mode `/v1/relay` serves.
pub const MODE_RELAY: &str = "relay";
/// The only mode `/v1/aws/credentials` serves (D2).
pub const MODE_DELEGATE: &str = "delegate";

/// The unexpired `delegate` grant for `secret_id` at `now`, if any (the first, in the control
/// plane's order).
pub fn delegate_grant(grants: &[Grant], secret_id: Uuid, now: OffsetDateTime) -> Option<&Grant> {
    grants
        .iter()
        .find(|g| g.secret_id == secret_id && g.mode == MODE_DELEGATE && g.active_at(now))
}

/// Whether `grants` hold an unexpired relay grant for `secret_id` at `now`.
pub fn allows_relay(grants: &[Grant], secret_id: Uuid, now: OffsetDateTime) -> bool {
    grants
        .iter()
        .any(|g| g.secret_id == secret_id && g.mode == MODE_RELAY && g.active_at(now))
}

/// Why grants could not be read. Carries no response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantError {
    /// The control plane refused the service token.
    Denied,
    /// Unreachable, timed out or an unexpected status.
    Unavailable,
    /// The answer did not parse or names another agent.
    BadResponse,
}

impl GrantError {
    /// Stable, secret-free label for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Unavailable => "unavailable",
            Self::BadResponse => "bad_response",
        }
    }
}

/// Reads an agent's unexpired grants.
pub trait GrantSource: Send + Sync {
    fn grants(&self, agent_id: Uuid) -> BoxFuture<'_, Result<Vec<Grant>, GrantError>>;
}

#[derive(Deserialize)]
struct GrantSetJson {
    agent_id: Uuid,
    items: Vec<Grant>,
}

/// Parse the internal endpoint's answer and check it is for `agent_id`.
pub fn parse_grants(body: &[u8], agent_id: Uuid) -> Result<Vec<Grant>, GrantError> {
    let set: GrantSetJson = serde_json::from_slice(body).map_err(|_| GrantError::BadResponse)?;
    if set.agent_id != agent_id {
        return Err(GrantError::BadResponse);
    }
    Ok(set.items)
}

impl ControlPlane {
    async fn agent_grants(&self, agent_id: Uuid) -> Result<Vec<Grant>, GrantError> {
        let path = format!("internal/v1/agents/{agent_id}/grants");
        match self.internal_get(&path, MAX_GRANTS_RESPONSE).await {
            Ok(body) => parse_grants(&body, agent_id),
            // The agent was deleted (or never existed in this org): it holds no grants.
            Err(Internal::NotFound) => Ok(Vec::new()),
            Err(Internal::Denied) => Err(GrantError::Denied),
            Err(Internal::Unavailable) => Err(GrantError::Unavailable),
            Err(Internal::BadResponse) => Err(GrantError::BadResponse),
        }
    }
}

impl GrantSource for ControlPlane {
    fn grants(&self, agent_id: Uuid) -> BoxFuture<'_, Result<Vec<Grant>, GrantError>> {
        Box::pin(self.agent_grants(agent_id))
    }
}

/// Longest time a grant set is served from the cache (design decision 4: at most 10 s), so a
/// revocation takes effect within it. Larger configured TTLs are clamped to this.
pub const MAX_GRANT_TTL: Duration = Duration::from_secs(10);

/// Grant cache bounds.
#[derive(Debug, Clone, Copy)]
pub struct GrantCacheSettings {
    /// Clamped to [`MAX_GRANT_TTL`]; zero disables caching.
    pub ttl: Duration,
    pub max_entries: usize,
}

impl Default for GrantCacheSettings {
    fn default() -> Self {
        Self {
            ttl: MAX_GRANT_TTL,
            max_entries: 10_000,
        }
    }
}

struct CachedSet {
    grants: Vec<Grant>,
    fetched: Instant,
}

/// A [`GrantSource`] that serves each agent's grant set from memory for at most the TTL (an empty
/// set too, so a new grant may also take up to the TTL to be usable). Errors are never cached.
/// Expiry inside a cached set is re-checked by the caller ([`Grant::active_at`]).
pub struct GrantCache {
    source: Arc<dyn GrantSource>,
    settings: GrantCacheSettings,
    entries: Mutex<HashMap<Uuid, CachedSet>>,
}

impl GrantCache {
    pub fn new(source: Arc<dyn GrantSource>, settings: GrantCacheSettings) -> Self {
        Self {
            source,
            settings: GrantCacheSettings {
                ttl: settings.ttl.min(MAX_GRANT_TTL),
                ..settings
            },
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.settings.ttl
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<Uuid, CachedSet>> {
        // A panic while holding the lock cannot leave a half-written entry; keep serving.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn fresh(&self, e: &CachedSet, now: Instant) -> bool {
        now.saturating_duration_since(e.fetched) < self.settings.ttl
    }

    fn get_at(&self, agent_id: Uuid, now: Instant) -> Option<Vec<Grant>> {
        let mut map = self.lock();
        match map.get(&agent_id) {
            Some(e) if self.fresh(e, now) => Some(e.grants.clone()),
            Some(_) => {
                map.remove(&agent_id);
                None
            }
            None => None,
        }
    }

    fn insert_at(&self, agent_id: Uuid, grants: Vec<Grant>, now: Instant) {
        if self.settings.max_entries == 0 || self.settings.ttl.is_zero() {
            return;
        }
        let mut map = self.lock();
        // Expiry sweep only when the map is full and would otherwise evict (not on every
        // miss): below the bound an insert stays O(1) under the mutex, and at the bound the
        // eviction already scans the map. Stale entries below the bound are never served
        // ([`Self::get_at`] checks freshness) and are dropped on their next read or the next
        // sweep. Refreshing an agent already in the map replaces it and evicts nothing.
        if map.len() >= self.settings.max_entries && !map.contains_key(&agent_id) {
            map.retain(|_, e| self.fresh(e, now));
        }
        while map.len() >= self.settings.max_entries && !map.contains_key(&agent_id) {
            let oldest = map.iter().min_by_key(|(_, e)| e.fetched).map(|(k, _)| *k);
            match oldest {
                Some(k) => {
                    map.remove(&k);
                }
                None => break,
            }
        }
        map.insert(
            agent_id,
            CachedSet {
                grants,
                fetched: now,
            },
        );
    }

    async fn read(&self, agent_id: Uuid) -> Result<Vec<Grant>, GrantError> {
        if let Some(g) = self.get_at(agent_id, Instant::now()) {
            return Ok(g);
        }
        // Stamp the entry with the time the fetch started, so it never outlives the TTL
        // measured from when the control plane was asked.
        let started = Instant::now();
        let grants = self.source.grants(agent_id).await?;
        self.insert_at(agent_id, grants.clone(), started);
        Ok(grants)
    }
}

impl GrantSource for GrantCache {
    fn grants(&self, agent_id: Uuid) -> BoxFuture<'_, Result<Vec<Grant>, GrantError>> {
        Box::pin(self.read(agent_id))
    }
}

/// `GET /v1/grants` response: what the calling agent may use.
#[derive(Debug, Serialize, Deserialize)]
pub struct GrantList {
    pub agent_id: Uuid,
    pub grants: Vec<GrantView>,
}

/// One grant as the agent sees it. No value, ever.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantView {
    pub secret_id: Uuid,
    pub secret_name: String,
    pub mode: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    /// The origin this gateway sends the secret to; `null` when this gateway has no binding for
    /// it (the grant cannot be used here).
    pub allowed_origin: Option<String>,
}

async fn list(relay: &Relay, headers: &HeaderMap, request_id: &str) -> Response {
    let agent = match relay.auth().authenticate(headers).await {
        Ok(a) => a,
        Err(e) => {
            tracing::info!(reason = e.as_str(), "agent token refused");
            return error(StatusCode::UNAUTHORIZED, "unauthenticated", request_id);
        }
    };
    let span = tracing::info_span!(
        "list_grants",
        request_id = %request_id,
        agent.id = %agent.agent_id
    );
    let read = relay
        .grants()
        .grants(agent.agent_id)
        .instrument(span.clone())
        .await;
    let _entered = span.enter();
    let grants = match read {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(reason = e.as_str(), "agent grants could not be read");
            return error(StatusCode::BAD_GATEWAY, "grants_unavailable", request_id);
        }
    };
    let now = OffsetDateTime::now_utc();
    let grants: Vec<GrantView> = grants
        .into_iter()
        .filter(|g| g.active_at(now))
        .map(|g| GrantView {
            allowed_origin: relay
                .bindings()
                .for_secret(g.secret_id)
                .map(|b| b.origin.clone()),
            secret_id: g.secret_id,
            secret_name: g.secret_name,
            mode: g.mode,
            expires_at: g.expires_at,
        })
        .collect();
    tracing::info!(grants = grants.len(), "agent grants listed");
    let mut r = (
        StatusCode::OK,
        Json(GrantList {
            agent_id: agent.agent_id,
            grants,
        }),
    )
        .into_response();
    if let Ok(v) = request_id.parse() {
        r.headers_mut().insert("x-request-id", v);
    }
    r
}

/// Axum entry point: `503` until the gateway is configured.
pub async fn route(State(state): State<crate::app::AppState>, headers: HeaderMap) -> Response {
    let request_id = Uuid::new_v4().to_string();
    match state.relay() {
        Some(relay) => list(&relay, &headers, &request_id).await,
        None => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", &request_id),
    }
}

#[cfg(test)]
pub mod testkit {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Grants by agent; `fail` makes every read fail.
    #[derive(Default)]
    pub struct StubGrants {
        pub by_agent: Mutex<HashMap<Uuid, Vec<Grant>>>,
        pub fail: bool,
        pub calls: AtomicUsize,
    }

    impl StubGrants {
        pub fn set(&self, agent: Uuid, grants: Vec<Grant>) {
            self.by_agent.lock().unwrap().insert(agent, grants);
        }

        pub fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl GrantSource for StubGrants {
        fn grants(&self, agent_id: Uuid) -> BoxFuture<'_, Result<Vec<Grant>, GrantError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let r = if self.fail {
                Err(GrantError::Unavailable)
            } else {
                Ok(self
                    .by_agent
                    .lock()
                    .unwrap()
                    .get(&agent_id)
                    .cloned()
                    .unwrap_or_default())
            };
            Box::pin(async move { r })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000b1);
    const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000b2);

    #[tokio::test]
    async fn control_plane_grants_are_read_with_the_service_token() {
        let cp = MockServer::start().await;
        let secret = Uuid::now_v7();
        Mock::given(method("GET"))
            .and(path(format!("/internal/v1/agents/{AGENT}/grants")))
            .and(header(
                "authorization",
                format!("Bearer {}", "s".repeat(32)).as_str(),
            ))
            .and(header("x-locksmith-org", ORG.to_string().as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "agent_id": AGENT,
                "items": [{
                    "grant_id": Uuid::now_v7(), "secret_id": secret, "secret_name": "STRIPE_KEY",
                    "mode": "relay", "expires_at": "2099-01-01T00:00:00Z"
                }]
            })))
            .mount(&cp)
            .await;
        let other = Uuid::now_v7();
        Mock::given(method("GET"))
            .and(path(format!("/internal/v1/agents/{other}/grants")))
            .respond_with(ResponseTemplate::new(404))
            .mount(&cp)
            .await;
        let client = ControlPlane::new(
            cp.uri().parse().unwrap(),
            ORG,
            SecretString::from("s".repeat(32)),
        )
        .unwrap();
        let g = client.grants(AGENT).await.unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!(
            (
                g[0].secret_id,
                g[0].secret_name.as_str(),
                g[0].mode.as_str()
            ),
            (secret, "STRIPE_KEY", "relay")
        );
        assert!(g[0].expires_at.is_some());
        assert_eq!(client.grants(other).await, Ok(Vec::new()), "deleted agent");
    }

    fn grant(secret_id: Uuid, mode: &str, expires_at: Option<OffsetDateTime>) -> Grant {
        Grant {
            grant_id: Uuid::now_v7(),
            secret_id,
            secret_name: "S".to_owned(),
            mode: mode.to_owned(),
            scope: None,
            expires_at,
        }
    }

    #[test]
    fn allows_relay_needs_an_unexpired_relay_grant_for_the_secret() {
        let secret = Uuid::now_v7();
        let now = OffsetDateTime::now_utc();
        let past = Some(now - time::Duration::seconds(1));
        let future = Some(now + time::Duration::seconds(60));
        assert!(allows_relay(&[grant(secret, "relay", None)], secret, now));
        assert!(allows_relay(&[grant(secret, "relay", future)], secret, now));
        assert!(!allows_relay(&[], secret, now));
        assert!(!allows_relay(&[grant(secret, "relay", past)], secret, now));
        assert!(
            !allows_relay(&[grant(secret, "relay", Some(now))], secret, now),
            "expiry is exclusive"
        );
        assert!(!allows_relay(&[grant(secret, "inject", None)], secret, now));
        assert!(!allows_relay(
            &[grant(Uuid::now_v7(), "relay", None)],
            secret,
            now
        ));
    }

    #[test]
    fn cache_ttl_is_at_most_ten_seconds() {
        let src = Arc::new(testkit::StubGrants::default());
        let c = GrantCache::new(
            src.clone(),
            GrantCacheSettings {
                ttl: Duration::from_secs(3600),
                max_entries: 10,
            },
        );
        assert_eq!(c.ttl(), MAX_GRANT_TTL);
        assert_eq!(MAX_GRANT_TTL, Duration::from_secs(10));
        assert_eq!(
            GrantCache::new(src, GrantCacheSettings::default()).ttl(),
            MAX_GRANT_TTL
        );
    }

    #[test]
    fn cached_set_expires_at_the_ttl() {
        let c = GrantCache::new(
            Arc::new(testkit::StubGrants::default()),
            GrantCacheSettings::default(),
        );
        let t0 = Instant::now();
        let set = vec![grant(Uuid::now_v7(), "relay", None)];
        c.insert_at(AGENT, set.clone(), t0);
        assert_eq!(
            c.get_at(AGENT, t0 + Duration::from_millis(9_999)),
            Some(set)
        );
        assert_eq!(c.get_at(AGENT, t0 + MAX_GRANT_TTL), None, "gone at the TTL");
        assert_eq!(c.get_at(AGENT, t0), None, "and removed");
    }

    #[test]
    fn cache_is_bounded() {
        let c = GrantCache::new(
            Arc::new(testkit::StubGrants::default()),
            GrantCacheSettings {
                ttl: MAX_GRANT_TTL,
                max_entries: 2,
            },
        );
        let t0 = Instant::now();
        let (a, b, d) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        c.insert_at(a, Vec::new(), t0);
        c.insert_at(b, Vec::new(), t0 + Duration::from_millis(1));
        c.insert_at(d, Vec::new(), t0 + Duration::from_millis(2));
        let now = t0 + Duration::from_millis(3);
        assert_eq!(c.get_at(a, now), None, "oldest evicted");
        assert!(c.get_at(b, now).is_some() && c.get_at(d, now).is_some());
    }

    #[test]
    fn cache_sweeps_expired_entries_only_when_full() {
        let c = GrantCache::new(
            Arc::new(testkit::StubGrants::default()),
            GrantCacheSettings {
                ttl: MAX_GRANT_TTL,
                max_entries: 3,
            },
        );
        let t0 = Instant::now();
        let (a, b, d, e) = (
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );
        c.insert_at(a, Vec::new(), t0);
        c.insert_at(b, Vec::new(), t0 + Duration::from_secs(5));
        // `a` is stale but the map is below the bound: no sweep, and it is never served.
        let later = t0 + MAX_GRANT_TTL + Duration::from_secs(1);
        c.insert_at(d, Vec::new(), later);
        assert_eq!(c.lock().len(), 3, "no sweep below the bound");
        // Full: the sweep drops only the stale `a`; the fresh `b` and `d` survive.
        c.insert_at(e, Vec::new(), later);
        assert_eq!(c.lock().len(), 3);
        assert!(!c.lock().contains_key(&a), "stale entry swept");
        for k in [b, d, e] {
            assert!(c.get_at(k, later).is_some());
        }
        // Refreshing an agent already in a full map evicts nothing.
        c.insert_at(e, Vec::new(), later);
        assert_eq!(c.lock().len(), 3);
    }

    #[tokio::test]
    async fn cache_serves_within_the_ttl_and_never_caches_errors() {
        let src = Arc::new(testkit::StubGrants::default());
        src.set(AGENT, vec![grant(Uuid::now_v7(), "relay", None)]);
        let c = GrantCache::new(src.clone(), GrantCacheSettings::default());
        assert_eq!(c.grants(AGENT).await.unwrap().len(), 1);
        src.set(AGENT, Vec::new());
        assert_eq!(c.grants(AGENT).await.unwrap().len(), 1, "cached");
        assert_eq!(src.calls(), 1);

        let failing = Arc::new(testkit::StubGrants {
            fail: true,
            ..testkit::StubGrants::default()
        });
        let c = GrantCache::new(failing.clone(), GrantCacheSettings::default());
        assert_eq!(c.grants(AGENT).await, Err(GrantError::Unavailable));
        assert_eq!(c.grants(AGENT).await, Err(GrantError::Unavailable));
        assert_eq!(failing.calls(), 2, "errors are not cached");

        let off = GrantCache::new(
            src.clone(),
            GrantCacheSettings {
                ttl: Duration::ZERO,
                max_entries: 10,
            },
        );
        off.grants(AGENT).await.unwrap();
        off.grants(AGENT).await.unwrap();
        assert_eq!(src.calls(), 3, "zero TTL disables caching");
    }

    #[test]
    fn grants_for_another_agent_are_refused() {
        let body = serde_json::json!({ "agent_id": Uuid::now_v7(), "items": [] }).to_string();
        assert_eq!(
            parse_grants(body.as_bytes(), AGENT),
            Err(GrantError::BadResponse)
        );
    }
}
