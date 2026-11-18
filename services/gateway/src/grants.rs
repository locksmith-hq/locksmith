//! The calling agent's grants (S4 task 2.1, design decision 4).
//!
//! [`GrantSource`] reads an agent's unexpired grants; [`ControlPlane`] serves them from the
//! internal grants endpoint with the gateway service token. `GET /v1/grants` returns them to the
//! agent with the origin each secret may be sent to through this gateway: ids, names, modes,
//! expiry and origins only, never a value.
//!
//! Task 2.2 adds the short-lived cache and the check before unwrap on `/v1/relay`.

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
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

impl Grant {
    /// Unexpired at `now` (the control plane filters too; a cached copy must re-check).
    pub fn active_at(&self, now: OffsetDateTime) -> bool {
        self.expires_at.is_none_or(|e| e > now)
    }
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
        Err(_) => {
            tracing::warn!("agent grants could not be read");
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

    #[test]
    fn grants_for_another_agent_are_refused() {
        let body = serde_json::json!({ "agent_id": Uuid::now_v7(), "items": [] }).to_string();
        assert_eq!(
            parse_grants(body.as_bytes(), AGENT),
            Err(GrantError::BadResponse)
        );
    }
}
