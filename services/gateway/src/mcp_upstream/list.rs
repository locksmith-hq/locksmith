//! Task 6.1 of m2-mcp-gateway: `GET /v1/mcp/upstreams`, the names of the upstreams the calling
//! agent may use, so `smith init --mcp-gateway` rewrites only those MCP entries.
//!
//! An upstream is listed only when the agent holds an unexpired `relay` grant on its
//! `secret_id` (the same test as `/mcp/upstream/{name}`). The answer is names and nothing else:
//! no URL, header, template, secret id or tool rule.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::app::AppState;
use crate::grants::allows_relay;
use crate::relay::{Relay, error};

/// The route.
pub const PATH: &str = "/v1/mcp/upstreams";

/// The `GET /v1/mcp/upstreams` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamList {
    /// Upstream names (`[a-z0-9-]{1,32}`), sorted.
    pub upstreams: Vec<String>,
}

fn with_request_id(mut r: Response, request_id: &str) -> Response {
    if let Ok(v) = request_id.parse() {
        r.headers_mut().insert("x-request-id", v);
    }
    r
}

async fn list(relay: &Relay, headers: &HeaderMap, request_id: &str) -> Response {
    let agent = match relay.auth().authenticate(headers).await {
        Ok(a) => a,
        Err(e) => {
            tracing::info!(reason = e.as_str(), "agent token refused");
            return error(StatusCode::UNAUTHORIZED, "unauthenticated", request_id);
        }
    };
    let grants = match relay.grants().grants(agent.agent_id).await {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(reason = e.as_str(), "agent grants could not be read");
            return error(StatusCode::BAD_GATEWAY, "grants_unavailable", request_id);
        }
    };
    // The expiry is re-checked because the set may come from the cache.
    let now = OffsetDateTime::now_utc();
    let mut upstreams: Vec<String> = relay
        .bindings()
        .mcp_upstreams
        .iter()
        .filter(|u| allows_relay(&grants, u.secret_id, now))
        .map(|u| u.name.clone())
        .collect();
    upstreams.sort();
    tracing::info!(upstreams = upstreams.len(), "mcp upstreams listed");
    with_request_id(
        (StatusCode::OK, Json(UpstreamList { upstreams })).into_response(),
        request_id,
    )
}

/// Axum entry point: `503` until the gateway is configured.
pub async fn route(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let request_id = Uuid::new_v4().to_string();
    match state.relay() {
        Some(relay) => list(&relay, &headers, &request_id).await,
        None => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", &request_id),
    }
}
