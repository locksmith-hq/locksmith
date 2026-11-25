//! The gateway router: health probes, `POST /v1/relay` ([`crate::relay`]) and `GET /v1/grants`
//! ([`crate::grants`]), `/git/{host}/...` ([`crate::git`]), `/mcp` ([`crate::mcp_endpoint`]) and
//! `/mcp/upstream/{name}` ([`crate::mcp_upstream`]).

use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use ls_control_plane::readiness::Readiness;

use crate::aws;
use crate::git;
use crate::grants;
use crate::mcp_endpoint::{self, McpEndpoint};
use crate::mcp_upstream;
use crate::relay::{self, Relay};
use ls_mcp_server::upstream::ToolPolicy;

/// Shared, cheaply cloneable state.
#[derive(Clone)]
pub struct AppState {
    readiness: Arc<dyn Readiness>,
    relay: Option<Arc<Relay>>,
    mcp: Option<Arc<McpEndpoint>>,
    tool_policy: Option<Arc<dyn ToolPolicy>>,
}

impl AppState {
    pub fn new(readiness: Arc<dyn Readiness>) -> Self {
        Self {
            readiness,
            relay: None,
            mcp: None,
            tool_policy: None,
        }
    }

    /// Serve `/v1/relay` and `/v1/grants` (without it both answer `503`).
    pub fn with_relay(mut self, relay: Arc<Relay>) -> Self {
        self.relay = Some(relay);
        self
    }

    /// Serve `/mcp` (without it the route answers `401`, fail closed).
    pub fn with_mcp(mut self, mcp: McpEndpoint) -> Self {
        self.mcp = Some(Arc::new(mcp));
        self
    }

    /// Decide the tools of the `/mcp/upstream/{name}` servers (without it every tool is hidden
    /// and every call refused, fail closed).
    pub fn with_tool_policy(mut self, policy: Arc<dyn ToolPolicy>) -> Self {
        self.tool_policy = Some(policy);
        self
    }

    pub fn tool_policy(&self) -> Option<Arc<dyn ToolPolicy>> {
        self.tool_policy.clone()
    }

    pub fn mcp(&self) -> Option<Arc<McpEndpoint>> {
        self.mcp.clone()
    }

    pub fn relay(&self) -> Option<Arc<Relay>> {
        self.relay.clone()
    }
}

pub fn build(state: AppState) -> Router {
    // The JSON envelope carries the upstream body, base64 at worst (4/3) plus headers.
    let body_limit = state
        .relay
        .as_ref()
        .map_or(64 * 1024, |r| r.options().max_request_body * 2 + 64 * 1024);
    let mcp = mcp_endpoint::router(&state);
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route(
            "/v1/relay",
            post(relay::route).layer(DefaultBodyLimit::max(body_limit)),
        )
        .route("/v1/grants", get(grants::route))
        // AWS credential vending (D2): a small JSON request.
        .route(
            "/v1/aws/credentials",
            post(aws::route).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        // Smart-HTTP Git (D1): bodies are streamed, so no whole-body limit applies.
        .route(
            "/git/{host}/{*rest}",
            get(git::route)
                .post(git::route)
                .layer(DefaultBodyLimit::disable()),
        )
        // Upstream MCP servers (m2-mcp-gateway): the same agent token, `Host` allowlist and rmcp
        // log cap as `/mcp`; an unknown name and one without a relay grant are the same `404`.
        .route(mcp_upstream::PATH, mcp_upstream::route(&state))
        // Which upstreams the calling agent may use (task 6.1): names only.
        .route(mcp_upstream::list::PATH, get(mcp_upstream::list::route))
        .merge(mcp)
        .with_state(state)
}

/// Liveness: `200` whenever the process serves requests.
async fn healthz() -> StatusCode {
    StatusCode::OK
}

/// Readiness: `200` while Postgres answers.
async fn readyz(State(state): State<AppState>) -> StatusCode {
    if state.readiness.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use ls_control_plane::readiness::ReadyFlag;
    use tower::ServiceExt;

    async fn status(app: &Router, path: &str) -> StatusCode {
        app.clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn health_and_readiness() {
        let flag = Arc::new(ReadyFlag::new(false));
        let app = build(AppState::new(flag.clone()));
        assert_eq!(status(&app, "/healthz").await, StatusCode::OK);
        assert_eq!(
            status(&app, "/readyz").await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        flag.set_ready(true);
        assert_eq!(status(&app, "/readyz").await, StatusCode::OK);
        assert_eq!(status(&app, "/nope").await, StatusCode::NOT_FOUND);
    }
}
