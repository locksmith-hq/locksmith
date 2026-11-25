//! The gateway router: health probes, `POST /v1/relay` ([`crate::relay`]) and `GET /v1/grants`
//! ([`crate::grants`]), `/git/{host}/...` ([`crate::git`]) and the OAuth connect start and
//! callback ([`crate::oauth`]).

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
use crate::oauth::{self, OAuth};
use crate::relay::{self, Relay};

/// Shared, cheaply cloneable state.
#[derive(Clone)]
pub struct AppState {
    readiness: Arc<dyn Readiness>,
    relay: Option<Arc<Relay>>,
    mcp: Option<Arc<McpEndpoint>>,
    oauth: Option<Arc<OAuth>>,
}

impl AppState {
    pub fn new(readiness: Arc<dyn Readiness>) -> Self {
        Self {
            readiness,
            relay: None,
            mcp: None,
            oauth: None,
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

    /// Serve `/v1/oauth/connect` and `/oauth/callback` (without it both answer `503`).
    pub fn with_oauth(mut self, oauth: Arc<OAuth>) -> Self {
        self.oauth = Some(oauth);
        self
    }

    pub fn oauth(&self) -> Option<Arc<OAuth>> {
        self.oauth.clone()
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
    // OAuth connections (C1): the console calls `/v1/oauth/*` cross-origin, so CORS for the
    // configured console origins applies there only. The callback is a top-level navigation.
    let oauth_routes = Router::new().route(
        "/v1/oauth/connect",
        post(oauth::connect).layer(DefaultBodyLimit::max(8 * 1024)),
    );
    let oauth_routes = match &state.oauth {
        Some(o) => oauth_routes.layer(o.cors()),
        None => oauth_routes,
    };
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
        .route("/oauth/callback", get(oauth::callback))
        .merge(oauth_routes)
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
