//! The gateway router: health probes and `POST /v1/relay` ([`crate::relay`]).

use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use ls_control_plane::readiness::Readiness;

use crate::relay::{self, Relay};

/// Shared, cheaply cloneable state.
#[derive(Clone)]
pub struct AppState {
    readiness: Arc<dyn Readiness>,
    relay: Option<Arc<Relay>>,
}

impl AppState {
    pub fn new(readiness: Arc<dyn Readiness>) -> Self {
        Self {
            readiness,
            relay: None,
        }
    }

    /// Serve `/v1/relay` (without it the route answers `503`).
    pub fn with_relay(mut self, relay: Arc<Relay>) -> Self {
        self.relay = Some(relay);
        self
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
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route(
            "/v1/relay",
            post(relay::route).layer(DefaultBodyLimit::max(body_limit)),
        )
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
