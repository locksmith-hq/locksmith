//! The gateway router. Task 2 has health probes only; `/v1/relay` arrives in task 3.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use ls_control_plane::readiness::Readiness;

/// Shared, cheaply cloneable state.
#[derive(Clone)]
pub struct AppState {
    readiness: Arc<dyn Readiness>,
}

impl AppState {
    pub fn new(readiness: Arc<dyn Readiness>) -> Self {
        Self { readiness }
    }
}

pub fn build(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
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
