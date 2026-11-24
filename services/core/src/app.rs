//! Router: open probes plus the authenticated internal API (operations arrive in group 3).

use std::sync::Arc;

use axum::Router;
use axum::middleware;
use axum::routing::get;
use http::StatusCode;

use crate::auth::{self, ServiceToken};

#[derive(Clone)]
pub struct AppState {
    token: Arc<ServiceToken>,
}

impl AppState {
    pub fn new(token: ServiceToken) -> Self {
        Self {
            token: Arc::new(token),
        }
    }

    pub(crate) fn token(&self) -> &ServiceToken {
        &self.token
    }
}

pub fn router(state: AppState) -> Router {
    // Authenticated operations are mounted here from task 3.1.
    let internal = Router::new().layer(middleware::from_fn_with_state(
        state.clone(),
        auth::require_service_token,
    ));
    Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/readyz", get(|| async { StatusCode::OK }))
        .merge(internal)
        .with_state(state)
}
