//! Router construction: health endpoints and the tower-http layer stack.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderName, StatusCode};
use axum::routing::get;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::db::Database;
use crate::problem::ApiError;
use crate::readiness::Readiness;

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const BODY_LIMIT_BYTES: usize = 64 * 1024;
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Shared, cheaply cloneable application state.
#[derive(Clone)]
pub struct AppState {
    dev_auth: bool,
    readiness: Arc<dyn Readiness>,
    db: Database,
}

impl AppState {
    pub fn new(dev_auth: bool, readiness: Arc<dyn Readiness>, db: Database) -> Self {
        Self {
            dev_auth,
            readiness,
            db,
        }
    }

    pub fn dev_auth(&self) -> bool {
        self.dev_auth
    }

    /// The database, reachable only through tenant transactions ([`Database::with_org`]).
    pub fn db(&self) -> &Database {
        &self.db
    }
}

/// Routes without layers or state applied; the `/v1` API is merged in.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .merge(crate::api::router())
        .fallback(fallback)
}

/// Apply the standard layer stack and state to a router.
pub fn with_layers(router: Router<AppState>, state: AppState) -> Router {
    let id_header = HeaderName::from_static(REQUEST_ID_HEADER);
    router.with_state(state).layer(
        ServiceBuilder::new()
            .layer(SetRequestIdLayer::new(id_header.clone(), MakeRequestUuid))
            .layer(TraceLayer::new_for_http())
            .layer(PropagateRequestIdLayer::new(id_header))
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                REQUEST_TIMEOUT,
            ))
            .layer(RequestBodyLimitLayer::new(BODY_LIMIT_BYTES)),
    )
}

/// The full application.
pub fn build(state: AppState) -> Router {
    with_layers(routes(), state)
}

async fn fallback() -> ApiError {
    ApiError::not_found()
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn readyz(State(state): State<AppState>) -> StatusCode {
    if state.readiness.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
