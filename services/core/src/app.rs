//! Router: open probes plus the authenticated internal API (operations arrive in group 3).

use std::sync::Arc;

use axum::Router;
use axum::middleware;
use axum::routing::{get, post};
use http::StatusCode;
use sqlx_postgres::PgPool;

use crate::audit_api;
use crate::auth::{self, ServiceToken};
use crate::checkpoint_api::{self, CheckpointSigner};

#[derive(Clone)]
pub struct AppState {
    token: Arc<ServiceToken>,
    pool: Option<PgPool>,
    signer: Option<Arc<dyn CheckpointSigner>>,
}

impl AppState {
    pub fn new(token: ServiceToken) -> Self {
        Self {
            token: Arc::new(token),
            pool: None,
            signer: None,
        }
    }

    /// The `locksmith_app` pool the audit ledger appends through.
    pub fn with_pool(mut self, pool: PgPool) -> Self {
        self.pool = Some(pool);
        self
    }

    /// The transit signer audit checkpoints are signed with.
    pub fn with_signer(mut self, signer: Arc<dyn CheckpointSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    pub(crate) fn signer(&self) -> Option<&Arc<dyn CheckpointSigner>> {
        self.signer.as_ref()
    }

    pub(crate) fn pool(&self) -> Option<&PgPool> {
        self.pool.as_ref()
    }

    pub(crate) fn token(&self) -> &ServiceToken {
        &self.token
    }
}

pub fn router(state: AppState) -> Router {
    // Authenticated operations are mounted here from task 3.1.
    let internal = Router::new()
        .route("/v1/audit/events", post(audit_api::append_event))
        .route(
            "/v1/audit/checkpoints",
            post(checkpoint_api::sign_checkpoint),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_service_token,
        ));
    Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/readyz", get(|| async { StatusCode::OK }))
        .merge(internal)
        .with_state(state)
}
