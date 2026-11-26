//! Router: open probes plus the authenticated internal API (operations arrive in group 3).

use std::sync::Arc;

use axum::Router;
use axum::middleware;
use axum::routing::{get, post};
use http::StatusCode;
use ls_agent_token::AgentTokenSigner;
use ls_oidc_verify::abuse::AbuseGuard;
use ls_oidc_verify::external::ExternalVerifier;
use sqlx_postgres::PgPool;

use crate::agent_token_api;
use crate::audit_api;
use crate::auth::{self, ServiceToken};
use crate::checkpoint_api::{self, CheckpointSigner};
use crate::dek_api::{self, DekKeyWrapper, HandleStore};
use crate::enrollment_api;
use crate::workload_api;

#[derive(Clone)]
pub struct AppState {
    token: Arc<ServiceToken>,
    pool: Option<PgPool>,
    signer: Option<Arc<dyn CheckpointSigner>>,
    agent_signer: Option<Arc<AgentTokenSigner>>,
    workload_verifier: Option<Arc<ExternalVerifier>>,
    workload_abuse: Arc<AbuseGuard>,
    dek_kms: Option<Arc<dyn DekKeyWrapper>>,
    deks: Arc<HandleStore>,
}

impl AppState {
    pub fn new(token: ServiceToken) -> Self {
        Self {
            token: Arc::new(token),
            pool: None,
            signer: None,
            agent_signer: None,
            workload_verifier: None,
            workload_abuse: Arc::new(AbuseGuard::default()),
            dek_kms: None,
            deks: Arc::new(HandleStore::default()),
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

    /// The Ed25519 key agent tokens are minted and verified with.
    pub fn with_agent_signer(mut self, signer: Arc<AgentTokenSigner>) -> Self {
        self.agent_signer = Some(signer);
        self
    }

    /// Verifier for external workload tokens (issuer discovery and JWKS).
    pub fn with_workload_verifier(mut self, verifier: ExternalVerifier) -> Self {
        self.workload_verifier = Some(Arc::new(verifier));
        self
    }

    /// The KMS data keys are wrapped and unwrapped with.
    pub fn with_dek_kms(mut self, kms: Arc<dyn DekKeyWrapper>) -> Self {
        self.dek_kms = Some(kms);
        self
    }

    pub(crate) fn dek_kms(&self) -> Option<&Arc<dyn DekKeyWrapper>> {
        self.dek_kms.as_ref()
    }

    pub(crate) fn deks(&self) -> &HandleStore {
        &self.deks
    }

    pub(crate) fn workload_verifier(&self) -> Option<&Arc<ExternalVerifier>> {
        self.workload_verifier.as_ref()
    }

    pub(crate) fn workload_abuse(&self) -> &AbuseGuard {
        &self.workload_abuse
    }

    pub(crate) fn agent_signer(&self) -> Option<&Arc<AgentTokenSigner>> {
        self.agent_signer.as_ref()
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
        .route("/v1/agent-tokens/mint", post(agent_token_api::mint))
        .route("/v1/agent-tokens/verify", post(agent_token_api::verify))
        .route(
            "/v1/workload-tokens/mint",
            post(agent_token_api::mint_workload),
        )
        .route("/v1/workload-tokens/verify", post(workload_api::verify))
        .route("/v1/deks/wrap", post(dek_api::wrap))
        .route("/v1/deks/unwrap", post(dek_api::unwrap))
        .route(
            "/v1/enrollment-secrets/generate",
            post(enrollment_api::generate),
        )
        .route(
            "/v1/enrollment-secrets/verify",
            post(enrollment_api::verify),
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
