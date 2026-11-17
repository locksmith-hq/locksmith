//! Router construction: health endpoints and the tower-http layer stack.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderName, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::db::Database;
use crate::problem::ApiError;
use crate::readiness::Readiness;

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const BODY_LIMIT_BYTES: usize = 64 * 1024;
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Document-level OpenAPI metadata; paths and schemas are collected from the routes.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Locksmith control-plane API",
        description = "Orgs, projects, environments and secret metadata. Secret values are never part of this API.",
        license(name = "see repository"),
    ),
    modifiers(&DevOrgSecurity),
    tags(
        (name = "health", description = "Liveness and readiness"),
        (name = "orgs"), (name = "projects"), (name = "environments"), (name = "secrets"),
    )
)]
struct ApiDoc;

/// Registers the dev-only org binding header as a security scheme (replaced by JWT in T1).
struct DevOrgSecurity;

impl Modify for DevOrgSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "dev_org",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                crate::auth::DEV_ORG_HEADER,
                "Dev-only org binding, honoured only with LOCKSMITH_DEV_AUTH=1.",
            ))),
        );
    }
}

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

/// The OpenAPI document and routes, declared once. Needs no state or database.
fn api_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(healthz))
        .routes(routes!(readyz))
        .merge(crate::api::router())
}

/// The OpenAPI 3.1 document for the whole service, built from the router definitions.
pub fn openapi() -> utoipa::openapi::OpenApi {
    api_router().split_for_parts().1
}

/// Routes without layers or state applied: the `/v1` API, health, and `/openapi.json`.
pub fn routes() -> Router<AppState> {
    let (router, api) = api_router().split_for_parts();
    router
        .route("/openapi.json", get(move || async move { Json(api) }))
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

/// Liveness: `200` whenever the process serves requests.
#[utoipa::path(get, path = "/healthz", tag = "health", summary = "Liveness probe",
    responses((status = 200, description = "The process is up")))]
async fn healthz() -> StatusCode {
    StatusCode::OK
}

/// Readiness: `200` once migrations are applied and Postgres answers.
#[utoipa::path(get, path = "/readyz", tag = "health", summary = "Readiness probe",
    responses((status = 200, description = "Ready"), (status = 503, description = "Not ready")))]
async fn readyz(State(state): State<AppState>) -> StatusCode {
    if state.readiness.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
