//! Router construction: health endpoints and the tower-http layer stack.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use tower::ServiceBuilder;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, Http, HttpAuthScheme, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::agent_token::AgentTokenSigner;
use crate::auth::ServiceToken;
use crate::auth::human::HumanAuth;
use crate::db::Database;
use crate::issuer_admin::IssuerAdmin;
use crate::kms::DekWrapper;
use crate::mcp_endpoint::{self, McpEndpoint};
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
        description = "Orgs, projects, environments, secret metadata, write-only secret versions, agents and their grants. A secret value can be written to a new version; no endpoint ever returns a value. An agent's enrollment secret is returned once, when it is created or rotated.",
        license(name = "see repository"),
    ),
    // The shared error sets in `api::responses` reference `Problem` by `$ref`.
    components(schemas(crate::problem::Problem)),
    modifiers(&DevOrgSecurity),
    tags(
        (name = "health", description = "Liveness and readiness"),
        (name = "auth", description = "Sign-in and sign-out markers for the audit ledger; human bearer token only"),
        (name = "orgs"), (name = "projects"), (name = "environments"), (name = "secrets"),
        (name = "agents", description = "Agent identities, their relay grants, agent tokens and the token-signing JWKS"),
        (name = "internal", description = "Service-to-service routes for the gateway; service token only, never exposed to users or agents"),
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
        components.add_security_scheme(
            "service_token",
            SecurityScheme::Http(
                Http::builder()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "Gateway service token (LOCKSMITH_GATEWAY_SERVICE_TOKEN); the org is named in the X-Locksmith-Org header.",
                    ))
                    .build(),
            ),
        );
    }
}

/// Shared, cheaply cloneable application state.
#[derive(Clone)]
pub struct AppState {
    dev_auth: bool,
    readiness: Arc<dyn Readiness>,
    db: Database,
    kms: Option<Arc<dyn DekWrapper>>,
    service_token: Option<Arc<ServiceToken>>,
    agent_signer: Option<Arc<AgentTokenSigner>>,
    human_auth: Option<Arc<HumanAuth>>,
    mcp: Option<Arc<McpEndpoint>>,
    issuer_admin: Option<Arc<IssuerAdmin>>,
}

impl AppState {
    /// State without a KMS: secret version writes answer `503` until [`Self::with_kms`].
    pub fn new(dev_auth: bool, readiness: Arc<dyn Readiness>, db: Database) -> Self {
        Self {
            dev_auth,
            readiness,
            db,
            kms: None,
            service_token: None,
            agent_signer: None,
            human_auth: None,
            mcp: None,
            issuer_admin: None,
        }
    }

    /// Revoke the person's consent at the issuer after a hub MCP client revoke (M1 task 4.2).
    /// Without one that step is skipped.
    pub fn with_issuer_admin(mut self, admin: IssuerAdmin) -> Self {
        self.issuer_admin = Some(Arc::new(admin));
        self
    }

    /// The issuer admin client, if one is configured.
    pub fn issuer_admin(&self) -> Option<&IssuerAdmin> {
        self.issuer_admin.as_deref()
    }

    /// Mint agent tokens with `signer` and publish its public key in the JWKS (S4). Without
    /// one, token requests answer `503` and the JWKS is empty.
    pub fn with_agent_signer(mut self, signer: AgentTokenSigner) -> Self {
        self.agent_signer = Some(Arc::new(signer));
        self
    }

    /// The agent-token signing key, if one is configured.
    pub fn agent_signer(&self) -> Option<&AgentTokenSigner> {
        self.agent_signer.as_deref()
    }

    /// Verify human bearer tokens with `auth` (T1). Without it every bearer token is refused.
    pub fn with_human_auth(mut self, auth: HumanAuth) -> Self {
        self.human_auth = Some(Arc::new(auth));
        self
    }

    /// The human token verifier, if an issuer is configured.
    pub fn human_auth(&self) -> Option<&HumanAuth> {
        self.human_auth.as_deref()
    }

    /// Serve the hub `/mcp` route with `endpoint` (M1 task 2.1). Without one `/mcp` answers `401`.
    pub fn with_mcp(mut self, endpoint: McpEndpoint) -> Self {
        self.mcp = Some(Arc::new(endpoint));
        self
    }

    /// The hub MCP endpoint, if one is configured.
    pub fn mcp(&self) -> Option<&Arc<McpEndpoint>> {
        self.mcp.as_ref()
    }

    /// Accept `token` on the `/internal/v1` routes. Without one they answer `401` (fail closed).
    pub fn with_service_token(mut self, token: ServiceToken) -> Self {
        self.service_token = Some(Arc::new(token));
        self
    }

    /// The gateway service token, if one is configured.
    pub fn service_token(&self) -> Option<&ServiceToken> {
        self.service_token.as_deref()
    }

    /// Wrap secret-version DEKs with `kms` (S2 design decision 3).
    pub fn with_kms(mut self, kms: Arc<dyn DekWrapper>) -> Self {
        self.kms = Some(kms);
        self
    }

    /// The DEK wrapper, if one is configured.
    pub fn kms(&self) -> Option<&Arc<dyn DekWrapper>> {
        self.kms.as_ref()
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

/// CORS for the desktop app's webview only (Tauri origins). The desktop Agents tab calls this API
/// cross-origin with a custom header, so the preflight must succeed; no other origin is allowed.
fn desktop_cors() -> CorsLayer {
    let origins = [
        "tauri://localhost",
        "http://tauri.localhost",
        "https://tauri.localhost",
    ]
    .map(HeaderValue::from_static);
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("content-type"),
            HeaderName::from_static("x-locksmith-dev-org"),
        ])
}

/// Apply the standard layer stack and state to a router.
pub fn with_layers(router: Router<AppState>, state: AppState) -> Router {
    let id_header = HeaderName::from_static(REQUEST_ID_HEADER);
    let router = router.merge(mcp_endpoint::router(&state));
    router.with_state(state).layer(
        ServiceBuilder::new()
            .layer(SetRequestIdLayer::new(id_header.clone(), MakeRequestUuid))
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(request_span)
                    .on_response(record_response),
            )
            .layer(PropagateRequestIdLayer::new(id_header))
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                REQUEST_TIMEOUT,
            ))
            .layer(RequestBodyLimitLayer::new(BODY_LIMIT_BYTES))
            .layer(desktop_cors()),
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
#[utoipa::path(get, path = "/healthz", operation_id = "get_healthz", tag = "health", summary = "Liveness probe",
    responses((status = 200, description = "The process is up")))]
async fn healthz() -> StatusCode {
    StatusCode::OK
}

/// Readiness: `200` once migrations are applied and Postgres answers.
#[utoipa::path(get, path = "/readyz", operation_id = "get_readyz", tag = "health", summary = "Readiness probe",
    responses((status = 200, description = "Ready"), (status = 503, description = "Not ready")))]
async fn readyz(State(state): State<AppState>) -> StatusCode {
    if state.readiness.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Server span named by route template (`GET /v1/projects/{id}`), never by the raw path.
/// Records only method and route; status and org id are filled in later. No headers, no bodies.
fn request_span(req: &Request) -> tracing::Span {
    let method = req.method().as_str();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str);
    tracing::info_span!(
        "http.request",
        otel.name = %format_args!("{method} {route}"),
        otel.kind = "server",
        http.request.method = method,
        http.route = route,
        http.response.status_code = tracing::field::Empty,
        org.id = tracing::field::Empty,
    )
}

fn record_response<B>(res: &Response<B>, latency: Duration, span: &tracing::Span) {
    let status = res.status().as_u16();
    // As i64: tracing-opentelemetry exports u64 fields as strings, OTel wants an int.
    span.record("http.response.status_code", i64::from(status));
    tracing::info!(
        status,
        latency_ms = latency.as_millis() as u64,
        "request finished"
    );
}
