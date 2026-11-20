//! The hub `/mcp` route (change m1-remote-mcp, task 2.1).
//!
//! `/mcp` is an OAuth 2.1 resource server per the MCP authorization spec (revision 2025-11-25,
//! `docs/research/remote-mcp-auth.md`). The protocol and the Streamable HTTP transport are
//! `rmcp` (mounted with `nest_service`); this module adds what is Locksmith's:
//!
//! - Token auth in front of the service. The bearer token is verified by the same code as the
//!   console API ([`HumanAuth`]: JWKS signature, `iss`, `exp`), but its `aud` must be the
//!   canonical MCP resource URL, not the console API audience, so a token minted for one is
//!   refused at the other (the spec's "no token passthrough"). Every failure is the same `401`.
//! - A `401` carries `WWW-Authenticate: Bearer resource_metadata="<url>"` (RFC 9728), and the
//!   protected-resource metadata is served at the root and at the path-inserted well-known URL.
//! - The Host allowlist (DNS rebinding protection) is the resource URL's authority plus
//!   loopback; it is never disabled.
//!
//! The verified person is passed to handlers as an [`McpPrincipal`] request extension (read from
//! `RequestContext.extensions` as `http::request::Parts`). Tools, switches and audit are later
//! tasks (2.2 to 2.5); this server lists none yet. No token text is logged or echoed.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use rmcp::ServerHandler;
use rmcp::model::{ServerCapabilities, ServerConfig};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use serde_json::json;

use crate::app::AppState;
use crate::auth::bearer;
use crate::auth::human::{HumanAuth, HumanAuthConfig, HumanIdentity};
use crate::auth::jwks::JwksError;
use crate::problem::ApiError;

/// The path the MCP service is mounted at.
pub const MCP_PATH: &str = "/mcp";
/// Well-known prefix of the protected-resource metadata (RFC 9728 section 3).
pub const METADATA_PREFIX: &str = "/.well-known/oauth-protected-resource";

/// Why the MCP endpoint could not be configured. Names the setting, never a value.
#[derive(Debug, PartialEq, Eq)]
pub enum McpConfigError {
    /// The resource URL is not an `http`/`https` URL with a host, or has a query or fragment.
    ResourceUrl,
    Jwks(String),
}

impl std::fmt::Display for McpConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResourceUrl => f.write_str("the MCP resource URL is invalid"),
            Self::Jwks(e) => write!(f, "MCP token verification setup failed: {e}"),
        }
    }
}

impl std::error::Error for McpConfigError {}

/// The verified person behind an MCP request, inserted as a request extension.
#[derive(Debug, Clone)]
pub struct McpPrincipal(pub HumanIdentity);

/// Verifier and metadata for the hub `/mcp` route.
pub struct McpEndpoint {
    auth: HumanAuth,
    resource: String,
    issuer: String,
    metadata_url: String,
    metadata_path: String,
    allowed_hosts: Vec<String>,
}

impl McpEndpoint {
    /// `human` names the issuer and JWKS (shared with the console API); `resource_url` is the
    /// canonical public URL of `/mcp` and becomes the required token audience.
    pub fn new(human: &HumanAuthConfig, resource_url: &str) -> Result<Self, McpConfigError> {
        let auth = HumanAuth::new(&HumanAuthConfig {
            audience: resource_url.to_owned(),
            ..human.clone()
        })
        .map_err(|e: JwksError| McpConfigError::Jwks(e.to_string()))?;
        Self::build(auth, human, resource_url)
    }

    /// As [`Self::new`] with a prepared verifier (tests control the JWKS refresh timing).
    pub fn with_auth(
        auth: HumanAuth,
        human: &HumanAuthConfig,
        resource_url: &str,
    ) -> Result<Self, McpConfigError> {
        Self::build(auth, human, resource_url)
    }

    fn build(
        auth: HumanAuth,
        human: &HumanAuthConfig,
        resource_url: &str,
    ) -> Result<Self, McpConfigError> {
        let uri: http::Uri = resource_url
            .parse()
            .map_err(|_| McpConfigError::ResourceUrl)?;
        let scheme = uri.scheme_str().ok_or(McpConfigError::ResourceUrl)?;
        let authority = uri.authority().ok_or(McpConfigError::ResourceUrl)?;
        if !matches!(scheme, "http" | "https")
            || uri.query().is_some()
            || resource_url.contains('#')
        {
            return Err(McpConfigError::ResourceUrl);
        }
        let path = uri.path().trim_end_matches('/');
        let metadata_path = format!("{METADATA_PREFIX}{path}");
        let metadata_url = format!("{scheme}://{authority}{metadata_path}");
        let mut allowed_hosts: Vec<String> = ["localhost", "127.0.0.1", "::1"]
            .map(str::to_owned)
            .to_vec();
        allowed_hosts.push(authority.as_str().to_owned());
        Ok(Self {
            auth,
            resource: resource_url.to_owned(),
            issuer: human.issuer.clone(),
            metadata_url,
            metadata_path,
            allowed_hosts,
        })
    }

    /// The `WWW-Authenticate` challenge. `invalid_token` is added when a token was presented.
    fn challenge(&self, token_presented: bool) -> HeaderValue {
        let error = if token_presented {
            r#"error="invalid_token", "#
        } else {
            ""
        };
        // Built from validated URL text; a bad value would fall back to the bare scheme.
        HeaderValue::from_str(&format!(
            r#"Bearer {error}resource_metadata="{}""#,
            self.metadata_url
        ))
        .unwrap_or_else(|_| HeaderValue::from_static("Bearer"))
    }

    fn metadata(&self) -> serde_json::Value {
        json!({
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "bearer_methods_supported": ["header"],
        })
    }
}

/// What the rmcp service answers until tools land (tasks 2.2 and later).
#[derive(Clone)]
struct HubMcp;

impl ServerHandler for HubMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Locksmith hub. Tools return ids, names and metadata, never secret values.",
        )
    }
}

fn unauthorized(endpoint: Option<&McpEndpoint>, token_presented: bool) -> Response {
    let mut response = ApiError::unauthenticated().into_response();
    let challenge = endpoint.map_or(HeaderValue::from_static("Bearer"), |e| {
        e.challenge(token_presented)
    });
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, challenge);
    response
}

async fn require_token(
    State(endpoint): State<Arc<McpEndpoint>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(value) = request.headers().get(header::AUTHORIZATION) else {
        return unauthorized(Some(&endpoint), false);
    };
    let token = bearer(value.as_bytes()).and_then(|t| std::str::from_utf8(t).ok());
    let Some(token) = token else {
        return unauthorized(Some(&endpoint), true);
    };
    match endpoint.auth.verify(token).await {
        Ok(identity) => {
            request.extensions_mut().insert(McpPrincipal(identity));
            next.run(request).await
        }
        Err(_) => unauthorized(Some(&endpoint), true),
    }
}

/// The `/mcp` service and the protected-resource metadata routes. Without a configured endpoint
/// `/mcp` answers `401` to everything (fail closed) and no metadata is served.
pub fn router(endpoint: Option<&Arc<McpEndpoint>>) -> Router<AppState> {
    let Some(endpoint) = endpoint else {
        return Router::new()
            .route(MCP_PATH, any(|| async { unauthorized(None, false) }))
            .route("/mcp/{*rest}", any(|| async { unauthorized(None, false) }));
    };
    let config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(endpoint.allowed_hosts.clone())
        .with_legacy_session_mode(true);
    let service = StreamableHttpService::new(
        || Ok(HubMcp),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let guarded =
        Router::new()
            .nest_service(MCP_PATH, service)
            .layer(middleware::from_fn_with_state(
                endpoint.clone(),
                require_token,
            ));
    let meta = endpoint.clone();
    let meta_handler = move || {
        let meta = meta.clone();
        async move { (StatusCode::OK, Json(meta.metadata())) }
    };
    let mut router = Router::new()
        .route(METADATA_PREFIX, get(meta_handler.clone()))
        .merge(guarded);
    if endpoint.metadata_path != METADATA_PREFIX {
        router = router.route(&endpoint.metadata_path, get(meta_handler));
    }
    router
}
