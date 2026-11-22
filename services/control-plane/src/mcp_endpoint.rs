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
//! `RequestContext.extensions` as `http::request::Parts`). Tools live in `mcp_tools` (task 2.2);
//! the per-org switches and the client upsert on `initialize` are task 2.3; audit (2.5) is `mcp.call` per tool call. No token text is logged or echoed.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use ls_audit::{Code, outcome};
use ls_mcp_server::{Layer, Refusal, Registry, ToolDef, hub_tools};
use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, InitializeRequestParams, InitializeResult,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
    ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer};
use serde_json::json;

use crate::mcp_tools;

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
        // Built from validated URL text; a bad value falls back to the bare scheme.
        crate::auth::bearer_challenge(token_presented, Some(&self.metadata_url))
    }

    fn metadata(&self) -> serde_json::Value {
        json!({
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "bearer_methods_supported": ["header"],
        })
    }
}

/// The hub MCP server: the registry's hub tools (with the org's switches), each run as the person behind the request token ([`crate::mcp_tools`]).
#[derive(Clone)]
struct HubMcp {
    state: AppState,
    registry: Arc<Registry>,
}

impl HubMcp {
    fn new(state: AppState) -> Self {
        // The shipped registry carries no value field (tested in `ls-mcp-server`).
        let registry = Registry::new(Layer::Hub, hub_tools())
            .map_err(|e| format!("hub tool registry invalid: {e}"))
            .map(Arc::new);
        Self {
            state,
            registry: registry.unwrap_or_else(|e| panic!("{e}")),
        }
    }

    fn principal(context: &RequestContext<RoleServer>) -> Result<McpPrincipal, McpError> {
        context
            .extensions
            .get::<http::request::Parts>()
            .and_then(|p| p.extensions.get::<McpPrincipal>())
            .cloned()
            .ok_or_else(|| McpError::invalid_request("unauthenticated", None))
    }
}

/// A failed lookup before a tool runs, without detail.
fn internal(_: ApiError) -> McpError {
    McpError::internal_error("the request could not be completed", None)
}

fn to_tool(def: &ToolDef) -> Tool {
    let mut tool = ls_mcp_server::tool_from_def(def);
    // Read tools are those that ship on; state-changing tools ship off.
    tool.annotations = Some(ToolAnnotations::new().read_only(def.default_enabled));
    tool
}

impl ServerHandler for HubMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Locksmith hub. Tools return ids, names and metadata, never secret values.",
        )
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        let principal = Self::principal(&context)?;
        mcp_tools::record_client(&self.state, &principal, &request.client_info.name)
            .await
            .map_err(internal)?;
        context.peer.set_peer_info(request.clone());
        self.negotiate_initialize(&request)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let principal = Self::principal(&context)?;
        let overrides = mcp_tools::tool_overrides(&self.state, &principal)
            .await
            .map_err(internal)?;
        let tools = self
            .registry
            .list(&overrides)
            .into_iter()
            .map(to_tool)
            .collect();
        Ok(ListToolsResult {
            tools,
            ..ListToolsResult::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let principal = Self::principal(&context)?;
        // The same typed refusal the REST API gives (an unverified email, say). Such a person has
        // no user or org, so there is no ledger to record the call in.
        let user = match mcp_tools::caller(&self.state, &principal).await {
            Ok(u) => u,
            Err(e) => return Ok(mcp_tools::result(Err(e)).into()),
        };
        let overrides = match mcp_tools::overrides_for(&self.state, user.org_id).await {
            Ok(o) => o,
            Err(e) => return Ok(mcp_tools::result(Err(e)).into()),
        };
        let layer = self.registry.layer().as_str();
        // An off tool is refused exactly like an unknown one; the ledger keeps the typed reason.
        // Only a registry name is ever recorded, never the requested text.
        let def = match self.registry.authorize(&request.name, &overrides) {
            Ok(def) => def,
            Err(refusal) => {
                let (tool, reason) = match refusal {
                    Refusal::Disabled => (
                        self.registry.tool_name(&request.name).unwrap_or("unknown"),
                        Code::new("tool_off"),
                    ),
                    Refusal::Unknown => ("unknown", Code::new("unknown_tool")),
                };
                mcp_tools::record_call(
                    &self.state,
                    &user,
                    layer,
                    tool,
                    outcome::DENIED,
                    Some(reason),
                )
                .await
                .map_err(internal)?;
                return Err(McpError::invalid_params("unknown tool", None));
            }
        };
        // Mutating tools (revoke_grant, pause_agents) are handled in `mcp_tools::call`, off by default.
        let result = mcp_tools::call(&self.state, &principal, def.name, request.arguments).await;
        // Fail closed: a call that cannot be recorded is reported as failed.
        let (call_outcome, reason) = mcp_tools::call_outcome(&result);
        mcp_tools::record_call(&self.state, &user, layer, def.name, call_outcome, reason)
            .await
            .map_err(internal)?;
        Ok(result?.into())
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
    State((endpoint, state)): State<(Arc<McpEndpoint>, AppState)>,
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
            let principal = McpPrincipal(identity);
            // A revoked client is refused like a bad token, on every request (task 4.2). If the
            // check cannot run, fail closed.
            match mcp_tools::client_revoked(&state, &principal).await {
                Ok(false) => {}
                Ok(true) | Err(_) => return unauthorized(Some(&endpoint), true),
            }
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(_) => unauthorized(Some(&endpoint), true),
    }
}

/// The `/mcp` service and the protected-resource metadata routes. Without a configured endpoint
/// `/mcp` answers `401` to everything (fail closed) and no metadata is served.
pub fn router(state: &AppState) -> Router<AppState> {
    let Some(endpoint) = state.mcp() else {
        return Router::new()
            .route(MCP_PATH, any(|| async { unauthorized(None, false) }))
            .route("/mcp/{*rest}", any(|| async { unauthorized(None, false) }));
    };
    let config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(endpoint.allowed_hosts.clone())
        .with_legacy_session_mode(true);
    let hub_state = state.clone();
    let service = StreamableHttpService::new(
        move || Ok(HubMcp::new(hub_state.clone())),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let guarded =
        Router::new()
            .nest_service(MCP_PATH, service)
            .layer(middleware::from_fn_with_state(
                (endpoint.clone(), state.clone()),
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
