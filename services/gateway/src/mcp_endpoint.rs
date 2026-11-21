//! The gateway `/mcp` route (change m1-remote-mcp, task 3.1): the agent MCP server.
//!
//! The protocol and the Streamable HTTP transport are `rmcp`, mounted with `nest_service` as on
//! the hub (`ls_control_plane::mcp_endpoint`). What is Locksmith's here is the auth in front of
//! it: the bearer token is an agent token (EdDSA, audience `gateway`, 15 minutes), verified by
//! the same [`AgentAuth`] that guards `/v1`, so an expired, forged, wrong-audience or
//! wrong-org token gets the one `401` with a `WWW-Authenticate: Bearer` challenge and nothing
//! runs. A missing or unconfigured endpoint also answers `401` (fail closed).
//!
//! The verified agent is passed to handlers as an [`AgentIdentity`] request extension (read from
//! `RequestContext.extensions` as `http::request::Parts`). The default-on tools are in
//! [`crate::mcp_tools`] (task 3.2). The `Host` allowlist is loopback plus the configured public
//! hosts and is never disabled. No token text is logged or echoed.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::any;
use ls_mcp_server::{Layer, Registry, agent_tools};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, InitializeRequestParams, InitializeResult,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use uuid::Uuid;

use crate::app::AppState;
use crate::audit::{McpCallEvent, McpOutcome, McpReason};
use crate::auth::{AgentAuth, AgentIdentity};
use crate::mcp_clients::{AgentClients, NoClients};
use crate::mcp_settings::{StaticSettings, ToolSettingsSource};
use crate::mcp_tools;
use crate::relay::{Relay, error};

/// rmcp targets that log whole JSON-RPC messages (tool results included) at `debug`/`trace`.
const RMCP_MESSAGE_TARGETS: &[&str] = &["rmcp", "rmcp::service", "rmcp::transport"];

/// Cap rmcp's logging at `info`, whatever else `filter` allows. rmcp logs every response message
/// at `debug`, which would put an `issue_short_lived_credential` result (the credential) in the
/// logs; the more specific directives also override a `RUST_LOG=rmcp::service=trace`.
pub fn cap_rmcp_logs(mut filter: tracing_subscriber::EnvFilter) -> tracing_subscriber::EnvFilter {
    for target in RMCP_MESSAGE_TARGETS {
        if let Ok(d) = format!("{target}=info").parse() {
            filter = filter.add_directive(d);
        }
    }
    filter
}

/// The path the MCP service is mounted at.
pub const MCP_PATH: &str = "/mcp";

/// Verifier and `Host` allowlist for `/mcp`.
pub struct McpEndpoint {
    auth: Arc<AgentAuth>,
    allowed_hosts: Vec<String>,
    settings: Arc<dyn ToolSettingsSource>,
    clients: Arc<dyn AgentClients>,
    /// Agents whose short-lived credentials were already dropped for a revoke (task 4.2).
    swept: Mutex<HashSet<Uuid>>,
}

impl McpEndpoint {
    /// `auth` is the gateway's agent-token verifier (shared with `/v1`); `public_hosts` are the
    /// `Host` values accepted besides loopback.
    pub fn new(auth: Arc<AgentAuth>, public_hosts: &[String]) -> Self {
        let mut allowed_hosts: Vec<String> = ["localhost", "127.0.0.1", "::1"]
            .map(str::to_owned)
            .to_vec();
        allowed_hosts.extend(public_hosts.iter().cloned());
        Self {
            auth,
            allowed_hosts,
            settings: Arc::new(StaticSettings::default()),
            clients: Arc::new(NoClients),
            swept: Mutex::new(HashSet::new()),
        }
    }

    /// Fixed tool switches over the registry defaults (tool name to on/off), for tests and for a
    /// gateway without a control plane. Without any, every tool is at its default, so
    /// `issue_short_lived_credential` is off.
    pub fn with_tool_settings(mut self, settings: HashMap<String, bool>) -> Self {
        self.settings = Arc::new(StaticSettings(settings));
        self
    }

    /// The org's switches, read on every list and call (task 3.4): in production the control
    /// plane's `mcp_tool_settings` through a short cache ([`crate::mcp_settings::SettingsCache`]).
    pub fn with_settings_source(mut self, source: Arc<dyn ToolSettingsSource>) -> Self {
        self.settings = source;
        self
    }

    /// The agent-layer client registry (task 4.2): agents are recorded on `initialize` and a
    /// revoked agent is refused with `401` on every request. In production the control plane's
    /// `mcp_clients` through a short cache ([`crate::mcp_clients::ClientsCache`]); a registry
    /// that cannot be read refuses every request (fail closed). Without one, nobody is revoked.
    pub fn with_clients(mut self, clients: Arc<dyn AgentClients>) -> Self {
        self.clients = clients;
        self
    }
}

/// The gateway MCP server: the registry's agent tools that are on, run as the agent behind the
/// verified token ([`crate::mcp_tools`]). The switches are read from the endpoint's settings
/// source on every list and call; a tool that is off (by default `issue_short_lived_credential`,
/// task 3.3) is neither listed nor callable, and a switch that cannot be read fails closed.
/// Every call appends one `mcp.call` event.
#[derive(Clone)]
struct GatewayMcp {
    relay: Option<Arc<Relay>>,
    registry: Arc<Registry>,
    settings: Arc<dyn ToolSettingsSource>,
    clients: Arc<dyn AgentClients>,
}

impl GatewayMcp {
    fn new(
        relay: Option<Arc<Relay>>,
        settings: Arc<dyn ToolSettingsSource>,
        clients: Arc<dyn AgentClients>,
    ) -> Self {
        // The shipped registry carries no value field (tested in `ls-mcp-server`).
        let registry = Registry::new(Layer::Agent, agent_tools())
            .unwrap_or_else(|e| panic!("agent tool registry invalid: {e}"));
        Self {
            relay,
            registry: Arc::new(registry),
            settings,
            clients,
        }
    }

    fn agent(context: &RequestContext<RoleServer>) -> Result<AgentIdentity, McpError> {
        context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|p| p.extensions.get::<AgentIdentity>())
            .cloned()
            .ok_or_else(|| McpError::invalid_request("unauthenticated", None))
    }
}

impl ServerHandler for GatewayMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Locksmith gateway. Tools return ids, names and relay results, never secret values.",
        )
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        let agent = Self::agent(&context)?;
        // Record the agent as an MCP client so the console can list and revoke it. A revoked
        // agent never gets here (the middleware refused it with 401); a row that cannot be
        // recorded would make a later revoke impossible, so the session is not opened.
        let name: String = request.client_info.name.chars().take(200).collect();
        match self.clients.record(agent.agent_id, &name).await {
            Ok(false) => {}
            Ok(true) | Err(_) => {
                return Err(McpError::internal_error(
                    "the client could not be registered",
                    None,
                ));
            }
        }
        context.peer.set_peer_info(request.clone());
        self.negotiate_initialize(&request)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Self::agent(&context)?;
        // An unreadable switch lists nothing: never fall back to the defaults.
        let settings = self
            .settings
            .settings()
            .await
            .map_err(|_| McpError::internal_error("tool settings unavailable", None))?;
        let tools = self
            .registry
            .list(&settings)
            .into_iter()
            .map(ls_mcp_server::tool_from_def)
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
        let agent = Self::agent(&context)?;
        // Only a registry name is ever recorded, never client-supplied text.
        let tool = self.registry.tool_name(&request.name).unwrap_or("unknown");
        let settings = match self.settings.settings().await {
            Ok(s) => s,
            Err(_) => {
                self.record(
                    &agent,
                    tool,
                    McpOutcome::Denied,
                    Some(McpReason::SettingsUnavailable),
                )
                .await;
                return Ok(mcp_tools::unavailable_result("settings_unavailable").into());
            }
        };
        // An off or unknown tool is refused the same way: not callable.
        let def = match self.registry.authorize(&request.name, &settings) {
            Ok(def) => def,
            Err(_) => {
                self.record(&agent, tool, McpOutcome::Denied, Some(McpReason::ToolOff))
                    .await;
                return Err(McpError::invalid_params("unknown tool", None));
            }
        };
        let result =
            mcp_tools::call(self.relay.as_ref(), &agent, def.name, request.arguments).await;
        let (outcome, reason) = call_outcome(&result);
        self.record(&agent, tool, outcome, reason).await;
        Ok(result?.into())
    }
}

/// The audit outcome of a finished call: `ok`; `denied` for a tool error the REST API would give
/// as `401`/`403`; `error` for any other failure.
fn call_outcome(
    result: &Result<rmcp::model::CallToolResult, McpError>,
) -> (McpOutcome, Option<McpReason>) {
    match result {
        Err(_) => (McpOutcome::Error, Some(McpReason::InvalidArguments)),
        Ok(r) if r.is_error != Some(true) => (McpOutcome::Ok, None),
        Ok(r) => {
            if matches!(ls_mcp_server::error_status(r), Some(401 | 403)) {
                (McpOutcome::Denied, Some(McpReason::ToolError))
            } else {
                (McpOutcome::Error, Some(McpReason::ToolError))
            }
        }
    }
}

impl GatewayMcp {
    /// Append the call's `mcp.call` event. A ledger that cannot take it is logged, not fatal:
    /// the relay and credential events behind a tool already fail closed.
    async fn record(
        &self,
        agent: &AgentIdentity,
        tool: &'static str,
        outcome: McpOutcome,
        reason: Option<McpReason>,
    ) {
        let Some(relay) = &self.relay else { return };
        let event = McpCallEvent {
            agent_id: agent.agent_id,
            tool,
            outcome,
            reason,
        };
        if let Err(e) = relay.audit().append_mcp_call(event).await {
            tracing::warn!(error = %e, tool, "mcp.call event not appended");
        }
    }
}

fn unauthorized(token_presented: bool) -> Response {
    let mut response = error(
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        &Uuid::new_v4().to_string(),
    );
    let challenge = if token_presented {
        HeaderValue::from_static(r#"Bearer error="invalid_token""#)
    } else {
        HeaderValue::from_static("Bearer")
    };
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, challenge);
    response
}

/// Whether `agent`'s MCP access is revoked, read on every request (cached for at most the
/// registry's TTL). A registry that cannot be read counts as revoked: fail closed. The first time
/// an agent is seen revoked its live short-lived credentials are destroyed, and the caller's
/// again every time (a credential issued by a call already in flight at the revoke).
async fn agent_revoked(
    endpoint: &McpEndpoint,
    relay: Option<&Arc<Relay>>,
    agent: &AgentIdentity,
) -> bool {
    let Ok(revoked) = endpoint.clients.revoked().await else {
        tracing::warn!("revoked MCP agents unreadable; request refused");
        return true;
    };
    if let Some(relay) = relay {
        let first_seen: Vec<Uuid> = {
            let mut swept = endpoint.swept.lock().unwrap_or_else(|e| e.into_inner());
            swept.retain(|id| revoked.contains(id));
            revoked
                .iter()
                .filter(|id| swept.insert(**id))
                .copied()
                .collect()
        };
        for id in first_seen {
            let dropped = relay.short_lived().drop_agent(id);
            tracing::info!(agent.id = %id, dropped, "revoked MCP agent: short-lived credentials dropped");
        }
        if revoked.contains(&agent.agent_id) {
            relay.short_lived().drop_agent(agent.agent_id);
        }
    }
    revoked.contains(&agent.agent_id)
}

async fn require_agent(
    State((endpoint, relay)): State<(Arc<McpEndpoint>, Option<Arc<Relay>>)>,
    mut request: Request,
    next: Next,
) -> Response {
    let presented = request.headers().contains_key(header::AUTHORIZATION);
    match endpoint.auth.authenticate(request.headers()).await {
        Ok(identity) => {
            // A revoked agent is refused like a bad token, on calls and on a fresh initialize.
            if agent_revoked(&endpoint, relay.as_ref(), &identity).await {
                return unauthorized(true);
            }
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Err(e) => {
            // The reason is a fixed label, never token text.
            tracing::debug!(reason = e.as_str(), "mcp request refused");
            unauthorized(presented)
        }
    }
}

/// The `/mcp` service. Without a configured endpoint `/mcp` answers `401` to everything.
pub fn router(state: &AppState) -> Router<AppState> {
    let Some(endpoint) = state.mcp() else {
        return Router::new()
            .route(MCP_PATH, any(|| async { unauthorized(false) }))
            .route("/mcp/{*rest}", any(|| async { unauthorized(false) }));
    };
    let config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(endpoint.allowed_hosts.clone())
        .with_legacy_session_mode(true);
    let relay = state.relay();
    let settings = endpoint.settings.clone();
    let clients = endpoint.clients.clone();
    let guard = (endpoint.clone(), state.relay());
    let service = StreamableHttpService::new(
        move || {
            Ok(GatewayMcp::new(
                relay.clone(),
                settings.clone(),
                clients.clone(),
            ))
        },
        Arc::new(LocalSessionManager::default()),
        config,
    );
    Router::new()
        .nest_service(MCP_PATH, service)
        .layer(middleware::from_fn_with_state(guard, require_agent))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{self, AppState};
    use crate::auth::JwksSettings;
    use crate::auth::testkit::StubJwks;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use ls_control_plane::agent_token::{AUDIENCE, AgentClaims, AgentTokenSigner};
    use ls_control_plane::readiness::ReadyFlag;
    use time::OffsetDateTime;
    use tower::ServiceExt;
    use zeroize::Zeroizing;

    const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000b1);
    const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000b2);
    const HOST: &str = "gateway.test";
    const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;

    fn signer() -> AgentTokenSigner {
        AgentTokenSigner::from_seed(Zeroizing::new([5; 32])).unwrap()
    }

    fn token(aud: &str, exp_in: i64, org: Uuid) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        signer()
            .sign(&AgentClaims {
                sub: AGENT,
                org,
                aud: aud.to_owned(),
                iat: now,
                exp: now + exp_in,
            })
            .unwrap()
    }

    fn app(configured: bool) -> Router {
        let mut state = AppState::new(Arc::new(ReadyFlag::new(true)));
        if configured {
            let auth = Arc::new(AgentAuth::new(
                ORG,
                Arc::new(StubJwks::with(vec![signer().jwk().clone()])),
                JwksSettings::default(),
            ));
            state = state.with_mcp(McpEndpoint::new(auth, &[HOST.to_owned()]));
        }
        app::build(state)
    }

    async fn post(app: &Router, authorization: Option<&str>, host: &str) -> (Response, String) {
        let mut b = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, host)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(a) = authorization {
            b = b.header(header::AUTHORIZATION, a);
        }
        let resp = app
            .clone()
            .oneshot(b.body(Body::from(INITIALIZE)).unwrap())
            .await
            .unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        (Response::from_parts(parts, Body::empty()), text)
    }

    fn challenge(resp: &Response) -> &str {
        resp.headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("401 carries WWW-Authenticate")
            .to_str()
            .unwrap()
    }

    #[tokio::test]
    async fn mcp_missing_token_is_401_with_challenge() {
        let (resp, _) = post(&app(true), None, HOST).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(challenge(&resp), "Bearer");
    }

    #[tokio::test]
    async fn mcp_expired_token_is_401() {
        let t = token(AUDIENCE, -600, ORG);
        let (resp, body) = post(&app(true), Some(&format!("Bearer {t}")), HOST).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(challenge(&resp), r#"Bearer error="invalid_token""#);
        assert!(!body.contains(&t), "token echoed back");
    }

    #[tokio::test]
    async fn mcp_wrong_audience_token_is_401() {
        for aud in ["control-plane", "locksmith-api", "https://gateway.test/mcp"] {
            let t = token(aud, 600, ORG);
            let (resp, body) = post(&app(true), Some(&format!("Bearer {t}")), HOST).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "aud {aud}");
            assert!(challenge(&resp).contains("invalid_token"));
            assert!(!body.contains(&t), "token echoed back");
        }
    }

    #[tokio::test]
    async fn mcp_wrong_org_garbage_and_non_bearer_are_401() {
        let other_org = token(AUDIENCE, 600, Uuid::now_v7());
        for auth in [
            format!("Bearer {other_org}"),
            "Bearer not.a.jwt".to_owned(),
            "Basic dXNlcjpwdw==".to_owned(),
        ] {
            let (resp, _) = post(&app(true), Some(&auth), HOST).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{auth}");
        }
    }

    #[tokio::test]
    async fn mcp_valid_agent_token_reaches_the_service() {
        let t = token(AUDIENCE, 600, ORG);
        let (resp, body) = post(&app(true), Some(&format!("Bearer {t}")), HOST).await;
        assert_eq!(resp.status(), StatusCode::OK, "{body}");
        assert!(body.contains("protocolVersion"), "{body}");
        assert!(!body.contains(&t));
    }

    #[tokio::test]
    async fn mcp_host_allowlist_refuses_other_hostnames() {
        let t = token(AUDIENCE, 600, ORG);
        let (resp, _) = post(&app(true), Some(&format!("Bearer {t}")), "evil.test").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn mcp_unconfigured_fails_closed() {
        let t = token(AUDIENCE, 600, ORG);
        let (resp, _) = post(&app(false), Some(&format!("Bearer {t}")), HOST).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(challenge(&resp), "Bearer");
    }
}
