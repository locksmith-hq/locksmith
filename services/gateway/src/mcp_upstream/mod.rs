//! M2 MCP gateway: upstream MCP servers served at `/mcp/upstream/{name}` (change m2-mcp-gateway).
//!
//! Task 2.2: the route and its gate. Each `[[mcp_upstream]]` binding gets its own rmcp
//! Streamable HTTP service (its own sessions), built once with the router. In front of it is the
//! same gate as `/mcp`: the agent token verified by the shared [`AgentAuth`](crate::auth::AgentAuth)
//! and the revoked-agent check ([`crate::mcp_endpoint::admit`]), the same `Host` allowlist (the
//! endpoint's list, enforced by rmcp), and rmcp logging capped process-wide by
//! [`crate::mcp_endpoint::cap_rmcp_logs`] (`rmcp=info` covers the client modules too). Then, on
//! every request, the agent's grants are read (cached at most 10 s, the relay's cache) and an
//! unknown `name` and an upstream whose `secret_id` the agent holds no unexpired `relay` grant
//! for get the same `404`, built by one function, so neither can be told from the other. A grant
//! read that fails is a `502 grants_unavailable` for every name, checked before the name.
//!
//! The server handler advertises only the tools capability, so every other method is
//! method-not-found; `initialize` and `ping` are answered here.
//!
//! Task 2.3: the upstream hop ([`hop`]) is built: per request it checks egress, decrypts,
//! injects the credential and runs one rmcp client exchange (`initialize`, then `ping`,
//! `tools/list` or `tools/call`), refusing upstream sampling, elicitation and roots. The handler
//! calls it through one seam, [`UpstreamMcp::raw_forwarding`], which is **off on every
//! production path** ([`route`]): until the catalogue and policy (group 3, design decisions 5-7)
//! and redaction (task 2.4, decision 11) land, forwarding would let an agent call any upstream
//! tool, hidden ones included, and read unredacted upstream text that can carry the credential.
//! So with the seam off `tools/list` stays empty and `tools/call` answers `unknown_tool` (fail
//! closed); only tests turn it on, to drive the hop end to end. Group 3 and 2.4 replace the
//! flag with policy and redaction at the marked seams.
//!
//! Spike 2.1: the rmcp client transport runs over the gateway's own pinned HTTP client
//! (`http_client.rs`: no redirects, no env proxy, pinned addresses); see the spike test.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{MethodRouter, any};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, InitializeRequestParams, InitializeResult,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use time::OffsetDateTime;
use uuid::Uuid;

pub mod hop;

use crate::app::AppState;
use crate::auth::AgentIdentity;
use crate::config::McpUpstream;
use crate::grants::allows_relay;
use crate::mcp_endpoint::{admit, unauthorized};
use crate::relay::{Relay, error};

/// The route the upstreams are served at.
pub const PATH: &str = "/mcp/upstream/{name}";

/// The one answer for an unknown upstream and for one the agent holds no grant for.
fn not_found(request_id: &str) -> Response {
    error(StatusCode::NOT_FOUND, "not_found", request_id)
}

/// One configured upstream: the secret its grant check is on, and its MCP service.
struct Upstream {
    secret_id: Uuid,
    service: StreamableHttpService<UpstreamMcp, LocalSessionManager>,
}

/// The configured upstreams by name.
#[derive(Default)]
struct Upstreams {
    by_name: HashMap<String, Upstream>,
}

impl Upstreams {
    fn new(relay: &Arc<Relay>, allowed_hosts: &[String], raw_forwarding: bool) -> Self {
        let by_name = relay
            .bindings()
            .mcp_upstreams
            .iter()
            .map(|b| {
                let config = StreamableHttpServerConfig::default()
                    .with_allowed_hosts(allowed_hosts.to_vec())
                    .with_legacy_session_mode(true);
                let handler = UpstreamMcp {
                    relay: relay.clone(),
                    upstream: Arc::new(b.clone()),
                    raw_forwarding,
                };
                let service = StreamableHttpService::new(
                    move || Ok(handler.clone()),
                    Arc::new(LocalSessionManager::default()),
                    config,
                );
                let upstream = Upstream {
                    secret_id: b.secret_id,
                    service,
                };
                (b.name.clone(), upstream)
            })
            .collect();
        Self { by_name }
    }
}

/// The `/mcp/upstream/{name}` handler for every method. The upstreams come from the relay's
/// bindings and the `Host` allowlist from the `/mcp` endpoint; without an endpoint every request
/// is `401` (fail closed, as `/mcp`), and without a relay (no grants to read) every name is `404`.
pub fn route(state: &AppState) -> MethodRouter<AppState> {
    // The seam stays closed in production: nothing unpoliced or unredacted is relayed.
    route_with(state, false)
}

/// [`route`] with the upstream forwarded raw (no policy, no redaction): tests of the hop only.
#[cfg(test)]
pub(crate) fn route_forwarding_raw_for_tests(state: &AppState) -> MethodRouter<AppState> {
    route_with(state, true)
}

fn route_with(state: &AppState, raw_forwarding: bool) -> MethodRouter<AppState> {
    let upstreams = Arc::new(match (state.mcp(), state.relay()) {
        (Some(endpoint), Some(relay)) => {
            Upstreams::new(&relay, endpoint.allowed_hosts(), raw_forwarding)
        }
        _ => Upstreams::default(),
    });
    any(
        move |State(state): State<AppState>,
              name: Result<Path<String>, PathRejection>,
              request: Request| {
            let upstreams = upstreams.clone();
            async move {
                // A name that does not decode is unknown, answered after the token check.
                let name = name.ok().map(|Path(n)| n);
                serve(&state, &upstreams, name.as_deref(), request).await
            }
        },
    )
}

async fn serve(
    state: &AppState,
    upstreams: &Upstreams,
    name: Option<&str>,
    mut request: Request,
) -> Response {
    let Some(endpoint) = state.mcp() else {
        return unauthorized(false);
    };
    let relay = state.relay();
    let agent = match admit(&endpoint, relay.as_ref(), &mut request).await {
        Ok(agent) => agent,
        Err(refused) => return *refused,
    };
    let request_id = Uuid::new_v4().to_string();
    let Some(relay) = relay else {
        return not_found(&request_id);
    };
    // Grants first, for every name, so a failed read cannot tell a configured name apart.
    let grants = match relay.grants().grants(agent.agent_id).await {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(reason = e.as_str(), "agent grants could not be read");
            return error(StatusCode::BAD_GATEWAY, "grants_unavailable", &request_id);
        }
    };
    // The expiry is re-checked here because the set may come from the cache.
    let now = OffsetDateTime::now_utc();
    let upstream = name
        .and_then(|n| upstreams.by_name.get(n))
        .filter(|u| allows_relay(&grants, u.secret_id, now));
    drop(grants);
    let Some(upstream) = upstream else {
        return not_found(&request_id);
    };
    upstream.service.handle(request).await.map(Body::new)
}

/// The MCP server an agent talks to at `/mcp/upstream/{name}`. Only the tools capability is
/// advertised, so prompts, resources, completions, logging and tasks are method-not-found.
#[derive(Clone)]
struct UpstreamMcp {
    relay: Arc<Relay>,
    upstream: Arc<McpUpstream>,
    /// The seam (see the module header): `false` on every production path, so `tools/list` is
    /// empty and `tools/call` is `unknown_tool` until policy (group 3) and redaction (task 2.4)
    /// sit here. `true` only from [`route_forwarding_raw_for_tests`].
    raw_forwarding: bool,
}

impl UpstreamMcp {
    fn deps(&self) -> hop::HopDeps<'_> {
        hop::HopDeps {
            decryptor: self.relay.decryptor(),
            resolver: self.relay.resolver(),
            connect_timeout: self.relay.options().connect_timeout,
        }
    }

    /// A hop failure as the agent sees it: a fixed slug, nothing from the upstream.
    fn hop_error(e: hop::HopError) -> McpError {
        McpError::internal_error(e.slug(), None)
    }

    /// The agent the gate verified for this request (fail closed if it is missing).
    fn agent(context: &RequestContext<RoleServer>) -> Result<AgentIdentity, McpError> {
        context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|p| p.extensions.get::<AgentIdentity>())
            .copied()
            .ok_or_else(|| McpError::invalid_request("unauthenticated", None))
    }
}

impl ServerHandler for UpstreamMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Locksmith gateway proxy for an upstream MCP server. The upstream credential stays in the gateway.",
        )
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        Self::agent(&context)?;
        context.peer.set_peer_info(request.clone());
        self.negotiate_initialize(&request)
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let agent = Self::agent(&context)?;
        // Seam (group 3 policy, 3.2 catalogue): closed, the agent sees no tool.
        if !self.raw_forwarding {
            return Ok(ListToolsResult::default());
        }
        let tools = hop::list_tools(&self.deps(), &self.upstream, agent, request)
            .await
            .map_err(Self::hop_error)?;
        // Seam (task 2.4): redact the upstream's names, descriptions and schemas here.
        Ok(tools)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let agent = Self::agent(&context)?;
        // Seam (3.3 decisions, 4.2 audit): closed, the catalogue is empty so every name is
        // unknown (design decision 7).
        if !self.raw_forwarding {
            return Err(McpError::invalid_params("unknown_tool", None));
        }
        let result = hop::call_tool(&self.deps(), &self.upstream, agent, request)
            .await
            .map_err(Self::hop_error)?;
        // Seam (task 2.4): redact the result and re-check here.
        Ok(CallToolResponse::Complete(result))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod spike_tests {
    use rmcp::transport::StreamableHttpClientTransport;
    use rmcp::transport::streamable_http_client::{
        StreamableHttpClient, StreamableHttpClientTransportConfig,
    };
    use std::time::Duration;

    fn assert_client<C: StreamableHttpClient>(_: &C) {}

    /// The client `http_client::build` returns is accepted as the rmcp Streamable HTTP client
    /// (no second HTTP stack), and a transport can be built over it with a per-request credential.
    #[tokio::test]
    async fn rmcp_transport_runs_over_the_gateway_client() {
        let client =
            crate::http_client::build(Duration::from_secs(5), Duration::from_secs(60), None)
                .expect("client");
        assert_client(&client);
        let config = StreamableHttpClientTransportConfig::with_uri("https://upstream.example/mcp")
            .auth_header("not-a-real-token");
        let _transport = StreamableHttpClientTransport::with_client(client, config);
    }
}
