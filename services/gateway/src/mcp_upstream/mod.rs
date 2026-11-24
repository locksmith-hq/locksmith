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
//! method-not-found. Nothing is forwarded yet: `tools/list` is empty and `tools/call` answers
//! `unknown_tool` until the upstream hop (task 2.3) and the catalogue (group 3) land.
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

use crate::app::AppState;
use crate::auth::AgentIdentity;
use crate::config::McpUpstream;
use crate::grants::allows_relay;
use crate::mcp_endpoint::{admit, unauthorized};
use crate::relay::error;

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
    fn new(bindings: &[McpUpstream], allowed_hosts: &[String]) -> Self {
        let by_name = bindings
            .iter()
            .map(|b| {
                let config = StreamableHttpServerConfig::default()
                    .with_allowed_hosts(allowed_hosts.to_vec())
                    .with_legacy_session_mode(true);
                let service = StreamableHttpService::new(
                    || Ok(UpstreamMcp),
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
    let upstreams = Arc::new(match (state.mcp(), state.relay()) {
        (Some(endpoint), Some(relay)) => {
            Upstreams::new(&relay.bindings().mcp_upstreams, endpoint.allowed_hosts())
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
struct UpstreamMcp;

impl UpstreamMcp {
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
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Self::agent(&context)?;
        // No catalogue until the upstream hop (task 2.3) and the policy (group 3).
        Ok(ListToolsResult::default())
    }

    async fn call_tool(
        &self,
        _request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        Self::agent(&context)?;
        // The catalogue is empty, so every name is not in it (design decision 7).
        Err(McpError::invalid_params("unknown_tool", None))
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
