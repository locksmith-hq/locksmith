//! M2 MCP gateway: upstream MCP servers served at `/mcp/upstream/{name}` (change m2-mcp-gateway).
//!
//! Task 2.2: the route and its gate. Each `[[mcp_upstream]]` binding gets its own rmcp
//! Streamable HTTP service (its own sessions), built once with the router. In front of it is the
//! same gate as `/mcp`: the agent token verified by the shared [`AgentAuth`](crate::auth::AgentAuth)
//! and the revoked-agent check ([`crate::mcp_endpoint::admit`]), the same `Host` allowlist (the
//! endpoint's list, enforced by rmcp), and rmcp logging capped process-wide by
//! [`crate::mcp_endpoint::cap_rmcp_logs`] (`rmcp=warn` covers the client modules too). Then, on
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
//! `tools/list` or `tools/call`), refusing upstream sampling, elicitation and roots; task 2.4
//! redacts every upstream message inside it.
//!
//! Group 3 (design decisions 5-7): the handler holds an `Arc<dyn ToolPolicy>` (set in `main.rs`,
//! [`policy::StaticToolPolicy`]; without one every tool is hidden and every call refused) and a
//! per-upstream [`catalogue::Catalogue`] cached in a `TtlCell` (at most `MAX_CACHE_TTL`).
//! `tools/list` shows the catalogue minus `hide`; `tools/call` for a name outside the catalogue
//! or decided `hide` is one `unknown_tool` error, `deny` is `tool_denied`, `hold` is
//! `approval_required` (no approver until M3) and only `allow` reaches the upstream. A failed
//! catalogue fetch is a fixed hop error, never a stale list.

//! Group 4 (design decision 8): every `tools/call` is audited ([`audit`]): `mcp.upstream_call`
//! (`pending`) before forwarding an allowed call (refused `audit_unavailable` if it cannot be
//! appended) and `mcp.upstream_outcome` after; one `denied` `mcp.upstream_call` for every refusal.
//! Never arguments or results.
//!
//! Spike 2.1: the rmcp client transport runs over the gateway's own pinned HTTP client
//! (`http_client.rs`: no redirects, no env proxy, pinned addresses); see the spike test.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{MethodRouter, any};
use ls_mcp_server::upstream::{ToolDecision, ToolPolicy, ToolQuery};
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

pub mod audit;
pub mod catalogue;
pub mod hop;
pub mod list;
pub mod policy;

use crate::app::AppState;
use crate::auth::AgentIdentity;
use crate::config::McpUpstream;
use crate::grants::allows_relay;
use crate::mcp_endpoint::{admit, unauthorized};
use crate::relay::{Relay, error};
use crate::ttl::{MAX_CACHE_TTL, TtlCell};

use crate::audit::McpUpstreamReason;
use audit::{CallAudit, UNKNOWN_TOOL};
use catalogue::Catalogue;
use policy::StaticToolPolicy;

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
    fn new(
        relay: &Arc<Relay>,
        allowed_hosts: &[String],
        policy: &Arc<dyn ToolPolicy>,
        catalogue_ttl: Duration,
    ) -> Self {
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
                    policy: policy.clone(),
                    catalogue: Arc::new(TtlCell::new(catalogue_ttl)),
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
    route_with(state, MAX_CACHE_TTL)
}

/// [`route`] with another catalogue TTL (clamped to `MAX_CACHE_TTL`): tests of the cache.
#[cfg(test)]
pub(crate) fn route_with_ttl_for_tests(state: &AppState, ttl: Duration) -> MethodRouter<AppState> {
    route_with(state, ttl)
}

fn route_with(state: &AppState, catalogue_ttl: Duration) -> MethodRouter<AppState> {
    // No policy configured: an empty static one, which fails closed for every upstream.
    let policy = state
        .tool_policy()
        .unwrap_or_else(|| Arc::new(StaticToolPolicy::default()));
    let upstreams = Arc::new(match (state.mcp(), state.relay()) {
        (Some(endpoint), Some(relay)) => {
            Upstreams::new(&relay, endpoint.allowed_hosts(), &policy, catalogue_ttl)
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

/// The one error for a name outside the catalogue and for a `hide` tool.
fn unknown_tool() -> McpError {
    McpError::invalid_params("unknown_tool", None)
}

/// The MCP server an agent talks to at `/mcp/upstream/{name}`. Only the tools capability is
/// advertised, so prompts, resources, completions, logging and tasks are method-not-found.
#[derive(Clone)]
struct UpstreamMcp {
    relay: Arc<Relay>,
    upstream: Arc<McpUpstream>,
    /// Decides every catalogue tool; the handler never reads the binding's table itself.
    policy: Arc<dyn ToolPolicy>,
    /// The upstream's catalogue, shared by every session and agent of this upstream.
    catalogue: Arc<TtlCell<Arc<Catalogue>>>,
}

impl UpstreamMcp {
    fn deps(&self) -> hop::HopDeps<'_> {
        hop::HopDeps {
            relay: Some(&self.relay),
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

    /// The current catalogue: cached for at most `MAX_CACHE_TTL`; an error is never cached.
    async fn catalogue(&self, agent: AgentIdentity) -> Result<Arc<Catalogue>, McpError> {
        self.catalogue
            .get_or_fetch(|| async {
                catalogue::fetch(&self.deps(), &self.upstream, agent)
                    .await
                    .map(Arc::new)
            })
            .await
            .map_err(Self::hop_error)
    }

    /// The policy's decision for every catalogue tool; a tool it does not name is hidden. An
    /// evaluator error is `None` (the caller hides everything and refuses the call).
    async fn decisions(
        &self,
        agent: AgentIdentity,
        catalogue: &Catalogue,
    ) -> Option<std::collections::HashMap<String, ToolDecision>> {
        let query = ToolQuery {
            org: agent.org_id.to_string(),
            agent: agent.agent_id.to_string(),
            upstream: self.upstream.name.clone(),
            catalogue: catalogue.entries(),
        };
        match self.policy.decide(&query).await {
            Ok(d) => Some(d),
            Err(e) => {
                tracing::warn!(upstream = %self.upstream.name, reason = e.code, "tool policy unavailable");
                None
            }
        }
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
        let agent = Self::agent(&context)?;
        let catalogue = self.catalogue(agent).await?;
        // The upstream's own paging is folded into the catalogue; the agent gets one page.
        let Some(decisions) = self.decisions(agent, &catalogue).await else {
            return Ok(ListToolsResult::default());
        };
        let tools = catalogue
            .tools()
            .iter()
            .filter(|t| {
                decisions
                    .get(t.name.as_ref())
                    .is_some_and(|d| *d != ToolDecision::Hide)
            })
            .cloned()
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
        let audit = CallAudit::new(&self.relay, agent, &self.upstream.name);
        let catalogue = match self.catalogue(agent).await {
            Ok(c) => c,
            Err(e) => {
                audit
                    .refused(
                        UNKNOWN_TOOL,
                        ToolDecision::Hide,
                        McpUpstreamReason::CatalogueUnavailable,
                    )
                    .await;
                return Err(e);
            }
        };
        if !catalogue.contains(&request.name) {
            // The agent's text is never recorded: a name outside the catalogue is `unknown`.
            audit
                .refused(
                    UNKNOWN_TOOL,
                    ToolDecision::Hide,
                    McpUpstreamReason::UnknownTool,
                )
                .await;
            return Err(unknown_tool());
        }
        // In the catalogue, so it passed the tool-name rule.
        let tool = request.name.to_string();
        let Some(decisions) = self.decisions(agent, &catalogue).await else {
            audit
                .refused(
                    &tool,
                    ToolDecision::Hide,
                    McpUpstreamReason::PolicyUnavailable,
                )
                .await;
            return Err(McpError::internal_error("policy_unavailable", None));
        };
        match decisions.get(request.name.as_ref()) {
            Some(ToolDecision::Allow) => {}
            Some(ToolDecision::Deny) => {
                audit
                    .refused(&tool, ToolDecision::Deny, McpUpstreamReason::Deny)
                    .await;
                return Err(McpError::invalid_request("tool_denied", None));
            }
            Some(ToolDecision::Hold) => {
                audit
                    .refused(&tool, ToolDecision::Hold, McpUpstreamReason::Hold)
                    .await;
                // No approver until M3: fail closed.
                return Err(McpError::invalid_request("approval_required", None));
            }
            Some(ToolDecision::Hide) | None => {
                audit
                    .refused(&tool, ToolDecision::Hide, McpUpstreamReason::Hide)
                    .await;
                return Err(unknown_tool());
            }
        }
        // The pending event first: without it nothing is forwarded.
        let attempt = audit.begin(&tool).await?;
        let result = hop::call_tool(&self.deps(), &self.upstream, agent, request).await;
        audit
            .finish(&tool, attempt, result.as_ref().map(|_| ()).map_err(|e| *e))
            .await;
        Ok(CallToolResponse::Complete(result.map_err(Self::hop_error)?))
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
