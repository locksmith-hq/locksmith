//! Task 2.3 of m2-mcp-gateway: the upstream hop, one fresh rmcp client exchange per agent request
//! (design decisions 2, 3 and 4).
//!
//! Per [`forward`] call, in this order (the relay's steps 4, 5, 7 and 8):
//! 1. egress: the binding's URL is checked against its own origin and the address guard
//!    ([`egress::check`]: resolved once, private and loopback refused unless
//!    `allow_private_hosts`, metadata always), before anything touches the material or the KMS;
//! 2. the client is [`egress::EgressTarget::client`]: pinned to those addresses, no redirects,
//!    no proxy from the environment;
//! 3. the secret version is fetched and unwrapped ([`Decryptor::decrypt`]) and the binding's
//!    `header` rendered from its `template` ([`crate::relay::render`], a sensitive header value
//!    built in a zeroized buffer); the plaintext is dropped (zeroized) right after;
//! 4. an rmcp client ([`HopClient`]) runs over that client: `initialize`, then the one request,
//!    then the session is closed and the transport, which holds the header, is dropped.
//!
//! Only [`Forward`] crosses: `ping`, `tools/list` and `tools/call` (with the `initialize`
//! handshake each exchange opens with). The enum is the allowlist, so any other method has no way
//! to reach the upstream. Requests the upstream sends to the client (sampling, elicitation,
//! roots, anything custom) are answered method-not-found and no client capability is advertised;
//! a `tools/call` answered with `input_required` or a task is refused, not driven.
//!
//! Nothing from the agent's HTTP request reaches the upstream: the exchange is built from the
//! binding alone, so the agent's `Authorization` and any other header it sent are never copied.
//!
//! Credential header: it always goes through rmcp's `custom_headers`, never `auth_header`. In
//! rmcp 3.11.0 `custom_headers` reserves only `Accept`, `Mcp-Session-Id`, `Last-Event-Id` and
//! `MCP-Protocol-Version` (`transport/common/http_header.rs`), so `Authorization` is accepted
//! there with any scheme (`Bearer`, `token`, ...), no `StreamableHttpClient` wrapper is needed,
//! and the value stays a sensitive `HeaderValue` instead of rmcp's plain `String` token. The
//! `HeaderValue` copies inside rmcp, hyper and rustls are not zeroized (best effort, as the
//! relay).
//!
//! Errors are fixed slugs ([`HopError`]); no upstream error text, URL or value is kept.
//! What comes back is redacted before it is returned ([`redact`], task 2.4).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ls_redact::{MIN_ENCODED_LEN, Redactor, Secret};
use reqwest::header::HeaderName;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ClientCapabilities, ClientConfig,
    ClientRequest, ElicitRequestParams, ElicitResult, ElicitationCreateRequestMethod,
    Implementation, ListToolsResult, PaginatedRequestParams,
};
// Sampling and roots are deprecated in rmcp (SEP-2577); the gateway only refuses them.
#[expect(deprecated, reason = "refused, never served")]
use rmcp::model::{
    CreateMessageRequestMethod, CreateMessageRequestParams, CreateMessageResult,
    ListRootsRequestMethod, ListRootsResult,
};
use rmcp::service::RequestContext;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::common::client_side_sse::NeverRetry;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::{ClientHandler, ErrorData as McpError, RoleClient, ServiceError, ServiceExt as _};
use tracing::Instrument as _;
use url::Url;

use crate::auth::AgentIdentity;
use crate::config::{Binding, McpUpstream};
use crate::decrypt::Decryptor;
use crate::egress::{self, EgressError, Resolver};

/// Whole exchange with the upstream: connect, handshake, request and answer (design decision 11).
pub const TIMEOUT: Duration = Duration::from_secs(60);
/// Largest upstream JSON body or SSE event read (design decision 11).
pub const MAX_MESSAGE: usize = 1024 * 1024;

/// What the hop needs from the gateway: the decrypt path, the resolver and the connect timeout
/// (the relay's).
pub struct HopDeps<'a> {
    /// Where a honey secret is recorded (`honey.triggered`, path `inject`); `None` in tests that
    /// drive the hop alone.
    pub relay: Option<&'a crate::relay::Relay>,
    pub decryptor: &'a Decryptor,
    pub resolver: &'a dyn Resolver,
    pub connect_timeout: Duration,
}

/// The only requests forwarded to an upstream (design decision 2). Every exchange opens with
/// `initialize`; nothing else can be expressed.
pub enum Forward {
    Ping,
    ListTools(Option<PaginatedRequestParams>),
    CallTool(CallToolRequestParams),
}

/// The upstream's answer to a [`Forward`], redacted by [`forward`].
#[derive(Debug)]
pub enum Answer {
    Pong,
    Tools(ListToolsResult),
    Call(CallToolResult),
}

/// Why the hop failed. Carries no upstream text, URL or value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopError {
    /// The URL is not the binding's origin (cannot happen for a validated binding).
    Denied,
    /// The upstream resolves to a private, loopback, link-local or metadata address.
    DeniedAddress,
    /// The host did not resolve, or the connection failed.
    Unreachable,
    /// The secret could not be fetched or unwrapped.
    SecretUnavailable,
    /// The value does not make a valid header.
    SecretUnusable,
    /// The upstream answered with an error, an unexpected status (a redirect included) or
    /// something that is not the expected MCP message.
    Upstream,
    /// The upstream asked for something the gateway does not drive (`input_required`, a task).
    Unsupported,
    /// The exchange took longer than [`TIMEOUT`].
    Timeout,
    /// The answer could not be scanned (too large, not serializable, or the value is too short
    /// for its encoded forms to be matched) or still held the credential after redaction; it is
    /// withheld (design decision 11).
    RedactionFailed,
    /// The client could not be built.
    Internal,
    /// The upstream's credential is a honey token (t5 task 3.1): refused before the unwrap and
    /// recorded; the agent sees `denied`, like any refusal.
    Honey,
}

impl HopError {
    /// The fixed slug the agent sees.
    pub fn slug(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::DeniedAddress => "denied_address",
            Self::Unreachable => "upstream_unreachable",
            Self::SecretUnavailable => "secret_unavailable",
            Self::SecretUnusable => "secret_unusable",
            Self::Upstream => "upstream_error",
            Self::Unsupported => "upstream_unsupported",
            Self::Timeout => "upstream_timeout",
            Self::RedactionFailed => "redaction_failed",
            Self::Internal => "internal",
            Self::Honey => "denied",
        }
    }
}

/// `tools/list` against the upstream.
pub async fn list_tools(
    deps: &HopDeps<'_>,
    upstream: &McpUpstream,
    agent: AgentIdentity,
    params: Option<PaginatedRequestParams>,
) -> Result<ListToolsResult, HopError> {
    match forward(deps, upstream, agent, Forward::ListTools(params)).await? {
        Answer::Tools(t) => Ok(t),
        _ => Err(HopError::Upstream),
    }
}

/// `tools/call` against the upstream.
pub async fn call_tool(
    deps: &HopDeps<'_>,
    upstream: &McpUpstream,
    agent: AgentIdentity,
    params: CallToolRequestParams,
) -> Result<CallToolResult, HopError> {
    match forward(deps, upstream, agent, Forward::CallTool(params)).await? {
        Answer::Call(c) => Ok(c),
        _ => Err(HopError::Upstream),
    }
}

/// One upstream exchange for `request`, with the credential injected for this exchange only.
pub async fn forward(
    deps: &HopDeps<'_>,
    upstream: &McpUpstream,
    agent: AgentIdentity,
    request: Forward,
) -> Result<Answer, HopError> {
    // Ids and the upstream's config name only: no arguments, results or header.
    let span = tracing::info_span!(
        "mcp.upstream.hop",
        upstream = %upstream.name,
        agent_id = %agent.agent_id,
    );
    let result = run(deps, upstream, request).instrument(span).await;
    if let (Err(HopError::Honey), Some(relay)) = (&result, deps.relay) {
        crate::honey_guard::record(
            relay,
            crate::audit::HoneyEvent {
                agent_id: agent.agent_id,
                secret_id: upstream.secret_id,
                path: crate::audit::HoneyPath::Inject,
                binding_id: None,
                peer: None,
            },
        )
        .await;
    }
    result
}

async fn run(
    deps: &HopDeps<'_>,
    upstream: &McpUpstream,
    request: Forward,
) -> Result<Answer, HopError> {
    // 1-2. Egress before the material: exact origin, address guard, pinned client.
    let url = Url::parse(&upstream.url).map_err(|_| HopError::Denied)?;
    let binding = Binding {
        secret_id: upstream.secret_id,
        origin: url.origin().ascii_serialization(),
        header: upstream.header.clone(),
        template: upstream.template.clone(),
        allow_private_hosts: upstream.allow_private_hosts,
    };
    let target = egress::check(&binding, &url, deps.resolver)
        .await
        .map_err(|e| match e {
            EgressError::HostNotAllowed => HopError::Denied,
            EgressError::AddressNotAllowed => HopError::DeniedAddress,
            EgressError::Unresolvable => HopError::Unreachable,
        })?;
    let client = target
        .client(deps.connect_timeout, TIMEOUT)
        .map_err(|_| HopError::Internal)?;
    let header_name =
        HeaderName::from_bytes(upstream.header.as_bytes()).map_err(|_| HopError::SecretUnusable)?;

    // 3. Decrypt, render, drop (zeroize) the plaintext.
    let value = deps
        .decryptor
        .decrypt(upstream.secret_id, upstream.version)
        .await
        .map_err(|e| match e {
            crate::decrypt::DecryptError::Honey(_) => HopError::Honey,
            _ => HopError::SecretUnavailable,
        })?;
    let header_value =
        crate::relay::render(&upstream.template, value.expose()).ok_or(HopError::SecretUnusable)?;
    // Encoded forms of values shorter than this are not matched by ls-redact, so an echo could
    // not be caught: refuse rather than forward unscannable (fail closed, as the relay).
    if value.expose().len() < MIN_ENCODED_LEN {
        return Err(HopError::RedactionFailed);
    }
    let redactor = Redactor::new(&[Secret::new(crate::relay::REDACTION_LABEL, value.expose())]);
    drop(value);

    // 4. One exchange; the transport, and the header with it, is dropped when it ends.
    let mut config = StreamableHttpClientTransportConfig::with_uri(target.url().as_str());
    config.retry_config = Arc::new(NeverRetry::default());
    config.allow_stateless = true;
    let config = config
        .custom_headers(HashMap::from([(header_name, header_value)]))
        .max_json_response_size(MAX_MESSAGE)
        .max_sse_event_size(MAX_MESSAGE)
        .reinit_on_expired_session(false);
    let transport = StreamableHttpClientTransport::with_client(client, config);
    let exchange = async move {
        let mut service = HopClient.serve(transport).await.map_err(|_| {
            tracing::warn!("upstream initialize failed");
            HopError::Upstream
        })?;
        let answer = match request {
            Forward::Ping => service
                .peer()
                .send_request(ClientRequest::PingRequest(Default::default()))
                .await
                .map(|_| Answer::Pong)
                .map_err(failed),
            Forward::ListTools(params) => service
                .peer()
                .list_tools(params)
                .await
                .map(Answer::Tools)
                .map_err(failed),
            // `call_tool_once`: an `input_required` round or a task is refused, not driven.
            Forward::CallTool(params) => match service.peer().call_tool_once(params).await {
                Ok(CallToolResponse::Complete(r)) => Ok(Answer::Call(r)),
                Ok(_) => Err(HopError::Unsupported),
                Err(e) => Err(failed(e)),
            },
        };
        let _ = service.close_with_timeout(CLOSE_TIMEOUT).await;
        answer
    };
    let answer = tokio::time::timeout(TIMEOUT, exchange)
        .await
        .unwrap_or(Err(HopError::Timeout))?;
    redact(&redactor, answer)
}

/// Every upstream message passes through the redactor (design decision 11): the answer is
/// serialized whole (tool names, descriptions and schemas; text, structured content and embedded
/// resources of results; the `_meta` objects), redacted in every encoding `ls-redact` knows,
/// re-checked, and parsed back. A message over [`MAX_MESSAGE`] or one that cannot be serialized
/// or parsed back is withheld, never passed unscanned.
fn redact(redactor: &Redactor, answer: Answer) -> Result<Answer, HopError> {
    fn go<T>(redactor: &Redactor, value: &T) -> Result<T, HopError>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let raw = serde_json::to_vec(value).map_err(|_| HopError::RedactionFailed)?;
        if raw.len() > MAX_MESSAGE {
            return Err(HopError::RedactionFailed);
        }
        let clean = redactor.redact_all(&raw);
        drop(raw);
        // Belt and braces: nothing the redactor knows may remain.
        if !redactor.find(&clean).is_empty() {
            return Err(HopError::RedactionFailed);
        }
        serde_json::from_slice(&clean).map_err(|_| HopError::RedactionFailed)
    }
    Ok(match answer {
        Answer::Pong => Answer::Pong,
        Answer::Tools(t) => Answer::Tools(go(redactor, &t)?),
        Answer::Call(c) => Answer::Call(go(redactor, &c)?),
    })
}

/// Wait for the session to close (`DELETE`) after the answer.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Logs the kind of an rmcp error only, never its text (which can quote the upstream's answer).
fn failed(e: ServiceError) -> HopError {
    let kind = match e {
        ServiceError::McpError(_) => "mcp_error",
        ServiceError::TransportSend(_) => "transport",
        ServiceError::TransportClosed => "transport_closed",
        ServiceError::UnexpectedResponse => "unexpected_response",
        ServiceError::Timeout { .. } => "timeout",
        ServiceError::Cancelled { .. } => "cancelled",
        _ => "other",
    };
    tracing::warn!(error = kind, "upstream request failed");
    HopError::Upstream
}

/// The gateway's side of the upstream exchange: advertises no client capability and refuses
/// every request the upstream sends to the client except `ping`.
#[derive(Clone, Copy)]
pub struct HopClient;

impl ClientHandler for HopClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::new(
            ClientCapabilities::default(),
            Implementation::new("locksmith-gateway", env!("CARGO_PKG_VERSION")),
        )
    }

    #[expect(deprecated, reason = "refused, never served")]
    async fn create_message(
        &self,
        _params: CreateMessageRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<CreateMessageResult, McpError> {
        Err(McpError::method_not_found::<CreateMessageRequestMethod>())
    }

    #[expect(deprecated, reason = "refused, never served")]
    async fn list_roots(
        &self,
        _context: RequestContext<RoleClient>,
    ) -> Result<ListRootsResult, McpError> {
        Err(McpError::method_not_found::<ListRootsRequestMethod>())
    }

    async fn create_elicitation(
        &self,
        _request: ElicitRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<ElicitResult, McpError> {
        Err(McpError::method_not_found::<ElicitationCreateRequestMethod>())
    }
}

#[cfg(test)]
#[path = "hop_tests.rs"]
mod tests;
