//! Relay audit events in the org's ledger (S5 design decisions 5 and 6).
//!
//! The gateway appends through the control plane's `POST /internal/v1/audit/events` with the
//! service token ([`HttpAudit`]), so each org has one chain. Per relay call:
//! - a refusal before the attempt (no grant, grants unreadable, no binding or wrong origin,
//!   private address) appends one `relay.denied` event;
//! - an allowed call appends `relay.attempt` (outcome `pending`) before the material fetch and
//!   key unwrap, and is refused with `503` if that append fails; after the upstream call (or a
//!   failure after the attempt) it appends `relay.outcome` naming the attempt's id, retried up to
//!   3 times. The control plane makes the outcome idempotent on that id.
//!
//! An event holds ids, closed codes, numbers and the upstream host only. The host is sent only
//! once the URL's origin has matched the secret's binding (configuration, not caller input), so
//! a refused caller's host never reaches the ledger.
//!
//! Every `/mcp` tool call also appends one `mcp.call` event (m1-remote-mcp task 3.4): the agent,
//! the tool (a registry name, else `unknown`), the outcome and a static reason; never arguments
//! or results. A ledger that cannot take it is logged and does not fail the call (the relay and
//! credential events behind a tool already fail closed).
//!
//! Every call through the MCP upstream proxy appends `mcp.upstream_call` events the same way
//! (m2-mcp-gateway task 4.2, [`McpUpstreamEvent`]): see `mcp_upstream::audit`.
//!
//! An agent MCP `issue_short_lived_credential` call (m1-remote-mcp task 3.3) appends one
//! `credential.issued` event before the credential becomes usable: the agent, the secret, the
//! credential's id and its expiry. Never the credential. Nothing here holds the value, a header, a
//! body, a path or the query string. `gateway_audit` is read-only legacy (migration 0009).
//!
//! OAuth connections (c1-oauth-connections task 3.4) append `oauth.connected`,
//! `oauth.connect_failed`, `oauth.refresh_failed` and `oauth.disconnected` ([`OAuthEvent`]): the
//! person, the provider id, the connection and, for a refresh an agent's relay hit, the agent.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use ls_mcp_server::upstream::ToolDecision;

use crate::decrypt::{BoxFuture, ControlPlane, Internal};
use crate::mcp_upstream::hop::HopError;

/// Largest append response read (`{"id": ..., "seq": ...}` or a problem body).
const MAX_APPEND_RESPONSE: usize = 16 * 1024;

/// The append endpoint, relative to the control-plane base URL.
const EVENTS_PATH: &str = "internal/v1/audit/events";
const MCP_CALLS_PATH: &str = "internal/v1/mcp/agent-calls";
const MCP_UPSTREAM_CALLS_PATH: &str = "internal/v1/mcp/upstream-calls";

/// What happened to one relay attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The upstream answered and the redacted response was returned.
    Ok,
    /// The agent holds no unexpired relay grant for the secret (S4 task 2.2).
    NoGrant,
    /// The agent's grants could not be read; refused (fail closed).
    GrantsUnavailable,
    /// No binding for the secret, or the target's origin is not the binding's.
    Denied,
    /// The host resolves to a private, loopback, link-local or metadata address.
    DeniedAddress,
    /// The control plane did not return the material.
    MaterialError,
    /// The data key did not unwrap or the ciphertext did not open.
    DecryptFailed,
    /// The value cannot be placed in the binding's header.
    InjectFailed,
    /// DNS failed or the connection was refused.
    UpstreamUnreachable,
    UpstreamTimeout,
    UpstreamError,
    /// The response could not be scanned safely (encoding, size), so it was withheld.
    RedactionFailed,
    /// The `relay.attempt` event could not be appended; refused before any unwrap. Never sent
    /// to the ledger (the ledger was not reachable); logs and spans only.
    AuditUnavailable,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NoGrant => "no_grant",
            Self::GrantsUnavailable => "grants_unavailable",
            Self::Denied => "denied",
            Self::DeniedAddress => "denied_address",
            Self::MaterialError => "material_error",
            Self::DecryptFailed => "decrypt_failed",
            Self::InjectFailed => "inject_failed",
            Self::UpstreamUnreachable => "upstream_unreachable",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::UpstreamError => "upstream_error",
            Self::RedactionFailed => "redaction_failed",
            Self::AuditUnavailable => "audit_unavailable",
        }
    }

    /// A policy refusal, recorded as `relay.denied`.
    pub fn is_denial(self) -> bool {
        matches!(
            self,
            Self::NoGrant | Self::GrantsUnavailable | Self::Denied | Self::DeniedAddress
        )
    }

    /// Whether the URL's origin matched the secret's binding before this outcome, so the host
    /// is configuration rather than caller input and may be recorded.
    pub fn origin_checked(self) -> bool {
        !matches!(self, Self::NoGrant | Self::GrantsUnavailable | Self::Denied)
    }
}

/// The kind of a relay event, with its outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// Before the material fetch and key unwrap; outcome `pending`.
    Attempt,
    /// After the upstream call or a failure after the attempt.
    Outcome(Outcome),
    /// A refusal before any attempt (`Outcome::is_denial`).
    Denied(Outcome),
    /// A Git clone or fetch through `/git/...` (D1), one event per call with its final outcome.
    GitFetch(Outcome),
    /// A Git push through `/git/...` (D1), one event per call with its final outcome.
    GitPush(Outcome),
    /// A refused Git call (`Outcome::is_denial`).
    GitDenied(Outcome),
    /// A refused session on the Postgres listener (D3), after the agent token verified
    /// (`Outcome::is_denial`).
    DbDenied(Outcome),
    /// A relayed Postgres session was established (D3); written before the upstream connect, and
    /// the session is refused if the append fails.
    DbOpened,
    /// A relayed Postgres session ended (D3), with why and how much.
    DbClosed(SessionClose),
    /// A short-lived credential was issued (outcome `ok`); the event carries [`Issued`].
    CredentialIssued,
}

/// Why a relayed Postgres session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    ClientClosed,
    UpstreamClosed,
    /// The grant behind the session was revoked or expired.
    Revoked,
    /// The agent token expired.
    Expired,
    Error,
}

impl CloseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientClosed => "client_closed",
            Self::UpstreamClosed => "upstream_closed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Error => "error",
        }
    }
}

/// The `db.session.closed` payload: a reason and numbers, never query text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionClose {
    pub reason: CloseReason,
    pub duration_ms: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl EventKind {
    fn wire(self) -> (&'static str, &'static str) {
        match self {
            Self::Attempt => ("relay.attempt", "pending"),
            Self::Outcome(o) => ("relay.outcome", o.as_str()),
            Self::Denied(o) => ("relay.denied", o.as_str()),
            Self::GitFetch(o) => ("git.fetch", o.as_str()),
            Self::GitPush(o) => ("git.push", o.as_str()),
            Self::GitDenied(o) => ("git.denied", o.as_str()),
            Self::DbDenied(o) => ("db.session.denied", o.as_str()),
            Self::DbOpened => ("db.session.opened", "ok"),
            Self::DbClosed(_) => ("db.session.closed", "ok"),
            Self::CredentialIssued => ("credential.issued", "ok"),
        }
    }
}

/// The upstream method, when it is one the ledger names. Others are recorded without a method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
}

impl Method {
    pub fn from_http(m: &reqwest::Method) -> Option<Self> {
        Some(match *m {
            reqwest::Method::GET => Self::Get,
            reqwest::Method::HEAD => Self::Head,
            reqwest::Method::POST => Self::Post,
            reqwest::Method::PUT => Self::Put,
            reqwest::Method::PATCH => Self::Patch,
            reqwest::Method::DELETE => Self::Delete,
            reqwest::Method::OPTIONS => Self::Options,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
        }
    }
}

/// One relay event. Ids, codes, numbers and a binding-checked host: never a value, header,
/// body, path or query string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEvent {
    pub kind: EventKind,
    /// The agent whose verified token made the call.
    pub agent_id: Uuid,
    pub secret_id: Uuid,
    /// The secret version (`0` and not sent for `credential.issued`, which is not
    /// version-bound).
    pub version: u32,
    pub method: Option<Method>,
    /// The upstream host (no port), set only when the origin matched the binding.
    pub host: Option<String>,
    /// The upstream port, when the URL names one and the host is set.
    pub port: Option<u16>,
    /// Upstream HTTP status, when a response was received.
    pub status: Option<u16>,
    /// The attempt this outcome closes (the attempt event's id).
    pub attempt_id: Option<Uuid>,
    /// For [`EventKind::CredentialIssued`] only: which credential, and until when.
    pub issued: Option<Issued>,
}

/// What a `credential.issued` event records about the credential: its id and expiry, never the
/// credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Issued {
    pub credential_id: Uuid,
    /// Unix seconds.
    pub expires_at: i64,
}

/// Why an append failed. Carries no response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    /// No answer, a timeout or a `5xx`: worth retrying (outcomes only; the control plane makes
    /// them idempotent).
    Unavailable,
    /// The control plane refused the event or the token (`4xx`), or answered nonsense:
    /// retrying the same request cannot help.
    Rejected,
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "audit ledger unavailable",
            Self::Rejected => "audit event refused",
        })
    }
}

impl std::error::Error for AuditError {}

/// Appends relay events. Returns the stored event's id (an attempt's id keys its outcome).
pub trait AuditSink: Send + Sync {
    fn append(&self, ev: RelayEvent) -> BoxFuture<'_, Result<Uuid, AuditError>>;

    /// Append an AWS credential-vending event (D2).
    fn append_aws(&self, ev: AwsEvent) -> BoxFuture<'_, Result<Uuid, AuditError>>;

    /// Append the `mcp.call` event for one `/mcp` tool call (m1-remote-mcp task 3.4).
    fn append_mcp_call(&self, ev: McpCallEvent) -> BoxFuture<'_, Result<Uuid, AuditError>>;

    /// Append an `mcp.upstream_call` or `mcp.upstream_outcome` event for one call through the MCP
    /// upstream proxy (m2-mcp-gateway task 4.2). An outcome is idempotent on its `attempt_id`.
    fn append_mcp_upstream(&self, ev: McpUpstreamEvent) -> BoxFuture<'_, Result<Uuid, AuditError>>;

    /// Append an `oauth.*` event (c1-oauth-connections task 3.4).
    fn append_oauth(&self, ev: OAuthEvent) -> BoxFuture<'_, Result<Uuid, AuditError>>;
}

/// Why an OAuth connect flow failed (`oauth.connect_failed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectFailure {
    /// Confirmed by someone other than the person who started the flow.
    WrongPerson,
    /// Not completed or confirmed in time.
    FlowExpired,
    /// The provider answered with an error.
    ProviderError,
    /// The code exchange (or storing its result) failed.
    ExchangeFailed,
}

/// Why a refresh failed (`oauth.refresh_failed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshFailure {
    InvalidGrant,
    ProviderError,
}

/// How a disconnect went at the provider (`oauth.disconnected`); the material is deleted in
/// every case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectOutcome {
    /// Revoked at the provider.
    Ok,
    RevokeFailed,
    RevokeUnsupported,
}

/// The kind of an `oauth.*` event with its outcome. Only the outcomes the control plane's
/// allow-list accepts for each kind can be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthEventKind {
    /// The person who started the flow confirmed it; outcome `ok`.
    Connected,
    ConnectFailed(ConnectFailure),
    RefreshFailed(RefreshFailure),
    Disconnected(DisconnectOutcome),
}

impl OAuthEventKind {
    fn wire(self) -> (&'static str, &'static str) {
        match self {
            Self::Connected => ("oauth.connected", "ok"),
            Self::ConnectFailed(f) => (
                "oauth.connect_failed",
                match f {
                    ConnectFailure::WrongPerson => "wrong_person",
                    ConnectFailure::FlowExpired => "flow_expired",
                    ConnectFailure::ProviderError => "provider_error",
                    ConnectFailure::ExchangeFailed => "exchange_failed",
                },
            ),
            Self::RefreshFailed(f) => (
                "oauth.refresh_failed",
                match f {
                    RefreshFailure::InvalidGrant => "invalid_grant",
                    RefreshFailure::ProviderError => "provider_error",
                },
            ),
            Self::Disconnected(o) => (
                "oauth.disconnected",
                match o {
                    DisconnectOutcome::Ok => "ok",
                    DisconnectOutcome::RevokeFailed => "revoke_failed",
                    DisconnectOutcome::RevokeUnsupported => "revoke_unsupported",
                },
            ),
        }
    }
}

/// One `oauth.*` event: the connection's person, the provider id, the connection and, for a
/// refresh an agent's relay hit, the agent. Never a token, code, verifier or provider answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthEvent {
    pub kind: OAuthEventKind,
    /// The user id of the connection's (or flow's) person.
    pub person: Uuid,
    /// The registry provider id (`[a-z0-9-]{1,32}`).
    pub provider: String,
    /// Required except for [`OAuthEventKind::ConnectFailed`].
    pub connection_id: Option<Uuid>,
    /// [`OAuthEventKind::RefreshFailed`] only.
    pub agent_id: Option<Uuid>,
}

impl OAuthEvent {
    /// Whether the control plane's allow-list takes this event's fields.
    fn fits(&self) -> bool {
        let refresh = matches!(self.kind, OAuthEventKind::RefreshFailed(_));
        let failed = matches!(self.kind, OAuthEventKind::ConnectFailed(_));
        (refresh || self.agent_id.is_none()) && (failed || self.connection_id.is_some())
    }
}

/// The wire body of an `oauth.*` event on `POST /internal/v1/audit/events` (`NewRelayEvent`
/// with `person`, `provider`, `connection_id` and `agent_id` only).
#[derive(Serialize)]
struct WireOAuthEvent<'a> {
    kind: &'static str,
    outcome: &'static str,
    person: Uuid,
    provider: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<Uuid>,
}

/// Which of the two upstream-call events an [`McpUpstreamEvent`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpUpstreamPhase {
    /// `mcp.upstream_call`: `pending` before forwarding, or `denied` alone for a refusal.
    Call,
    /// `mcp.upstream_outcome`: `ok` or `error`, linked to its call by `attempt_id`.
    Outcome,
}

impl McpUpstreamPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Outcome => "outcome",
        }
    }
}

/// How an upstream call stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpUpstreamOutcome {
    Pending,
    Ok,
    Denied,
    Error,
}

impl McpUpstreamOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::Error => "error",
        }
    }
}

/// Why an upstream call was refused or failed: a closed set of static codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpUpstreamReason {
    /// The policy decided `hide` for the tool, or did not name it.
    Hide,
    Deny,
    Hold,
    /// The tool is not in the upstream's catalogue.
    UnknownTool,
    /// The tool policy could not decide.
    PolicyUnavailable,
    /// The upstream's catalogue could not be fetched.
    CatalogueUnavailable,
    /// The hop failed after the call was forwarded (or while trying to).
    Hop(HopError),
}

impl McpUpstreamReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hide => "hide",
            Self::Deny => "deny",
            Self::Hold => "hold",
            Self::UnknownTool => "unknown_tool",
            Self::PolicyUnavailable => "policy_unavailable",
            Self::CatalogueUnavailable => "catalogue_unavailable",
            Self::Hop(e) => e.slug(),
        }
    }
}

/// One MCP upstream proxy call event: who, which upstream and tool, the decision and how it
/// stands. No arguments, no result, no credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpUpstreamEvent {
    pub phase: McpUpstreamPhase,
    pub agent_id: Uuid,
    /// The upstream's configured name.
    pub upstream: String,
    /// A catalogue tool name, else `unknown`.
    pub tool: String,
    pub decision: ToolDecision,
    pub outcome: McpUpstreamOutcome,
    pub reason: Option<McpUpstreamReason>,
    /// The `pending` call event's id, on an outcome.
    pub attempt_id: Option<Uuid>,
}

#[derive(Serialize)]
struct WireMcpUpstream<'a> {
    phase: &'static str,
    agent_id: Uuid,
    upstream: &'a str,
    tool: &'a str,
    decision: &'static str,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt_id: Option<Uuid>,
}

/// What happened to one `POST /v1/aws/credentials` call (D2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwsEventKind {
    /// Credentials were issued and returned; outcome `ok`.
    Issued,
    /// Refused or failed; never `ok` or `pending`.
    Denied(Outcome),
}

impl AwsEventKind {
    fn wire(self) -> (&'static str, &'static str) {
        match self {
            Self::Issued => ("aws.credentials.issued", "ok"),
            Self::Denied(o) => ("aws.credentials.denied", o.as_str()),
        }
    }
}

/// How an agent MCP call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpOutcome {
    Ok,
    Denied,
    Error,
}

impl McpOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::Error => "error",
        }
    }
}

/// One AWS credential event: the binding (its base-credential secret id names the bound role in
/// the gateway's bindings file), its region, the clamped duration and the outcome. Never a key,
/// a secret, a session token, a policy or an STS response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsEvent {
    pub kind: AwsEventKind,
    pub agent_id: Uuid,
    /// The binding's base-credential secret (the event's target).
    pub secret_id: Uuid,
    /// The bound region (configuration, validated at load).
    pub region: String,
    /// The credential lifetime, once clamped.
    pub duration_secs: Option<u32>,
}

/// The wire body of an AWS event on `POST /internal/v1/audit/events`.
#[derive(Serialize)]
struct WireAwsEvent {
    kind: &'static str,
    outcome: &'static str,
    agent_id: Uuid,
    secret_id: Uuid,
    region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_secs: Option<u32>,
}

/// Why a call was refused or failed: a closed set of static codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpReason {
    ToolOff,
    InvalidArguments,
    ToolError,
    SettingsUnavailable,
}

impl McpReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::ToolOff => "tool_off",
            Self::InvalidArguments => "invalid_arguments",
            Self::ToolError => "tool_error",
            Self::SettingsUnavailable => "settings_unavailable",
        }
    }
}

/// One agent MCP call: who, which tool (a registry name or `unknown`, never client text) and how
/// it ended. No arguments, no result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpCallEvent {
    pub agent_id: Uuid,
    pub tool: &'static str,
    pub outcome: McpOutcome,
    pub reason: Option<McpReason>,
}

#[derive(Serialize)]
struct WireMcpCall {
    agent_id: Uuid,
    tool: &'static str,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

/// The wire body of `POST /internal/v1/audit/events` (`NewRelayEvent` in `openapi.json`).
#[derive(Serialize)]
struct WireEvent {
    kind: &'static str,
    outcome: &'static str,
    agent_id: Uuid,
    secret_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_out: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<i64>,
}

#[derive(Deserialize)]
struct Appended {
    id: Uuid,
}

/// Appends through the control plane with the gateway service token (the org header is the
/// gateway's org).
pub struct HttpAudit {
    control_plane: Arc<ControlPlane>,
}

impl HttpAudit {
    pub fn new(control_plane: Arc<ControlPlane>) -> Self {
        Self { control_plane }
    }

    async fn post_aws(&self, ev: AwsEvent) -> Result<Uuid, AuditError> {
        if ev.kind == AwsEventKind::Denied(Outcome::AuditUnavailable)
            || ev.kind == AwsEventKind::Denied(Outcome::Ok)
        {
            return Err(AuditError::Rejected);
        }
        let (kind, outcome) = ev.kind.wire();
        let body = serde_json::to_vec(&WireAwsEvent {
            kind,
            outcome,
            agent_id: ev.agent_id,
            secret_id: ev.secret_id,
            region: ev.region,
            duration_secs: ev.duration_secs,
        })
        .map_err(|_| AuditError::Rejected)?;
        self.append_to(EVENTS_PATH, body, &[200, 201]).await
    }

    async fn post(&self, ev: RelayEvent) -> Result<Uuid, AuditError> {
        // Never a ledger outcome: the ledger was unreachable when it happened.
        if let EventKind::Outcome(Outcome::AuditUnavailable)
        | EventKind::Denied(Outcome::AuditUnavailable)
        | EventKind::GitFetch(Outcome::AuditUnavailable)
        | EventKind::GitPush(Outcome::AuditUnavailable)
        | EventKind::GitDenied(Outcome::AuditUnavailable)
        | EventKind::DbDenied(Outcome::AuditUnavailable) = ev.kind
        {
            return Err(AuditError::Rejected);
        }
        let (kind, outcome) = ev.kind.wire();
        let closed = match ev.kind {
            EventKind::DbClosed(c) => Some(c),
            _ => None,
        };
        let body = serde_json::to_vec(&WireEvent {
            kind,
            outcome,
            agent_id: ev.agent_id,
            secret_id: ev.secret_id,
            // A short-lived credential is scoped to the secret, not to one version.
            version: (ev.kind != EventKind::CredentialIssued).then_some(ev.version),
            method: ev.method.map(Method::as_str),
            host: ev.host,
            port: ev.port,
            status: ev.status,
            attempt_id: ev.attempt_id,
            reason: closed.map(|c| c.reason.as_str()),
            duration_ms: closed.map(|c| c.duration_ms),
            bytes_in: closed.map(|c| c.bytes_in),
            bytes_out: closed.map(|c| c.bytes_out),
            credential_id: ev.issued.map(|i| i.credential_id),
            expires_at: ev.issued.map(|i| i.expires_at),
        })
        .map_err(|_| AuditError::Rejected)?;
        // 201 appended; 200 an outcome already stored for this attempt (a retry).
        self.append_to(EVENTS_PATH, body, &[200, 201]).await
    }
}

impl HttpAudit {
    /// POST `body` to the control plane's append `path`. A status in `ok` is an append (its body
    /// must parse); `5xx` and an unreachable control plane are `Unavailable` (retried by the
    /// caller); anything else is `Rejected`. The fail-closed mapping for every audit append.
    async fn append_to(&self, path: &str, body: Vec<u8>, ok: &[u16]) -> Result<Uuid, AuditError> {
        let (status, resp) = self
            .control_plane
            .internal_post_json(path, body, MAX_APPEND_RESPONSE)
            .await
            .map_err(|e| match e {
                Internal::Unavailable => AuditError::Unavailable,
                _ => AuditError::Rejected,
            })?;
        match status {
            s if ok.contains(&s) => serde_json::from_slice::<Appended>(&resp)
                .map(|a| a.id)
                .map_err(|_| AuditError::Rejected),
            500..=599 => Err(AuditError::Unavailable),
            _ => Err(AuditError::Rejected),
        }
    }

    async fn post_mcp_call(&self, ev: McpCallEvent) -> Result<Uuid, AuditError> {
        let body = serde_json::to_vec(&WireMcpCall {
            agent_id: ev.agent_id,
            tool: ev.tool,
            outcome: ev.outcome.as_str(),
            reason: ev.reason.map(McpReason::as_str),
        })
        .map_err(|_| AuditError::Rejected)?;
        self.append_to(MCP_CALLS_PATH, body, &[201]).await
    }

    async fn post_mcp_upstream(&self, ev: McpUpstreamEvent) -> Result<Uuid, AuditError> {
        let body = serde_json::to_vec(&WireMcpUpstream {
            phase: ev.phase.as_str(),
            agent_id: ev.agent_id,
            upstream: &ev.upstream,
            tool: &ev.tool,
            decision: ev.decision.as_str(),
            outcome: ev.outcome.as_str(),
            reason: ev.reason.map(McpUpstreamReason::as_str),
            attempt_id: ev.attempt_id,
        })
        .map_err(|_| AuditError::Rejected)?;
        // 201 appended; 200 an outcome already stored for this attempt (a retry).
        self.append_to(MCP_UPSTREAM_CALLS_PATH, body, &[200, 201])
            .await
    }

    async fn post_oauth(&self, ev: OAuthEvent) -> Result<Uuid, AuditError> {
        if !ev.fits() {
            return Err(AuditError::Rejected);
        }
        let (kind, outcome) = ev.kind.wire();
        let body = serde_json::to_vec(&WireOAuthEvent {
            kind,
            outcome,
            person: ev.person,
            provider: &ev.provider,
            connection_id: ev.connection_id,
            agent_id: ev.agent_id,
        })
        .map_err(|_| AuditError::Rejected)?;
        self.append_to(EVENTS_PATH, body, &[201]).await
    }
}

impl AuditSink for HttpAudit {
    fn append(&self, ev: RelayEvent) -> BoxFuture<'_, Result<Uuid, AuditError>> {
        Box::pin(self.post(ev))
    }

    fn append_aws(&self, ev: AwsEvent) -> BoxFuture<'_, Result<Uuid, AuditError>> {
        Box::pin(self.post_aws(ev))
    }

    fn append_mcp_call(&self, ev: McpCallEvent) -> BoxFuture<'_, Result<Uuid, AuditError>> {
        Box::pin(self.post_mcp_call(ev))
    }

    fn append_mcp_upstream(&self, ev: McpUpstreamEvent) -> BoxFuture<'_, Result<Uuid, AuditError>> {
        Box::pin(self.post_mcp_upstream(ev))
    }

    fn append_oauth(&self, ev: OAuthEvent) -> BoxFuture<'_, Result<Uuid, AuditError>> {
        Box::pin(self.post_oauth(ev))
    }
}

/// In-memory sink for unit tests. `fail` fails every append, `fail_attempts` every
/// `relay.attempt`, `fail_outcomes_first` the first that many `relay.outcome` appends
/// (`Unavailable`, so they are retried).
#[derive(Default)]
pub struct MemoryAudit {
    pub events: Mutex<Vec<(Uuid, RelayEvent)>>,
    pub fail: bool,
    pub fail_attempts: bool,
    pub fail_outcomes_first: Mutex<usize>,
    /// Every append tried, failed ones included.
    pub tries: Mutex<usize>,
    /// Stored AWS events (D2); `fail` fails these too.
    pub aws_events: Mutex<Vec<AwsEvent>>,
    /// The `mcp.call` events appended.
    pub mcp_calls: Mutex<Vec<McpCallEvent>>,
    /// The upstream-call events appended, with the ids the sink gave them. `fail` fails these
    /// too.
    pub mcp_upstream: Mutex<Vec<(Uuid, McpUpstreamEvent)>>,
    /// Fail every `mcp.upstream_call` append.
    pub fail_upstream_calls: bool,
    /// Fail the first that many `mcp.upstream_outcome` appends (`Unavailable`, so retried).
    pub fail_upstream_outcomes_first: Mutex<usize>,
    /// Every upstream-call append tried, failed ones included.
    pub upstream_tries: Mutex<usize>,
    /// The `oauth.*` events appended. `fail` fails these too.
    pub oauth_events: Mutex<Vec<OAuthEvent>>,
}

impl MemoryAudit {
    /// The `oauth.*` events in order.
    pub fn oauth_events(&self) -> Vec<OAuthEvent> {
        self.oauth_events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The upstream-call events with the ids the sink gave them, in order.
    pub fn mcp_upstream(&self) -> Vec<(Uuid, McpUpstreamEvent)> {
        self.mcp_upstream
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Every upstream-call append tried.
    pub fn upstream_tries(&self) -> usize {
        *self
            .upstream_tries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// The `mcp.call` events in order.
    pub fn mcp_calls(&self) -> Vec<McpCallEvent> {
        self.mcp_calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The stored events in order.
    pub fn events(&self) -> Vec<RelayEvent> {
        self.stored().into_iter().map(|(_, e)| e).collect()
    }

    /// The stored events with the ids the sink gave them.
    pub fn stored(&self) -> Vec<(Uuid, RelayEvent)> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn tries(&self) -> usize {
        *self.tries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The stored AWS events in order.
    pub fn aws_events(&self) -> Vec<AwsEvent> {
        self.aws_events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl AuditSink for MemoryAudit {
    fn append_oauth(&self, ev: OAuthEvent) -> BoxFuture<'_, Result<Uuid, AuditError>> {
        let result = if self.fail {
            Err(AuditError::Unavailable)
        } else if !ev.fits() {
            Err(AuditError::Rejected)
        } else {
            self.oauth_events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(ev);
            Ok(Uuid::now_v7())
        };
        Box::pin(async move { result })
    }

    fn append_mcp_upstream(&self, ev: McpUpstreamEvent) -> BoxFuture<'_, Result<Uuid, AuditError>> {
        *self
            .upstream_tries
            .lock()
            .unwrap_or_else(|e| e.into_inner()) += 1;
        let result = {
            let mut first = self
                .fail_upstream_outcomes_first
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let outcome = ev.phase == McpUpstreamPhase::Outcome;
            if self.fail || (self.fail_upstream_calls && !outcome) {
                Err(AuditError::Unavailable)
            } else if outcome && *first > 0 {
                *first -= 1;
                Err(AuditError::Unavailable)
            } else {
                let mut stored = self.mcp_upstream.lock().unwrap_or_else(|e| e.into_inner());
                // Idempotent on the attempt, as the control plane is.
                let existing = ev.attempt_id.and_then(|a| {
                    stored
                        .iter()
                        .find(|(_, e)| {
                            e.phase == McpUpstreamPhase::Outcome && e.attempt_id == Some(a)
                        })
                        .map(|(id, _)| *id)
                });
                match existing {
                    Some(id) => Ok(id),
                    None => {
                        let id = Uuid::now_v7();
                        stored.push((id, ev));
                        Ok(id)
                    }
                }
            }
        };
        Box::pin(async move { result })
    }

    fn append_mcp_call(&self, ev: McpCallEvent) -> BoxFuture<'_, Result<Uuid, AuditError>> {
        let result = if self.fail {
            Err(AuditError::Unavailable)
        } else {
            self.mcp_calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(ev);
            Ok(Uuid::now_v7())
        };
        Box::pin(async move { result })
    }

    fn append(&self, ev: RelayEvent) -> BoxFuture<'_, Result<Uuid, AuditError>> {
        *self.tries.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        let result = {
            let mut first = self
                .fail_outcomes_first
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let outcome = matches!(ev.kind, EventKind::Outcome(_));
            if self.fail || (self.fail_attempts && ev.kind == EventKind::Attempt) {
                Err(AuditError::Unavailable)
            } else if outcome && *first > 0 {
                *first -= 1;
                Err(AuditError::Unavailable)
            } else {
                let id = Uuid::now_v7();
                self.events
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((id, ev));
                Ok(id)
            }
        };
        Box::pin(async move { result })
    }

    fn append_aws(&self, ev: AwsEvent) -> BoxFuture<'_, Result<Uuid, AuditError>> {
        *self.tries.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        let result = if self.fail {
            Err(AuditError::Unavailable)
        } else {
            self.aws_events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(ev);
            Ok(Uuid::now_v7())
        };
        Box::pin(async move { result })
    }
}

#[cfg(test)]
mod append_tests {
    use super::*;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ORG: Uuid = Uuid::from_u128(1);
    const ID: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000aa);

    fn sink(base: &str) -> HttpAudit {
        HttpAudit::new(Arc::new(
            ControlPlane::new(Url::parse(base).unwrap(), ORG, "t".to_owned().into()).unwrap(),
        ))
    }

    fn relay_event() -> RelayEvent {
        RelayEvent {
            kind: EventKind::CredentialIssued,
            agent_id: Uuid::from_u128(2),
            secret_id: Uuid::from_u128(3),
            version: 0,
            method: None,
            host: None,
            port: None,
            status: None,
            attempt_id: None,
            issued: None,
        }
    }

    fn mcp_event() -> McpCallEvent {
        McpCallEvent {
            agent_id: Uuid::from_u128(2),
            tool: "list_projects",
            outcome: McpOutcome::Ok,
            reason: None,
        }
    }

    async fn serve(status: u16, body: &str) -> (MockServer, HttpAudit) {
        let server = MockServer::start().await;
        for p in ["/internal/v1/audit/events", "/internal/v1/mcp/agent-calls"] {
            Mock::given(method("POST"))
                .and(path(p))
                .respond_with(ResponseTemplate::new(status).set_body_string(body))
                .mount(&server)
                .await;
        }
        let a = sink(&format!("{}/", server.uri()));
        (server, a)
    }

    fn appended() -> String {
        format!(r#"{{"id":"{ID}"}}"#)
    }

    #[tokio::test]
    async fn accepted_statuses_differ_per_caller() {
        let (_s, a) = serve(201, &appended()).await;
        assert_eq!(a.post(relay_event()).await, Ok(ID));
        assert_eq!(a.post_mcp_call(mcp_event()).await, Ok(ID));
        // 200 is an already-stored outcome for a relay event, but not an MCP call append.
        let (_s, a) = serve(200, &appended()).await;
        assert_eq!(a.post(relay_event()).await, Ok(ID));
        assert_eq!(
            a.post_mcp_call(mcp_event()).await,
            Err(AuditError::Rejected)
        );
    }

    #[tokio::test]
    async fn client_error_is_rejected_for_both() {
        let (_s, a) = serve(409, "{}").await;
        assert_eq!(a.post(relay_event()).await, Err(AuditError::Rejected));
        assert_eq!(
            a.post_mcp_call(mcp_event()).await,
            Err(AuditError::Rejected)
        );
    }

    #[tokio::test]
    async fn server_error_is_unavailable_for_both() {
        let (_s, a) = serve(503, "{}").await;
        assert_eq!(a.post(relay_event()).await, Err(AuditError::Unavailable));
        assert_eq!(
            a.post_mcp_call(mcp_event()).await,
            Err(AuditError::Unavailable)
        );
    }

    #[tokio::test]
    async fn unparsable_body_is_rejected_for_both() {
        let (_s, a) = serve(201, "not json").await;
        assert_eq!(a.post(relay_event()).await, Err(AuditError::Rejected));
        assert_eq!(
            a.post_mcp_call(mcp_event()).await,
            Err(AuditError::Rejected)
        );
    }

    #[tokio::test]
    async fn unreachable_control_plane_is_unavailable_for_both() {
        let a = sink("http://127.0.0.1:1/");
        assert_eq!(a.post(relay_event()).await, Err(AuditError::Unavailable));
        assert_eq!(
            a.post_mcp_call(mcp_event()).await,
            Err(AuditError::Unavailable)
        );
    }

    fn oauth_event(kind: OAuthEventKind) -> OAuthEvent {
        OAuthEvent {
            kind,
            person: Uuid::from_u128(4),
            provider: "github".to_owned(),
            connection_id: Some(Uuid::from_u128(5)),
            agent_id: None,
        }
    }

    /// The body carries the closed `oauth.*` fields only, in the shape the control plane's
    /// allow-list takes; events it would refuse are not sent at all.
    #[tokio::test]
    async fn oauth_events_send_the_allow_listed_fields_only() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/internal/v1/audit/events"))
            .respond_with(ResponseTemplate::new(201).set_body_string(appended()))
            .mount(&server)
            .await;
        let a = sink(&format!("{}/", server.uri()));
        let cases = [
            (
                oauth_event(OAuthEventKind::Connected),
                serde_json::json!({"kind": "oauth.connected", "outcome": "ok",
                    "person": Uuid::from_u128(4), "provider": "github",
                    "connection_id": Uuid::from_u128(5)}),
            ),
            (
                OAuthEvent {
                    connection_id: None,
                    ..oauth_event(OAuthEventKind::ConnectFailed(ConnectFailure::WrongPerson))
                },
                serde_json::json!({"kind": "oauth.connect_failed", "outcome": "wrong_person",
                    "person": Uuid::from_u128(4), "provider": "github"}),
            ),
            (
                OAuthEvent {
                    agent_id: Some(Uuid::from_u128(6)),
                    ..oauth_event(OAuthEventKind::RefreshFailed(RefreshFailure::InvalidGrant))
                },
                serde_json::json!({"kind": "oauth.refresh_failed", "outcome": "invalid_grant",
                    "person": Uuid::from_u128(4), "provider": "github",
                    "connection_id": Uuid::from_u128(5), "agent_id": Uuid::from_u128(6)}),
            ),
            (
                oauth_event(OAuthEventKind::Disconnected(
                    DisconnectOutcome::RevokeUnsupported,
                )),
                serde_json::json!({"kind": "oauth.disconnected", "outcome": "revoke_unsupported",
                    "person": Uuid::from_u128(4), "provider": "github",
                    "connection_id": Uuid::from_u128(5)}),
            ),
        ];
        for (ev, want) in &cases {
            assert_eq!(a.post_oauth(ev.clone()).await, Ok(ID));
            let got: serde_json::Value = serde_json::from_slice(
                &server
                    .received_requests()
                    .await
                    .unwrap()
                    .last()
                    .unwrap()
                    .body,
            )
            .unwrap();
            assert_eq!(&got, want);
        }

        // Refused locally: an agent outside a refresh, no connection outside a failed connect.
        let sent = server.received_requests().await.unwrap().len();
        for ev in [
            OAuthEvent {
                agent_id: Some(Uuid::from_u128(6)),
                ..oauth_event(OAuthEventKind::Connected)
            },
            OAuthEvent {
                connection_id: None,
                ..oauth_event(OAuthEventKind::Disconnected(DisconnectOutcome::Ok))
            },
        ] {
            assert_eq!(a.post_oauth(ev).await, Err(AuditError::Rejected));
        }
        assert_eq!(server.received_requests().await.unwrap().len(), sent);
        // 200 is not an append for these.
        let (_s, a) = serve(200, &appended()).await;
        assert_eq!(
            a.post_oauth(oauth_event(OAuthEventKind::Connected)).await,
            Err(AuditError::Rejected)
        );
    }
}
