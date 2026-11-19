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
//! a refused caller's host never reaches the ledger. Nothing here holds the value, a header, a
//! body, a path or the query string. `gateway_audit` is read-only legacy (migration 0009).

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::decrypt::{BoxFuture, ControlPlane, Internal};

/// Largest append response read (`{"id": ..., "seq": ...}` or a problem body).
const MAX_APPEND_RESPONSE: usize = 16 * 1024;

/// The append endpoint, relative to the control-plane base URL.
const EVENTS_PATH: &str = "internal/v1/audit/events";

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
}

/// The wire body of `POST /internal/v1/audit/events` (`NewRelayEvent` in `openapi.json`).
#[derive(Serialize)]
struct WireEvent {
    kind: &'static str,
    outcome: &'static str,
    agent_id: Uuid,
    secret_id: Uuid,
    version: u32,
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

    async fn post(&self, ev: RelayEvent) -> Result<Uuid, AuditError> {
        // Never a ledger outcome: the ledger was unreachable when it happened.
        if let EventKind::Outcome(Outcome::AuditUnavailable)
        | EventKind::Denied(Outcome::AuditUnavailable)
        | EventKind::GitFetch(Outcome::AuditUnavailable)
        | EventKind::GitPush(Outcome::AuditUnavailable)
        | EventKind::GitDenied(Outcome::AuditUnavailable) = ev.kind
        {
            return Err(AuditError::Rejected);
        }
        let (kind, outcome) = ev.kind.wire();
        let body = serde_json::to_vec(&WireEvent {
            kind,
            outcome,
            agent_id: ev.agent_id,
            secret_id: ev.secret_id,
            version: ev.version,
            method: ev.method.map(Method::as_str),
            host: ev.host,
            port: ev.port,
            status: ev.status,
            attempt_id: ev.attempt_id,
        })
        .map_err(|_| AuditError::Rejected)?;
        let (status, resp) = self
            .control_plane
            .internal_post_json(EVENTS_PATH, body, MAX_APPEND_RESPONSE)
            .await
            .map_err(|e| match e {
                Internal::Unavailable => AuditError::Unavailable,
                _ => AuditError::Rejected,
            })?;
        match status {
            // 201 appended; 200 an outcome already stored for this attempt (a retry).
            200 | 201 => serde_json::from_slice::<Appended>(&resp)
                .map(|a| a.id)
                .map_err(|_| AuditError::Rejected),
            500..=599 => Err(AuditError::Unavailable),
            _ => Err(AuditError::Rejected),
        }
    }
}

impl AuditSink for HttpAudit {
    fn append(&self, ev: RelayEvent) -> BoxFuture<'_, Result<Uuid, AuditError>> {
        Box::pin(self.post(ev))
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
}

impl MemoryAudit {
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
}

impl AuditSink for MemoryAudit {
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
}
