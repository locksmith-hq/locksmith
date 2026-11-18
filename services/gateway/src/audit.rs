//! One audit row per relay attempt (S3 design decision 8), appended to `gateway_audit`.
//!
//! A record names who and where (agent id, secret id, version, caller, method, scheme, host, path)
//! and what happened (outcome, upstream status). Refusals after authentication (no grant, expired
//! grant, disallowed host) are audited too, with the agent id. It never holds the value, a header, a body or the query
//! string. S5 moves this into the hash chain.

use std::sync::Mutex;

use ls_control_plane::db::{Database, sql};
use uuid::Uuid;

use crate::decrypt::BoxFuture;

/// What happened to one relay attempt. Stored as its [`Outcome::as_str`] form.
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
        }
    }
}

/// One `gateway_audit` row. Holds no secret material by construction: every field is an id, a
/// name or a URL component the caller sent (never the query).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub org_id: Uuid,
    /// The agent whose token made the call (`sub` of the verified token).
    pub agent_id: Uuid,
    pub secret_id: Uuid,
    pub version: u32,
    pub caller: String,
    pub method: String,
    pub scheme: String,
    /// `host` or `host:port` when the port is explicit.
    pub host: String,
    pub path: String,
    pub outcome: Outcome,
    /// Upstream HTTP status; `None` when no upstream response was received.
    pub status: Option<u16>,
    pub request_id: String,
}

/// The audit row could not be written. Carries nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditError;

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("audit record could not be written")
    }
}

impl std::error::Error for AuditError {}

pub trait AuditSink: Send + Sync {
    fn record(&self, rec: AuditRecord) -> BoxFuture<'_, Result<(), AuditError>>;
}

/// Writes to Postgres through the tenant transaction helper, as `locksmith_app` (INSERT only;
/// RLS binds the row to the org).
pub struct PgAudit {
    db: Database,
}

impl PgAudit {
    pub fn new(db: Database) -> Self {
        Self { db }
    }
}

impl AuditSink for PgAudit {
    fn record(&self, rec: AuditRecord) -> BoxFuture<'_, Result<(), AuditError>> {
        Box::pin(async move {
            let org = rec.org_id;
            let version = i32::try_from(rec.version).map_err(|_| AuditError)?;
            self.db
                .with_org(org, move |c| {
                    Box::pin(async move {
                        sql::query(
                            "INSERT INTO gateway_audit \
                             (org_id, agent_id, secret_id, version, caller, method, scheme, host, \
                              path, outcome, status, request_id) \
                             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                        )
                        .bind(rec.org_id)
                        .bind(rec.agent_id)
                        .bind(rec.secret_id)
                        .bind(version)
                        .bind(rec.caller)
                        .bind(rec.method)
                        .bind(rec.scheme)
                        .bind(rec.host)
                        .bind(rec.path)
                        .bind(rec.outcome.as_str())
                        .bind(rec.status.map(i32::from))
                        .bind(rec.request_id)
                        .execute(c)
                        .await
                        .map(|_| ())
                    })
                })
                .await
                .map_err(|_: sql::Error| AuditError)
        })
    }
}

/// In-memory sink for tests and local runs without Postgres. `fail` makes every write fail.
#[derive(Default)]
pub struct MemoryAudit {
    pub records: Mutex<Vec<AuditRecord>>,
    pub fail: bool,
}

impl MemoryAudit {
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl AuditSink for MemoryAudit {
    fn record(&self, rec: AuditRecord) -> BoxFuture<'_, Result<(), AuditError>> {
        let result = if self.fail {
            Err(AuditError)
        } else {
            self.records
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(rec);
            Ok(())
        };
        Box::pin(async move { result })
    }
}
