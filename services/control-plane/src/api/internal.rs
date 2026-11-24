//! Service-to-service routes under `/internal/v1` (S3 design decision 2; S4 decision 4).
//!
//! The gateway fetches the stored envelope of one secret version here: the A0-7 ciphertext, the
//! KMS-wrapped DEK and the key id. None of it is plaintext, and the control plane cannot unwrap
//! the DEK (its KMS token may only encrypt, S2 decision 4), so this route returns no secret
//! value. It is reachable only with the gateway service token ([`ServiceOrgBinding`]), and the
//! read runs in a tenant transaction for the org the gateway names, so another org's secret is a
//! `404`, the same as one that does not exist.
//!
//! `GET /internal/v1/agents/{agent_id}/grants` gives the gateway an agent's unexpired grants
//! (ids, secret names and modes; never a value), so it can enforce them before any unwrap. The
//! same service token and org scoping apply.
//!
//! `POST /internal/v1/audit/events` appends a relay event (`relay.attempt`, `relay.outcome`,
//! `relay.denied`, for Git `git.fetch`, `git.push`, `git.denied`, `credential.issued` for a
//! short-lived credential the agent MCP issued, and for AWS credential vending
//! `aws.credentials.issued`, `aws.credentials.denied`) to the org's audit ledger (S5 design decision 5). The body is typed end to
//! end: kinds, outcomes and methods are closed enums mapped to static codes, ids are UUIDs, the
//! host is validated as a bare host name or IP, and unknown fields are refused. There is no field
//! for a URL, path, query, header or body, so none of them can reach the ledger.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ls_audit::{Actor, Attrs, Code, Event, Host, Target, attr, kind, outcome};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::agents::{GrantMode, GrantScope, grant_cols, optional_utc, scope_from_row};
use super::extract::{ApiJson, ApiPath};
use super::responses::{InternalReadErrors, InternalWriteErrors};
use super::{all, exists_or_404, one};
use crate::app::AppState;
use crate::auth::ServiceOrgBinding;
use crate::db::sql::{self, Row};
use crate::mcp_store;
use crate::problem::{ApiError, Kind, Problem};

/// The stored envelope of one secret version. Ciphertext and a wrapped data key only: never the
/// value, and never an unwrapped key.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecretVersionMaterial {
    pub secret_id: Uuid,
    pub version: u32,
    /// The KMS key the data key is wrapped under, e.g. `gateway:v1`.
    pub key_id: String,
    /// A0-7 ciphertext blob (header, nonce, ciphertext, tag), standard base64 with padding.
    #[schema(content_encoding = "base64")]
    pub ciphertext: String,
    /// A0-7 `dek-wrap` blob (the KMS-wrapped data key), standard base64 with padding.
    #[schema(content_encoding = "base64")]
    pub wrapped_dek: String,
}

#[utoipa::path(
    get,
    path = "/internal/v1/secrets/{secret_id}/versions/{version}/material",
    operation_id = "get_secret_version_material",
    tag = "internal",
    summary = "Fetch the encrypted material of a secret version (gateway only; no plaintext)",
    params(
        ("secret_id" = Uuid, Path, description = "Secret id"),
        ("version" = u32, Path, description = "Version number, starting at 1", minimum = 1),
        ("X-Locksmith-Org" = Uuid, Header, description = "The org the gateway acts for"),
    ),
    responses(
        (status = 200, description = "Ciphertext, wrapped data key and key id", body = SecretVersionMaterial),
        InternalReadErrors,
    ),
    security(("service_token" = []))
)]
pub async fn material(
    State(state): State<AppState>,
    org: ServiceOrgBinding,
    ApiPath((secret_id, version)): ApiPath<(Uuid, u32)>,
) -> Result<Json<SecretVersionMaterial>, ApiError> {
    // Stored versions are 1..=i32::MAX; anything else cannot exist.
    let stored = i32::try_from(version)
        .ok()
        .filter(|v| *v >= 1)
        .ok_or_else(ApiError::not_found)?;
    let org_id = org.org_id;
    let material = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                // RLS limits the read to the bound org; the explicit org_id is belt and braces.
                let row = sql::query(
                    "SELECT ciphertext, wrapped_dek, key_id FROM secret_versions \
                     WHERE org_id = $1 AND secret_id = $2 AND version = $3",
                )
                .bind(org_id)
                .bind(secret_id)
                .bind(stored)
                .fetch_optional(c)
                .await?;
                one(row, |r| {
                    let ciphertext: Vec<u8> = r.try_get("ciphertext")?;
                    let wrapped_dek: Vec<u8> = r.try_get("wrapped_dek")?;
                    Ok(SecretVersionMaterial {
                        secret_id,
                        version,
                        key_id: r.try_get("key_id")?,
                        ciphertext: STANDARD.encode(ciphertext),
                        wrapped_dek: STANDARD.encode(wrapped_dek),
                    })
                })
            })
        })
        .await?;
    // Ids only: never the material.
    tracing::info!(
        secret.id = %secret_id,
        secret.version = version,
        "secret version material served"
    );
    Ok(Json(material))
}

/// One unexpired grant, as the gateway needs it. Ids, a name and a mode: never a value.
#[derive(Debug, Serialize, ToSchema)]
pub struct ActiveGrant {
    pub grant_id: Uuid,
    pub secret_id: Uuid,
    pub secret_name: String,
    pub mode: GrantMode,
    /// The allow-list of a `delegate` grant; `null` for `relay`.
    pub scope: Option<GrantScope>,
    /// `null` when the grant does not expire. The gateway must still refuse it at or after this
    /// time, even while cached.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub expires_at: Option<OffsetDateTime>,
}

/// An agent's unexpired grants at the time of the request.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentGrantSet {
    pub agent_id: Uuid,
    pub items: Vec<ActiveGrant>,
}

#[utoipa::path(
    get,
    path = "/internal/v1/agents/{agent_id}/grants",
    operation_id = "get_internal_agent_grants",
    tag = "internal",
    summary = "List an agent's unexpired grants (gateway only)",
    description = "The gateway calls this with the agent id and org id from a verified agent token. An agent that does not exist in the org (deleted, or another org's) is a `404`.",
    params(
        ("agent_id" = Uuid, Path, description = "Agent id (the token's `sub`)"),
        ("X-Locksmith-Org" = Uuid, Header, description = "The agent's org (the token's `org`)"),
    ),
    responses(
        (status = 200, description = "Unexpired grants", body = AgentGrantSet),
        InternalReadErrors,
    ),
    security(("service_token" = []))
)]
pub async fn agent_grants(
    State(state): State<AppState>,
    org: ServiceOrgBinding,
    ApiPath(agent_id): ApiPath<Uuid>,
) -> Result<Json<AgentGrantSet>, ApiError> {
    let items = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                exists_or_404(
                    &mut *c,
                    sql::query_scalar("SELECT 1 FROM agents WHERE id = $1").bind(agent_id),
                )
                .await?;
                let rows = sql::query(concat!(
                    "SELECT ",
                    grant_cols!(),
                    " FROM agent_grants g JOIN secrets s ON s.org_id = g.org_id AND s.id = g.secret_id \
                     WHERE g.agent_id = $1 AND (g.expires_at IS NULL OR g.expires_at > now()) \
                     ORDER BY g.id"
                ))
                .bind(agent_id)
                .fetch_all(c)
                .await?;
                all(&rows, |r| {
                    Ok(ActiveGrant {
                        grant_id: r.try_get("id")?,
                        secret_id: r.try_get("secret_id")?,
                        secret_name: r.try_get("secret_name")?,
                        mode: GrantMode::parse(r.try_get::<&str, _>("mode")?)?,
                        scope: scope_from_row(r)?,
                        expires_at: optional_utc(r, "expires_at")?,
                    })
                })
            })
        })
        .await?;
    tracing::info!(agent.id = %agent_id, grants = items.len(), "agent grants served");
    Ok(Json(AgentGrantSet { agent_id, items }))
}

/// The kind of a relay event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
pub enum RelayEventKind {
    /// Written before the key unwrap; outcome `pending`.
    #[serde(rename = "relay.attempt")]
    Attempt,
    /// Written after the upstream call; any outcome but `pending`.
    #[serde(rename = "relay.outcome")]
    Outcome,
    /// A refused call; outcome `denied`, `no_grant`, `grants_unavailable` or `denied_address`.
    #[serde(rename = "relay.denied")]
    Denied,
    /// A completed Git clone or fetch through `/git/...` (D1); any outcome but `pending` and the
    /// denials. One event per call, no attempt.
    #[serde(rename = "git.fetch")]
    GitFetch,
    /// A completed Git push through `/git/...` (D1); same outcomes as `git.fetch`.
    #[serde(rename = "git.push")]
    GitPush,
    /// A refused Git call; outcome `denied`, `grants_unavailable`, `no_grant` or `denied_address`.
    #[serde(rename = "git.denied")]
    GitDenied,
    /// Short-lived AWS credentials issued (D2); outcome `ok`, with `region` and `duration_secs`.
    #[serde(rename = "aws.credentials.issued")]
    AwsIssued,
    /// A refused or failed AWS credential request (D2); any outcome but `pending` and `ok`, with
    /// `region`.
    #[serde(rename = "aws.credentials.denied")]
    AwsDenied,
    /// A refused Postgres session on the gateway's pg listener (D3); a denial outcome, or
    /// `upstream_unreachable`, `material_error` or `decrypt_failed` (refused before any upstream
    /// connect).
    #[serde(rename = "db.session.denied")]
    DbSessionDenied,
    /// A relayed Postgres session was established (D3); outcome `ok`.
    #[serde(rename = "db.session.opened")]
    DbSessionOpened,
    /// A relayed Postgres session ended (D3); outcome `ok`, with `reason`, `duration_ms`,
    /// `bytes_in` and `bytes_out` (and `attempt_id`: the `db.session.opened` event's id).
    #[serde(rename = "db.session.closed")]
    DbSessionClosed,
    /// The gateway issued a short-lived credential scoped to the secret (m1-remote-mcp task 3.3,
    /// decision H1-2); outcome `ok`, with `credential_id` and `expires_at`. Written before the
    /// credential is usable, so a failed append means nothing was issued.
    #[serde(rename = "credential.issued")]
    CredentialIssued,
}

impl RelayEventKind {
    fn code(self) -> Code {
        match self {
            Self::Attempt => kind::RELAY_ATTEMPT,
            Self::Outcome => kind::RELAY_OUTCOME,
            Self::Denied => kind::RELAY_DENIED,
            Self::GitFetch => kind::GIT_FETCH,
            Self::GitPush => kind::GIT_PUSH,
            Self::GitDenied => kind::GIT_DENIED,
            Self::AwsIssued => kind::AWS_CREDENTIALS_ISSUED,
            Self::AwsDenied => kind::AWS_CREDENTIALS_DENIED,
            Self::DbSessionDenied => kind::DB_SESSION_DENIED,
            Self::DbSessionOpened => kind::DB_SESSION_OPENED,
            Self::DbSessionClosed => kind::DB_SESSION_CLOSED,
            Self::CredentialIssued => kind::CREDENTIAL_ISSUED,
        }
    }

    fn is_aws(self) -> bool {
        matches!(self, Self::AwsIssued | Self::AwsDenied)
    }
}

/// The outcome of a relay event (the gateway's outcome codes, plus `pending` for an attempt).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RelayOutcome {
    Pending,
    Ok,
    NoGrant,
    GrantsUnavailable,
    Denied,
    DeniedAddress,
    MaterialError,
    DecryptFailed,
    InjectFailed,
    UpstreamUnreachable,
    UpstreamTimeout,
    UpstreamError,
    RedactionFailed,
}

impl RelayOutcome {
    fn code(self) -> Code {
        match self {
            Self::Pending => outcome::PENDING,
            Self::Ok => outcome::OK,
            Self::NoGrant => Code::new("no_grant"),
            Self::GrantsUnavailable => Code::new("grants_unavailable"),
            Self::Denied => outcome::DENIED,
            Self::DeniedAddress => Code::new("denied_address"),
            Self::MaterialError => Code::new("material_error"),
            Self::DecryptFailed => Code::new("decrypt_failed"),
            Self::InjectFailed => Code::new("inject_failed"),
            Self::UpstreamUnreachable => Code::new("upstream_unreachable"),
            Self::UpstreamTimeout => Code::new("upstream_timeout"),
            Self::UpstreamError => Code::new("upstream_error"),
            Self::RedactionFailed => Code::new("redaction_failed"),
        }
    }

    fn is_denial(self) -> bool {
        matches!(
            self,
            Self::Denied | Self::NoGrant | Self::GrantsUnavailable | Self::DeniedAddress
        )
    }
}

/// Why a relayed Postgres session ended (`db.session.closed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionCloseReason {
    /// The client disconnected.
    ClientClosed,
    /// The upstream database closed the connection.
    UpstreamClosed,
    /// The grant behind the session was revoked or expired.
    Revoked,
    /// The agent token expired.
    Expired,
    /// The relay failed before or during the session.
    Error,
}

impl SessionCloseReason {
    fn code(self) -> Code {
        match self {
            Self::ClientClosed => Code::new("client_closed"),
            Self::UpstreamClosed => Code::new("upstream_closed"),
            Self::Revoked => Code::new("revoked"),
            Self::Expired => Code::new("expired"),
            Self::Error => Code::new("error"),
        }
    }
}

/// The upstream request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum RelayMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
}

impl RelayMethod {
    fn code(self) -> Code {
        match self {
            Self::Get => Code::new("get"),
            Self::Head => Code::new("head"),
            Self::Post => Code::new("post"),
            Self::Put => Code::new("put"),
            Self::Patch => Code::new("patch"),
            Self::Delete => Code::new("delete"),
            Self::Options => Code::new("options"),
        }
    }
}

/// One relay event from the gateway. Ids, codes, a host and numbers only: there is no field
/// for a URL, path, query string, header, body or value.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewRelayEvent {
    pub kind: RelayEventKind,
    pub outcome: RelayOutcome,
    /// The agent whose verified token made the call (the event's actor).
    pub agent_id: Uuid,
    /// The secret the call used (the event's target).
    pub secret_id: Uuid,
    #[schema(minimum = 1)]
    pub version: Option<u32>,
    pub method: Option<RelayMethod>,
    /// Upstream host name or IP literal only (an IPv6 address in brackets); no port, path or
    /// query.
    pub host: Option<String>,
    /// Upstream port, when the URL names one explicitly.
    pub port: Option<u16>,
    /// Upstream HTTP status, when a response was received.
    #[schema(minimum = 100, maximum = 599)]
    pub status: Option<u16>,
    /// Links the `relay.outcome` event to its `relay.attempt` event (the `id` the attempt's
    /// append returned). Required for `relay.outcome`, and its idempotency key: an outcome
    /// resent for the same attempt returns the stored event instead of appending another.
    pub attempt_id: Option<Uuid>,
    /// Why the session ended; required for `db.session.closed`, refused elsewhere.
    pub reason: Option<SessionCloseReason>,
    /// Session length in milliseconds (`db.session.closed` only).
    pub duration_ms: Option<u64>,
    /// Bytes relayed client to upstream (`db.session.closed` only).
    pub bytes_in: Option<u64>,
    /// Bytes relayed upstream to client (`db.session.closed` only).
    pub bytes_out: Option<u64>,
    /// The id of the short-lived credential (`credential.issued` only; never the credential).
    pub credential_id: Option<Uuid>,
    /// When the short-lived credential expires, Unix seconds (`credential.issued` only).
    pub expires_at: Option<i64>,
    /// AWS region of the binding (`aws.credentials.*` only, required there), e.g. `us-east-1`.
    pub region: Option<String>,
    /// Lifetime of the vended credentials (`aws.credentials.*` only; required for `issued`).
    #[schema(minimum = 900, maximum = 3600)]
    pub duration_secs: Option<u32>,
}

/// An AWS region code: lowercase letters, digits and inner hyphens.
fn valid_region(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= 32
        && !r.starts_with('-')
        && !r.ends_with('-')
        && r.contains('-')
        && r.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl NewRelayEvent {
    /// The ledger event, or a `400` naming the field that is not allowed.
    fn into_event(self) -> Result<Event, ApiError> {
        let ok = match self.kind {
            RelayEventKind::Attempt => self.outcome == RelayOutcome::Pending,
            RelayEventKind::Outcome => self.outcome != RelayOutcome::Pending,
            RelayEventKind::GitFetch | RelayEventKind::GitPush => {
                self.outcome != RelayOutcome::Pending && !self.outcome.is_denial()
            }
            RelayEventKind::Denied | RelayEventKind::GitDenied => self.outcome.is_denial(),
            RelayEventKind::AwsIssued => self.outcome == RelayOutcome::Ok,
            RelayEventKind::AwsDenied => {
                !matches!(self.outcome, RelayOutcome::Ok | RelayOutcome::Pending)
            }
            RelayEventKind::DbSessionDenied => {
                self.outcome.is_denial()
                    || matches!(
                        self.outcome,
                        RelayOutcome::UpstreamUnreachable
                            | RelayOutcome::MaterialError
                            | RelayOutcome::DecryptFailed
                    )
            }
            RelayEventKind::DbSessionOpened | RelayEventKind::DbSessionClosed => {
                self.outcome == RelayOutcome::Ok
            }
            RelayEventKind::CredentialIssued => self.outcome == RelayOutcome::Ok,
        };
        if !ok {
            return Err(ApiError::validation("`outcome` does not fit `kind`"));
        }
        let closed = self.kind == RelayEventKind::DbSessionClosed;
        if closed != self.reason.is_some() {
            return Err(ApiError::validation(
                "`reason` is required for `db.session.closed` and refused otherwise",
            ));
        }
        if !closed
            && (self.duration_ms.is_some() || self.bytes_in.is_some() || self.bytes_out.is_some())
        {
            return Err(ApiError::validation(
                "`duration_ms`, `bytes_in` and `bytes_out` are for `db.session.closed` only",
            ));
        }
        // An issue names the credential and its expiry and nothing about an upstream call; no
        // other kind carries either field.
        if self.kind == RelayEventKind::CredentialIssued {
            if self.credential_id.is_none() || self.expires_at.is_none() {
                return Err(ApiError::validation(
                    "`credential.issued` needs `credential_id` and `expires_at`",
                ));
            }
            if self.method.is_some()
                || self.host.is_some()
                || self.port.is_some()
                || self.status.is_some()
                || self.attempt_id.is_some()
            {
                return Err(ApiError::validation(
                    "`credential.issued` takes no upstream fields",
                ));
            }
        } else if self.credential_id.is_some() || self.expires_at.is_some() {
            return Err(ApiError::validation(
                "`credential_id` and `expires_at` are for `credential.issued` only",
            ));
        }
        let mut attrs = Attrs::new();
        if self.kind.is_aws() {
            // Binding, region, duration and outcome only.
            if self.version.is_some()
                || self.method.is_some()
                || self.host.is_some()
                || self.port.is_some()
                || self.status.is_some()
                || self.attempt_id.is_some()
            {
                return Err(ApiError::validation(
                    "`aws.credentials.*` takes only `region` and `duration_secs`",
                ));
            }
            let region = self
                .region
                .as_deref()
                .filter(|r| valid_region(r))
                .and_then(|r| Host::parse(r).ok())
                .ok_or_else(|| ApiError::validation("`region` must be an AWS region code"))?;
            attrs = attrs.host(attr::REGION, region);
            match self.duration_secs {
                Some(d) if (900..=3600).contains(&d) => {
                    attrs = attrs.int(attr::DURATION_SECS, i64::from(d));
                }
                Some(_) => {
                    return Err(ApiError::validation("`duration_secs` must be 900 to 3600"));
                }
                None if self.kind == RelayEventKind::AwsIssued => {
                    return Err(ApiError::validation(
                        "`aws.credentials.issued` needs `duration_secs`",
                    ));
                }
                None => {}
            }
            return Ok(Event {
                kind: self.kind.code(),
                actor: Actor::Agent(self.agent_id),
                target: Some(Target::Secret(self.secret_id)),
                outcome: self.outcome.code(),
                attrs,
            });
        }
        if self.region.is_some() || self.duration_secs.is_some() {
            return Err(ApiError::validation(
                "`region` and `duration_secs` are for `aws.credentials.*` only",
            ));
        }
        // The outcome is idempotent on its attempt (design decision 5), so it must name one.
        if self.kind == RelayEventKind::Outcome && self.attempt_id.is_none() {
            return Err(ApiError::validation("`relay.outcome` needs `attempt_id`"));
        }
        if let Some(v) = self.version {
            if v == 0 {
                return Err(ApiError::validation("`version` must be at least 1"));
            }
            attrs = attrs.int(attr::VERSION, i64::from(v));
        }
        if let Some(m) = self.method {
            attrs = attrs.code(attr::METHOD, m.code());
        }
        if let Some(h) = self.host {
            // The error never echoes the value.
            let host = Host::parse(&h)
                .map_err(|_| ApiError::validation("`host` must be a bare host name or IP"))?;
            attrs = attrs.host(attr::HOST, host);
        }
        if let Some(p) = self.port {
            attrs = attrs.int(attr::PORT, i64::from(p));
        }
        if let Some(s) = self.status {
            if !(100..=599).contains(&s) {
                return Err(ApiError::validation("`status` must be 100 to 599"));
            }
            attrs = attrs.int(attr::STATUS, i64::from(s));
        }
        if let Some(a) = self.attempt_id {
            attrs = attrs.id(attr::ATTEMPT_ID, a);
        }
        if let Some(r) = self.reason {
            attrs = attrs.code(attr::REASON, r.code());
        }
        for (key, v) in [
            (attr::DURATION_MS, self.duration_ms),
            (attr::BYTES_IN, self.bytes_in),
            (attr::BYTES_OUT, self.bytes_out),
        ] {
            if let Some(v) = v {
                // Saturate rather than wrap: the ledger integer is signed.
                attrs = attrs.int(key, i64::try_from(v).unwrap_or(i64::MAX));
            }
        }
        if let Some(c) = self.credential_id {
            attrs = attrs.id(attr::CREDENTIAL_ID, c);
        }
        if let Some(t) = self.expires_at {
            attrs = attrs.int(attr::EXPIRES_AT, t);
        }
        Ok(Event {
            kind: self.kind.code(),
            actor: Actor::Agent(self.agent_id),
            target: Some(Target::Secret(self.secret_id)),
            outcome: self.outcome.code(),
            attrs,
        })
    }
}

/// Where an event landed in the org's chain.
#[derive(Debug, Serialize, ToSchema)]
pub struct AppendedEvent {
    pub id: Uuid,
    /// The event's sequence number in the org's chain, starting at 1.
    pub seq: u64,
}

#[utoipa::path(
    post,
    path = "/internal/v1/audit/events",
    operation_id = "append_audit_event",
    tag = "internal",
    summary = "Append a relay event to the org's audit ledger (gateway only)",
    description = "The gateway appends `relay.attempt` before any key unwrap and refuses the call when this fails, `relay.outcome` after the upstream call, `relay.denied` for a refused call, and `credential.issued` (with `credential_id` and `expires_at`, no upstream fields) before a short-lived credential becomes usable. Unknown fields, kinds, outcomes and methods are a `400`; so is a host with a port, path or query. `relay.outcome` needs `attempt_id` and is idempotent on it: resending the same outcome returns the stored event with `200`, and a different outcome for the same attempt is a `409`.",
    params(
        ("X-Locksmith-Org" = Uuid, Header, description = "The org the event belongs to (the agent token's `org`)"),
    ),
    request_body = NewRelayEvent,
    responses(
        (status = 201, description = "Appended", body = AppendedEvent),
        (status = 200, description = "`relay.outcome` already recorded for this `attempt_id` with the same fields; nothing appended", body = AppendedEvent),
        (status = 409, description = "`relay.outcome` already recorded for this `attempt_id` with different fields", body = Problem, content_type = "application/problem+json"),
        InternalWriteErrors,
    ),
    security(("service_token" = []))
)]
pub async fn append_event(
    State(state): State<AppState>,
    org: ServiceOrgBinding,
    ApiJson(input): ApiJson<NewRelayEvent>,
) -> Result<(StatusCode, Json<AppendedEvent>), ApiError> {
    let attempt_id = match input.kind {
        RelayEventKind::Outcome => input.attempt_id,
        _ => None,
    };
    let event = input.into_event()?;
    let org_id = org.org_id;
    let appended = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                match attempt_id {
                    Some(a) => crate::audit::append_outcome_once(c, org_id, a, &event).await,
                    None => crate::audit::append(c, org_id, &event)
                        .await
                        .map(crate::audit::Once::Appended),
                }
            })
        })
        .await
        .map_err(ApiError::from)?;
    let (status, a) = match appended {
        crate::audit::Once::Appended(a) => (StatusCode::CREATED, a),
        crate::audit::Once::Existing(a) => (StatusCode::OK, a),
        crate::audit::Once::Conflict => {
            return Err(ApiError::new(
                Kind::Conflict,
                "a different outcome is already recorded for this attempt",
            ));
        }
    };
    Ok((
        status,
        Json(AppendedEvent {
            id: a.id,
            seq: a.seq,
        }),
    ))
}

/// One per-org override of an agent-layer MCP tool's default (an `mcp_tool_settings` row).
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentToolSetting {
    /// A registry tool name.
    pub tool: String,
    pub enabled: bool,
}

/// The org's agent-layer tool overrides. A tool with no row is at its registry default.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentToolSettingSet {
    pub items: Vec<AgentToolSetting>,
}

#[utoipa::path(
    get,
    path = "/internal/v1/mcp/agent-tool-settings",
    operation_id = "get_internal_agent_tool_settings",
    tag = "internal",
    summary = "List the org's agent-layer MCP tool overrides (gateway only)",
    description = "The gateway reads this (cached for seconds) to decide which agent tools it lists and runs. Only overrides are returned; the defaults live in the tool registry. Tool names and booleans only.",
    params(
        ("X-Locksmith-Org" = Uuid, Header, description = "The org the gateway acts for"),
    ),
    responses(
        (status = 200, description = "The org's overrides", body = AgentToolSettingSet),
        InternalReadErrors,
    ),
    security(("service_token" = []))
)]
pub async fn agent_tool_settings(
    State(state): State<AppState>,
    org: ServiceOrgBinding,
) -> Result<Json<AgentToolSettingSet>, ApiError> {
    let org_id = org.org_id;
    let items = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                let rows = mcp_store::layer_settings(c, org_id, "agent").await?;
                Ok::<_, ApiError>(
                    rows.into_iter()
                        .map(|(tool, enabled)| AgentToolSetting { tool, enabled })
                        .collect::<Vec<_>>(),
                )
            })
        })
        .await?;
    Ok(Json(AgentToolSettingSet { items }))
}

/// The outcome of an agent MCP call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum McpCallOutcome {
    /// The tool ran and returned a result.
    Ok,
    /// The tool was off, unknown, or answered a refusal (`401`/`403`).
    Denied,
    /// Bad arguments or any other failure.
    Error,
}

/// One agent MCP call, as the gateway records it: who, which tool, and how it ended. There is no
/// field for arguments or a result.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewMcpAgentCall {
    /// The agent whose verified token made the call (the event's actor).
    pub agent_id: Uuid,
    /// The tool name as the client sent it; recorded only when it is a registry tool, else
    /// `unknown`.
    #[schema(max_length = 200)]
    pub tool: String,
    pub outcome: McpCallOutcome,
    /// Why a call was `denied` or `error`: a closed set of static codes.
    pub reason: Option<McpCallReason>,
}

/// Static reason codes for a refused or failed agent MCP call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum McpCallReason {
    ToolOff,
    InvalidArguments,
    ToolError,
    SettingsUnavailable,
}

impl McpCallReason {
    fn code(self) -> Code {
        match self {
            Self::ToolOff => Code::new("tool_off"),
            Self::InvalidArguments => Code::new("invalid_arguments"),
            Self::ToolError => Code::new("tool_error"),
            Self::SettingsUnavailable => Code::new("settings_unavailable"),
        }
    }
}

#[utoipa::path(
    post,
    path = "/internal/v1/mcp/agent-calls",
    operation_id = "append_agent_mcp_call",
    tag = "internal",
    summary = "Append an `mcp.call` event for an agent MCP call (gateway only)",
    description = "The gateway records every `/mcp` tool call: the agent, the tool (a registry name, else `unknown`), the outcome and a static reason; never arguments or results. Unknown fields are a `400`.",
    params(
        ("X-Locksmith-Org" = Uuid, Header, description = "The org the event belongs to (the agent token's `org`)"),
    ),
    request_body = NewMcpAgentCall,
    responses(
        (status = 201, description = "Appended", body = AppendedEvent),
        InternalWriteErrors,
    ),
    security(("service_token" = []))
)]
pub async fn append_agent_mcp_call(
    State(state): State<AppState>,
    org: ServiceOrgBinding,
    ApiJson(input): ApiJson<NewMcpAgentCall>,
) -> Result<(StatusCode, Json<AppendedEvent>), ApiError> {
    use ls_mcp_server::{Layer, Registry, agent_tools};
    let registry = Registry::new(Layer::Agent, agent_tools())
        .map_err(|_| ApiError::new(Kind::Internal, "tool registry invalid"))?;
    // Only a registry name is recorded, never client-supplied text.
    let tool = registry
        .tool_name(&input.tool)
        .and_then(|n| Code::try_new(n).ok())
        .unwrap_or(Code::new("unknown"));
    let ok = match input.outcome {
        McpCallOutcome::Ok => input.reason.is_none(),
        McpCallOutcome::Denied | McpCallOutcome::Error => input.reason.is_some(),
    };
    if !ok {
        return Err(ApiError::validation("`reason` does not fit `outcome`"));
    }
    let mut attrs = Attrs::new()
        .code(attr::LAYER, Code::new("agent"))
        .code(attr::TOOL, tool);
    if let Some(r) = input.reason {
        attrs = attrs.code(attr::REASON, r.code());
    }
    let org_id = org.org_id;
    let event = Event {
        kind: kind::MCP_CALL,
        actor: Actor::Agent(input.agent_id),
        target: Some(Target::Org(org_id)),
        outcome: match input.outcome {
            McpCallOutcome::Ok => outcome::OK,
            McpCallOutcome::Denied => outcome::DENIED,
            McpCallOutcome::Error => outcome::ERROR,
        },
        attrs,
    };
    let a = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move { crate::audit::append(c, org_id, &event).await })
        })
        .await
        .map_err(ApiError::from)?;
    Ok((
        StatusCode::CREATED,
        Json(AppendedEvent {
            id: a.id,
            seq: a.seq,
        }),
    ))
}

/// Body of `POST /internal/v1/mcp/agent-clients`: the agent that just initialized an MCP session.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewAgentMcpClient {
    /// The agent whose verified token opened the session; also the row's `client_id` and
    /// `principal` (an agent token has no OAuth client id).
    pub agent_id: Uuid,
    /// The client's display name from `initialize`; stored capped at 200 characters.
    #[schema(max_length = 200)]
    pub client_name: String,
}

/// The agent-layer `mcp_clients` row after the upsert.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentMcpClientState {
    /// Whether an admin has revoked this agent's MCP access.
    pub revoked: bool,
}

#[utoipa::path(
    post,
    path = "/internal/v1/mcp/agent-clients",
    operation_id = "upsert_agent_mcp_client",
    tag = "internal",
    summary = "Record an agent MCP client on initialize (gateway only)",
    description = "Upserts the agent-layer `mcp_clients` row for the agent (`client_id` and `principal` are the agent id): inserted on first sight, name and last-seen time refreshed afterwards. A revoked row stays revoked. The answer says whether it is revoked. An agent that does not exist in the org is a `404`. Ids and a display name only; never a token.",
    params(
        ("X-Locksmith-Org" = Uuid, Header, description = "The agent's org (the token's `org`)"),
    ),
    request_body = NewAgentMcpClient,
    responses(
        (status = 200, description = "Recorded", body = AgentMcpClientState),
        (status = 404, description = "The agent does not exist in the org", body = Problem, content_type = "application/problem+json"),
        InternalWriteErrors,
    ),
    security(("service_token" = []))
)]
pub async fn upsert_agent_mcp_client(
    State(state): State<AppState>,
    org: ServiceOrgBinding,
    ApiJson(input): ApiJson<NewAgentMcpClient>,
) -> Result<Json<AgentMcpClientState>, ApiError> {
    let org_id = org.org_id;
    let agent_id = input.agent_id;
    let name = input.client_name;
    let revoked = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                exists_or_404(
                    &mut *c,
                    sql::query_scalar("SELECT 1 FROM agents WHERE id = $1").bind(agent_id),
                )
                .await?;
                let id = agent_id.to_string();
                let at = mcp_store::upsert_client(c, org_id, "agent", &id, &id, &name).await?;
                Ok::<_, ApiError>(at.is_some())
            })
        })
        .await?;
    Ok(Json(AgentMcpClientState { revoked }))
}

/// One agent whose MCP access was revoked.
#[derive(Debug, Serialize, ToSchema)]
pub struct RevokedAgentClient {
    pub agent_id: Uuid,
}

/// The org's agents with revoked MCP access.
#[derive(Debug, Serialize, ToSchema)]
pub struct RevokedAgentClientSet {
    pub items: Vec<RevokedAgentClient>,
}

#[utoipa::path(
    get,
    path = "/internal/v1/mcp/revoked-agent-clients",
    operation_id = "get_internal_revoked_agent_clients",
    tag = "internal",
    summary = "List the agents whose MCP access is revoked (gateway only)",
    description = "The gateway reads this (cached for seconds, failing closed when unreadable) and refuses `/mcp` to every agent listed, on calls and on a fresh `initialize`. Agent ids only.",
    params(
        ("X-Locksmith-Org" = Uuid, Header, description = "The org the gateway acts for"),
    ),
    responses(
        (status = 200, description = "Agents with a revoked agent-layer client row", body = RevokedAgentClientSet),
        InternalReadErrors,
    ),
    security(("service_token" = []))
)]
pub async fn revoked_agent_clients(
    State(state): State<AppState>,
    org: ServiceOrgBinding,
) -> Result<Json<RevokedAgentClientSet>, ApiError> {
    let org_id = org.org_id;
    let items = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                let rows = sql::query(
                    "SELECT client_id FROM mcp_clients \
                     WHERE org_id = $1 AND layer = 'agent' AND revoked_at IS NOT NULL \
                     ORDER BY id",
                )
                .bind(org_id)
                .fetch_all(c)
                .await?;
                // A row whose client id is not an agent id cannot name an agent; it is skipped.
                Ok::<_, ApiError>(
                    rows.iter()
                        .filter_map(|r| r.try_get::<String, _>("client_id").ok())
                        .filter_map(|id| id.parse::<Uuid>().ok())
                        .map(|agent_id| RevokedAgentClient { agent_id })
                        .collect::<Vec<_>>(),
                )
            })
        })
        .await?;
    Ok(Json(RevokedAgentClientSet { items }))
}
