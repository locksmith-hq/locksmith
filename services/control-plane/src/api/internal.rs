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
//! `relay.denied`, and for Git `git.fetch`, `git.push`, `git.denied`) to the org's audit ledger (S5 design decision 5). The body is typed end to
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

use super::agents::{GrantMode, grant_cols, optional_utc};
use super::extract::{ApiJson, ApiPath};
use super::responses::{InternalReadErrors, InternalWriteErrors};
use super::{all, exists_or_404, one};
use crate::app::AppState;
use crate::auth::ServiceOrgBinding;
use crate::db::sql::{self, Row};
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
    /// A refused Postgres session on the gateway's pg listener (D3); outcome `denied`,
    /// `grants_unavailable`, `no_grant` or `denied_address`.
    #[serde(rename = "db.session.denied")]
    DbSessionDenied,
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
            Self::DbSessionDenied => kind::DB_SESSION_DENIED,
        }
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
            RelayEventKind::Denied
            | RelayEventKind::GitDenied
            | RelayEventKind::DbSessionDenied => self.outcome.is_denial(),
        };
        if !ok {
            return Err(ApiError::validation("`outcome` does not fit `kind`"));
        }
        // The outcome is idempotent on its attempt (design decision 5), so it must name one.
        if self.kind == RelayEventKind::Outcome && self.attempt_id.is_none() {
            return Err(ApiError::validation("`relay.outcome` needs `attempt_id`"));
        }
        let mut attrs = Attrs::new();
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
    description = "The gateway appends `relay.attempt` before any key unwrap and refuses the call when this fails, `relay.outcome` after the upstream call, and `relay.denied` for a refused call. Unknown fields, kinds, outcomes and methods are a `400`; so is a host with a port, path or query. `relay.outcome` needs `attempt_id` and is idempotent on it: resending the same outcome returns the stored event with `200`, and a different outcome for the same attempt is a `409`.",
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
