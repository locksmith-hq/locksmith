//! The audit ledger, read side (S5 task 6.1): `GET /v1/audit/events` pages the bound org's
//! events newest first, and `GET /v1/audit/status` reports its latest checkpoint and latest
//! verify run.
//!
//! Reads only, through [`crate::db::Database::with_org`], so row-level security shows an org
//! nothing but its own ledger. Responses carry the identifier-only columns the ledger stores
//! (kind, actor, target, outcome, identifier attributes) and the public chain digests and
//! signature metadata; there is no secret value anywhere in the ledger to expose.

use axum::Json;
use axum::extract::State;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::extract::ApiQuery;
use super::responses::{ListErrors, ReadErrors};
use super::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, all, utc};
use crate::app::AppState;
use crate::auth::OrgBinding;
use crate::db::sql::{self, Row};
use crate::problem::ApiError;

/// One audit event.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEvent {
    /// Position in the org's chain, starting at 1 with no gaps.
    pub seq: i64,
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub at: OffsetDateTime,
    /// Static event code, e.g. `relay.attempt` or `agent.created`.
    pub kind: String,
    /// `agent:<id>`, `user:<id>` or `service:<code>`.
    pub actor: String,
    /// `secret:<id>`, `agent:<id>`, `grant:<id>`, ...; absent when the event has no target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub outcome: String,
    /// Identifier-typed attributes (ids, hosts, codes, integers) only.
    #[schema(value_type = Object)]
    pub attrs: serde_json::Value,
    /// SHA-256 chain digest of the previous event, lowercase hex (64 zeros for `seq` 1).
    pub prev_digest: String,
    /// This event's SHA-256 chain digest, lowercase hex.
    pub digest: String,
}

/// One page of events, newest first. `next` is absent on the last page.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEventPage {
    pub items: Vec<AuditEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct AuditEventParams {
    /// Page size, 1 to 100 (default 50).
    limit: Option<u32>,
    /// Opaque cursor: the `next` value of the previous page.
    cursor: Option<String>,
}

/// The cursor is the last `seq` returned, so paging stays stable while new events are appended.
fn encode_cursor(seq: i64) -> String {
    URL_SAFE_NO_PAD.encode(seq.to_be_bytes())
}

fn decode_cursor(cursor: &str) -> Option<i64> {
    let bytes: [u8; 8] = URL_SAFE_NO_PAD.decode(cursor).ok()?.try_into().ok()?;
    Some(i64::from_be_bytes(bytes)).filter(|seq| *seq >= 1)
}

fn event_from_row(r: &sql::PgRow) -> sql::Result<AuditEvent> {
    let hex_of = |c: &str| r.try_get::<Vec<u8>, _>(c).map(hex::encode);
    Ok(AuditEvent {
        seq: r.try_get("seq")?,
        id: r.try_get("id")?,
        at: utc(r, "at")?,
        kind: r.try_get("kind")?,
        actor: r.try_get("actor")?,
        target: r.try_get("target")?,
        outcome: r.try_get("outcome")?,
        attrs: serde_json::from_str(&r.try_get::<String, _>("attrs")?)
            .map_err(|e| sql::Error::Decode(Box::new(e)))?,
        prev_digest: hex_of("prev_hash")?,
        digest: hex_of("hash")?,
    })
}

/// `GET /v1/audit/events`: the org's events, newest first.
#[utoipa::path(
    get,
    path = "/v1/audit/events",
    operation_id = "list_audit_events",
    tag = "audit",
    summary = "List audit events, newest first",
    params(AuditEventParams),
    responses(
        (status = 200, description = "A page of audit events", body = AuditEventPage),
        ListErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn list_events(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiQuery(params): ApiQuery<AuditEventParams>,
) -> Result<Json<AuditEventPage>, ApiError> {
    let limit = params.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if limit == 0 || limit > MAX_PAGE_LIMIT {
        return Err(ApiError::validation(format!(
            "`limit` must be between 1 and {MAX_PAGE_LIMIT}"
        )));
    }
    let before = params
        .cursor
        .as_deref()
        .map(|c| decode_cursor(c).ok_or_else(|| ApiError::validation("`cursor` is not valid")))
        .transpose()?;
    let mut rows = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let rows = sql::query(
                    "SELECT seq, id, at, kind, actor, target, outcome, attrs::text AS attrs, prev_hash, hash \
                     FROM audit_events WHERE ($1::bigint IS NULL OR seq < $1) \
                     ORDER BY seq DESC LIMIT $2",
                )
                .bind(before)
                .bind(i64::from(limit) + 1)
                .fetch_all(c)
                .await?;
                all(&rows, event_from_row)
            })
        })
        .await?;
    let next = if rows.len() > limit as usize {
        rows.truncate(limit as usize);
        rows.last().map(|e| encode_cursor(e.seq))
    } else {
        None
    };
    Ok(Json(AuditEventPage { items: rows, next }))
}

/// The newest signed checkpoint of the org's chain.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditCheckpoint {
    /// Chain position the checkpoint covers.
    pub seq: i64,
    /// The chain digest at `seq`, lowercase hex.
    pub digest: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub at: OffsetDateTime,
    /// Signing key name and version, e.g. `audit-checkpoint:1`.
    pub key_id: String,
}

/// The newest `locksmith-audit verify` run recorded for the org.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditVerifyRun {
    pub id: Uuid,
    /// `db` or `dir`.
    pub mode: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub finished_at: OffsetDateTime,
    pub ok: bool,
    /// Events and checkpoints the run walked.
    pub events: i64,
    pub checkpoints: i64,
    /// The first broken seq, when the run failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_seq: Option<i64>,
    /// `sequence`, `link`, `hash` or `checkpoint`, when the run failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub break_kind: Option<String>,
    /// Set when the chain ends before the latest checkpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_at: Option<i64>,
}

/// Chain status of the bound org.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditStatus {
    /// Seq of the newest event (0 when the org has none).
    pub head_seq: i64,
    /// Absent until the first checkpoint is signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_checkpoint: Option<AuditCheckpoint>,
    /// Absent until a verify run has been recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_verify: Option<AuditVerifyRun>,
}

/// `GET /v1/audit/status`: head, latest checkpoint and latest verify run.
#[utoipa::path(
    get,
    path = "/v1/audit/status",
    operation_id = "get_audit_status",
    tag = "audit",
    summary = "Get the audit chain status",
    responses(
        (status = 200, description = "OK", body = AuditStatus),
        ReadErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn status(
    State(state): State<AppState>,
    org: OrgBinding,
) -> Result<Json<AuditStatus>, ApiError> {
    let status = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let head_seq: Option<i64> = sql::query_scalar("SELECT seq FROM audit_heads")
                    .fetch_optional(&mut *c)
                    .await?;
                let checkpoint = sql::query(
                    "SELECT seq, hash, at, key_id FROM audit_checkpoints \
                     ORDER BY seq DESC LIMIT 1",
                )
                .fetch_optional(&mut *c)
                .await?
                .map(|r| -> sql::Result<AuditCheckpoint> {
                    Ok(AuditCheckpoint {
                        seq: r.try_get("seq")?,
                        digest: hex::encode(r.try_get::<Vec<u8>, _>("hash")?),
                        at: utc(&r, "at")?,
                        key_id: r.try_get("key_id")?,
                    })
                })
                .transpose()?;
                let verify = sql::query(
                    "SELECT id, mode, started_at, finished_at, ok, events, checkpoints, \
                     broken_seq, break_kind, truncated_at FROM audit_verify_runs \
                     ORDER BY finished_at DESC, id DESC LIMIT 1",
                )
                .fetch_optional(&mut *c)
                .await?
                .map(|r| -> sql::Result<AuditVerifyRun> {
                    Ok(AuditVerifyRun {
                        id: r.try_get("id")?,
                        mode: r.try_get("mode")?,
                        started_at: utc(&r, "started_at")?,
                        finished_at: utc(&r, "finished_at")?,
                        ok: r.try_get("ok")?,
                        events: r.try_get("events")?,
                        checkpoints: r.try_get("checkpoints")?,
                        broken_seq: r.try_get("broken_seq")?,
                        break_kind: r.try_get("break_kind")?,
                        truncated_at: r.try_get("truncated_at")?,
                    })
                })
                .transpose()?;
                Ok::<_, ApiError>(AuditStatus {
                    head_seq: head_seq.unwrap_or(0),
                    latest_checkpoint: checkpoint,
                    latest_verify: verify,
                })
            })
        })
        .await?;
    Ok(Json(status))
}
