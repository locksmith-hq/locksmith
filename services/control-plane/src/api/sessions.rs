//! Live agent sessions, revoke and pause (change t8-sessions-and-revoke, task 1.1: the contract).
//!
//! - `GET /v1/sessions` lists the org's live agent sessions.
//! - `POST /v1/sessions/{session_id}/revoke` revokes one; `POST /v1/sessions/revoke-all` all.
//! - `POST /v1/orgs/current/agents/pause` and `.../resume` set the org-wide pause flag.
//!
//! Authorization is the existing org-member pattern ([`OrgBinding`]), as for revoking a grant or
//! an MCP client (design decision 5). No schema here carries a token, its `jti`, an address or a
//! secret value: ids, a kind, a binding slug and times only.
//!
//! The list (task 2.1) and the gateway's internal report endpoint, `POST /internal/v1/sessions`
//! (open, heartbeat, close; service token only), are implemented. Revoke and pause land in task
//! 2.2; until then those handlers answer `501` with a problem body rather than an empty or fake
//! success, and the OpenAPI description of each route says so.
//!
//! `token_jti` is written by the report endpoint and read only by the revoke path (task 2.2); no
//! response here selects or returns it.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::extract::{ApiJson, ApiPath, ApiQuery};
use super::responses::{InternalWriteErrors, ListErrors, WriteErrors};
use super::{Page, PageParams, Paged, all, exists_or_404};
use crate::app::AppState;
use crate::auth::{OrgBinding, ServiceOrgBinding};
use crate::db::sql::{self, Row};
use crate::problem::{ApiError, Problem};

/// A session is live while the gateway reported it within this many seconds: three heartbeats at
/// the gateway's 5 s interval (design decision 1).
pub const LIVENESS_SECS: i64 = 15;

/// Sessions not seen for this long drop out of the list altogether (a recently ended session
/// stays visible, not live, for this long).
const LIST_WINDOW_SECS: i64 = 3600;

/// The liveness rule: reported within [`LIVENESS_SECS`] of `now` and not revoked. A last-seen
/// time in the future (clock skew) counts as just seen.
pub fn is_live(now: OffsetDateTime, last_seen_at: OffsetDateTime, revoked: bool) -> bool {
    !revoked && now - last_seen_at <= time::Duration::seconds(LIVENESS_SECS)
}

/// Which gateway path a session came in on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SessionKind {
    /// An HTTP relay session.
    Http,
    /// A Postgres relay session.
    Pg,
    /// A remote MCP session.
    Mcp,
}

impl SessionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Pg => "pg",
            Self::Mcp => "mcp",
        }
    }

    fn parse(s: &str) -> sql::Result<Self> {
        match s {
            "http" => Ok(Self::Http),
            "pg" => Ok(Self::Pg),
            "mcp" => Ok(Self::Mcp),
            other => Err(sql::Error::Decode(
                format!("unknown session kind `{other}`").into(),
            )),
        }
    }
}

/// A live (or recently live) agent session. Never carries a token, an address or a value.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentSession {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub kind: SessionKind,
    /// The binding slug the session targets; may be empty for a session with no binding.
    pub slug: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub last_seen_at: OffsetDateTime,
    /// True while the gateway reported the session within the last 15 seconds (three
    /// heartbeats) and it is not revoked.
    pub live: bool,
}

/// Result of revoke-all.
#[derive(Debug, Serialize, ToSchema)]
pub struct SessionsRevoked {
    /// How many sessions were revoked.
    pub revoked: u32,
}

/// The org's pause state.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentsPauseState {
    /// While true the gateway refuses every agent request of the org.
    pub agents_paused: bool,
}

/// The `501` the revoke and pause handlers return until task 2.2.
const NOT_IMPLEMENTED_DESC: &str = "Not implemented yet: the route is part of the contract and answers `501` until the control-plane behaviour lands (t8 task 2.2).";

#[utoipa::path(
    get,
    path = "/v1/sessions",
    operation_id = "list_agent_sessions",
    tag = "sessions",
    summary = "List the org's live agent sessions",
    description = "Agent id, kind, binding slug, start and last-seen times, and whether the session is live (reported within 15 seconds and not revoked). Sessions last seen within the past hour are listed, so a just-ended or revoked session shows as not live. No token, its `jti`, address or secret value is ever returned.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of sessions", body = Paged<AgentSession>),
        ListErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiQuery(params): ApiQuery<PageParams>,
) -> Result<Json<Paged<AgentSession>>, ApiError> {
    let page: Page = params.resolve()?;
    let org_id = org.org_id;
    let rows = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                // Never selects `token_jti`. `now()` comes from the database so the liveness rule
                // and the stored `last_seen_at` share one clock.
                let rows = sql::query(
                    "SELECT id, agent_id, kind, slug, started_at, last_seen_at, \
                     revoked_at IS NOT NULL AS revoked, now() AS db_now \
                     FROM agent_sessions \
                     WHERE org_id = $1 AND ($2::uuid IS NULL OR id > $2) \
                       AND last_seen_at > now() - make_interval(secs => $3) \
                     ORDER BY id LIMIT $4",
                )
                .bind(org_id)
                .bind(page.after)
                .bind(LIST_WINDOW_SECS as f64)
                .bind(page.fetch())
                .fetch_all(c)
                .await?;
                all(&rows, |r| {
                    let utc = |col: &str| -> sql::Result<OffsetDateTime> {
                        Ok(r.try_get::<OffsetDateTime, _>(col)?
                            .to_offset(time::UtcOffset::UTC))
                    };
                    let last_seen_at = utc("last_seen_at")?;
                    Ok(AgentSession {
                        id: r.try_get("id")?,
                        agent_id: r.try_get("agent_id")?,
                        kind: SessionKind::parse(r.try_get::<&str, _>("kind")?)?,
                        slug: r.try_get("slug")?,
                        started_at: utc("started_at")?,
                        last_seen_at,
                        live: is_live(utc("db_now")?, last_seen_at, r.try_get("revoked")?),
                    })
                })
            })
        })
        .await?;
    Ok(Json(Paged::new(rows, page, |s| s.id)))
}

#[utoipa::path(
    post,
    path = "/v1/sessions/{session_id}/revoke",
    operation_id = "revoke_agent_session",
    tag = "sessions",
    summary = "Revoke one agent session",
    description = "Marks the session's agent token revoked; the gateway closes the session and refuses that token within 10 seconds. Appends a `session.revoked` ledger event. Not implemented yet: answers `501` until t8 task 2.2.",
    params(("session_id" = Uuid, Path, description = "Session id from the list")),
    responses(
        (status = 200, description = "The revoked session", body = AgentSession),
        (status = 501, description = NOT_IMPLEMENTED_DESC, body = Problem, content_type = "application/problem+json"),
        WriteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn revoke_one(
    State(_state): State<AppState>,
    _org: OrgBinding,
    ApiPath(_session_id): ApiPath<Uuid>,
) -> Result<Json<AgentSession>, ApiError> {
    Err(ApiError::not_implemented())
}

#[utoipa::path(
    post,
    path = "/v1/sessions/revoke-all",
    operation_id = "revoke_all_agent_sessions",
    tag = "sessions",
    summary = "Revoke every live agent session of the org",
    description = "Every live session closes within 10 seconds; new sessions from the same agents still work if their grants do. Appends a `session.revoked` ledger event with the count. Not implemented yet: answers `501` until t8 task 2.2.",
    responses(
        (status = 200, description = "How many sessions were revoked", body = SessionsRevoked),
        (status = 501, description = NOT_IMPLEMENTED_DESC, body = Problem, content_type = "application/problem+json"),
        WriteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn revoke_all(
    State(_state): State<AppState>,
    _org: OrgBinding,
) -> Result<Json<SessionsRevoked>, ApiError> {
    Err(ApiError::not_implemented())
}

#[utoipa::path(
    post,
    path = "/v1/orgs/current/agents/pause",
    operation_id = "pause_agents",
    tag = "sessions",
    summary = "Pause every agent of the org",
    description = "Sets the org's `agents_paused` flag: the gateway refuses every agent request and closes live sessions within 10 seconds, before any decrypt. Idempotent. Appends an `agents.paused` ledger event. Not implemented yet: answers `501` until t8 task 2.2.",
    responses(
        (status = 200, description = "The org's pause state", body = AgentsPauseState),
        (status = 501, description = NOT_IMPLEMENTED_DESC, body = Problem, content_type = "application/problem+json"),
        WriteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn pause(
    State(_state): State<AppState>,
    _org: OrgBinding,
) -> Result<Json<AgentsPauseState>, ApiError> {
    Err(ApiError::not_implemented())
}

#[utoipa::path(
    post,
    path = "/v1/orgs/current/agents/resume",
    operation_id = "resume_agents",
    tag = "sessions",
    summary = "Resume the agents of the org",
    description = "Clears the org's `agents_paused` flag; requests with valid grants succeed again without re-enrolment. Idempotent. Appends an `agents.resumed` ledger event. Not implemented yet: answers `501` until t8 task 2.2.",
    responses(
        (status = 200, description = "The org's pause state", body = AgentsPauseState),
        (status = 501, description = NOT_IMPLEMENTED_DESC, body = Problem, content_type = "application/problem+json"),
        WriteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn resume(
    State(_state): State<AppState>,
    _org: OrgBinding,
) -> Result<Json<AgentsPauseState>, ApiError> {
    Err(ApiError::not_implemented())
}

/// A gateway report about one agent session. Ids, a kind and a binding slug only: there is no
/// field for an address or a secret value.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionReport {
    /// A session opened. Answers `201` with its id, which the gateway uses for the rest.
    Open {
        agent_id: Uuid,
        /// The `jti` claim of the agent token the session was opened with. Stored so a revoke
        /// can refuse that token; never returned by any route.
        token_jti: Uuid,
        kind: SessionKind,
        /// The binding slug the session targets (at most 100 characters); empty for none.
        slug: String,
    },
    /// The session is still open: sets its last-seen time to now. Answers `204`.
    Heartbeat { session_id: Uuid },
    /// The session ended: it stops being live at once. Answers `204`.
    Close { session_id: Uuid },
}

/// The id of a newly opened session.
#[derive(Debug, Serialize, ToSchema)]
pub struct OpenedSession {
    pub id: Uuid,
}

#[utoipa::path(
    post,
    path = "/internal/v1/sessions",
    operation_id = "report_agent_session",
    tag = "internal",
    summary = "Report an agent session opening, a heartbeat or a close (gateway only)",
    description = "The gateway reports `open` (agent, token `jti`, kind, binding slug; answers `201` with the session id), `heartbeat` every 5 seconds and `close`. A session not reported within 15 seconds is not live. An agent or session that does not exist in the org is a `404`. Unknown fields and kinds, and a slug over 100 characters, are a `400`. No response carries the `jti`.",
    params(
        ("X-Locksmith-Org" = Uuid, Header, description = "The org the session belongs to (the agent token's `org`)"),
    ),
    request_body = SessionReport,
    responses(
        (status = 201, description = "Opened", body = OpenedSession),
        (status = 204, description = "Heartbeat or close recorded"),
        InternalWriteErrors,
    ),
    security(("service_token" = []))
)]
pub async fn report(
    State(state): State<AppState>,
    org: ServiceOrgBinding,
    ApiJson(report): ApiJson<SessionReport>,
) -> Result<Response, ApiError> {
    let org_id = org.org_id;
    match report {
        SessionReport::Open {
            agent_id,
            token_jti,
            kind,
            slug,
        } => {
            if slug.chars().count() > 100 {
                return Err(ApiError::validation(
                    "`slug` must be at most 100 characters",
                ));
            }
            let id = state
                .db()
                .with_org(org_id, move |c| {
                    Box::pin(async move {
                        exists_or_404(
                            &mut *c,
                            sql::query_scalar("SELECT 1 FROM agents WHERE id = $1").bind(agent_id),
                        )
                        .await?;
                        let id: Uuid = sql::query_scalar(
                            "INSERT INTO agent_sessions (org_id, agent_id, token_jti, kind, slug) \
                             VALUES ($1, $2, $3, $4, $5) RETURNING id",
                        )
                        .bind(org_id)
                        .bind(agent_id)
                        .bind(token_jti)
                        .bind(kind.as_str())
                        .bind(slug)
                        .fetch_one(c)
                        .await?;
                        Ok::<_, ApiError>(id)
                    })
                })
                .await?;
            tracing::info!(session.id = %id, agent.id = %agent_id, "agent session opened");
            Ok((StatusCode::CREATED, Json(OpenedSession { id })).into_response())
        }
        SessionReport::Heartbeat { session_id } => {
            touch(&state, org_id, session_id, false).await?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        SessionReport::Close { session_id } => {
            touch(&state, org_id, session_id, true).await?;
            tracing::info!(session.id = %session_id, "agent session closed");
            Ok(StatusCode::NO_CONTENT.into_response())
        }
    }
}

/// A heartbeat sets `last_seen_at` to now; a close sets it a minute into the past, which the
/// app role may do (it can update only `last_seen_at` and `revoked_at`) and which ends liveness.
/// `404` when the session is not the org's.
async fn touch(
    state: &AppState,
    org_id: Uuid,
    session_id: Uuid,
    close: bool,
) -> Result<(), ApiError> {
    let sql_text = if close {
        "UPDATE agent_sessions SET last_seen_at = now() - interval '1 minute' \
         WHERE org_id = $1 AND id = $2"
    } else {
        "UPDATE agent_sessions SET last_seen_at = now() WHERE org_id = $1 AND id = $2"
    };
    let n = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                let r = sql::query(sql_text)
                    .bind(org_id)
                    .bind(session_id)
                    .execute(c)
                    .await?;
                Ok::<_, ApiError>(r.rows_affected())
            })
        })
        .await?;
    if n == 0 {
        return Err(ApiError::not_found());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(secs)
    }

    #[test]
    fn sessions_liveness_window_is_fifteen_seconds_inclusive() {
        let now = t(1000);
        assert!(is_live(now, t(1000), false));
        assert!(is_live(now, t(985), false));
        assert!(!is_live(now, t(984), false));
        assert!(!is_live(now, t(0), false));
    }

    #[test]
    fn sessions_revoked_is_never_live() {
        assert!(!is_live(t(1000), t(1000), true));
    }

    #[test]
    fn sessions_future_last_seen_counts_as_live() {
        assert!(is_live(t(1000), t(1003), false));
    }

    #[test]
    fn sessions_report_rejects_unknown_fields_and_kinds() {
        let ok = r#"{"event":"open","agent_id":"0192f0a0-0000-7000-8000-0000000000a1","token_jti":"0192f0a0-0000-7000-8000-0000000000b1","kind":"pg","slug":"x"}"#;
        assert!(serde_json::from_str::<SessionReport>(ok).is_ok());
        for bad in [
            r#"{"event":"open","agent_id":"0192f0a0-0000-7000-8000-0000000000a1","token_jti":"0192f0a0-0000-7000-8000-0000000000b1","kind":"ssh","slug":"x"}"#,
            r#"{"event":"heartbeat","session_id":"0192f0a0-0000-7000-8000-0000000000a1","address":"10.0.0.1"}"#,
            r#"{"event":"nope"}"#,
        ] {
            assert!(serde_json::from_str::<SessionReport>(bad).is_err(), "{bad}");
        }
    }
}
