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
//! The behaviour lands in tasks 2.1 (list) and 2.2 (revoke, pause). Until then every handler
//! answers `501` with a problem body rather than an empty or fake success, and the OpenAPI
//! description of each route says so.

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::extract::{ApiPath, ApiQuery};
use super::responses::{ListErrors, WriteErrors};
use super::{PageParams, Paged};
use crate::app::AppState;
use crate::auth::OrgBinding;
use crate::problem::{ApiError, Problem};

/// Which gateway path a session came in on.
// Constructed by the list handler in task 2.1; until then only the OpenAPI schema uses it.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SessionKind {
    /// An HTTP relay session.
    Http,
    /// A Postgres relay session.
    Pg,
    /// A remote MCP session.
    Mcp,
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

/// The `501` every handler returns until tasks 2.1 and 2.2.
const NOT_IMPLEMENTED_DESC: &str = "Not implemented yet: the route is part of the contract and answers `501` until the control-plane behaviour lands (t8 tasks 2.1 and 2.2).";

#[utoipa::path(
    get,
    path = "/v1/sessions",
    operation_id = "list_agent_sessions",
    tag = "sessions",
    summary = "List the org's live agent sessions",
    description = "Agent id, kind, binding slug, start and last-seen times, and whether the session is live (reported within 15 seconds and not revoked). No token, address or secret value is ever returned. Not implemented yet: answers `501` until t8 task 2.1.",
    params(PageParams),
    responses(
        (status = 200, description = "A page of sessions", body = Paged<AgentSession>),
        (status = 501, description = NOT_IMPLEMENTED_DESC, body = Problem, content_type = "application/problem+json"),
        ListErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn list(
    State(_state): State<AppState>,
    _org: OrgBinding,
    ApiQuery(_params): ApiQuery<PageParams>,
) -> Result<Json<Paged<AgentSession>>, ApiError> {
    Err(ApiError::not_implemented())
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
