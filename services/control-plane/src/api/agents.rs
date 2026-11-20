//! Agents, their relay grants, agent tokens and the signing JWKS (S4 design decisions 1, 2, 4).
//!
//! - `POST /v1/agents` registers an agent and returns its enrollment secret once; only the
//!   Argon2id hash is stored. `POST /v1/agents/{id}/enrollment-secret` replaces it (the old one
//!   stops working) and returns the new one once. No other response carries it.
//! - `POST /v1/agents/{id}/grants` grants relay use of one secret, optionally until an expiry.
//! - `POST /v1/agent-tokens` exchanges an enrollment secret for a 15-minute EdDSA JWT with
//!   audience `gateway`. `GET /.well-known/jwks.json` publishes the public key.
//!
//! Registration and grants are org-scoped through [`OrgBinding`] and the tenant helper, like
//! every `/v1` resource. No response carries a secret value.
//!
//! Every successful registration, rotation, delete, grant and revocation appends an event to the
//! org's audit ledger (S5) in the same transaction as the change, so neither commits without the
//! other. Events carry ids, a mode code and an expiry only, never a name, description or secret.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::Instrument;
use utoipa::ToSchema;
use uuid::Uuid;

use super::extract::{ApiJson, ApiPath, ApiQuery, SecretJson};
use super::responses::{
    CreateErrors, DeleteErrors, ListErrors, ReadErrors, TokenErrors, WriteErrors,
};
use super::{
    Page, PageParams, Paged, all, created, deleted_or_404, exists_or_404, one, utc,
    validate_description, validate_name,
};
use crate::agent_token::{AUDIENCE, JwkSet, MintedToken};
use crate::app::AppState;
use crate::audit::{self, DEV_AUTH_ACTOR};
use crate::auth::OrgBinding;
use crate::db::sql::{self, Row};
use crate::enrollment::{EnrollmentInput, EnrollmentSecret};
use crate::problem::{ApiError, Kind};

/// A registered agent. Never carries its enrollment secret or the secret's hash.
#[derive(Debug, Serialize, ToSchema)]
pub struct Agent {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewAgent {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// The response that shows an enrollment secret, once. No `Debug`.
#[derive(Serialize, ToSchema)]
pub struct AgentEnrollment {
    pub agent: Agent,
    /// Exchange at `POST /v1/agent-tokens`. Shown only in this response; only its Argon2id
    /// hash is stored, so it cannot be read back. Not a vault secret.
    #[schema(value_type = String, format = Password, read_only)]
    pub enrollment_secret: EnrollmentSecret,
}

/// How a grant lets the agent use the secret.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum GrantMode {
    /// The gateway injects the secret into an upstream request; the agent never sees it.
    #[default]
    Relay,
    /// The gateway vends short-lived credentials limited by the grant's `scope`. Off unless the
    /// gateway binding also allows it.
    Delegate,
}

/// The allow-list a `delegate` grant carries: what the vended credentials may do.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantScope {
    /// IAM actions, for example `s3:GetObject`.
    #[serde(default)]
    pub actions: Vec<String>,
    /// Resource ARNs the actions apply to.
    #[serde(default)]
    pub resources: Vec<String>,
    /// Upper bound on a credential's lifetime in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_secs: Option<u32>,
}

impl GrantScope {
    /// A scope must name at least one action and one resource, and stay within sane bounds.
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        const MAX_ITEMS: usize = 64;
        const MAX_LEN: usize = 512;
        if self.actions.is_empty() || self.resources.is_empty() {
            return Err("scope needs at least one action and one resource");
        }
        if self.actions.len() > MAX_ITEMS || self.resources.len() > MAX_ITEMS {
            return Err("scope has too many entries");
        }
        let bad = |v: &String| v.is_empty() || v.len() > MAX_LEN || v.chars().any(char::is_control);
        if self.actions.iter().any(bad) || self.resources.iter().any(bad) {
            return Err("scope entries must be non-empty printable strings");
        }
        if matches!(self.max_duration_secs, Some(0)) {
            return Err("max_duration_secs must be positive");
        }
        Ok(())
    }
}

impl GrantMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            GrantMode::Relay => "relay",
            GrantMode::Delegate => "delegate",
        }
    }

    /// The mode as an audit code.
    pub(crate) fn audit_code(self) -> ls_audit::Code {
        match self {
            GrantMode::Relay => ls_audit::Code::new("relay"),
            GrantMode::Delegate => ls_audit::Code::new("delegate"),
        }
    }

    pub(crate) fn parse(s: &str) -> sql::Result<Self> {
        match s {
            "relay" => Ok(GrantMode::Relay),
            "delegate" => Ok(GrantMode::Delegate),
            other => Err(sql::Error::Decode(
                format!("unknown grant mode {other:?}").into(),
            )),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewAgentGrant {
    /// The secret the agent may relay (same org).
    pub secret_id: Uuid,
    /// Defaults to `relay`.
    #[serde(default)]
    pub mode: GrantMode,
    /// Required for `delegate` (the allow-list), and refused for `relay`.
    #[serde(default)]
    pub scope: Option<GrantScope>,
    /// Optional expiry (RFC 3339, in the future). Omit for no expiry.
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub expires_at: Option<OffsetDateTime>,
}

/// A grant: the agent may use the named secret in `mode` until `expires_at`. Names and ids
/// only; never the value.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentGrant {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub secret_id: Uuid,
    pub secret_name: String,
    pub mode: GrantMode,
    /// The allow-list of a `delegate` grant; `null` for `relay`.
    pub scope: Option<GrantScope>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
}

/// Request body of a token exchange. No `Debug`.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentTokenRequest {
    /// The enrollment secret from `POST /v1/agents`.
    #[schema(value_type = String, format = Password, write_only)]
    pub enrollment_secret: EnrollmentInput,
}

/// A minted agent token (RFC 6749 section 5.1 shape). No `Debug`: the token is a bearer
/// credential for the gateway only.
#[derive(Serialize, ToSchema)]
pub struct AgentToken {
    /// EdDSA JWT; claims `sub` (agent id), `org`, `aud` (`gateway`), `iat`, `exp`.
    #[schema(read_only)]
    pub access_token: String,
    /// Always `Bearer`.
    pub token_type: &'static str,
    /// Seconds until expiry (900).
    pub expires_in: u64,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
}

macro_rules! agent_cols {
    () => {
        "id, name, description, created_at, updated_at"
    };
}

/// Grant columns, from `agent_grants g` joined with `secrets s`.
macro_rules! grant_cols {
    () => {
        "g.id, g.agent_id, g.secret_id, s.name AS secret_name, g.mode, g.scope::text AS scope, g.expires_at, g.created_at"
    };
}
pub(crate) use grant_cols;

fn agent_from_row(r: &sql::PgRow) -> sql::Result<Agent> {
    Ok(Agent {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        description: r.try_get("description")?,
        created_at: utc(r, "created_at")?,
        updated_at: utc(r, "updated_at")?,
    })
}

pub(crate) fn optional_utc(row: &sql::PgRow, column: &str) -> sql::Result<Option<OffsetDateTime>> {
    Ok(row
        .try_get::<Option<OffsetDateTime>, _>(column)?
        .map(|t| t.to_offset(time::UtcOffset::UTC)))
}

/// The `scope` column as a [`GrantScope`], `None` for a relay grant.
pub(crate) fn scope_from_row(r: &sql::PgRow) -> sql::Result<Option<GrantScope>> {
    let v: Option<String> = r.try_get("scope")?;
    v.map(|t| serde_json::from_str(&t).map_err(|e| sql::Error::Decode(Box::new(e))))
        .transpose()
}

fn grant_from_row(r: &sql::PgRow) -> sql::Result<AgentGrant> {
    Ok(AgentGrant {
        id: r.try_get("id")?,
        agent_id: r.try_get("agent_id")?,
        secret_id: r.try_get("secret_id")?,
        secret_name: r.try_get("secret_name")?,
        mode: GrantMode::parse(r.try_get::<&str, _>("mode")?)?,
        scope: scope_from_row(r)?,
        expires_at: optional_utc(r, "expires_at")?,
        created_at: utc(r, "created_at")?,
    })
}

/// `Cache-Control: no-store` (RFC 6749 section 5.1): responses carrying a credential must not be
/// cached by any intermediary.
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// A new enrollment secret and its hash, made on a blocking thread (Argon2id is CPU-bound).
async fn new_enrollment(
    org_id: Uuid,
    agent_id: Uuid,
) -> Result<(EnrollmentSecret, String), ApiError> {
    tokio::task::spawn_blocking(move || EnrollmentSecret::generate(org_id, agent_id))
        .await
        .map_err(|_| ApiError::bare(Kind::Internal))?
        .map_err(|_| ApiError::bare(Kind::Internal))
}

#[utoipa::path(
    post,
    path = "/v1/agents",
    operation_id = "create_agent",
    tag = "agents",
    summary = "Register an agent; returns its enrollment secret once",
    request_body = NewAgent,
    responses(
        (status = 201, description = "Created. `enrollment_secret` is shown only here.", body = AgentEnrollment,
            headers(("Location" = String, description = "URL of the new agent"),
                    ("Cache-Control" = String, description = "`no-store`"))),
        CreateErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn create(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiJson(input): ApiJson<NewAgent>,
) -> Result<Response, ApiError> {
    validate_name(&input.name)?;
    validate_description(&input.description)?;
    let agent_id = Uuid::now_v7();
    let (secret, hash) = new_enrollment(org.org_id, agent_id).await?;
    let agent = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let row = sql::query(concat!(
                    "INSERT INTO agents (id, org_id, name, description, enrollment_hash) \
                     VALUES ($1, $2, $3, $4, $5) RETURNING ",
                    agent_cols!()
                ))
                .bind(agent_id)
                .bind(org.org_id)
                .bind(input.name)
                .bind(input.description)
                .bind(hash)
                .fetch_one(&mut *c)
                .await?;
                let agent = agent_from_row(&row)?;
                audit::append(
                    c,
                    org.org_id,
                    &audit::agent_created(DEV_AUTH_ACTOR, agent_id),
                )
                .await?;
                Ok::<_, ApiError>(agent)
            })
        })
        .await?;
    tracing::info!(agent.id = %agent_id, "agent registered");
    Ok(no_store(created(
        format!("/v1/agents/{agent_id}"),
        AgentEnrollment {
            agent,
            enrollment_secret: secret,
        },
    )))
}

#[utoipa::path(
    get,
    path = "/v1/agents",
    operation_id = "list_agents",
    tag = "agents",
    summary = "List agents",
    params(PageParams),
    responses(
        (status = 200, description = "A page of agents", body = Paged<Agent>),
        ListErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiQuery(params): ApiQuery<PageParams>,
) -> Result<Json<Paged<Agent>>, ApiError> {
    let page: Page = params.resolve()?;
    let rows = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let rows = sql::query(concat!(
                    "SELECT ",
                    agent_cols!(),
                    " FROM agents WHERE ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2"
                ))
                .bind(page.after)
                .bind(page.fetch())
                .fetch_all(c)
                .await?;
                all(&rows, agent_from_row)
            })
        })
        .await?;
    Ok(Json(Paged::new(rows, page, |a| a.id)))
}

#[utoipa::path(
    get,
    path = "/v1/agents/{agent_id}",
    operation_id = "get_agent",
    tag = "agents",
    summary = "Get an agent",
    params(("agent_id" = Uuid, Path, description = "Agent id")),
    responses(
        (status = 200, description = "OK", body = Agent),
        ReadErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn get_one(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(agent_id): ApiPath<Uuid>,
) -> Result<Json<Agent>, ApiError> {
    let agent = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let row = sql::query(concat!(
                    "SELECT ",
                    agent_cols!(),
                    " FROM agents WHERE id = $1"
                ))
                .bind(agent_id)
                .fetch_optional(c)
                .await?;
                one(row, agent_from_row)
            })
        })
        .await?;
    Ok(Json(agent))
}

#[utoipa::path(
    delete,
    path = "/v1/agents/{agent_id}",
    operation_id = "delete_agent",
    tag = "agents",
    summary = "Delete an agent and revoke all its grants",
    description = "Tokens already minted stay valid until they expire (at most 15 minutes), but every relay is refused because the agent has no grants.",
    params(("agent_id" = Uuid, Path, description = "Agent id")),
    responses(
        (status = 204, description = "Deleted"),
        DeleteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn delete(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(agent_id): ApiPath<Uuid>,
) -> Result<StatusCode, ApiError> {
    let status = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                // The grants go with the agent (ON DELETE CASCADE); count them for the event.
                let grants: i64 =
                    sql::query_scalar("SELECT count(*) FROM agent_grants WHERE agent_id = $1")
                        .bind(agent_id)
                        .fetch_one(&mut *c)
                        .await?;
                let n = sql::query("DELETE FROM agents WHERE id = $1")
                    .bind(agent_id)
                    .execute(&mut *c)
                    .await?
                    .rows_affected();
                let status = deleted_or_404(n)?;
                audit::append(
                    c,
                    org.org_id,
                    &audit::agent_deleted(DEV_AUTH_ACTOR, agent_id, grants),
                )
                .await?;
                Ok::<_, ApiError>(status)
            })
        })
        .await?;
    tracing::info!(agent.id = %agent_id, "agent deleted");
    Ok(status)
}

#[utoipa::path(
    post,
    path = "/v1/agents/{agent_id}/enrollment-secret",
    operation_id = "rotate_agent_enrollment_secret",
    tag = "agents",
    summary = "Replace an agent's enrollment secret; returns the new one once",
    description = "The previous enrollment secret stops working immediately. Tokens already minted stay valid until they expire.",
    params(("agent_id" = Uuid, Path, description = "Agent id")),
    responses(
        (status = 200, description = "The new enrollment secret, shown only here", body = AgentEnrollment,
            headers(("Cache-Control" = String, description = "`no-store`"))),
        ReadErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn rotate_enrollment(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(agent_id): ApiPath<Uuid>,
) -> Result<Response, ApiError> {
    let (secret, hash) = new_enrollment(org.org_id, agent_id).await?;
    let agent = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let row = sql::query(concat!(
                    "UPDATE agents SET enrollment_hash = $2, updated_at = now() \
                     WHERE id = $1 RETURNING ",
                    agent_cols!()
                ))
                .bind(agent_id)
                .bind(hash)
                .fetch_optional(&mut *c)
                .await?;
                let agent = one(row, agent_from_row)?;
                audit::append(
                    c,
                    org.org_id,
                    &audit::agent_rotated(DEV_AUTH_ACTOR, agent_id),
                )
                .await?;
                Ok::<_, ApiError>(agent)
            })
        })
        .await?;
    tracing::info!(agent.id = %agent_id, "agent enrollment secret rotated");
    Ok(no_store(
        Json(AgentEnrollment {
            agent,
            enrollment_secret: secret,
        })
        .into_response(),
    ))
}

#[utoipa::path(
    post,
    path = "/v1/agents/{agent_id}/grants",
    operation_id = "create_agent_grant",
    tag = "agents",
    summary = "Grant an agent relay use of a secret",
    params(("agent_id" = Uuid, Path, description = "Agent id")),
    request_body = NewAgentGrant,
    responses(
        (status = 201, description = "Created", body = AgentGrant, headers(("Location" = String, description = "URL of the new grant"))),
        WriteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn create_grant(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(agent_id): ApiPath<Uuid>,
    ApiJson(input): ApiJson<NewAgentGrant>,
) -> Result<Response, ApiError> {
    if input
        .expires_at
        .is_some_and(|t| t <= OffsetDateTime::now_utc())
    {
        return Err(ApiError::validation("`expires_at` must be in the future"));
    }
    let scope_json = match (input.mode, input.scope.as_ref()) {
        (GrantMode::Relay, None) => None,
        (GrantMode::Relay, Some(_)) => {
            return Err(ApiError::validation(
                "`scope` is only for `delegate` grants",
            ));
        }
        (GrantMode::Delegate, None) => {
            return Err(ApiError::validation("a `delegate` grant needs a `scope`"));
        }
        (GrantMode::Delegate, Some(scope)) => {
            scope.validate().map_err(ApiError::validation)?;
            Some(
                serde_json::to_string(scope)
                    .map_err(|_| ApiError::validation("invalid `scope`"))?,
            )
        }
    };
    let grant = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                exists_or_404(
                    &mut *c,
                    sql::query_scalar("SELECT 1 FROM agents WHERE id = $1").bind(agent_id),
                )
                .await?;
                exists_or_404(
                    &mut *c,
                    sql::query_scalar("SELECT 1 FROM secrets WHERE id = $1").bind(input.secret_id),
                )
                .await?;
                let row = sql::query(concat!(
                    "WITH g AS (INSERT INTO agent_grants (org_id, agent_id, secret_id, mode, scope, expires_at) \
                     VALUES ($1, $2, $3, $4, $5::text::jsonb, $6) RETURNING *) \
                     SELECT ",
                    grant_cols!(),
                    " FROM g JOIN secrets s ON s.org_id = g.org_id AND s.id = g.secret_id"
                ))
                .bind(org.org_id)
                .bind(agent_id)
                .bind(input.secret_id)
                .bind(input.mode.as_str())
                .bind(scope_json)
                .bind(input.expires_at)
                .fetch_one(&mut *c)
                .await
                .map_err(grant_conflict)?;
                let grant = grant_from_row(&row)?;
                let event = audit::grant_created(
                    DEV_AUTH_ACTOR,
                    grant.id,
                    agent_id,
                    grant.secret_id,
                    grant.mode.audit_code(),
                    grant.expires_at,
                );
                audit::append(c, org.org_id, &event).await?;
                Ok::<_, ApiError>(grant)
            })
        })
        .await?;
    tracing::info!(agent.id = %agent_id, secret.id = %grant.secret_id, grant.id = %grant.id, "agent grant created");
    Ok(created(
        format!("/v1/agents/{agent_id}/grants/{}", grant.id),
        grant,
    ))
}

/// A duplicate grant is a `409` that says so (the generic message speaks of names).
fn grant_conflict(e: sql::Error) -> ApiError {
    let unique = e
        .as_database_error()
        .is_some_and(|d| d.kind() == sqlx_core::error::ErrorKind::UniqueViolation);
    if unique {
        ApiError::new(
            Kind::Conflict,
            "the agent already holds a grant for this secret and mode",
        )
    } else {
        e.into()
    }
}

#[utoipa::path(
    get,
    path = "/v1/agents/{agent_id}/grants",
    operation_id = "list_agent_grants",
    tag = "agents",
    summary = "List an agent's grants (including expired ones)",
    params(("agent_id" = Uuid, Path, description = "Agent id"), PageParams),
    responses(
        (status = 200, description = "A page of grants", body = Paged<AgentGrant>),
        ListErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn list_grants(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(agent_id): ApiPath<Uuid>,
    ApiQuery(params): ApiQuery<PageParams>,
) -> Result<Json<Paged<AgentGrant>>, ApiError> {
    let page: Page = params.resolve()?;
    let rows = state
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
                     WHERE g.agent_id = $1 AND ($2::uuid IS NULL OR g.id > $2) ORDER BY g.id LIMIT $3"
                ))
                .bind(agent_id)
                .bind(page.after)
                .bind(page.fetch())
                .fetch_all(c)
                .await?;
                all(&rows, grant_from_row)
            })
        })
        .await?;
    Ok(Json(Paged::new(rows, page, |g| g.id)))
}

#[utoipa::path(
    delete,
    path = "/v1/agents/{agent_id}/grants/{grant_id}",
    operation_id = "delete_agent_grant",
    tag = "agents",
    summary = "Revoke a grant",
    description = "The gateway caches grants for at most 10 seconds; the revocation takes effect within that window.",
    params(("agent_id" = Uuid, Path, description = "Agent id"), ("grant_id" = Uuid, Path, description = "Grant id")),
    responses(
        (status = 204, description = "Revoked"),
        DeleteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn delete_grant(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath((agent_id, grant_id)): ApiPath<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let status = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let n = sql::query("DELETE FROM agent_grants WHERE id = $1 AND agent_id = $2")
                    .bind(grant_id)
                    .bind(agent_id)
                    .execute(&mut *c)
                    .await?
                    .rows_affected();
                let status = deleted_or_404(n)?;
                audit::append(
                    c,
                    org.org_id,
                    &audit::grant_revoked(DEV_AUTH_ACTOR, grant_id, agent_id),
                )
                .await?;
                Ok::<_, ApiError>(status)
            })
        })
        .await?;
    tracing::info!(agent.id = %agent_id, grant.id = %grant_id, "agent grant revoked");
    Ok(status)
}

#[utoipa::path(
    post,
    path = "/v1/agent-tokens",
    operation_id = "create_agent_token",
    tag = "agents",
    summary = "Exchange an enrollment secret for a short-lived agent token",
    description = "Returns an EdDSA JWT valid for 15 minutes with audience `gateway`, verifiable with the keys at `/.well-known/jwks.json`. Any invalid, unknown or replaced enrollment secret is the same `401`.",
    request_body = AgentTokenRequest,
    responses(
        (status = 200, description = "A token", body = AgentToken,
            headers(("Cache-Control" = String, description = "`no-store`"))),
        TokenErrors,
    ),
)]
pub async fn mint_token(
    State(state): State<AppState>,
    SecretJson(input): SecretJson<AgentTokenRequest>,
) -> Result<Response, ApiError> {
    let span = tracing::info_span!(
        "mint_token",
        agent.id = tracing::field::Empty,
        org.id = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    let minted = mint(&state, input)
        .instrument(span.clone())
        .await
        .inspect_err(|outcome| {
            span.record("outcome", outcome.as_str());
            tracing::info!(parent: &span, outcome = outcome.as_str(), "agent token refused");
        })
        .map_err(Outcome::into_error)?;
    span.record("outcome", "ok");
    tracing::info!(parent: &span, aud = AUDIENCE, "agent token minted");
    Ok(no_store(
        Json(AgentToken {
            access_token: minted.token,
            token_type: "Bearer",
            expires_in: minted.ttl.as_secs(),
            expires_at: minted.expires_at,
        })
        .into_response(),
    ))
}

/// Why a token request was refused. Recorded on the span (never returned in the body): every
/// credential failure is the same `401`.
#[derive(Clone, Copy)]
enum Outcome {
    NoSigningKey,
    Malformed,
    UnknownAgent,
    WrongSecret,
    Database(Kind),
    Internal,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::NoSigningKey => "no_signing_key",
            Outcome::Malformed => "malformed",
            Outcome::UnknownAgent => "unknown_agent",
            Outcome::WrongSecret => "wrong_secret",
            Outcome::Database(_) => "database_error",
            Outcome::Internal => "internal_error",
        }
    }

    fn into_error(self) -> ApiError {
        match self {
            Outcome::NoSigningKey => {
                ApiError::new(Kind::Unavailable, "agent token signing is not configured")
            }
            Outcome::Malformed | Outcome::UnknownAgent | Outcome::WrongSecret => {
                ApiError::unauthenticated()
            }
            Outcome::Database(kind) => ApiError::bare(kind),
            Outcome::Internal => ApiError::bare(Kind::Internal),
        }
    }
}

/// Look the agent up in the org its secret names, verify the secret against the stored hash
/// (an unknown agent costs the same Argon2id work), then sign.
async fn mint(state: &AppState, input: AgentTokenRequest) -> Result<MintedToken, Outcome> {
    let signer = state.agent_signer().ok_or(Outcome::NoSigningKey)?;
    let presented = input.enrollment_secret.parse().ok_or(Outcome::Malformed)?;
    drop(input);
    let (org_id, agent_id) = (presented.org_id, presented.agent_id);
    let span = tracing::Span::current();
    span.record("agent.id", tracing::field::display(agent_id));
    span.record("org.id", tracing::field::display(org_id));

    let hash: Option<String> = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                sql::query_scalar("SELECT enrollment_hash FROM agents WHERE id = $1")
                    .bind(agent_id)
                    .fetch_optional(c)
                    .await
            })
        })
        .await
        .map_err(|e| Outcome::Database(ApiError::from(e).kind))?;
    let found = hash.is_some();
    let verified = tokio::task::spawn_blocking(move || match hash {
        Some(phc) => presented.verify(&phc),
        None => {
            presented.verify_against_dummy();
            false
        }
    })
    .await
    .map_err(|_| Outcome::Internal)?;
    match (found, verified) {
        (_, true) => signer
            .mint(agent_id, org_id, OffsetDateTime::now_utc())
            .map_err(|_| Outcome::Internal),
        (true, false) => Err(Outcome::WrongSecret),
        (false, false) => Err(Outcome::UnknownAgent),
    }
}

#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    operation_id = "get_jwks",
    tag = "agents",
    summary = "Public keys that verify agent tokens (JWKS)",
    description = "Ed25519 public keys (RFC 8037). Verifiers select a key by the token's `kid`. Empty when token signing is not configured.",
    responses(
        (status = 200, description = "The JWK set", body = JwkSet,
            headers(("Cache-Control" = String, description = "`public, max-age=60`"))),
    ),
)]
pub async fn jwks(State(state): State<AppState>) -> Response {
    let keys = state
        .agent_signer()
        .map(|s| vec![s.jwk().clone()])
        .unwrap_or_default();
    let mut response = Json(JwkSet { keys }).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60"),
    );
    response
}
