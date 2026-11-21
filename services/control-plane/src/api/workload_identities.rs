//! Workload identity trust policies (D4 design decisions 3, 4 and 8).
//!
//! A policy links one issuer and a list of claim conditions to one existing agent. These routes
//! manage the policies under human auth, bound to an org like every `/v1` resource. They hold
//! configuration only: no response carries a token or a secret. The exchange route that uses a
//! policy is separate (`POST /v1/workload-tokens`, D4 task 3).
//!
//! Create and delete append an audit event in the same transaction as the change.

use axum::Json;
use axum::extract::State;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::extract::{ApiJson, ApiPath, ApiQuery};
use super::responses::{CreateErrors, DeleteErrors, ListErrors, ReadErrors};
use super::{Page, PageParams, Paged, all, created, deleted_or_404, exists_or_404, one, utc};
use crate::app::AppState;
use crate::audit::{self, DEV_AUTH_ACTOR};
use crate::auth::OrgBinding;
use crate::db::sql::{self, Row};
use crate::problem::{ApiError, Kind, Problem};
use crate::workload::{self, Condition, ConditionInput, IssuerKind, Op};

/// One claim test as shown to callers: `pattern` ends in `*` for a prefix match.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ConditionView {
    pub claim: String,
    /// Exact value, or a prefix ending in one `*`.
    pub pattern: String,
}

/// A trust policy. The `handle` is the non-secret routing value a workload sends to the
/// exchange route.
#[derive(Debug, Serialize, ToSchema)]
pub struct WorkloadIdentity {
    pub id: Uuid,
    pub name: String,
    /// `github` or `oidc`.
    pub issuer_kind: String,
    pub issuer: String,
    pub audience: String,
    pub agent_id: Uuid,
    pub conditions: Vec<ConditionView>,
    /// `lsw_...`: names the org and this policy. Not a secret.
    pub handle: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub last_used_at: Option<OffsetDateTime>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewWorkloadIdentity {
    pub name: String,
    /// `github` (the GitHub Actions issuer) or `oidc` (an explicit https issuer, e.g. a
    /// Kubernetes cluster).
    pub issuer_kind: String,
    /// Required for `oidc`; for `github` omit it or give the GitHub Actions issuer.
    #[serde(default)]
    pub issuer: Option<String>,
    /// The `aud` the external token must carry.
    pub audience: String,
    /// The existing agent whose token the workload receives (same org).
    pub agent_id: Uuid,
    /// ANDed. A value is exact, or ends in one `*` for a prefix. At least one condition must
    /// pin the subject: `repository` or `sub` for `github`, `sub` for `oidc`.
    pub conditions: Vec<ConditionView>,
}

macro_rules! cols {
    () => {
        "id, org_id, name, issuer_kind, issuer, audience, agent_id, \
         conditions::text AS conditions, created_at, last_used_at"
    };
}

fn view(r: &sql::PgRow) -> sql::Result<WorkloadIdentity> {
    let id: Uuid = r.try_get("id")?;
    let org_id: Uuid = r.try_get("org_id")?;
    let stored: Vec<Condition> = serde_json::from_str(r.try_get::<&str, _>("conditions")?)
        .map_err(|e| sql::Error::Decode(e.into()))?;
    let conditions = stored
        .into_iter()
        .map(|c| ConditionView {
            pattern: match c.op {
                Op::Eq => c.value,
                Op::Prefix => format!("{}*", c.value),
            },
            claim: c.claim,
        })
        .collect();
    Ok(WorkloadIdentity {
        id,
        name: r.try_get("name")?,
        issuer_kind: r.try_get("issuer_kind")?,
        issuer: r.try_get("issuer")?,
        audience: r.try_get("audience")?,
        agent_id: r.try_get("agent_id")?,
        conditions,
        handle: workload::encode_handle(org_id, id),
        created_at: utc(r, "created_at")?,
        last_used_at: super::agents::optional_utc(r, "last_used_at")?,
    })
}

fn name_conflict(e: sql::Error) -> ApiError {
    let unique = e
        .as_database_error()
        .is_some_and(|d| d.kind() == sqlx_core::error::ErrorKind::UniqueViolation);
    if unique {
        ApiError::new(Kind::Conflict, "a workload identity with this name exists")
    } else {
        e.into()
    }
}

#[utoipa::path(
    post,
    path = "/v1/workload-identities",
    operation_id = "create_workload_identity",
    tag = "workload-identities",
    summary = "Create a workload identity trust policy",
    description = "Maps an issuer and claim conditions to an existing agent. A policy with no subject pin, or a bare `*`, is refused.",
    request_body = NewWorkloadIdentity,
    responses(
        (status = 201, description = "Created", body = WorkloadIdentity,
            headers(("Location" = String, description = "URL of the new policy"))),
        (status = 422, description = "Policy refused: no subject pin, a bare `*`, or an issuer at a private address",
            body = Problem, content_type = "application/problem+json"),
        CreateErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn create(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiJson(input): ApiJson<NewWorkloadIdentity>,
) -> Result<Response, ApiError> {
    super::validate_name(&input.name)?;
    let kind = IssuerKind::parse(&input.issuer_kind)
        .ok_or_else(|| ApiError::validation("issuer_kind must be `github` or `oidc`"))?;
    let inputs: Vec<ConditionInput> = input
        .conditions
        .into_iter()
        .map(|c| ConditionInput {
            claim: c.claim,
            value: c.pattern,
        })
        .collect();
    let policy = workload::validate(
        &input.name,
        kind,
        input.issuer.as_deref(),
        &input.audience,
        &inputs,
    )
    .map_err(|e| ApiError::unprocessable(e.detail()))?;
    // A private or metadata issuer address is refused at create time (the exchange also refuses
    // it). Makes no HTTP request.
    if let Some(verifier) = state.workload_verifier() {
        verifier
            .issuers()
            .check_issuer_host(&policy.issuer)
            .await
            .map_err(|_| ApiError::unprocessable("the issuer host is not an allowed address"))?;
    }
    let stored =
        serde_json::to_string(&policy.conditions).map_err(|_| ApiError::bare(Kind::Internal))?;
    let (name, agent_id, id) = (input.name, input.agent_id, Uuid::now_v7());
    let created_row = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                exists_or_404(
                    &mut *c,
                    sql::query_scalar("SELECT 1 FROM agents WHERE id = $1").bind(agent_id),
                )
                .await?;
                let row = sql::query(concat!(
                    "INSERT INTO workload_identities \
                     (id, org_id, name, issuer_kind, issuer, audience, agent_id, conditions) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb) RETURNING ",
                    cols!()
                ))
                .bind(id)
                .bind(org.org_id)
                .bind(name.trim())
                .bind(policy.issuer_kind.as_str())
                .bind(&policy.issuer)
                .bind(&policy.audience)
                .bind(agent_id)
                .bind(stored)
                .fetch_one(&mut *c)
                .await
                .map_err(name_conflict)?;
                let out = view(&row)?;
                audit::append(
                    c,
                    org.org_id,
                    &audit::workload_identity_created(DEV_AUTH_ACTOR, id, agent_id, &policy.issuer),
                )
                .await?;
                Ok::<_, ApiError>(out)
            })
        })
        .await?;
    tracing::info!(policy.id = %id, agent.id = %agent_id, "workload identity created");
    Ok(created(
        format!("/v1/workload-identities/{id}"),
        created_row,
    ))
}

#[utoipa::path(
    get,
    path = "/v1/workload-identities",
    operation_id = "list_workload_identities",
    tag = "workload-identities",
    summary = "List workload identity trust policies",
    params(PageParams),
    responses(
        (status = 200, description = "A page of policies", body = Paged<WorkloadIdentity>),
        ListErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiQuery(params): ApiQuery<PageParams>,
) -> Result<Json<Paged<WorkloadIdentity>>, ApiError> {
    let page: Page = params.resolve()?;
    let rows = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let rows = sql::query(concat!(
                    "SELECT ",
                    cols!(),
                    " FROM workload_identities \
                     WHERE ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2"
                ))
                .bind(page.after)
                .bind(page.fetch())
                .fetch_all(c)
                .await?;
                all(&rows, view)
            })
        })
        .await?;
    Ok(Json(Paged::new(rows, page, |p| p.id)))
}

#[utoipa::path(
    get,
    path = "/v1/workload-identities/{id}",
    operation_id = "get_workload_identity",
    tag = "workload-identities",
    summary = "Get a workload identity trust policy",
    params(("id" = Uuid, Path, description = "Policy id")),
    responses(
        (status = 200, description = "OK", body = WorkloadIdentity),
        ReadErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn get_one(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<WorkloadIdentity>, ApiError> {
    let out = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let row = sql::query(concat!(
                    "SELECT ",
                    cols!(),
                    " FROM workload_identities WHERE id = $1"
                ))
                .bind(id)
                .fetch_optional(c)
                .await?;
                one(row, view)
            })
        })
        .await?;
    Ok(Json(out))
}

#[utoipa::path(
    delete,
    path = "/v1/workload-identities/{id}",
    operation_id = "delete_workload_identity",
    tag = "workload-identities",
    summary = "Delete a workload identity trust policy",
    description = "Exchanges for this policy fail from now on. Agent tokens already minted stay valid until they expire (at most 15 minutes).",
    params(("id" = Uuid, Path, description = "Policy id")),
    responses(
        (status = 204, description = "Deleted"),
        DeleteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn delete(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<axum::http::StatusCode, ApiError> {
    let status = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let row =
                    sql::query("DELETE FROM workload_identities WHERE id = $1 RETURNING agent_id")
                        .bind(id)
                        .fetch_optional(&mut *c)
                        .await?;
                let agent_id: Uuid = match row {
                    Some(r) => r.try_get("agent_id")?,
                    None => return Err(ApiError::not_found()),
                };
                let status = deleted_or_404(1)?;
                audit::append(
                    c,
                    org.org_id,
                    &audit::workload_identity_deleted(DEV_AUTH_ACTOR, id, agent_id),
                )
                .await?;
                Ok::<_, ApiError>(status)
            })
        })
        .await?;
    tracing::info!(policy.id = %id, "workload identity deleted");
    Ok(status)
}
