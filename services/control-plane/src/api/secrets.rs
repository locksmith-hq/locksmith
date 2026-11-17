//! Secret metadata under a project and environment. There is no value field anywhere: input
//! types reject unknown fields, so a `value` is a `400` and nothing is stored.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::extract::{ApiJson, ApiPath, ApiQuery};
use super::{
    Page, PageParams, Paged, Patch, common_cols, created, validate_description, validate_name,
};
use crate::app::AppState;
use crate::auth::OrgBinding;
use crate::db::sql::{self, PgConnection, Row};
use crate::problem::{ApiError, Problem};

#[derive(Debug, Serialize, ToSchema)]
pub struct Secret {
    pub id: Uuid,
    pub project_id: Uuid,
    pub environment_id: Uuid,
    pub name: String,
    pub description: String,
    /// Always 0 in S1; S2 adds versions.
    pub version_count: u32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewSecret {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

fn from_row(r: &sql::PgRow) -> sql::Result<Secret> {
    Ok(Secret {
        id: r.try_get("id")?,
        project_id: r.try_get("project_id")?,
        environment_id: r.try_get("environment_id")?,
        name: r.try_get("name")?,
        description: r.try_get("description")?,
        version_count: 0,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

/// `404` unless the environment exists in the project for the bound org.
async fn require_environment(
    c: &mut PgConnection,
    project_id: Uuid,
    environment_id: Uuid,
) -> Result<(), ApiError> {
    let found: Option<i32> =
        sql::query_scalar("SELECT 1 FROM environments WHERE id = $1 AND project_id = $2")
            .bind(environment_id)
            .bind(project_id)
            .fetch_optional(c)
            .await?;
    found.map(|_| ()).ok_or_else(ApiError::not_found)
}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_id}/environments/{environment_id}/secrets",
    tag = "secrets",
    summary = "Create a secret (metadata only, never a value)",
    params(("project_id" = Uuid, Path, description = "Project id"), ("environment_id" = Uuid, Path, description = "Environment id")),
    request_body = NewSecret,
    responses(
        (status = 201, description = "Created", body = Secret, headers(("Location" = String, description = "URL of the new resource"))),
        (status = 400, description = "Invalid request", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or invalid org binding", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Not found", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Conflict", body = Problem, content_type = "application/problem+json"),
        (status = 503, description = "Service unavailable", body = Problem, content_type = "application/problem+json"),
    ),
    security(("dev_org" = []))
)]
pub async fn create(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath((project_id, environment_id)): ApiPath<(Uuid, Uuid)>,
    ApiJson(input): ApiJson<NewSecret>,
) -> Result<Response, ApiError> {
    validate_name(&input.name)?;
    validate_description(&input.description)?;
    let secret = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                require_environment(c, project_id, environment_id).await?;
                let row = sql::query(concat!(
                    "INSERT INTO secrets (org_id, project_id, environment_id, name, description) \
                     VALUES ($1, $2, $3, $4, $5) RETURNING project_id, environment_id, ",
                    common_cols!()
                ))
                .bind(org.org_id)
                .bind(project_id)
                .bind(environment_id)
                .bind(input.name)
                .bind(input.description)
                .fetch_one(c)
                .await?;
                Ok::<_, ApiError>(from_row(&row)?)
            })
        })
        .await?;
    Ok(created(
        format!(
            "/v1/projects/{project_id}/environments/{environment_id}/secrets/{}",
            secret.id
        ),
        secret,
    ))
}

#[utoipa::path(
    get,
    path = "/v1/projects/{project_id}/environments/{environment_id}/secrets/{secret_id}",
    tag = "secrets",
    summary = "Get secret metadata",
    params(("project_id" = Uuid, Path, description = "Project id"), ("environment_id" = Uuid, Path, description = "Environment id"), ("secret_id" = Uuid, Path, description = "Secret id")),
    responses(
        (status = 200, description = "OK", body = Secret),
        (status = 401, description = "Missing or invalid org binding", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Not found", body = Problem, content_type = "application/problem+json"),
        (status = 503, description = "Service unavailable", body = Problem, content_type = "application/problem+json"),
    ),
    security(("dev_org" = []))
)]
pub async fn get_one(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath((project_id, environment_id, secret_id)): ApiPath<(Uuid, Uuid, Uuid)>,
) -> Result<Json<Secret>, ApiError> {
    let row = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let row = sql::query(concat!(
                    "SELECT project_id, environment_id, ",
                    common_cols!(),
                    " FROM secrets WHERE id = $1 AND project_id = $2 AND environment_id = $3"
                ))
                .bind(secret_id)
                .bind(project_id)
                .bind(environment_id)
                .fetch_optional(c)
                .await?;
                row.as_ref()
                    .map(from_row)
                    .transpose()
                    .map_err(ApiError::from)
            })
        })
        .await?;
    row.map(Json).ok_or_else(ApiError::not_found)
}

#[utoipa::path(
    get,
    path = "/v1/projects/{project_id}/environments/{environment_id}/secrets",
    tag = "secrets",
    summary = "List secrets",
    params(("project_id" = Uuid, Path, description = "Project id"), ("environment_id" = Uuid, Path, description = "Environment id"), PageParams),
    responses(
        (status = 200, description = "A page of secrets", body = Paged<Secret>),
        (status = 400, description = "Invalid request", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or invalid org binding", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Not found", body = Problem, content_type = "application/problem+json"),
        (status = 503, description = "Service unavailable", body = Problem, content_type = "application/problem+json"),
    ),
    security(("dev_org" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath((project_id, environment_id)): ApiPath<(Uuid, Uuid)>,
    ApiQuery(params): ApiQuery<PageParams>,
) -> Result<Json<Paged<Secret>>, ApiError> {
    let page: Page = params.resolve()?;
    let rows = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                require_environment(c, project_id, environment_id).await?;
                let rows = sql::query(concat!(
                    "SELECT project_id, environment_id, ",
                    common_cols!(),
                    " FROM secrets WHERE project_id = $1 AND environment_id = $2 \
                     AND ($3::uuid IS NULL OR id > $3) ORDER BY id LIMIT $4"
                ))
                .bind(project_id)
                .bind(environment_id)
                .bind(page.after)
                .bind(page.fetch())
                .fetch_all(c)
                .await?;
                rows.iter()
                    .map(from_row)
                    .collect::<sql::Result<Vec<_>>>()
                    .map_err(ApiError::from)
            })
        })
        .await?;
    Ok(Json(Paged::new(rows, page, |s| s.id)))
}

#[utoipa::path(
    patch,
    path = "/v1/projects/{project_id}/environments/{environment_id}/secrets/{secret_id}",
    tag = "secrets",
    summary = "Update secret metadata",
    params(("project_id" = Uuid, Path, description = "Project id"), ("environment_id" = Uuid, Path, description = "Environment id"), ("secret_id" = Uuid, Path, description = "Secret id")),
    request_body = Patch,
    responses(
        (status = 200, description = "OK", body = Secret),
        (status = 400, description = "Invalid request", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Missing or invalid org binding", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Not found", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Conflict", body = Problem, content_type = "application/problem+json"),
        (status = 503, description = "Service unavailable", body = Problem, content_type = "application/problem+json"),
    ),
    security(("dev_org" = []))
)]
pub async fn patch(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath((project_id, environment_id, secret_id)): ApiPath<(Uuid, Uuid, Uuid)>,
    ApiJson(input): ApiJson<Patch>,
) -> Result<Json<Secret>, ApiError> {
    input.validate()?;
    let row = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let row = sql::query(concat!(
                    "UPDATE secrets SET name = COALESCE($4, name), \
                     description = COALESCE($5, description), updated_at = now() \
                     WHERE id = $1 AND project_id = $2 AND environment_id = $3 \
                     RETURNING project_id, environment_id, ",
                    common_cols!()
                ))
                .bind(secret_id)
                .bind(project_id)
                .bind(environment_id)
                .bind(input.name)
                .bind(input.description)
                .fetch_optional(c)
                .await?;
                row.as_ref()
                    .map(from_row)
                    .transpose()
                    .map_err(ApiError::from)
            })
        })
        .await?;
    row.map(Json).ok_or_else(ApiError::not_found)
}

#[utoipa::path(
    delete,
    path = "/v1/projects/{project_id}/environments/{environment_id}/secrets/{secret_id}",
    tag = "secrets",
    summary = "Delete a secret",
    params(("project_id" = Uuid, Path, description = "Project id"), ("environment_id" = Uuid, Path, description = "Environment id"), ("secret_id" = Uuid, Path, description = "Secret id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid org binding", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Not found", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Conflict", body = Problem, content_type = "application/problem+json"),
        (status = 503, description = "Service unavailable", body = Problem, content_type = "application/problem+json"),
    ),
    security(("dev_org" = []))
)]
pub async fn delete(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath((project_id, environment_id, secret_id)): ApiPath<(Uuid, Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let deleted = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let n = sql::query(
                    "DELETE FROM secrets WHERE id = $1 AND project_id = $2 AND environment_id = $3",
                )
                .bind(secret_id)
                .bind(project_id)
                .bind(environment_id)
                .execute(c)
                .await?
                .rows_affected();
                Ok::<_, ApiError>(n > 0)
            })
        })
        .await?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found())
    }
}
