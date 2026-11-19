//! Environments under a project: create, get, list, patch, delete.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::extract::{ApiJson, ApiPath, ApiQuery};
use super::responses::{DeleteErrors, ListErrors, ReadErrors, WriteErrors};
use super::{
    Page, PageParams, Paged, Patch, all, common_cols, created, deleted_or_404, exists_or_404, one,
    utc, validate_description, validate_name,
};
use crate::app::AppState;
use crate::auth::OrgBinding;
use crate::db::sql::{self, Row};
use crate::problem::ApiError;

#[derive(Debug, Serialize, ToSchema)]
pub struct Environment {
    pub id: Uuid,
    pub project_id: Uuid,
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
pub struct NewEnvironment {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

fn from_row(r: &sql::PgRow) -> sql::Result<Environment> {
    Ok(Environment {
        id: r.try_get("id")?,
        project_id: r.try_get("project_id")?,
        name: r.try_get("name")?,
        description: r.try_get("description")?,
        created_at: utc(r, "created_at")?,
        updated_at: utc(r, "updated_at")?,
    })
}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_id}/environments",
    operation_id = "create_environment",
    tag = "environments",
    summary = "Create an environment",
    params(("project_id" = Uuid, Path, description = "Project id")),
    request_body = NewEnvironment,
    responses(
        (status = 201, description = "Created", body = Environment, headers(("Location" = String, description = "URL of the new resource"))),
        WriteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn create(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(project_id): ApiPath<Uuid>,
    ApiJson(input): ApiJson<NewEnvironment>,
) -> Result<Response, ApiError> {
    validate_name(&input.name)?;
    validate_description(&input.description)?;
    let env = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                exists_or_404(
                    c,
                    sql::query_scalar("SELECT 1 FROM projects WHERE id = $1").bind(project_id),
                )
                .await?;
                let row = sql::query(concat!(
                    "INSERT INTO environments (org_id, project_id, name, description) \
                     VALUES ($1, $2, $3, $4) RETURNING project_id, ",
                    common_cols!()
                ))
                .bind(org.org_id)
                .bind(project_id)
                .bind(input.name)
                .bind(input.description)
                .fetch_one(c)
                .await?;
                Ok::<_, ApiError>(from_row(&row)?)
            })
        })
        .await?;
    Ok(created(
        format!("/v1/projects/{project_id}/environments/{}", env.id),
        env,
    ))
}

#[utoipa::path(
    get,
    path = "/v1/projects/{project_id}/environments/{environment_id}",
    operation_id = "get_environment",
    tag = "environments",
    summary = "Get an environment",
    params(("project_id" = Uuid, Path, description = "Project id"), ("environment_id" = Uuid, Path, description = "Environment id")),
    responses(
        (status = 200, description = "OK", body = Environment),
        ReadErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn get_one(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath((project_id, environment_id)): ApiPath<(Uuid, Uuid)>,
) -> Result<Json<Environment>, ApiError> {
    let row = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let row = sql::query(concat!(
                    "SELECT project_id, ",
                    common_cols!(),
                    " FROM environments WHERE id = $1 AND project_id = $2"
                ))
                .bind(environment_id)
                .bind(project_id)
                .fetch_optional(c)
                .await?;
                one(row, from_row)
            })
        })
        .await?;
    Ok(Json(row))
}

#[utoipa::path(
    get,
    path = "/v1/projects/{project_id}/environments",
    operation_id = "list_environments",
    tag = "environments",
    summary = "List environments",
    params(("project_id" = Uuid, Path, description = "Project id"), PageParams),
    responses(
        (status = 200, description = "A page of environments", body = Paged<Environment>),
        ListErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(project_id): ApiPath<Uuid>,
    ApiQuery(params): ApiQuery<PageParams>,
) -> Result<Json<Paged<Environment>>, ApiError> {
    let page: Page = params.resolve()?;
    let rows = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                exists_or_404(
                    c,
                    sql::query_scalar("SELECT 1 FROM projects WHERE id = $1").bind(project_id),
                )
                .await?;
                let rows = sql::query(concat!(
                    "SELECT project_id, ",
                    common_cols!(),
                    " FROM environments WHERE project_id = $1 AND ($2::uuid IS NULL OR id > $2) \
                     ORDER BY id LIMIT $3"
                ))
                .bind(project_id)
                .bind(page.after)
                .bind(page.fetch())
                .fetch_all(c)
                .await?;
                all(&rows, from_row)
            })
        })
        .await?;
    Ok(Json(Paged::new(rows, page, |e| e.id)))
}

#[utoipa::path(
    patch,
    path = "/v1/projects/{project_id}/environments/{environment_id}",
    operation_id = "update_environment",
    tag = "environments",
    summary = "Update an environment",
    params(("project_id" = Uuid, Path, description = "Project id"), ("environment_id" = Uuid, Path, description = "Environment id")),
    request_body = Patch,
    responses(
        (status = 200, description = "OK", body = Environment),
        WriteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn patch(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath((project_id, environment_id)): ApiPath<(Uuid, Uuid)>,
    ApiJson(input): ApiJson<Patch>,
) -> Result<Json<Environment>, ApiError> {
    input.validate()?;
    let row = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let row = sql::query(concat!(
                    "UPDATE environments SET name = COALESCE($3, name), \
                     description = COALESCE($4, description), updated_at = now() \
                     WHERE id = $1 AND project_id = $2 RETURNING project_id, ",
                    common_cols!()
                ))
                .bind(environment_id)
                .bind(project_id)
                .bind(input.name)
                .bind(input.description)
                .fetch_optional(c)
                .await?;
                one(row, from_row)
            })
        })
        .await?;
    Ok(Json(row))
}

/// `409` while the environment still has secrets (RESTRICT).
#[utoipa::path(
    delete,
    path = "/v1/projects/{project_id}/environments/{environment_id}",
    operation_id = "delete_environment",
    tag = "environments",
    summary = "Delete an environment",
    params(("project_id" = Uuid, Path, description = "Project id"), ("environment_id" = Uuid, Path, description = "Environment id")),
    responses(
        (status = 204, description = "Deleted"),
        DeleteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn delete(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath((project_id, environment_id)): ApiPath<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let status = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let n = sql::query("DELETE FROM environments WHERE id = $1 AND project_id = $2")
                    .bind(environment_id)
                    .bind(project_id)
                    .execute(c)
                    .await?
                    .rows_affected();
                deleted_or_404(n)
            })
        })
        .await?;
    Ok(status)
}
