//! Projects: create, get, list, patch, delete.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::extract::{ApiJson, ApiPath, ApiQuery};
use super::responses::{CreateErrors, DeleteErrors, ListErrors, ReadErrors, WriteErrors};
use super::{
    Page, PageParams, Paged, Patch, all, common_cols, created, deleted_or_404, one, utc,
    validate_description, validate_name,
};
use crate::app::AppState;
use crate::auth::OrgBinding;
use crate::db::sql::{self, Row};
use crate::problem::ApiError;

#[derive(Debug, Serialize, ToSchema)]
pub struct Project {
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
pub struct NewProject {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

pub(super) fn from_row(r: &sql::PgRow) -> sql::Result<Project> {
    Ok(Project {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        description: r.try_get("description")?,
        created_at: utc(r, "created_at")?,
        updated_at: utc(r, "updated_at")?,
    })
}

#[utoipa::path(
    post,
    path = "/v1/projects",
    operation_id = "create_project",
    tag = "projects",
    summary = "Create a project",
    request_body = NewProject,
    responses(
        (status = 201, description = "Created", body = Project, headers(("Location" = String, description = "URL of the new resource"))),
        CreateErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn create(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiJson(input): ApiJson<NewProject>,
) -> Result<Response, ApiError> {
    validate_name(&input.name)?;
    validate_description(&input.description)?;
    let project = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let row = sql::query(concat!(
                    "INSERT INTO projects (org_id, name, description) VALUES ($1, $2, $3) RETURNING ",
                    common_cols!()
                ))
                .bind(org.org_id)
                .bind(input.name)
                .bind(input.description)
                .fetch_one(c)
                .await?;
                Ok::<_, ApiError>(from_row(&row)?)
            })
        })
        .await?;
    Ok(created(format!("/v1/projects/{}", project.id), project))
}

#[utoipa::path(
    get,
    path = "/v1/projects/{project_id}",
    operation_id = "get_project",
    tag = "projects",
    summary = "Get a project",
    params(("project_id" = Uuid, Path, description = "Project id")),
    responses(
        (status = 200, description = "OK", body = Project),
        ReadErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn get_one(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(project_id): ApiPath<Uuid>,
) -> Result<Json<Project>, ApiError> {
    let row = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let row = sql::query(concat!(
                    "SELECT ",
                    common_cols!(),
                    " FROM projects WHERE id = $1"
                ))
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
    path = "/v1/projects",
    operation_id = "list_projects",
    tag = "projects",
    summary = "List projects",
    params(PageParams),
    responses(
        (status = 200, description = "A page of projects", body = Paged<Project>),
        ListErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiQuery(params): ApiQuery<PageParams>,
) -> Result<Json<Paged<Project>>, ApiError> {
    let page: Page = params.resolve()?;
    let rows = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let rows = sql::query(concat!(
                    "SELECT ",
                    common_cols!(),
                    " FROM projects WHERE ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2"
                ))
                .bind(page.after)
                .bind(page.fetch())
                .fetch_all(c)
                .await?;
                all(&rows, from_row)
            })
        })
        .await?;
    Ok(Json(Paged::new(rows, page, |p| p.id)))
}

#[utoipa::path(
    patch,
    path = "/v1/projects/{project_id}",
    operation_id = "update_project",
    tag = "projects",
    summary = "Update a project",
    params(("project_id" = Uuid, Path, description = "Project id")),
    request_body = Patch,
    responses(
        (status = 200, description = "OK", body = Project),
        WriteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn patch(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(project_id): ApiPath<Uuid>,
    ApiJson(input): ApiJson<Patch>,
) -> Result<Json<Project>, ApiError> {
    input.validate()?;
    let row = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let row = sql::query(concat!(
                    "UPDATE projects SET name = COALESCE($2, name), \
                     description = COALESCE($3, description), updated_at = now() \
                     WHERE id = $1 RETURNING ",
                    common_cols!()
                ))
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

/// Deleting a project with environments (or secrets) is `409`: parents are RESTRICT-deleted.
#[utoipa::path(
    delete,
    path = "/v1/projects/{project_id}",
    operation_id = "delete_project",
    tag = "projects",
    summary = "Delete a project",
    params(("project_id" = Uuid, Path, description = "Project id")),
    responses(
        (status = 204, description = "Deleted"),
        DeleteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn delete(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(project_id): ApiPath<Uuid>,
) -> Result<StatusCode, ApiError> {
    let status = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let n = sql::query("DELETE FROM projects WHERE id = $1")
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
