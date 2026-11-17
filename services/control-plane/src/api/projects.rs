//! Projects: create, get, list, patch, delete.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::extract::{ApiJson, ApiPath, ApiQuery};
use super::{
    Page, PageParams, Paged, Patch, common_cols, created, validate_description, validate_name,
};
use crate::app::AppState;
use crate::auth::OrgBinding;
use crate::db::sql::{self, Row};
use crate::problem::ApiError;

#[derive(Debug, Serialize)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
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
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

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
                row.as_ref()
                    .map(from_row)
                    .transpose()
                    .map_err(ApiError::from)
            })
        })
        .await?;
    row.map(Json).ok_or_else(ApiError::not_found)
}

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
                rows.iter()
                    .map(from_row)
                    .collect::<sql::Result<Vec<_>>>()
                    .map_err(ApiError::from)
            })
        })
        .await?;
    Ok(Json(Paged::new(rows, page, |p| p.id)))
}

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
                row.as_ref()
                    .map(from_row)
                    .transpose()
                    .map_err(ApiError::from)
            })
        })
        .await?;
    row.map(Json).ok_or_else(ApiError::not_found)
}

/// Deleting a project with environments (or secrets) is `409`: parents are RESTRICT-deleted.
pub async fn delete(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(project_id): ApiPath<Uuid>,
) -> Result<StatusCode, ApiError> {
    let deleted = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let n = sql::query("DELETE FROM projects WHERE id = $1")
                    .bind(project_id)
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
