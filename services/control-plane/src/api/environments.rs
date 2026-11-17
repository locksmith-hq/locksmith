//! Environments under a project: create, get, list, patch, delete.

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
use crate::db::sql::{self, PgConnection, Row};
use crate::problem::ApiError;

#[derive(Debug, Serialize)]
pub struct Environment {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
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
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

/// `404` unless the project exists for the bound org (row-level security hides other orgs').
pub(super) async fn require_project(
    c: &mut PgConnection,
    project_id: Uuid,
) -> Result<(), ApiError> {
    let found: Option<i32> = sql::query_scalar("SELECT 1 FROM projects WHERE id = $1")
        .bind(project_id)
        .fetch_optional(c)
        .await?;
    found.map(|_| ()).ok_or_else(ApiError::not_found)
}

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
                require_project(c, project_id).await?;
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
    ApiPath(project_id): ApiPath<Uuid>,
    ApiQuery(params): ApiQuery<PageParams>,
) -> Result<Json<Paged<Environment>>, ApiError> {
    let page: Page = params.resolve()?;
    let rows = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                require_project(c, project_id).await?;
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
                rows.iter()
                    .map(from_row)
                    .collect::<sql::Result<Vec<_>>>()
                    .map_err(ApiError::from)
            })
        })
        .await?;
    Ok(Json(Paged::new(rows, page, |e| e.id)))
}

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
                row.as_ref()
                    .map(from_row)
                    .transpose()
                    .map_err(ApiError::from)
            })
        })
        .await?;
    row.map(Json).ok_or_else(ApiError::not_found)
}

/// `409` while the environment still has secrets (RESTRICT).
pub async fn delete(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath((project_id, environment_id)): ApiPath<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let deleted = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let n = sql::query("DELETE FROM environments WHERE id = $1 AND project_id = $2")
                    .bind(environment_id)
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
