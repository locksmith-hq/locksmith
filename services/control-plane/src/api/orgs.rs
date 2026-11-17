//! Orgs: dev-only create, and get of the bound org.

use axum::Json;
use axum::extract::State;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::extract::{ApiJson, ApiPath};
use super::{created, validate_name};
use crate::app::AppState;
use crate::auth::OrgBinding;
use crate::db::sql::{self, Row};
use crate::problem::ApiError;

#[derive(Debug, Serialize)]
pub struct Org {
    pub id: Uuid,
    pub name: String,
    pub region: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewOrg {
    pub name: String,
}

macro_rules! cols {
    () => {
        "id, name, region, \
    to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, \
    to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at"
    };
}

fn from_row(r: &sql::PgRow) -> sql::Result<Org> {
    Ok(Org {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        region: r.try_get("region")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

/// `POST /v1/orgs`: dev only (design decision 7). The app generates a UUIDv7, binds it as the
/// org context, and inserts through row-level security. Without dev auth there is no way to
/// name an org yet, so the request is `401` and no query runs.
pub async fn create(
    State(state): State<AppState>,
    ApiJson(input): ApiJson<NewOrg>,
) -> Result<Response, ApiError> {
    if !state.dev_auth() {
        return Err(ApiError::unauthenticated());
    }
    validate_name(&input.name)?;
    let id = Uuid::now_v7();
    let org = state
        .db()
        .with_org(id, move |c| {
            Box::pin(async move {
                let row = sql::query(concat!(
                    "INSERT INTO orgs (id, name) VALUES ($1, $2) RETURNING ",
                    cols!()
                ))
                .bind(id)
                .bind(input.name)
                .fetch_one(c)
                .await?;
                Ok::<_, ApiError>(from_row(&row)?)
            })
        })
        .await?;
    Ok(created(format!("/v1/orgs/{id}"), org))
}

/// `GET /v1/orgs/{org_id}`: only the bound org exists as far as a request can tell.
pub async fn get_one(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(org_id): ApiPath<Uuid>,
) -> Result<Json<Org>, ApiError> {
    if org_id != org.org_id {
        return Err(ApiError::not_found());
    }
    let row = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let row = sql::query(concat!("SELECT ", cols!(), " FROM orgs WHERE id = $1"))
                    .bind(org_id)
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
