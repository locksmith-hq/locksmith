//! Orgs: dev-only create, and get of the bound org (by id, or as `current` for a caller that
//! does not know its org id, such as the web console after sign-in).

use axum::Json;
use axum::extract::State;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::extract::{ApiJson, ApiPath};
use super::responses::{DevCreateErrors, ReadErrors};
use super::{created, one, utc, validate_name};
use crate::app::AppState;
use crate::auth::OrgBinding;
use crate::db::sql::{self, Row};
use crate::problem::ApiError;

#[derive(Debug, Serialize, ToSchema)]
pub struct Org {
    pub id: Uuid,
    pub name: String,
    pub region: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewOrg {
    pub name: String,
}

macro_rules! cols {
    () => {
        "id, name, region, created_at, updated_at"
    };
}

fn from_row(r: &sql::PgRow) -> sql::Result<Org> {
    Ok(Org {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        region: r.try_get("region")?,
        created_at: utc(r, "created_at")?,
        updated_at: utc(r, "updated_at")?,
    })
}

/// `POST /v1/orgs`: dev only (design decision 7). The app generates a UUIDv7, binds it as the
/// org context, and inserts through row-level security. Without dev auth there is no way to
/// name an org yet, so the request is `401` and no query runs.
#[utoipa::path(
    post,
    path = "/v1/orgs",
    operation_id = "create_org",
    tag = "orgs",
    summary = "Create an org (dev only)",
    request_body = NewOrg,
    responses(
        (status = 201, description = "Created", body = Org, headers(("Location" = String, description = "URL of the new resource"))),
        DevCreateErrors,
    ),
)]
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

/// `GET /v1/orgs/current`: the org the request is bound to. A human's org is resolved on the
/// server from the verified user, so the console needs no org claim in the token to learn it.
#[utoipa::path(
    get,
    path = "/v1/orgs/current",
    operation_id = "get_current_org",
    tag = "orgs",
    summary = "Get the caller's org",
    responses(
        (status = 200, description = "OK", body = Org),
        ReadErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn get_current(
    State(state): State<AppState>,
    org: OrgBinding,
) -> Result<Json<Org>, ApiError> {
    Ok(Json(load(&state, org.org_id).await?))
}

/// `GET /v1/orgs/{org_id}`: only the bound org exists as far as a request can tell.
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}",
    operation_id = "get_org",
    tag = "orgs",
    summary = "Get the bound org",
    params(("org_id" = Uuid, Path, description = "Org id")),
    responses(
        (status = 200, description = "OK", body = Org),
        ReadErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn get_one(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(org_id): ApiPath<Uuid>,
) -> Result<Json<Org>, ApiError> {
    if org_id != org.org_id {
        return Err(ApiError::not_found());
    }
    Ok(Json(load(&state, org_id).await?))
}

/// The bound org's row, read inside its own tenant transaction.
async fn load(state: &AppState, org_id: Uuid) -> Result<Org, ApiError> {
    state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                let row = sql::query(concat!("SELECT ", cols!(), " FROM orgs WHERE id = $1"))
                    .bind(org_id)
                    .fetch_optional(c)
                    .await?;
                one(row, from_row)
            })
        })
        .await
}
