//! The `/v1` resource API: orgs, projects, environments and secret metadata.
//!
//! Handlers reach Postgres only through [`crate::db::Database::with_org`], bound to the org
//! from [`crate::auth::OrgBinding`]. Closures never set another org. Input types are all
//! `deny_unknown_fields`, and no type here has a secret value field.

mod environments;
mod extract;
mod orgs;
mod projects;
mod secrets;

use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app::AppState;
use crate::problem::ApiError;

pub const MAX_NAME_CHARS: usize = 200;
pub const MAX_DESCRIPTION_CHARS: usize = 4096;
pub const DEFAULT_PAGE_LIMIT: u32 = 50;
pub const MAX_PAGE_LIMIT: u32 = 100;

/// The `/v1` routes (without layers or state).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs", post(orgs::create))
        .route("/v1/orgs/{org_id}", get(orgs::get_one))
        .route("/v1/projects", post(projects::create).get(projects::list))
        .route(
            "/v1/projects/{project_id}",
            get(projects::get_one)
                .patch(projects::patch)
                .delete(projects::delete),
        )
        .route(
            "/v1/projects/{project_id}/environments",
            post(environments::create).get(environments::list),
        )
        .route(
            "/v1/projects/{project_id}/environments/{environment_id}",
            get(environments::get_one)
                .patch(environments::patch)
                .delete(environments::delete),
        )
        .route(
            "/v1/projects/{project_id}/environments/{environment_id}/secrets",
            post(secrets::create).get(secrets::list),
        )
        .route(
            "/v1/projects/{project_id}/environments/{environment_id}/secrets/{secret_id}",
            get(secrets::get_one)
                .patch(secrets::patch)
                .delete(secrets::delete),
        )
}

/// SQL column list shared by projects, environments and secrets (timestamps as RFC 3339 UTC).
macro_rules! common_cols {
    () => {
        "id, name, description, \
         to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, \
         to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at"
    };
}
pub(crate) use common_cols;

/// Names must be non-blank and bounded; descriptions bounded.
pub(crate) fn validate_name(name: &str) -> Result<(), ApiError> {
    if name.trim().is_empty() {
        return Err(ApiError::validation("`name` must not be empty"));
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(ApiError::validation(format!(
            "`name` must be at most {MAX_NAME_CHARS} characters"
        )));
    }
    Ok(())
}

pub(crate) fn validate_description(description: &str) -> Result<(), ApiError> {
    if description.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err(ApiError::validation(format!(
            "`description` must be at most {MAX_DESCRIPTION_CHARS} characters"
        )));
    }
    Ok(())
}

/// `PATCH` body for projects, environments and secrets: name and description only.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Patch {
    pub name: Option<String>,
    pub description: Option<String>,
}

impl Patch {
    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        if self.name.is_none() && self.description.is_none() {
            return Err(ApiError::validation(
                "provide `name` and/or `description` to change",
            ));
        }
        if let Some(n) = &self.name {
            validate_name(n)?;
        }
        if let Some(d) = &self.description {
            validate_description(d)?;
        }
        Ok(())
    }
}

/// `201 Created` with a `Location` header.
pub(crate) fn created<T: Serialize>(location: String, body: T) -> Response {
    let mut response = (StatusCode::CREATED, axum::Json(body)).into_response();
    // Locations are built from UUIDs, so they are always valid header values.
    if let Ok(v) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, v);
    }
    response
}

/// List query: `limit` (1 to 100, default 50) and the opaque `cursor` from a previous `next`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageParams {
    limit: Option<u32>,
    cursor: Option<String>,
}

/// Validated paging: fetch `limit + 1` rows after `after`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Page {
    pub limit: u32,
    pub after: Option<Uuid>,
}

impl Page {
    /// Rows to request, so one extra row says whether another page exists.
    pub fn fetch(&self) -> i64 {
        i64::from(self.limit) + 1
    }
}

impl PageParams {
    pub(crate) fn resolve(self) -> Result<Page, ApiError> {
        let limit = self.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
        if limit == 0 || limit > MAX_PAGE_LIMIT {
            return Err(ApiError::validation(format!(
                "`limit` must be between 1 and {MAX_PAGE_LIMIT}"
            )));
        }
        let after = self
            .cursor
            .as_deref()
            .map(decode_cursor)
            .transpose()
            .map_err(|()| ApiError::validation("`cursor` is not valid"))?;
        Ok(Page { limit, after })
    }
}

/// An opaque cursor: base64url of the last id returned (keyset pagination on UUIDv7 ids).
fn encode_cursor(id: Uuid) -> String {
    URL_SAFE_NO_PAD.encode(id.as_bytes())
}

fn decode_cursor(cursor: &str) -> Result<Uuid, ()> {
    let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| ())?;
    Uuid::from_slice(&bytes).map_err(|_| ())
}

/// One page of a list. `next` is absent on the last page.
#[derive(Debug, Serialize)]
pub struct Paged<T> {
    pub items: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

impl<T> Paged<T> {
    /// `rows` holds up to `page.fetch()` rows ordered by id.
    pub(crate) fn new(mut rows: Vec<T>, page: Page, id_of: impl Fn(&T) -> Uuid) -> Self {
        let next = if rows.len() > page.limit as usize {
            rows.truncate(page.limit as usize);
            rows.last().map(|r| encode_cursor(id_of(r)))
        } else {
            None
        };
        Self { items: rows, next }
    }
}
