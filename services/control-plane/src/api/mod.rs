//! The `/v1` resource API: orgs, projects, environments, secret metadata and write-only secret
//! versions.
//!
//! Handlers reach Postgres only through [`crate::db::Database::with_org`], bound to the org
//! from [`crate::auth::OrgBinding`]. Closures never set another org. Input types are all
//! `deny_unknown_fields`. Only `versions::NewSecretVersion` has a value field: it deserializes
//! straight into `SecretBytes` and has no `Debug`; no response type carries a value.

mod environments;
mod extract;
mod orgs;
mod projects;
mod secrets;
mod versions;

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::app::AppState;
use crate::problem::ApiError;

pub const MAX_NAME_CHARS: usize = 200;
pub const MAX_DESCRIPTION_CHARS: usize = 4096;
pub const DEFAULT_PAGE_LIMIT: u32 = 50;
pub const MAX_PAGE_LIMIT: u32 = 100;

/// The `/v1` routes (without layers or state), with their OpenAPI path items.
pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(orgs::create))
        .routes(routes!(orgs::get_one))
        .routes(routes!(projects::create, projects::list))
        .routes(routes!(
            projects::get_one,
            projects::patch,
            projects::delete
        ))
        .routes(routes!(environments::create, environments::list))
        .routes(routes!(
            environments::get_one,
            environments::patch,
            environments::delete
        ))
        .routes(routes!(secrets::create, secrets::list))
        .routes(routes!(secrets::get_one, secrets::patch, secrets::delete))
        .routes(routes!(versions::create, versions::list))
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
#[derive(Debug, Deserialize, ToSchema)]
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
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct PageParams {
    /// Page size, 1 to 100 (default 50).
    limit: Option<u32>,
    /// Opaque cursor: the `next` value of the previous page.
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
#[derive(Debug, Serialize, ToSchema)]
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
