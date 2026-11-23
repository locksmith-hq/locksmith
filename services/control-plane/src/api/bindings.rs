//! The gateway's binding inventory (change d3-db-relay, task 6.1: the contract).
//!
//! `GET /v1/bindings` lists, for the caller's org, the bindings the gateway reports (decision
//! 10): one [`BindingSummary`] per binding, non-secret fields only. A summary never carries a
//! password, a header template, a secret id or any key material. The console and desktop read
//! only this endpoint.
//!
//! Task 6.2: the gateway publishes its inventory at startup with
//! `PUT /internal/v1/gateway/bindings` (service token, D3-1). The control plane keeps the latest
//! snapshot per org, replaced whole, and `GET /v1/bindings` serves it; until a snapshot exists
//! the list is empty. The snapshot type refuses unknown fields, so a gateway cannot store a
//! password, template, secret id or any other field this contract does not name.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::extract::ApiJson;
use super::responses::{InternalWriteErrors, ReadErrors};
use crate::app::AppState;
use crate::auth::{OrgBinding, ServiceOrgBinding};
use crate::db::sql::{self, Row};
use crate::problem::{ApiError, Kind};

/// The most bindings one snapshot may hold.
const MAX_ITEMS: usize = 1000;
/// The longest any text field of a binding may be, in bytes.
const MAX_TEXT: usize = 512;

/// What a binding lets the gateway do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum BindingKind {
    /// Inject a secret into an HTTP request to one origin.
    Http,
    /// Inject a secret into Git smart-HTTP requests to one repository or owner.
    Git,
    /// Relay a Postgres session with the stored password.
    Pg,
    /// Vend or relay AWS access through a role.
    Aws,
}

/// How the gateway reaches a Postgres upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BindingTls {
    Require,
    VerifyFull,
    Disable,
}

/// One gateway binding, non-secret fields only. Which optional fields are set depends on `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BindingSummary {
    pub kind: BindingKind,
    /// Display name: the database name (`pg`), the origin or host (`http`, `git`), the role (`aws`).
    pub name: String,
    /// `http`: the exact upstream origin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// `http`: the header the secret is injected into (never its value or template).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// `git`: `owner` or `owner/repo`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// `pg`, `git`: the upstream host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// `pg`: the upstream port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// `pg`: the bound database user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// `pg`: the bound database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// `pg`: the upstream TLS mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<BindingTls>,
    /// `aws`: the role ARN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// `aws`: the region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// `aws`: whether short-lived credentials may be vended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vend: Option<bool>,
    /// `aws`: the longest vended session, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_secs: Option<u32>,
}

/// Every binding the gateway reports for the org.
#[derive(Debug, Serialize, ToSchema)]
pub struct BindingList {
    pub items: Vec<BindingSummary>,
}

#[utoipa::path(
    get,
    path = "/v1/bindings",
    operation_id = "list_bindings",
    tag = "bindings",
    summary = "List the gateway's bindings (non-secret fields only)",
    responses(
        (status = 200, description = "The org's bindings", body = BindingList),
        ReadErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    org: OrgBinding,
) -> Result<Json<BindingList>, ApiError> {
    let org_id = org.org_id;
    let stored: Option<String> = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                let row = sql::query("SELECT items::text AS items FROM gateway_bindings")
                    .fetch_optional(c)
                    .await?;
                Ok::<_, ApiError>(match row {
                    Some(r) => Some(r.try_get::<String, _>("items")?),
                    None => None,
                })
            })
        })
        .await?;
    let items = match stored {
        Some(text) => serde_json::from_str(&text).map_err(|_| ApiError::bare(Kind::Internal))?,
        None => Vec::new(),
    };
    Ok(Json(BindingList { items }))
}

/// The gateway's full inventory. It replaces the org's previous snapshot.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BindingSnapshot {
    #[schema(max_items = 1000)]
    pub items: Vec<BindingSummary>,
}

impl BindingSnapshot {
    fn validate(&self) -> Result<(), ApiError> {
        if self.items.len() > MAX_ITEMS {
            return Err(ApiError::validation("too many bindings"));
        }
        for b in &self.items {
            let texts = [
                Some(&b.name),
                b.origin.as_ref(),
                b.header.as_ref(),
                b.repo.as_ref(),
                b.host.as_ref(),
                b.user.as_ref(),
                b.database.as_ref(),
                b.role.as_ref(),
                b.region.as_ref(),
            ];
            if b.name.trim().is_empty() {
                return Err(ApiError::validation("a binding needs a `name`"));
            }
            if texts.iter().flatten().any(|t| t.len() > MAX_TEXT) {
                return Err(ApiError::validation("a binding field is too long"));
            }
        }
        Ok(())
    }
}

#[utoipa::path(
    put,
    path = "/internal/v1/gateway/bindings",
    operation_id = "put_gateway_bindings",
    tag = "internal",
    summary = "Replace the org's binding inventory (gateway only)",
    description = "The gateway publishes its non-secret binding inventory at startup. The body replaces the org's latest snapshot, which `GET /v1/bindings` serves. Fields are names, hosts, ports, users, databases, header names and similar; a password, header template, secret id or any unknown field is a `400`.",
    params(
        ("X-Locksmith-Org" = Uuid, Header, description = "The org the gateway acts for (the token's `org`)"),
    ),
    request_body = BindingSnapshot,
    responses(
        (status = 204, description = "Stored"),
        InternalWriteErrors,
    ),
    security(("service_token" = []))
)]
pub async fn put_snapshot(
    State(state): State<AppState>,
    org: ServiceOrgBinding,
    ApiJson(input): ApiJson<BindingSnapshot>,
) -> Result<StatusCode, ApiError> {
    input.validate()?;
    let items = serde_json::to_string(&input.items).map_err(|_| ApiError::bare(Kind::Internal))?;
    let org_id = org.org_id;
    state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                sql::query(
                    "INSERT INTO gateway_bindings (org_id, items) VALUES ($1, $2::jsonb) \
                     ON CONFLICT (org_id) DO UPDATE SET items = EXCLUDED.items, updated_at = now()",
                )
                .bind(org_id)
                .bind(items)
                .execute(c)
                .await?;
                Ok::<_, ApiError>(())
            })
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
