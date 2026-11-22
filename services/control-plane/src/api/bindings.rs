//! The gateway's binding inventory (change d3-db-relay, task 6.1: the contract).
//!
//! `GET /v1/bindings` lists, for the caller's org, the bindings the gateway reports (decision
//! 10): one [`BindingSummary`] per binding, non-secret fields only. A summary never carries a
//! password, a header template, a secret id or any key material. The console and desktop read
//! only this endpoint.
//!
//! Task 6.2 stores the gateway's latest snapshot per org and fills the list; until a snapshot
//! exists the list is empty.

use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

use super::responses::ReadErrors;
use crate::auth::OrgBinding;
use crate::problem::ApiError;

/// What a binding lets the gateway do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)] // built by the snapshot store in task 6.2
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)] // built by the snapshot store in task 6.2
pub enum BindingTls {
    Require,
    VerifyFull,
    Disable,
}

/// One gateway binding, non-secret fields only. Which optional fields are set depends on `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[allow(dead_code)] // built by the snapshot store in task 6.2
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
pub async fn list(_org: OrgBinding) -> Result<Json<BindingList>, ApiError> {
    Ok(Json(BindingList { items: Vec::new() }))
}
