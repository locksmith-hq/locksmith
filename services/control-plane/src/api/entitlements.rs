//! `GET /internal/v1/orgs/{org_id}/entitlements` (T10 OC-6): the org's plan and paid feature keys.
//!
//! The NestJS API asks this before it serves a paid route (for example audit streaming), so a Free
//! org is refused with `feature_not_in_plan` at the edge. The answer comes from the injected
//! [`ls_entitlements::EntitlementSource`] (default `FreeTier`). Entitlements are not secret, but
//! the route is service-token only and the org in the path must be the org the caller binds with
//! `X-Locksmith-Org`: any other org is a `404`. Core operations (unlock, export, read, write) are
//! never gated by a plan, so they are not listed.

use axum::Json;
use axum::extract::State;
use ls_entitlements::{Feature, Plan};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use super::extract::ApiPath;
use super::responses::InternalReadErrors;
use crate::app::AppState;
use crate::auth::ServiceOrgBinding;
use crate::problem::ApiError;

/// An org's plan.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanKey {
    Free,
    Enterprise,
}

/// The plan and paid features of one org.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrgEntitlements {
    pub org_id: Uuid,
    pub plan: PlanKey,
    /// Stable feature keys the plan includes, for example `audit_streaming`; sorted.
    pub features: Vec<String>,
}

#[utoipa::path(
    get,
    path = "/internal/v1/orgs/{org_id}/entitlements",
    operation_id = "get_org_entitlements",
    tag = "entitlements",
    summary = "The org's plan and paid feature keys (service token only)",
    description = "The org in the path must be the org named in `X-Locksmith-Org`; another org is a `404`. A Free org has no features.",
    params(
        ("org_id" = Uuid, Path, description = "Org id"),
        ("X-Locksmith-Org" = Uuid, Header, description = "The org the caller acts for"),
    ),
    responses(
        (status = 200, description = "The org's entitlements", body = OrgEntitlements),
        InternalReadErrors,
    ),
    security(("service_token" = []))
)]
pub async fn get(
    State(state): State<AppState>,
    org: ServiceOrgBinding,
    ApiPath(org_id): ApiPath<Uuid>,
) -> Result<Json<OrgEntitlements>, ApiError> {
    if org.org_id != org_id {
        return Err(ApiError::not_found());
    }
    let e = state.entitlements().entitlements(&org_id.to_string());
    let mut features: Vec<String> = Feature::ALL
        .into_iter()
        .filter(|f| e.has(*f))
        .map(|f| f.key().to_owned())
        .collect();
    features.sort();
    let plan = match e.plan() {
        Plan::Free => PlanKey::Free,
        Plan::Enterprise => PlanKey::Enterprise,
    };
    Ok(Json(OrgEntitlements {
        org_id,
        plan,
        features,
    }))
}
