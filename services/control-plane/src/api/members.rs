//! Org membership and invites (T6). Contract group: the types and routes below are final. The
//! org routes (`GET /v1/orgs`, rename, delete) are built (group 3); the member and invite
//! handlers answer `501` until group 4 lands. `OrgRole` (defined with the binding in
//! [`crate::auth`]) is the shared role type T2 reads.
//!
//! An invite token is 32 random bytes (base64url) shown once in [`InviteCreated`] and never
//! stored or listed; only its SHA-256 is kept. It travels in a request body, never a URL.

// Contract stubs: request fields are read once the handlers land (groups 3 and 4).
#![allow(dead_code)]

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::extract::{ApiJson, ApiPath};
use super::orgs::{self, Org};
use super::responses::MemberErrors;
use super::{exists_or_404, one, validate_name};
use crate::app::AppState;
use crate::audit;
use crate::auth::OrgBinding;
use crate::db::sql::{self, Row};
use crate::problem::ApiError;

pub use crate::auth::OrgRole;

/// An org the caller belongs to, with the caller's role in it.
#[derive(Debug, Serialize, ToSchema)]
pub struct MyOrg {
    #[serde(flatten)]
    pub org: Org,
    pub role: OrgRole,
    /// True for the caller's personal org (the default when no `X-Locksmith-Org` is sent).
    pub personal: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MyOrgList {
    pub items: Vec<MyOrg>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchOrg {
    pub name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Member {
    pub user_id: Uuid,
    pub email: Option<String>,
    pub role: OrgRole,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MemberList {
    /// The caller's own role, so a client can hide buttons without a second request.
    pub caller_role: OrgRole,
    pub items: Vec<Member>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchMember {
    pub role: OrgRole,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewInvite {
    pub email: String,
    pub role: OrgRole,
}

/// A pending, accepted or revoked invite. Never carries the token.
#[derive(Debug, Serialize, ToSchema)]
pub struct Invite {
    pub id: Uuid,
    pub email: String,
    pub role: OrgRole,
    pub invited_by: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub accepted_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InviteList {
    pub items: Vec<Invite>,
}

/// The create response: the only place the invite token is ever returned.
// No `Debug`: it carries the one-time invite token.
#[derive(Serialize, ToSchema)]
pub struct InviteCreated {
    pub invite: Invite,
    /// Shown once; the server keeps only its hash.
    pub token: String,
}

// No `Debug`: it carries the invite token.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AcceptInvite {
    pub token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AcceptedInvite {
    pub org_id: Uuid,
    pub role: OrgRole,
}

/// `GET /v1/orgs`: every org the caller is a member of, with their role, read through the
/// `app.login_user` slice (migration 0015).
#[utoipa::path(
    get,
    path = "/v1/orgs",
    operation_id = "list_orgs",
    tag = "orgs",
    summary = "List the caller's orgs",
    responses((status = 200, description = "OK", body = MyOrgList), MemberErrors),
    security(("dev_org" = []))
)]
pub async fn list_orgs(
    State(state): State<AppState>,
    org: OrgBinding,
) -> Result<Json<MyOrgList>, ApiError> {
    // The dev-only header names no user: it sees just the org it names, as owner.
    let Some(user) = org.user else {
        let bound = orgs::load(&state, org.org_id).await?;
        return Ok(Json(MyOrgList {
            items: vec![MyOrg {
                org: bound,
                role: org.role,
                personal: true,
            }],
        }));
    };
    let items = state
        .db()
        .with_user(user.user_id, move |c| {
            Box::pin(async move {
                let rows = sql::query(concat!(
                    "SELECT o.id, o.name, o.region, o.created_at, o.updated_at, m.role \
                     FROM memberships m JOIN orgs o ON o.id = m.org_id \
                     WHERE m.user_id = $1 ORDER BY o.created_at, o.id"
                ))
                .bind(user.user_id)
                .fetch_all(&mut *c)
                .await?;
                let mut items = Vec::with_capacity(rows.len());
                for r in &rows {
                    let role: String = r.try_get("role")?;
                    let Some(role) = OrgRole::from_db(&role) else {
                        continue;
                    };
                    let org = orgs::from_row(r)?;
                    items.push(MyOrg {
                        personal: org.id == user.personal_org_id,
                        org,
                        role,
                    });
                }
                Ok::<_, ApiError>(items)
            })
        })
        .await?;
    Ok(Json(MyOrgList { items }))
}

/// `PATCH /v1/orgs/{org_id}`: rename (owner or admin). `{org_id}` must be the bound org (select
/// it with `X-Locksmith-Org`); any other id is `404`. Appends `org.renamed`.
#[utoipa::path(
    patch,
    path = "/v1/orgs/{org_id}",
    operation_id = "patch_org",
    tag = "orgs",
    summary = "Rename an org",
    params(("org_id" = Uuid, Path, description = "Org id")),
    request_body = PatchOrg,
    responses((status = 200, description = "OK", body = Org), MemberErrors),
    security(("dev_org" = []))
)]
pub async fn patch_org(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(org_id): ApiPath<Uuid>,
    ApiJson(input): ApiJson<PatchOrg>,
) -> Result<Json<Org>, ApiError> {
    // Only the bound org exists as far as a request can tell (select it with X-Locksmith-Org).
    if org_id != org.org_id {
        return Err(ApiError::not_found());
    }
    org.require(&[OrgRole::Owner, OrgRole::Admin])?;
    validate_name(&input.name)?;
    let actor = org.actor();
    let updated = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                require_role_in_tx(c, &org, &[OrgRole::Owner, OrgRole::Admin]).await?;
                let row = sql::query(concat!(
                    "UPDATE orgs SET name = $2, updated_at = now() WHERE id = $1 RETURNING ",
                    orgs::cols!()
                ))
                .bind(org_id)
                .bind(input.name)
                .fetch_optional(&mut *c)
                .await?;
                let updated = one(row, orgs::from_row)?;
                audit::append(c, org_id, &audit::org_renamed(actor, org_id)).await?;
                Ok::<_, ApiError>(updated)
            })
        })
        .await?;
    Ok(Json(updated))
}

/// Re-check the caller's role inside the write transaction, locking their membership row, so a
/// role change or removal that commits after the binding cannot be acted on. The dev-only
/// header has no membership row and keeps its binding role.
async fn require_role_in_tx(
    c: &mut sql::PgConnection,
    org: &OrgBinding,
    allowed: &[OrgRole],
) -> Result<(), ApiError> {
    let Some(user) = org.user else {
        return org.require(allowed);
    };
    let role: Option<String> = sql::query_scalar(
        "SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2 FOR UPDATE",
    )
    .bind(org.org_id)
    .bind(user.user_id)
    .fetch_optional(&mut *c)
    .await?;
    match role.as_deref().and_then(OrgRole::from_db) {
        None => Err(ApiError::not_found()),
        Some(r) if allowed.contains(&r) => Ok(()),
        Some(_) => Err(ApiError::forbidden()),
    }
}

/// `DELETE /v1/orgs/{org_id}`: owner only; `409` while the org still has secrets, and for a
/// personal org. `{org_id}` must be the bound org. Every membership ends and open invites are
/// revoked, in one transaction with the `org.deleted` event; the org row and its ledger are
/// kept (the ledger is append-only), unreachable because nobody is a member any more.
#[utoipa::path(
    delete,
    path = "/v1/orgs/{org_id}",
    operation_id = "delete_org",
    tag = "orgs",
    summary = "Delete an org",
    params(("org_id" = Uuid, Path, description = "Org id")),
    responses((status = 204, description = "Deleted"), MemberErrors),
    security(("dev_org" = []))
)]
pub async fn delete_org(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(org_id): ApiPath<Uuid>,
) -> Result<StatusCode, ApiError> {
    if org_id != org.org_id {
        return Err(ApiError::not_found());
    }
    org.require(&[OrgRole::Owner])?;
    let actor = org.actor();
    state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                // Serialise with renames and other deletes of this org.
                exists_or_404(
                    c,
                    sql::query_scalar("SELECT 1 FROM orgs WHERE id = $1 FOR UPDATE").bind(org_id),
                )
                .await?;
                require_role_in_tx(c, &org, &[OrgRole::Owner]).await?;
                let personal: bool = sql::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM users WHERE personal_org_id = $1)",
                )
                .bind(org_id)
                .fetch_one(&mut *c)
                .await?;
                if personal {
                    return Err(ApiError::conflict("a personal org cannot be deleted"));
                }
                let has_secrets: bool = sql::query_scalar("SELECT EXISTS (SELECT 1 FROM secrets)")
                    .fetch_one(&mut *c)
                    .await?;
                if has_secrets {
                    return Err(ApiError::conflict("the org still has secrets"));
                }
                sql::query(
                    "UPDATE invites SET revoked_at = now() \
                     WHERE accepted_at IS NULL AND revoked_at IS NULL",
                )
                .execute(&mut *c)
                .await?;
                sql::query("DELETE FROM memberships WHERE org_id = $1")
                    .bind(org_id)
                    .execute(&mut *c)
                    .await?;
                audit::append(c, org_id, &audit::org_deleted(actor, org_id)).await?;
                Ok::<_, ApiError>(())
            })
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/orgs/current/members`.
#[utoipa::path(
    get,
    path = "/v1/orgs/current/members",
    operation_id = "list_members",
    tag = "members",
    summary = "List the org's members",
    responses((status = 200, description = "OK", body = MemberList), MemberErrors),
    security(("dev_org" = []))
)]
pub async fn list_members(_org: OrgBinding) -> Result<Json<MemberList>, ApiError> {
    Err(ApiError::not_implemented())
}

/// `PATCH /v1/orgs/current/members/{user_id}`: change a role (last-owner rule applies).
#[utoipa::path(
    patch,
    path = "/v1/orgs/current/members/{user_id}",
    operation_id = "patch_member",
    tag = "members",
    summary = "Change a member's role",
    params(("user_id" = Uuid, Path, description = "User id")),
    request_body = PatchMember,
    responses((status = 200, description = "OK", body = Member), MemberErrors),
    security(("dev_org" = []))
)]
pub async fn patch_member(
    _org: OrgBinding,
    ApiPath(_user_id): ApiPath<Uuid>,
    ApiJson(_input): ApiJson<PatchMember>,
) -> Result<Json<Member>, ApiError> {
    Err(ApiError::not_implemented())
}

/// `DELETE /v1/orgs/current/members/{user_id}`: remove a member, or leave when it is the caller.
#[utoipa::path(
    delete,
    path = "/v1/orgs/current/members/{user_id}",
    operation_id = "remove_member",
    tag = "members",
    summary = "Remove a member or leave",
    params(("user_id" = Uuid, Path, description = "User id")),
    responses((status = 204, description = "Removed"), MemberErrors),
    security(("dev_org" = []))
)]
pub async fn remove_member(
    _org: OrgBinding,
    ApiPath(_user_id): ApiPath<Uuid>,
) -> Result<StatusCode, ApiError> {
    Err(ApiError::not_implemented())
}

/// `POST /v1/orgs/current/invites`: the response carries the token once.
#[utoipa::path(
    post,
    path = "/v1/orgs/current/invites",
    operation_id = "create_invite",
    tag = "members",
    summary = "Invite someone by email",
    request_body = NewInvite,
    responses((status = 201, description = "Created", body = InviteCreated), MemberErrors),
    security(("dev_org" = []))
)]
pub async fn create_invite(
    _org: OrgBinding,
    ApiJson(_input): ApiJson<NewInvite>,
) -> Result<Json<InviteCreated>, ApiError> {
    Err(ApiError::not_implemented())
}

/// `GET /v1/orgs/current/invites`.
#[utoipa::path(
    get,
    path = "/v1/orgs/current/invites",
    operation_id = "list_invites",
    tag = "members",
    summary = "List the org's invites",
    responses((status = 200, description = "OK", body = InviteList), MemberErrors),
    security(("dev_org" = []))
)]
pub async fn list_invites(_org: OrgBinding) -> Result<Json<InviteList>, ApiError> {
    Err(ApiError::not_implemented())
}

/// `DELETE /v1/orgs/current/invites/{invite_id}`: revoke.
#[utoipa::path(
    delete,
    path = "/v1/orgs/current/invites/{invite_id}",
    operation_id = "revoke_invite",
    tag = "members",
    summary = "Revoke an invite",
    params(("invite_id" = Uuid, Path, description = "Invite id")),
    responses((status = 204, description = "Revoked"), MemberErrors),
    security(("dev_org" = []))
)]
pub async fn revoke_invite(
    _org: OrgBinding,
    ApiPath(_invite_id): ApiPath<Uuid>,
) -> Result<StatusCode, ApiError> {
    Err(ApiError::not_implemented())
}

/// `POST /v1/invites/accept`: the token is in the body so it stays out of access logs. Every
/// failure (unknown, reused, expired, other email) is the same `404`.
#[utoipa::path(
    post,
    path = "/v1/invites/accept",
    operation_id = "accept_invite",
    tag = "members",
    summary = "Accept an invite",
    request_body = AcceptInvite,
    responses((status = 200, description = "Joined", body = AcceptedInvite), MemberErrors),
    security(("dev_org" = []))
)]
pub async fn accept_invite(
    _org: OrgBinding,
    ApiJson(_input): ApiJson<AcceptInvite>,
) -> Result<Json<AcceptedInvite>, ApiError> {
    Err(ApiError::not_implemented())
}
