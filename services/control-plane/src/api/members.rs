//! Org membership and invites (T6). Contract group: the types and routes below are final, the
//! handlers answer `501` until their groups land. `OrgRole` is the shared role type T2 reads.
//!
//! An invite token is 32 random bytes (base64url) shown once in [`InviteCreated`] and never
//! stored or listed; only its SHA-256 is kept. It travels in a request body, never a URL.

// Contract stubs: request fields are read once the handlers land (groups 3 and 4).
#![allow(dead_code)]

use axum::Json;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::extract::{ApiJson, ApiPath};
use super::orgs::Org;
use super::responses::MemberErrors;
use crate::auth::OrgBinding;
use crate::problem::ApiError;

/// A member's role in an org. Data only in T6: member management is enforced, the rest is T2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum OrgRole {
    Owner,
    Admin,
    Member,
}

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

/// `GET /v1/orgs`: every org the caller is a member of.
#[utoipa::path(
    get,
    path = "/v1/orgs",
    operation_id = "list_orgs",
    tag = "orgs",
    summary = "List the caller's orgs",
    responses((status = 200, description = "OK", body = MyOrgList), MemberErrors),
    security(("dev_org" = []))
)]
pub async fn list_orgs(_org: OrgBinding) -> Result<Json<MyOrgList>, ApiError> {
    Err(ApiError::not_implemented())
}

/// `PATCH /v1/orgs/{org_id}`: rename (owner only).
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
    _org: OrgBinding,
    ApiPath(_org_id): ApiPath<Uuid>,
    ApiJson(_input): ApiJson<PatchOrg>,
) -> Result<Json<Org>, ApiError> {
    Err(ApiError::not_implemented())
}

/// `DELETE /v1/orgs/{org_id}`: owner only; `409` while the org still has secrets.
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
    _org: OrgBinding,
    ApiPath(_org_id): ApiPath<Uuid>,
) -> Result<StatusCode, ApiError> {
    Err(ApiError::not_implemented())
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
