//! Org membership and invites (T6). The types and routes below are the contract group; the org
//! routes (`GET /v1/orgs`, rename, delete) are group 3 and the member and invite handlers are
//! group 4. `OrgRole` (defined with the binding in [`crate::auth`]) is the shared role type T2
//! reads.
//!
//! An invite token is 32 random bytes (base64url) shown once in [`InviteCreated`] and never
//! stored or listed; only its SHA-256 is kept. It travels in a request body, never a URL.
//!
//! Role rules (member management only; the rest of the roles are T2): an `owner` manages
//! everyone and may invite any role; an `admin` manages `member`s and other `admin`s, may invite
//! `admin` and `member` and cannot create an `owner`; a `member` may only list members and leave.
//! Demoting, removing or leaving as the last `owner` is `409`: the org's owner rows are locked in
//! one transaction first, so two owners acting at once cannot both succeed.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::extract::{ApiJson, ApiPath};
use super::orgs::{self, Org};
use super::responses::MemberErrors;
use super::{all, created, deleted_or_404, exists_or_404, one, utc, validate_name};
use crate::app::AppState;
use crate::audit;
use crate::auth::{OrgBinding, human_login};
use crate::db::sql::{self, Row};
use crate::db::{bind_invite_hash, bind_org};
use crate::problem::{ApiError, Kind};

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
                let rows = sql::query(
                    "SELECT o.id, o.name, o.region, o.created_at, o.updated_at, m.role \
                     FROM memberships m JOIN orgs o ON o.id = m.org_id \
                     WHERE m.user_id = $1 ORDER BY o.created_at, o.id",
                )
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
) -> Result<OrgRole, ApiError> {
    let Some(user) = org.user else {
        return org.require(allowed).map(|()| org.role);
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
        Some(r) if allowed.contains(&r) => Ok(r),
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

/// How long an invite stays open.
const INVITE_TTL_DAYS: i32 = 7;
/// Longest accepted email address (RFC 5321).
const MAX_EMAIL_CHARS: usize = 254;
/// A real token is 43 characters; anything longer cannot match and is not worth hashing.
const MAX_TOKEN_CHARS: usize = 128;
/// Invites returned by one list call.
const MAX_INVITES_LISTED: i64 = 200;

const LAST_OWNER: &str = "an org needs at least one owner";

fn role_of(row: &sql::PgRow, column: &str) -> Result<OrgRole, ApiError> {
    let role: String = row.try_get(column)?;
    OrgRole::from_db(&role).ok_or_else(|| ApiError::bare(Kind::Internal))
}

/// The lower-cased, trimmed address, or `400` when it cannot be one.
fn normalize_email(raw: &str) -> Result<String, ApiError> {
    let email = raw.trim().to_lowercase();
    let ok = email.chars().count() <= MAX_EMAIL_CHARS
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && !domain.is_empty() && !domain.contains('@')
        });
    if ok {
        Ok(email)
    } else {
        Err(ApiError::validation("`email` must be an email address"))
    }
}

/// SHA-256 of a presented or freshly generated token (the only form stored).
fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// A fresh invite token: 32 random bytes, base64url. Never `Debug`, wiped on drop.
fn new_token() -> Result<SecretString, ApiError> {
    let key = ls_crypto::SecretKey32::random().map_err(|_| ApiError::bare(Kind::Internal))?;
    Ok(SecretString::from(URL_SAFE_NO_PAD.encode(key.expose())))
}

macro_rules! invite_cols {
    () => {
        "id, email, role, invited_by, expires_at, accepted_at, revoked_at"
    };
}

fn invite_from_row(r: &sql::PgRow) -> Result<Invite, ApiError> {
    Ok(Invite {
        id: r.try_get("id")?,
        email: r.try_get("email")?,
        role: role_of(r, "role")?,
        invited_by: r.try_get("invited_by")?,
        expires_at: utc(r, "expires_at")?,
        accepted_at: r
            .try_get::<Option<OffsetDateTime>, _>("accepted_at")?
            .map(|t| t.to_offset(time::UtcOffset::UTC)),
        revoked_at: r
            .try_get::<Option<OffsetDateTime>, _>("revoked_at")?
            .map(|t| t.to_offset(time::UtcOffset::UTC)),
    })
}

/// Lock every owner row of the org (in id order, so two callers cannot deadlock) and return the
/// owners. Held to the end of the transaction. A row another transaction has just demoted or
/// removed is re-read after it commits and drops out, so the count is the committed truth.
async fn lock_owners(c: &mut sql::PgConnection, org_id: Uuid) -> Result<Vec<Uuid>, ApiError> {
    Ok(sql::query_scalar(
        "SELECT user_id FROM memberships WHERE org_id = $1 AND role = 'owner' \
         ORDER BY user_id FOR UPDATE",
    )
    .bind(org_id)
    .fetch_all(c)
    .await?)
}

/// The member as the API shows it, read in the bound org.
async fn load_member(
    c: &mut sql::PgConnection,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<Member, ApiError> {
    let row = sql::query(
        "SELECT m.user_id, u.email, m.role, m.created_at \
         FROM memberships m LEFT JOIN users u ON u.id = m.user_id \
         WHERE m.org_id = $1 AND m.user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(c)
    .await?;
    one(row, member_from_row_checked)
}

fn member_from_row_checked(r: &sql::PgRow) -> sql::Result<Member> {
    let role: String = r.try_get("role")?;
    Ok(Member {
        user_id: r.try_get("user_id")?,
        email: r.try_get("email")?,
        role: OrgRole::from_db(&role).ok_or_else(|| sql::Error::Decode("unknown role".into()))?,
        created_at: utc(r, "created_at")?,
    })
}

/// `GET /v1/orgs/current/members`: any member may list.
#[utoipa::path(
    get,
    path = "/v1/orgs/current/members",
    operation_id = "list_members",
    tag = "members",
    summary = "List the org's members",
    responses((status = 200, description = "OK", body = MemberList), MemberErrors),
    security(("dev_org" = []))
)]
pub async fn list_members(
    State(state): State<AppState>,
    org: OrgBinding,
) -> Result<Json<MemberList>, ApiError> {
    let org_id = org.org_id;
    let items = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                let rows = sql::query(
                    "SELECT m.user_id, u.email, m.role, m.created_at \
                     FROM memberships m LEFT JOIN users u ON u.id = m.user_id \
                     WHERE m.org_id = $1 ORDER BY m.created_at, m.user_id",
                )
                .bind(org_id)
                .fetch_all(&mut *c)
                .await?;
                all(&rows, member_from_row_checked)
            })
        })
        .await?;
    Ok(Json(MemberList {
        caller_role: org.role,
        items,
    }))
}

/// `PATCH /v1/orgs/current/members/{user_id}`: change a role (last-owner rule applies). An admin
/// may not touch an owner or make one.
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
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(user_id): ApiPath<Uuid>,
    ApiJson(input): ApiJson<PatchMember>,
) -> Result<Json<Member>, ApiError> {
    org.require(&[OrgRole::Owner, OrgRole::Admin])?;
    let org_id = org.org_id;
    let actor = org.actor();
    let new_role = input.role;
    let member = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                let owners = lock_owners(c, org_id).await?;
                let caller = require_role_in_tx(c, &org, &[OrgRole::Owner, OrgRole::Admin]).await?;
                let current: Option<String> = sql::query_scalar(
                    "SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2 FOR UPDATE",
                )
                .bind(org_id)
                .bind(user_id)
                .fetch_optional(&mut *c)
                .await?;
                let current = current
                    .as_deref()
                    .and_then(OrgRole::from_db)
                    .ok_or_else(ApiError::not_found)?;
                if caller != OrgRole::Owner
                    && (current == OrgRole::Owner || new_role == OrgRole::Owner)
                {
                    return Err(ApiError::forbidden());
                }
                if current != new_role {
                    if current == OrgRole::Owner && owners == [user_id] {
                        return Err(ApiError::conflict(LAST_OWNER));
                    }
                    sql::query(
                        "UPDATE memberships SET role = $3 WHERE org_id = $1 AND user_id = $2",
                    )
                    .bind(org_id)
                    .bind(user_id)
                    .bind(new_role.as_str())
                    .execute(&mut *c)
                    .await?;
                    audit::append(
                        c,
                        org_id,
                        &audit::member_role_changed(actor, org_id, user_id, new_role),
                    )
                    .await?;
                }
                load_member(c, org_id, user_id).await
            })
        })
        .await?;
    Ok(Json(member))
}

/// `DELETE /v1/orgs/current/members/{user_id}`: remove a member, or leave when it is the caller
/// (any role may leave). The last owner cannot go, and nobody leaves their personal org.
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
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(user_id): ApiPath<Uuid>,
) -> Result<StatusCode, ApiError> {
    let leaving = org.user.is_some_and(|u| u.user_id == user_id);
    if !leaving {
        org.require(&[OrgRole::Owner, OrgRole::Admin])?;
    }
    let org_id = org.org_id;
    let actor = org.actor();
    state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                let owners = lock_owners(c, org_id).await?;
                let caller =
                    require_role_in_tx(c, &org, &[OrgRole::Owner, OrgRole::Admin, OrgRole::Member])
                        .await?;
                if !leaving && caller == OrgRole::Member {
                    return Err(ApiError::forbidden());
                }
                let current: Option<String> = sql::query_scalar(
                    "SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2 FOR UPDATE",
                )
                .bind(org_id)
                .bind(user_id)
                .fetch_optional(&mut *c)
                .await?;
                let current = current
                    .as_deref()
                    .and_then(OrgRole::from_db)
                    .ok_or_else(ApiError::not_found)?;
                if !leaving && caller == OrgRole::Admin && current == OrgRole::Owner {
                    return Err(ApiError::forbidden());
                }
                if current == OrgRole::Owner && owners == [user_id] {
                    return Err(ApiError::conflict(LAST_OWNER));
                }
                let personal: bool = sql::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND personal_org_id = $2)",
                )
                .bind(user_id)
                .bind(org_id)
                .fetch_one(&mut *c)
                .await?;
                if personal {
                    return Err(ApiError::conflict(
                        "a member cannot leave their personal org",
                    ));
                }
                let removed =
                    sql::query("DELETE FROM memberships WHERE org_id = $1 AND user_id = $2")
                        .bind(org_id)
                        .bind(user_id)
                        .execute(&mut *c)
                        .await?
                        .rows_affected();
                deleted_or_404(removed)?;
                let event = if leaving {
                    audit::member_left(org_id, user_id)
                } else {
                    audit::member_removed(actor, org_id, user_id)
                };
                audit::append(c, org_id, &event).await?;
                Ok::<_, ApiError>(())
            })
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/orgs/current/invites`: owner or admin (only an owner may invite an owner). The
/// response carries the token once; only its SHA-256 is stored. No email is sent in T6.
#[utoipa::path(
    post,
    path = "/v1/orgs/current/invites",
    operation_id = "create_invite",
    tag = "members",
    summary = "Invite someone by email",
    request_body = NewInvite,
    responses(
        (status = 201, description = "Created", body = InviteCreated, headers(("Location" = String, description = "URL of the new invite"))),
        MemberErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn create_invite(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiJson(input): ApiJson<NewInvite>,
) -> Result<Response, ApiError> {
    org.require(&[OrgRole::Owner, OrgRole::Admin])?;
    // The inviter is recorded as a user; the dev-only header names none.
    let inviter = org.user.ok_or_else(ApiError::forbidden)?.user_id;
    let email = normalize_email(&input.email)?;
    let role = input.role;
    let allowed: &'static [OrgRole] = if role == OrgRole::Owner {
        &[OrgRole::Owner]
    } else {
        &[OrgRole::Owner, OrgRole::Admin]
    };
    org.require(allowed)?;
    let org_id = org.org_id;
    let actor = org.actor();
    let token = new_token()?;
    let hash = token_hash(token.expose_secret()).to_vec();
    let invite = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                require_role_in_tx(c, &org, allowed).await?;
                let row = sql::query(concat!(
                    "INSERT INTO invites (org_id, email, role, token_hash, invited_by, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, now() + make_interval(days => $6)) RETURNING ",
                    invite_cols!()
                ))
                .bind(org_id)
                .bind(email)
                .bind(role.as_str())
                .bind(hash)
                .bind(inviter)
                .bind(INVITE_TTL_DAYS)
                .fetch_one(&mut *c)
                .await?;
                let invite = invite_from_row(&row)?;
                audit::append(
                    c,
                    org_id,
                    &audit::member_invited(actor, org_id, invite.id, role),
                )
                .await?;
                Ok::<_, ApiError>(invite)
            })
        })
        .await?;
    let location = format!("/v1/orgs/current/invites/{}", invite.id);
    Ok(created(
        location,
        InviteCreated {
            invite,
            token: token.expose_secret().to_owned(),
        },
    ))
}

/// `GET /v1/orgs/current/invites`: owner or admin. Never carries a token.
#[utoipa::path(
    get,
    path = "/v1/orgs/current/invites",
    operation_id = "list_invites",
    tag = "members",
    summary = "List the org's invites",
    responses((status = 200, description = "OK", body = InviteList), MemberErrors),
    security(("dev_org" = []))
)]
pub async fn list_invites(
    State(state): State<AppState>,
    org: OrgBinding,
) -> Result<Json<InviteList>, ApiError> {
    org.require(&[OrgRole::Owner, OrgRole::Admin])?;
    let org_id = org.org_id;
    let items = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                let rows = sql::query(concat!(
                    "SELECT ",
                    invite_cols!(),
                    " FROM invites WHERE org_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2"
                ))
                .bind(org_id)
                .bind(MAX_INVITES_LISTED)
                .fetch_all(&mut *c)
                .await?;
                rows.iter()
                    .map(invite_from_row)
                    .collect::<Result<Vec<_>, _>>()
            })
        })
        .await?;
    Ok(Json(InviteList { items }))
}

/// `DELETE /v1/orgs/current/invites/{invite_id}`: revoke an open invite (an admin cannot revoke
/// an owner invite). An unknown, accepted or already revoked invite is `404`.
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
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(invite_id): ApiPath<Uuid>,
) -> Result<StatusCode, ApiError> {
    org.require(&[OrgRole::Owner, OrgRole::Admin])?;
    let org_id = org.org_id;
    let actor = org.actor();
    state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                let caller = require_role_in_tx(c, &org, &[OrgRole::Owner, OrgRole::Admin]).await?;
                let role: Option<String> = sql::query_scalar(
                    "SELECT role FROM invites WHERE org_id = $1 AND id = $2 \
                     AND accepted_at IS NULL AND revoked_at IS NULL FOR UPDATE",
                )
                .bind(org_id)
                .bind(invite_id)
                .fetch_optional(&mut *c)
                .await?;
                let role = role
                    .as_deref()
                    .and_then(OrgRole::from_db)
                    .ok_or_else(ApiError::not_found)?;
                if role == OrgRole::Owner && caller != OrgRole::Owner {
                    return Err(ApiError::forbidden());
                }
                sql::query("UPDATE invites SET revoked_at = now() WHERE org_id = $1 AND id = $2")
                    .bind(org_id)
                    .bind(invite_id)
                    .execute(&mut *c)
                    .await?;
                audit::append(
                    c,
                    org_id,
                    &audit::member_invite_revoked(actor, org_id, invite_id),
                )
                .await?;
                Ok::<_, ApiError>(())
            })
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/invites/accept`: the token is in the body so it stays out of access logs. The
/// caller is a signed-in human with a verified email (`401` / `403` before the token is looked
/// at); then every failure (unknown, reused, revoked, expired, other email, already a member) is
/// the same `404`. Single use: the invite row is locked and marked accepted in the transaction
/// that adds the membership, with a `member.joined` ledger event.
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
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<AcceptInvite>,
) -> Result<Json<AcceptedInvite>, ApiError> {
    let token = Zeroizing::new(input.token);
    let authorization = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(ApiError::unauthenticated)?;
    // Never the dev header: accepting needs a verified human.
    let (identity, user) = human_login(&state, authorization.as_bytes()).await?;
    let email = identity
        .email
        .as_deref()
        .map(|e| e.trim().to_lowercase())
        .filter(|e| !e.is_empty())
        .ok_or_else(ApiError::not_found)?;
    if token.is_empty() || token.len() > MAX_TOKEN_CHARS {
        return Err(ApiError::not_found());
    }
    let hash = token_hash(&token).to_vec();
    let hash_hex = to_hex(&hash);
    let user_id = user.user_id;
    let accepted = state
        .db()
        .with_user(user_id, move |c| {
            Box::pin(async move {
                bind_invite_hash(c, &hash_hex).await?;
                // Lock the open invite for this address: a concurrent accept waits here, then
                // finds it accepted and gets the same 404.
                let row = sql::query(
                    "SELECT id, org_id, role FROM invites \
                     WHERE token_hash = $1 AND email = $2 AND accepted_at IS NULL \
                     AND revoked_at IS NULL AND expires_at > now() FOR UPDATE",
                )
                .bind(hash)
                .bind(email)
                .fetch_optional(&mut *c)
                .await?
                .ok_or_else(ApiError::not_found)?;
                let invite_id: Uuid = row.try_get("id")?;
                let org_id: Uuid = row.try_get("org_id")?;
                let role = role_of(&row, "role")?;
                let member: bool = sql::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM memberships WHERE org_id = $1 AND user_id = $2)",
                )
                .bind(org_id)
                .bind(user_id)
                .fetch_one(&mut *c)
                .await?;
                if member {
                    return Err(ApiError::not_found());
                }
                // The join policy needs the invite still open, so insert before closing it.
                sql::query("INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, $3)")
                    .bind(org_id)
                    .bind(user_id)
                    .bind(role.as_str())
                    .execute(&mut *c)
                    .await?;
                sql::query("UPDATE invites SET accepted_at = now() WHERE id = $1")
                    .bind(invite_id)
                    .execute(&mut *c)
                    .await?;
                bind_org(c, org_id).await?;
                audit::append(
                    c,
                    org_id,
                    &audit::member_joined(user_id, org_id, invite_id, role),
                )
                .await?;
                Ok::<_, ApiError>(AcceptedInvite { org_id, role })
            })
        })
        .await?;
    Ok(Json(accepted))
}
