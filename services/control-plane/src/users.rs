//! Users and personal orgs (T1 design decision 6).
//!
//! [`resolve`] turns a verified [`HumanIdentity`] into the user's personal org. A first sign-in
//! creates the org and the `users` row in one transaction; a repeat sign-in only reads. The
//! transaction takes a per-identity advisory lock before creating, so concurrent first requests
//! for the same `(issuer, subject)` produce exactly one user and one org.
//!
//! Identity linking: a new identity whose email the issuer reports as verified joins the
//! personal org of an existing user with the same verified email. Nothing links on an unverified
//! email, and an unverified identity is refused before any row is read or written ([`resolve`]).
//!
//! Only public identity claims are stored or logged here; a token never reaches this module.

use uuid::Uuid;

use crate::auth::human::HumanIdentity;
use crate::db::{Database, bind_org, sql};
use crate::problem::ApiError;

/// Name of an auto-created personal org. Renaming is a later change (T6).
pub const PERSONAL_ORG_NAME: &str = "Personal";

/// Whose org a verified identity acts in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedUser {
    pub user_id: Uuid,
    pub org_id: Uuid,
    /// The identity was seen for the first time by this call.
    pub created: bool,
    /// A new personal org was created by this call (false when the identity joined an existing
    /// one by verified email).
    pub org_created: bool,
}

/// Find or create the user for `identity` and return its personal org.
///
/// `403` ([`ApiError::email_verification_required`]) when the identity's email is not verified,
/// before the database is touched: an unverified address may be someone else's, so it gets no
/// user, no org and no link.
pub async fn resolve(db: &Database, identity: &HumanIdentity) -> Result<ResolvedUser, ApiError> {
    if !identity.email_verified {
        return Err(ApiError::email_verification_required());
    }
    let email = identity
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty());
    let issuer = identity.issuer.clone();
    let subject = identity.subject.clone();
    let email_owned = email.map(str::to_owned);
    db.with_login(&identity.issuer, &identity.subject, email, move |c| {
        Box::pin(async move { resolve_in_tx(c, &issuer, &subject, email_owned.as_deref()).await })
    })
    .await
}

async fn find(
    c: &mut sql::PgConnection,
    issuer: &str,
    subject: &str,
) -> sql::Result<Option<(Uuid, Uuid, Option<String>)>> {
    sql::query_as("SELECT id, personal_org_id, email FROM users WHERE issuer = $1 AND subject = $2")
        .bind(issuer)
        .bind(subject)
        .fetch_optional(c)
        .await
}

async fn resolve_in_tx(
    c: &mut sql::PgConnection,
    issuer: &str,
    subject: &str,
    email: Option<&str>,
) -> Result<ResolvedUser, ApiError> {
    if let Some(found) = find(c, issuer, subject).await? {
        return known(c, found, email).await;
    }

    // Serialise first sign-ins of one identity: the loser waits here, then finds the winner's
    // committed row. The unique `(issuer, subject)` key is the backstop (a violation is a `409`).
    sql::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("user:{}:{issuer}{subject}", issuer.len()))
        .execute(&mut *c)
        .await?;
    if let Some(found) = find(c, issuer, subject).await? {
        return known(c, found, email).await;
    }

    // Link by verified email: join the personal org of an existing user with the same address.
    let linked: Option<Uuid> = match email {
        Some(email) => {
            sql::query_scalar(
                "SELECT personal_org_id FROM users \
                 WHERE email_verified AND lower(email) = lower($1) \
                 ORDER BY created_at, id LIMIT 1",
            )
            .bind(email)
            .fetch_optional(&mut *c)
            .await?
        }
        None => None,
    };
    let org_id = linked.unwrap_or_else(Uuid::now_v7);
    bind_org(c, org_id).await?;
    if linked.is_none() {
        sql::query("INSERT INTO orgs (id, name) VALUES ($1, $2)")
            .bind(org_id)
            .bind(PERSONAL_ORG_NAME)
            .execute(&mut *c)
            .await?;
    }
    let user_id: Uuid = sql::query_scalar(
        "INSERT INTO users (issuer, subject, email, email_verified, personal_org_id) \
         VALUES ($1, $2, $3, true, $4) RETURNING id",
    )
    .bind(issuer)
    .bind(subject)
    .bind(email)
    .bind(org_id)
    .fetch_one(&mut *c)
    .await?;
    Ok(ResolvedUser {
        user_id,
        org_id,
        created: true,
        org_created: linked.is_none(),
    })
}

/// A known identity: bind its org and keep its email claim current.
async fn known(
    c: &mut sql::PgConnection,
    (user_id, org_id, stored_email): (Uuid, Uuid, Option<String>),
    email: Option<&str>,
) -> Result<ResolvedUser, ApiError> {
    if stored_email.as_deref() != email {
        bind_org(c, org_id).await?;
        sql::query("UPDATE users SET email = $1, email_verified = true WHERE id = $2")
            .bind(email)
            .bind(user_id)
            .execute(c)
            .await?;
    }
    Ok(ResolvedUser {
        user_id,
        org_id,
        created: false,
        org_created: false,
    })
}
