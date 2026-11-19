//! Sign-in and sign-out markers for the audit ledger (T1 task 5.1).
//!
//! Authentication itself happens at the OIDC issuer and on every request (bearer token). These
//! two routes let a client say "a session started" and "a session ended", so the org's ledger
//! records `auth.sign_in` and `auth.sign_out` once per session instead of once per request.
//! Both need a verified human bearer token (the dev header is refused), take no body and
//! return `204`. Sign-out is stateless: the client discards its tokens; the access token stays
//! valid until it expires. The event holds the user id and the issuer host only, never a token.

use axum::extract::State;
use axum::http::StatusCode;

use super::audit_append;
use super::responses::ReadErrors;
use crate::app::AppState;
use crate::audit;
use crate::auth::HumanSession;
use crate::problem::ApiError;

/// `POST /v1/auth/sign-in`: record `auth.sign_in` for the caller.
#[utoipa::path(
    post,
    path = "/v1/auth/sign-in",
    operation_id = "auth_sign_in",
    tag = "auth",
    summary = "Record a sign-in in the audit ledger",
    responses((status = 204, description = "Recorded"), ReadErrors),
)]
pub async fn sign_in(
    State(state): State<AppState>,
    session: HumanSession,
) -> Result<StatusCode, ApiError> {
    let event = audit::auth_sign_in(session.user_id, session.org_id, &session.issuer);
    audit_append(&state, session.org_id, event).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/auth/sign-out`: record `auth.sign_out` for the caller.
#[utoipa::path(
    post,
    path = "/v1/auth/sign-out",
    operation_id = "auth_sign_out",
    tag = "auth",
    summary = "Record a sign-out in the audit ledger",
    responses((status = 204, description = "Recorded"), ReadErrors),
)]
pub async fn sign_out(
    State(state): State<AppState>,
    session: HumanSession,
) -> Result<StatusCode, ApiError> {
    let event = audit::auth_sign_out(session.user_id, session.org_id, &session.issuer);
    audit_append(&state, session.org_id, event).await?;
    Ok(StatusCode::NO_CONTENT)
}
