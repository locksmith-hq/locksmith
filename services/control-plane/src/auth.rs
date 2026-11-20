//! Org binding. A human request carries a bearer access token, verified against the configured
//! OIDC issuer's JWKS ([`human`], [`jwks`]); the dev-only `X-Locksmith-Dev-Org` header is
//! honoured only when dev auth is enabled and no bearer token is sent. Handlers depend only on
//! [`OrgBinding`].
//!
//! The `/internal/v1` routes use [`ServiceOrgBinding`] instead: the caller is the gateway
//! service, authenticated by a static bearer token compared in constant time (S3 design
//! decision 2), which names the org it acts for in [`SERVICE_ORG_HEADER`].

pub mod external;
pub mod human;
pub mod issuers;
pub mod jwks;

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::app::AppState;
use crate::problem::ApiError;
use crate::users;

pub const DEV_ORG_HEADER: &str = "x-locksmith-dev-org";
/// The org an internal (service-token) request acts for.
pub const SERVICE_ORG_HEADER: &str = "x-locksmith-org";

/// The org a request is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgBinding {
    pub org_id: Uuid,
}

/// Rejection for a request with no valid org binding: `401` problem details, no detail about why.
#[derive(Debug)]
pub struct Unauthenticated;

impl IntoResponse for Unauthenticated {
    fn into_response(self) -> Response {
        ApiError::unauthenticated().into_response()
    }
}

impl FromRequestParts<AppState> for OrgBinding {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // A bearer token is a human credential: it is verified, and a bad one is never
        // downgraded to the dev header. Without human auth configured it is refused too.
        if let Some(value) = parts.headers.get(header::AUTHORIZATION) {
            let (_, user) = human_login(state, value.as_bytes()).await?;
            tracing::Span::current().record("org.id", tracing::field::display(user.org_id));
            return Ok(Self {
                org_id: user.org_id,
            });
        }
        if !state.dev_auth() {
            return Err(ApiError::unauthenticated());
        }
        let value = parts
            .headers
            .get(DEV_ORG_HEADER)
            .ok_or_else(ApiError::unauthenticated)?;
        let org_id = value
            .to_str()
            .ok()
            .and_then(|s| Uuid::parse_str(s.trim()).ok())
            .ok_or_else(ApiError::unauthenticated)?;
        tracing::Span::current().record("org.id", tracing::field::display(org_id));
        Ok(Self { org_id })
    }
}

/// Verify the bearer token in an `Authorization` value and resolve its user (T1): `401` for any
/// bad token, `403` for an unverified email. A first sign-in creates the user and personal org.
async fn human_login(
    state: &AppState,
    authorization: &[u8],
) -> Result<(human::HumanIdentity, users::ResolvedUser), ApiError> {
    let auth = state.human_auth().ok_or_else(ApiError::unauthenticated)?;
    let token = bearer(authorization)
        .and_then(|t| std::str::from_utf8(t).ok())
        .ok_or_else(ApiError::unauthenticated)?;
    let identity = auth
        .verify(token)
        .await
        .map_err(|_| ApiError::unauthenticated())?;
    let user = users::resolve(state.db(), &identity).await?;
    Ok((identity, user))
}

/// A signed-in human: requires a verified bearer token (the dev header is never accepted) and
/// names the user as well as the org. Used by the sign-in and sign-out routes, whose audit
/// events need the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanSession {
    pub user_id: Uuid,
    pub org_id: Uuid,
    /// The issuer that vouched for the identity (public configuration, not a claim to trust
    /// beyond verification).
    pub issuer: String,
}

impl FromRequestParts<AppState> for HumanSession {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let value = parts
            .headers
            .get(header::AUTHORIZATION)
            .ok_or_else(ApiError::unauthenticated)?;
        let (identity, user) = human_login(state, value.as_bytes()).await?;
        tracing::Span::current().record("org.id", tracing::field::display(user.org_id));
        Ok(Self {
            user_id: user.user_id,
            org_id: user.org_id,
            issuer: identity.issuer,
        })
    }
}

/// The gateway service token (S3 design decision 2). No `Debug`, `Display` or `Clone`; the
/// value is only ever compared, in constant time, and never logged or returned.
pub struct ServiceToken(SecretString);

impl ServiceToken {
    pub fn new(token: SecretString) -> Self {
        Self(token)
    }

    /// Constant-time equality with `presented`. Only the length can leak through timing
    /// (`subtle` returns early on a length mismatch); the token's bytes cannot.
    pub fn matches(&self, presented: &[u8]) -> bool {
        self.0.expose_secret().as_bytes().ct_eq(presented).into()
    }
}

/// The org an internal request acts for, after its service token was verified. Built only by
/// its extractor: `401` when no token is configured (fail closed), when the bearer token is
/// missing or wrong, or when [`SERVICE_ORG_HEADER`] is missing or not a UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceOrgBinding {
    pub org_id: Uuid,
}

impl FromRequestParts<AppState> for ServiceOrgBinding {
    type Rejection = Unauthenticated;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let expected = state.service_token().ok_or(Unauthenticated)?;
        let presented = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| bearer(v.as_bytes()))
            .ok_or(Unauthenticated)?;
        if !expected.matches(presented) {
            return Err(Unauthenticated);
        }
        let org_id = parts
            .headers
            .get(SERVICE_ORG_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| Uuid::parse_str(s.trim()).ok())
            .ok_or(Unauthenticated)?;
        tracing::Span::current().record("org.id", tracing::field::display(org_id));
        Ok(Self { org_id })
    }
}

/// The credential of an `Authorization: Bearer <token>` value (scheme case-insensitive,
/// surrounding whitespace trimmed, empty refused). The one bearer parser: the gateway uses it for
/// agent tokens too.
pub fn bearer(value: &[u8]) -> Option<&[u8]> {
    const SCHEME: &[u8] = b"bearer ";
    let (scheme, rest) = value.split_at_checked(SCHEME.len())?;
    scheme
        .eq_ignore_ascii_case(SCHEME)
        .then(|| rest.trim_ascii())
        .filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_parses_the_scheme_case_insensitively() {
        assert_eq!(bearer(b"Bearer abc"), Some(&b"abc"[..]));
        assert_eq!(bearer(b"bearer  abc "), Some(&b"abc"[..]));
        assert_eq!(bearer(b"Basic abc"), None);
        assert_eq!(bearer(b"Bearer "), None);
        assert_eq!(bearer(b"Bearer"), None);
    }

    #[test]
    fn service_token_matches_only_the_exact_value() {
        let t = ServiceToken::new(SecretString::from("0123456789abcdef0123456789abcdef"));
        assert!(t.matches(b"0123456789abcdef0123456789abcdef"));
        assert!(!t.matches(b"0123456789abcdef0123456789abcdeF"));
        assert!(!t.matches(b"0123456789abcdef0123456789abcde"));
        assert!(!t.matches(b""));
    }
}
