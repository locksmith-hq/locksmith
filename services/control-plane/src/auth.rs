//! Org binding. A human request carries a bearer access token, verified against the configured
//! OIDC issuer's JWKS ([`human`], [`jwks`]); the dev-only `X-Locksmith-Dev-Org` header is
//! honoured only when dev auth is enabled and no bearer token is sent. Handlers depend only on
//! [`OrgBinding`].
//!
//! T6: a human names the org it acts in with [`ORG_HEADER`]. The header is never trusted alone:
//! the user's membership in that org is checked in the binding transaction
//! ([`users::bind`]), and a miss (not a member, no such org, a malformed id) is the same `404`.
//! Without the header the request acts in the user's personal org. Removing a membership takes
//! effect on the next request: nothing caches a binding.
//!
//! The `/internal/v1` routes use [`ServiceOrgBinding`] instead: the caller is the gateway
//! service, authenticated by a static bearer token compared in constant time (S3 design
//! decision 2), which names the org it acts for in [`SERVICE_ORG_HEADER`].

pub mod abuse;
pub mod external;
pub mod human;
pub mod issuers;
pub mod jwks;
pub mod jwt;

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::Instrument;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::app::AppState;
use crate::problem::ApiError;
use crate::users;

pub const DEV_ORG_HEADER: &str = "x-locksmith-dev-org";
/// The org an internal (service-token) request acts for.
pub const SERVICE_ORG_HEADER: &str = "x-locksmith-org";
/// The org a signed-in human selects (T6). Same name as [`SERVICE_ORG_HEADER`]; the two never
/// meet, since internal routes use [`ServiceOrgBinding`].
pub const ORG_HEADER: &str = "x-locksmith-org";

/// A member's role in an org. Data only in T6: member management is enforced, the rest is T2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum OrgRole {
    Owner,
    Admin,
    Member,
}

impl OrgRole {
    /// The stored form (the `memberships.role` check constraint).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }

    /// Parse the stored form; `None` for anything else.
    pub fn from_db(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            _ => None,
        }
    }
}

/// The verified user behind a human binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundUser {
    pub user_id: Uuid,
    /// The default org when no [`ORG_HEADER`] is sent.
    pub personal_org_id: Uuid,
}

/// The org a request is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgBinding {
    pub org_id: Uuid,
    /// The caller's role in `org_id`, read from `memberships` in the binding transaction. The
    /// dev-only header names no user and acts as `owner`.
    pub role: OrgRole,
    /// The signed-in user; `None` for the dev-only header.
    pub user: Option<BoundUser>,
}

impl OrgBinding {
    /// The ledger actor: the user, or the dev-auth service actor.
    pub fn actor(&self) -> ls_audit::Actor {
        self.user.map_or(crate::audit::DEV_AUTH_ACTOR, |u| {
            ls_audit::Actor::User(u.user_id)
        })
    }

    /// `403` unless the caller's role is one of `allowed`.
    pub fn require(&self, allowed: &[OrgRole]) -> Result<(), ApiError> {
        if allowed.contains(&self.role) {
            Ok(())
        } else {
            Err(ApiError::forbidden())
        }
    }
}

/// Bind a verified human to `requested` (or their personal org) after the membership check:
/// `404` when they are not a member. Shared by [`OrgBinding`] and the hub MCP tools.
pub async fn bind_human(
    state: &AppState,
    identity: &human::HumanIdentity,
    requested: Option<Uuid>,
) -> Result<OrgBinding, ApiError> {
    let membership = users::bind(state.db(), identity, requested)
        .await?
        .ok_or_else(ApiError::not_found)?;
    Ok(OrgBinding {
        org_id: membership.org_id,
        role: membership.role,
        user: Some(BoundUser {
            user_id: membership.user.user_id,
            personal_org_id: membership.user.org_id,
        }),
    })
}

/// The org named by [`ORG_HEADER`]: `Ok(None)` when absent, `404` when it is not a UUID (it
/// cannot name an org the caller belongs to).
fn requested_org(parts: &Parts) -> Result<Option<Uuid>, ApiError> {
    parts
        .headers
        .get(ORG_HEADER)
        .map(|v| {
            v.to_str()
                .ok()
                .and_then(|s| Uuid::parse_str(s.trim()).ok())
                .ok_or_else(ApiError::not_found)
        })
        .transpose()
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
            let identity = verify_bearer(state, value.as_bytes()).await?;
            let requested = requested_org(parts)?;
            let span = tracing::info_span!("org.select", org.selected = requested.is_some());
            let binding = bind_human(state, &identity, requested)
                .instrument(span)
                .await?;
            tracing::Span::current().record("org.id", tracing::field::display(binding.org_id));
            return Ok(binding);
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
        Ok(Self {
            org_id,
            role: OrgRole::Owner,
            user: None,
        })
    }
}

/// Verify the bearer token in an `Authorization` value: `401` for any bad token.
async fn verify_bearer(
    state: &AppState,
    authorization: &[u8],
) -> Result<human::HumanIdentity, ApiError> {
    let auth = state.human_auth().ok_or_else(ApiError::unauthenticated)?;
    let token = bearer(authorization)
        .and_then(|t| std::str::from_utf8(t).ok())
        .ok_or_else(ApiError::unauthenticated)?;
    auth.verify(token)
        .await
        .map_err(|_| ApiError::unauthenticated())
}

/// Verify the bearer token in an `Authorization` value and resolve its user (T1): `401` for any
/// bad token, `403` for an unverified email. A first sign-in creates the user and personal org.
pub(crate) async fn human_login(
    state: &AppState,
    authorization: &[u8],
) -> Result<(human::HumanIdentity, users::ResolvedUser), ApiError> {
    let identity = verify_bearer(state, authorization).await?;
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

/// The `WWW-Authenticate` challenge of a refused bearer request: `Bearer`, then
/// `error="invalid_token"` when a token was presented and `resource_metadata="<url>"` when the
/// endpoint publishes protected-resource metadata, joined with `", "`. A value that is not a valid
/// header falls back to the bare scheme. The one builder for the hub and the gateway `/mcp`.
pub fn bearer_challenge(
    token_presented: bool,
    resource_metadata: Option<&str>,
) -> axum::http::HeaderValue {
    let mut params = Vec::new();
    if token_presented {
        params.push(r#"error="invalid_token""#.to_owned());
    }
    if let Some(url) = resource_metadata {
        params.push(format!(r#"resource_metadata="{url}""#));
    }
    let value = if params.is_empty() {
        "Bearer".to_owned()
    } else {
        format!("Bearer {}", params.join(", "))
    };
    axum::http::HeaderValue::from_str(&value)
        .unwrap_or_else(|_| axum::http::HeaderValue::from_static("Bearer"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_challenge_is_byte_identical_to_the_old_forms() {
        let u = "https://hub.example/.well-known/oauth-protected-resource";
        // Hub, as built before: with and without a presented token.
        assert_eq!(
            bearer_challenge(true, Some(u)).as_bytes(),
            format!(r#"Bearer error="invalid_token", resource_metadata="{u}""#).as_bytes()
        );
        assert_eq!(
            bearer_challenge(false, Some(u)).as_bytes(),
            format!(r#"Bearer resource_metadata="{u}""#).as_bytes()
        );
        // Gateway, as built before.
        assert_eq!(
            bearer_challenge(true, None).as_bytes(),
            br#"Bearer error="invalid_token""#
        );
        assert_eq!(bearer_challenge(false, None).as_bytes(), b"Bearer");
        // An invalid header value falls back to the bare scheme.
        assert_eq!(bearer_challenge(false, Some("a\nb")).as_bytes(), b"Bearer");
    }

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
