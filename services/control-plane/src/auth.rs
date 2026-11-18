//! Org binding. Until T1 lands, the org is chosen with the dev-only `X-Locksmith-Dev-Org`
//! header, honoured only when dev auth is enabled. T1 replaces this extractor with JWT
//! verification; handlers depend only on [`OrgBinding`].
//!
//! The `/internal/v1` routes use [`ServiceOrgBinding`] instead: the caller is the gateway
//! service, authenticated by a static bearer token compared in constant time (S3 design
//! decision 2), which names the org it acts for in [`SERVICE_ORG_HEADER`].

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::app::AppState;
use crate::problem::ApiError;

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
    type Rejection = Unauthenticated;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if !state.dev_auth() {
            return Err(Unauthenticated);
        }
        let value = parts.headers.get(DEV_ORG_HEADER).ok_or(Unauthenticated)?;
        let org_id = value
            .to_str()
            .ok()
            .and_then(|s| Uuid::parse_str(s.trim()).ok())
            .ok_or(Unauthenticated)?;
        tracing::Span::current().record("org.id", tracing::field::display(org_id));
        Ok(Self { org_id })
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
