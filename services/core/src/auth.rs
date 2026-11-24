//! Caller authentication: a shared service token in `Authorization: Bearer` (design.md
//! decision 5). Compared in constant time; never logged or returned.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::{StatusCode, header};
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;

use crate::app::AppState;

/// No `Debug`, `Display` or `Clone`.
pub struct ServiceToken(SecretString);

impl ServiceToken {
    pub fn new(token: SecretString) -> Self {
        Self(token)
    }

    /// Only the length can leak through timing, not the bytes.
    pub fn matches(&self, presented: &[u8]) -> bool {
        self.0.expose_secret().as_bytes().ct_eq(presented).into()
    }
}

fn bearer(value: &[u8]) -> Option<&[u8]> {
    let (scheme, rest) = value.split_at_checked(7)?;
    scheme.eq_ignore_ascii_case(b"bearer ").then_some(rest)
}

/// Middleware for every route except the probes: 401 unless the bearer token matches.
pub async fn require_service_token(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| bearer(v.as_bytes()))
        .is_some_and(|t| state.token().matches(t));
    if ok {
        next.run(req).await
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}
