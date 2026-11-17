//! Org binding. Until T1 lands, the org is chosen with the dev-only `X-Locksmith-Dev-Org`
//! header, honoured only when dev auth is enabled. T1 replaces this extractor with JWT
//! verification; handlers depend only on [`OrgBinding`].

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::app::AppState;
use crate::problem::ApiError;

pub const DEV_ORG_HEADER: &str = "x-locksmith-dev-org";

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
        Ok(Self { org_id })
    }
}
