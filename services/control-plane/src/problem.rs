//! RFC 9457 problem details (design decision 9). Built in-house: `http-api-problem` 0.60 is
//! RFC 7807-era and adds an axum-core dependency for a 40-line type. Every error response is
//! `application/problem+json` with a stable `type` URI, and never echoes a request body.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

use crate::db::sql;

/// Media type of every error body.
pub const PROBLEM_JSON: &str = "application/problem+json";

/// The kinds of error the API returns. Each has a fixed status, title and `type` URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Validation,
    Unprocessable,
    Unauthenticated,
    EmailVerificationRequired,
    /// `403`: authenticated, but not allowed to do this (e.g. not the org's owner).
    Forbidden,
    NotFound,
    Conflict,
    PayloadTooLarge,
    UnsupportedMediaType,
    Unavailable,
    Internal,
    NotImplemented,
}

impl Kind {
    pub fn status(self) -> StatusCode {
        match self {
            Kind::Validation => StatusCode::BAD_REQUEST,
            Kind::Unprocessable => StatusCode::UNPROCESSABLE_ENTITY,
            Kind::Unauthenticated => StatusCode::UNAUTHORIZED,
            Kind::EmailVerificationRequired => StatusCode::FORBIDDEN,
            Kind::Forbidden => StatusCode::FORBIDDEN,
            Kind::NotFound => StatusCode::NOT_FOUND,
            Kind::Conflict => StatusCode::CONFLICT,
            Kind::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Kind::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Kind::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Kind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Kind::NotImplemented => StatusCode::NOT_IMPLEMENTED,
        }
    }

    /// Stable identifier of the kind; the last segment of the `type` URI.
    pub fn slug(self) -> &'static str {
        match self {
            Kind::Validation => "validation",
            Kind::Unprocessable => "unprocessable",
            Kind::Unauthenticated => "unauthenticated",
            Kind::EmailVerificationRequired => "email-verification-required",
            Kind::Forbidden => "forbidden",
            Kind::NotFound => "not-found",
            Kind::Conflict => "conflict",
            Kind::PayloadTooLarge => "payload-too-large",
            Kind::UnsupportedMediaType => "unsupported-media-type",
            Kind::Unavailable => "unavailable",
            Kind::Internal => "internal",
            Kind::NotImplemented => "not-implemented",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Kind::Validation => "Invalid request",
            Kind::Unprocessable => "Request refused",
            Kind::Unauthenticated => "Authentication required",
            Kind::EmailVerificationRequired => "Email verification required",
            Kind::Forbidden => "Forbidden",
            Kind::NotFound => "Resource not found",
            Kind::Conflict => "Conflict",
            Kind::PayloadTooLarge => "Request body too large",
            Kind::UnsupportedMediaType => "Unsupported media type",
            Kind::Unavailable => "Service unavailable",
            Kind::Internal => "Internal error",
            Kind::NotImplemented => "Not implemented",
        }
    }

    /// The `type` URI. A URN, so it is stable and needs no hosted documentation page.
    pub fn type_uri(self) -> String {
        format!("urn:locksmith:problem:{}", self.slug())
    }
}

/// The JSON body of an error response.
#[derive(Debug, Serialize, ToSchema)]
pub struct Problem {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: &'static str,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// An API error: a [`Kind`] plus an optional human-readable detail that never contains request
/// data other than a field name.
#[derive(Debug)]
pub struct ApiError {
    pub kind: Kind,
    pub detail: Option<String>,
}

impl ApiError {
    pub fn new(kind: Kind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: Some(detail.into()),
        }
    }

    pub fn bare(kind: Kind) -> Self {
        Self { kind, detail: None }
    }

    pub fn validation(detail: impl Into<String>) -> Self {
        Self::new(Kind::Validation, detail)
    }

    /// `422`: the request is well formed but refused on its content (an unpinned workload
    /// policy, a private issuer address).
    pub fn unprocessable(detail: impl Into<String>) -> Self {
        Self::new(Kind::Unprocessable, detail)
    }

    pub fn not_found() -> Self {
        Self::bare(Kind::NotFound)
    }

    pub fn unauthenticated() -> Self {
        Self::bare(Kind::Unauthenticated)
    }

    /// `403`: the token is valid but its email is not verified (T1 spec: unverified email).
    pub fn email_verification_required() -> Self {
        Self::bare(Kind::EmailVerificationRequired)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.kind.status();
        let body = Problem {
            type_uri: self.kind.type_uri(),
            title: self.kind.title(),
            status: status.as_u16(),
            detail: self.detail,
        };
        let mut response = (status, Json(body)).into_response();
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON));
        response
    }
}

impl From<sql::Error> for ApiError {
    fn from(e: sql::Error) -> Self {
        use sqlx_core::error::ErrorKind;
        if let Some(db) = e.as_database_error() {
            match db.kind() {
                ErrorKind::UniqueViolation => {
                    return Self::new(
                        Kind::Conflict,
                        "a resource with that name already exists in this parent",
                    );
                }
                // Parents are RESTRICT-deleted (design decision 15): a parent with children
                // cannot be removed. Inserts check their parent first, so this is the delete.
                ErrorKind::ForeignKeyViolation => {
                    return Self::new(Kind::Conflict, "the resource still has child resources");
                }
                _ => {}
            }
        }
        match e {
            sql::Error::PoolTimedOut | sql::Error::Io(_) | sql::Error::PoolClosed => {
                tracing::warn!("database unavailable");
                Self::bare(Kind::Unavailable)
            }
            other => {
                // Log only the error class: never the statement, parameters or message text.
                let code = other
                    .as_database_error()
                    .and_then(|d| d.code().map(|c| c.into_owned()));
                tracing::error!(db_error_code = ?code, "database error");
                Self::bare(Kind::Internal)
            }
        }
    }
}
