//! Request extractors whose rejections are problem details, and never echo request data
//! other than a field name.

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, FromRequestParts, Path, Query, Request};
use axum::http::StatusCode;
use axum::http::request::Parts;
use serde::de::DeserializeOwned;

use crate::problem::{ApiError, Kind};

/// JSON body. Input types derive `deny_unknown_fields`, so a stray `value` is a `400`.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(v)) => Ok(Self(v)),
            Err(rejection) => Err(map_json_rejection(rejection)),
        }
    }
}

fn map_json_rejection(rejection: JsonRejection) -> ApiError {
    match rejection.status() {
        StatusCode::PAYLOAD_TOO_LARGE => ApiError::bare(Kind::PayloadTooLarge),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => ApiError::new(
            Kind::UnsupportedMediaType,
            "expected content-type: application/json",
        ),
        _ => match rejection {
            JsonRejection::JsonDataError(e) => {
                // serde messages can quote request values (`invalid type: string "..."`), so
                // only a field name is ever passed on.
                let text = e.body_text();
                if let Some(f) = quoted_after(&text, "unknown field `") {
                    ApiError::validation(format!("unknown field `{f}`"))
                } else if let Some(f) = quoted_after(&text, "missing field `") {
                    ApiError::validation(format!("missing field `{f}`"))
                } else {
                    ApiError::validation("request body does not match the expected shape")
                }
            }
            _ => ApiError::validation("request body is not valid JSON"),
        },
    }
}

/// The identifier between `marker` and the next backtick, if short and plain.
fn quoted_after<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    let rest = &text[text.find(marker)? + marker.len()..];
    let name = &rest[..rest.find('`')?];
    (name.len() <= 64 && !name.chars().any(char::is_control)).then_some(name)
}

/// Path parameters. A malformed id cannot name an existing resource, so it is a `404`.
pub struct ApiPath<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiPath<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(v)| Self(v))
            .map_err(|_| ApiError::not_found())
    }
}

/// Query string; input types derive `deny_unknown_fields`.
pub struct ApiQuery<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(v)| Self(v))
            .map_err(|_| ApiError::validation("invalid query parameters"))
    }
}
