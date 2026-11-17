//! Request extractors whose rejections are problem details, and never echo request data
//! other than a field name.

use axum::body::Bytes;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, FromRequestParts, Path, Query, Request};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use serde::de::DeserializeOwned;
use zeroize::Zeroize;

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
            JsonRejection::JsonDataError(e) => shape_problem(&e.body_text()),
            _ => ApiError::validation("request body is not valid JSON"),
        },
    }
}

/// JSON body that carries a secret value (S2 design decision 5).
///
/// Unlike [`ApiJson`], the body is never handed to `axum::Json` or `serde_json::Value`: it is
/// buffered once, deserialized straight into `T` (whose value field deserializes into
/// `SecretBytes`), and the buffer is wiped afterwards whether parsing succeeded or not. Errors
/// name at most a field, never a value. Copies made inside hyper and serde_json's escape
/// scratch buffer are outside this code's control; this is best effort, as for the KMS client.
pub struct SecretJson<T>(pub T);

/// Wipes the request body when dropped, if no other handle shares the buffer.
struct WipeOnDrop(Option<Bytes>);

impl Drop for WipeOnDrop {
    fn drop(&mut self) {
        if let Some(bytes) = self.0.take()
            && let Ok(mut owned) = bytes.try_into_mut()
        {
            owned.as_mut().zeroize();
        }
    }
}

impl<S, T> FromRequest<S> for SecretJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        let is_json = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(|m| {
                let m = m.trim().to_ascii_lowercase();
                m == "application/json" || (m.starts_with("application/") && m.ends_with("+json"))
            })
            .unwrap_or(false);
        if !is_json {
            return Err(ApiError::new(
                Kind::UnsupportedMediaType,
                "expected content-type: application/json",
            ));
        }
        let body = Bytes::from_request(req, state).await.map_err(|rejection| {
            match rejection.status() {
                StatusCode::PAYLOAD_TOO_LARGE => ApiError::bare(Kind::PayloadTooLarge),
                _ => ApiError::validation("request body could not be read"),
            }
        })?;
        let body = WipeOnDrop(Some(body));
        let bytes = body.0.as_deref().unwrap_or_default();
        // Objects only: serde would also accept a struct as a JSON array of its fields.
        if bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
            return Err(ApiError::validation("request body must be a JSON object"));
        }
        let parsed = serde_json::from_slice::<T>(bytes);
        drop(body);
        parsed.map(Self).map_err(|e| map_serde_error(&e))
    }
}

/// A serde_json error as a problem that names at most a field (its message can quote values).
fn map_serde_error(e: &serde_json::Error) -> ApiError {
    if !e.is_data() {
        return ApiError::validation("request body is not valid JSON");
    }
    shape_problem(&e.to_string())
}

/// A serde data error as a validation problem. serde messages can quote request values
/// (`invalid type: string "..."`), so only a field name is ever passed on.
fn shape_problem(text: &str) -> ApiError {
    if let Some(f) = quoted_after(text, "unknown field `") {
        ApiError::validation(format!("unknown field `{f}`"))
    } else if let Some(f) = quoted_after(text, "missing field `") {
        ApiError::validation(format!("missing field `{f}`"))
    } else {
        ApiError::validation("request body does not match the expected shape")
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
