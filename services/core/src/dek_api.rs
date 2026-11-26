//! `POST /v1/deks/wrap` and `POST /v1/deks/unwrap` (task 3.3).
//!
//! The core generates the data key inside itself, wraps it through the KMS (OpenBao transit)
//! and keeps the key in a short-lived in-memory store addressed by an opaque handle. Neither
//! endpoint ever returns key bytes: wrap returns the wrapped blob and a handle, unwrap returns
//! a handle. Handles expire after [`HANDLE_TTL`] and the store holds at most [`MAX_HANDLES`].
//! Errors are problem+json with static text; the KMS error text (which may carry an address)
//! is never forwarded.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use http::{HeaderValue, StatusCode, header};
use ls_crypto::SecretKey32;
use ls_envelope::{
    BaoToken, Binding, DataKey, Header, KeyId, KeyWrapper, OpenBaoTransit, Purpose, WrapError,
    WrapKeyId, WrappedDek,
};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app::AppState;
use crate::audit_api::problem;
use crate::config::DekKms;

/// How long a handle stays valid.
pub const HANDLE_TTL: Duration = Duration::from_secs(300);
/// Most handles held at once; further wraps answer 503 until some expire.
pub const MAX_HANDLES: usize = 4096;

/// The future [`DekKeyWrapper::wrap`] returns.
pub type WrapFuture<'a> = Pin<Box<dyn Future<Output = Result<WrappedDek, WrapError>> + Send + 'a>>;
/// The future [`DekKeyWrapper::unwrap`] returns.
pub type UnwrapFuture<'a> =
    Pin<Box<dyn Future<Output = Result<SecretKey32, WrapError>> + Send + 'a>>;

/// Object-safe form of [`KeyWrapper`], so the state holds an `Arc<dyn ...>`.
pub trait DekKeyWrapper: Send + Sync {
    fn wrap<'a>(&'a self, dek: &'a DataKey, binding: &'a Binding) -> WrapFuture<'a>;
    fn unwrap<'a>(&'a self, wrapped: &'a WrappedDek, binding: &'a Binding) -> UnwrapFuture<'a>;
}

impl<T: KeyWrapper + Send + Sync> DekKeyWrapper for T {
    fn wrap<'a>(&'a self, dek: &'a DataKey, binding: &'a Binding) -> WrapFuture<'a> {
        Box::pin(KeyWrapper::wrap(self, dek, binding))
    }
    fn unwrap<'a>(&'a self, wrapped: &'a WrappedDek, binding: &'a Binding) -> UnwrapFuture<'a> {
        Box::pin(KeyWrapper::unwrap(self, wrapped, binding))
    }
}

/// Build the OpenBao transit wrapper from configuration (token zeroized on drop).
pub fn openbao(config: &DekKms) -> Result<Arc<dyn DekKeyWrapper>, WrapError> {
    let key = WrapKeyId::new(&config.key, config.key_version)?;
    let token = BaoToken::new(config.token.expose_secret().to_owned());
    Ok(Arc::new(OpenBaoTransit::new(&config.addr, key, token)?))
}

/// Data keys the core holds for handle holders. No `Debug`, `Display` or `Clone`.
#[derive(Default)]
pub struct HandleStore {
    inner: Mutex<HashMap<String, (Instant, DataKey)>>,
}

impl HandleStore {
    /// Store `dek` under a fresh random handle; `None` when the store is full or the random
    /// source fails.
    fn insert(&self, dek: DataKey) -> Option<String> {
        let mut raw = [0u8; 16];
        getrandom::getrandom(&mut raw).ok()?;
        let handle = B64URL.encode(raw);
        let now = Instant::now();
        let mut map = self.inner.lock().ok()?;
        map.retain(|_, (at, _)| now.duration_since(*at) < HANDLE_TTL);
        if map.len() >= MAX_HANDLES {
            return None;
        }
        map.insert(handle.clone(), (now, dek));
        Some(handle)
    }

    /// Number of live handles (for tests and metrics).
    pub fn len(&self) -> usize {
        let now = Instant::now();
        self.inner.lock().map_or(0, |m| {
            m.values()
                .filter(|(at, _)| now.duration_since(*at) < HANDLE_TTL)
                .count()
        })
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum PurposeDto {
    SecretPayload,
    DekWrap,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingDto {
    org_id: Uuid,
    secret_id: Uuid,
    version: i64,
    purpose: PurposeDto,
}

impl BindingDto {
    fn to_binding(&self) -> Option<Binding> {
        // OpenAPI: int32, minimum 1.
        let version = i32::try_from(self.version)
            .ok()
            .filter(|v| *v >= 1)
            .and_then(|v| u32::try_from(v).ok())?;
        Some(Binding {
            org_id: *self.org_id.as_bytes(),
            secret_id: *self.secret_id.as_bytes(),
            version,
            purpose: match self.purpose {
                PurposeDto::SecretPayload => Purpose::SecretPayload,
                PurposeDto::DekWrap => Purpose::DekWrap,
            },
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WrapRequest {
    binding: BindingDto,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnwrapRequest {
    binding: BindingDto,
    wrapped_dek: String,
}

#[derive(Serialize)]
struct WrapResponse {
    dek_handle: String,
    key_id: String,
    wrapped_dek: String,
}

#[derive(Serialize)]
struct UnwrapResponse {
    dek_handle: String,
    key_id: String,
}

fn no_store<T: Serialize>(body: T) -> Response {
    (
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(body),
    )
        .into_response()
}

/// A bad binding or a blob the KMS refuses to open is the caller's input (400); anything
/// else is the dependency (503).
fn kms_problem(e: &WrapError) -> Response {
    match e {
        WrapError::Purpose
        | WrapError::Format(_)
        | WrapError::KeyMismatch
        | WrapError::InvalidKeyId
        | WrapError::Rejected { status: 400 } => {
            problem(StatusCode::BAD_REQUEST, "wrapped key or binding rejected")
        }
        _ => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "key management unavailable",
        ),
    }
}

pub async fn wrap(State(state): State<AppState>, body: Bytes) -> Response {
    let Some(binding) = serde_json::from_slice::<WrapRequest>(&body)
        .ok()
        .and_then(|r| r.binding.to_binding())
    else {
        return problem(StatusCode::BAD_REQUEST, "malformed request");
    };
    let Some(kms) = state.dek_kms() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "key management not configured",
        );
    };
    let (Ok(key), Some(id)) = (SecretKey32::random(), random_key_id()) else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "key generation unavailable",
        );
    };
    let dek = DataKey::from_parts(id, key);
    let wrapped = match kms.wrap(&dek, &binding).await {
        Ok(w) => w,
        Err(e) => return kms_problem(&e),
    };
    let key_id = wrapped.key_id().to_string();
    let wrapped_dek = B64.encode(wrapped.as_bytes());
    let Some(dek_handle) = state.deks().insert(dek) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "too many live key handles");
    };
    no_store(WrapResponse {
        dek_handle,
        key_id,
        wrapped_dek,
    })
}

pub async fn unwrap(State(state): State<AppState>, body: Bytes) -> Response {
    let Some(req) = serde_json::from_slice::<UnwrapRequest>(&body).ok() else {
        return problem(StatusCode::BAD_REQUEST, "malformed request");
    };
    let Some(binding) = req.binding.to_binding() else {
        return problem(StatusCode::BAD_REQUEST, "malformed request");
    };
    let Some(wrapped) = B64
        .decode(req.wrapped_dek.as_bytes())
        .ok()
        .and_then(|b| WrappedDek::from_bytes(b).ok())
    else {
        return problem(StatusCode::BAD_REQUEST, "malformed wrapped key");
    };
    let Some(kms) = state.dek_kms() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "key management not configured",
        );
    };
    let key = match kms.unwrap(&wrapped, &binding).await {
        Ok(k) => k,
        Err(e) => return kms_problem(&e),
    };
    let key_id = wrapped.key_id().to_string();
    let Some(id) = Header::parse(wrapped.as_bytes()).ok().map(|h| h.key_id) else {
        return problem(StatusCode::BAD_REQUEST, "malformed wrapped key");
    };
    let Some(dek_handle) = state.deks().insert(DataKey::from_parts(id, key)) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "too many live key handles");
    };
    no_store(UnwrapResponse { dek_handle, key_id })
}

fn random_key_id() -> Option<KeyId> {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).ok()?;
    Some(KeyId(id))
}
