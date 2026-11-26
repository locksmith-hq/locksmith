//! `POST /v1/audit/checkpoints` (task 3.1): sign `{org, seq, head hash, time}`.
//!
//! The message is `ls_audit::CheckpointBody::message()` (the same bytes the control plane's
//! checkpoint job signs), signed with the OpenBao transit Ed25519 key through a
//! [`CheckpointSigner`]. Message and signature are public; the OpenBao token stays inside
//! `ls_envelope::TransitSigner`. Errors are problem+json with static text.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use http::{HeaderValue, StatusCode, header};
use ls_audit::CheckpointBody;
use ls_envelope::{BaoToken, TransitSigner, WrapError};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit_api::problem;
use crate::config::CheckpointKms;

/// A checkpoint signature and the key that made it (`<transit key>:<version>`).
pub struct Signed {
    pub key_id: String,
    pub signature: [u8; 64],
}

/// The future [`CheckpointSigner::sign`] returns.
pub type SignFuture<'a> = Pin<Box<dyn Future<Output = Result<Signed, WrapError>> + Send + 'a>>;

/// Signs checkpoint messages with Ed25519. Object-safe so the state holds `Arc<dyn ...>`.
pub trait CheckpointSigner: Send + Sync {
    fn sign<'a>(&'a self, message: &'a [u8]) -> SignFuture<'a>;
}

impl CheckpointSigner for TransitSigner {
    fn sign<'a>(&'a self, message: &'a [u8]) -> SignFuture<'a> {
        Box::pin(async move {
            let s = TransitSigner::sign(self, message).await?;
            let signature =
                <[u8; 64]>::try_from(s.signature.as_slice()).map_err(|_| WrapError::BadResponse)?;
            Ok(Signed {
                key_id: format!("{}:{}", self.key(), s.key_version),
                signature,
            })
        })
    }
}

/// Build the OpenBao transit signer from configuration (token zeroized on drop).
pub fn openbao(config: &CheckpointKms) -> Result<Arc<dyn CheckpointSigner>, WrapError> {
    let token = BaoToken::new(config.token.expose_secret().to_owned());
    Ok(Arc::new(TransitSigner::new(
        &config.addr,
        &config.key,
        token,
    )?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignRequest {
    org_id: Uuid,
    seq: u64,
    hash: String,
    at: String,
}

#[derive(Serialize)]
struct SignResponse {
    key_id: String,
    signature: String,
}

fn parse_hash(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn parse_body(req: &SignRequest) -> Option<CheckpointBody> {
    let at = OffsetDateTime::parse(&req.at, &Rfc3339).ok()?;
    Some(CheckpointBody {
        org_id: req.org_id,
        seq: (req.seq >= 1 && i64::try_from(req.seq).is_ok()).then_some(req.seq)?,
        hash: parse_hash(&req.hash)?,
        at_micros: i64::try_from(at.unix_timestamp_nanos() / 1000).ok()?,
    })
}

pub async fn sign_checkpoint(State(state): State<AppState>, body: Bytes) -> Response {
    let Some(req) = serde_json::from_slice::<SignRequest>(&body).ok() else {
        return problem(StatusCode::BAD_REQUEST, "malformed request");
    };
    let Some(body) = parse_body(&req) else {
        return problem(StatusCode::BAD_REQUEST, "checkpoint fields out of range");
    };
    let Some(signer) = state.signer() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "signing key not configured",
        );
    };
    match signer.sign(&body.message()).await {
        Ok(s) => (
            [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            Json(SignResponse {
                key_id: s.key_id,
                signature: B64.encode(s.signature),
            }),
        )
            .into_response(),
        Err(_) => problem(StatusCode::SERVICE_UNAVAILABLE, "signing unavailable"),
    }
}
