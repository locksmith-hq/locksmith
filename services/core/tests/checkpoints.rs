//! `POST /v1/audit/checkpoints` with a fake signer (task 3.1; no network).

use std::sync::Arc;

use axum::body::Body;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use ls_audit::CheckpointBody;
use ls_core_service::app::{AppState, router};
use ls_core_service::auth::ServiceToken;
use ls_core_service::checkpoint_api::{CheckpointSigner, SignFuture, Signed};
use secrecy::SecretString;
use serde_json::{Value, json};
use tower::ServiceExt;

const ORG: &str = "11111111-1111-4111-8111-111111111111";
const HASH: &str = "ab00ab00ab00ab00ab00ab00ab00ab00ab00ab00ab00ab00ab00ab00ab00ab00";

/// Echoes the first 32 bytes of the message twice, so a test can see what was signed.
struct Fake;
impl CheckpointSigner for Fake {
    fn sign<'a>(&'a self, message: &'a [u8]) -> SignFuture<'a> {
        Box::pin(async move {
            let mut signature = [0u8; 64];
            let n = message.len().min(64);
            signature[..n].copy_from_slice(&message[..n]);
            Ok(Signed {
                key_id: "audit-checkpoint:1".into(),
                signature,
            })
        })
    }
}

fn app(signer: bool) -> axum::Router {
    let mut s = AppState::new(ServiceToken::new(SecretString::from(
        "test-token".to_owned(),
    )));
    if signer {
        s = s.with_signer(Arc::new(Fake));
    }
    router(s)
}

async fn post(app: &axum::Router, auth: Option<&str>, body: Value) -> (StatusCode, Value) {
    let mut req =
        Request::post("/v1/audit/checkpoints").header(header::CONTENT_TYPE, "application/json");
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn good() -> Value {
    json!({"org_id": ORG, "seq": 7, "hash": HASH, "at": "2025-11-17T12:00:00Z"})
}

const BEARER: Option<&str> = Some("Bearer test-token");

#[tokio::test]
async fn signs_the_ledger_checkpoint_message() {
    let (status, v) = post(&app(true), BEARER, good()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["key_id"], "audit-checkpoint:1");
    let sig = base64_decode(v["signature"].as_str().unwrap());
    let expected = CheckpointBody {
        org_id: ORG.parse().unwrap(),
        seq: 7,
        hash: [0xab, 0x00].repeat(16).try_into().unwrap(),
        at_micros: 1_763_380_800_000_000,
    }
    .message();
    assert_eq!(&sig[..], &expected[..sig.len().min(expected.len())]);
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

#[tokio::test]
async fn unauthenticated_is_401() {
    assert_eq!(
        post(&app(true), None, good()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post(&app(true), Some("Bearer nope"), good()).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn bad_input_is_400() {
    for body in [
        json!({"org_id": ORG}),
        json!({"org_id": ORG, "seq": 0, "hash": HASH, "at": "2025-11-17T12:00:00Z"}),
        json!({"org_id": ORG, "seq": 1, "hash": "AB", "at": "2025-11-17T12:00:00Z"}),
        json!({"org_id": ORG, "seq": 1, "hash": HASH, "at": "yesterday"}),
        json!({"org_id": ORG, "seq": 1, "hash": HASH, "at": "2025-11-17T12:00:00Z", "x": 1}),
    ] {
        assert_eq!(
            post(&app(true), BEARER, body).await.0,
            StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
async fn no_signer_is_503() {
    assert_eq!(
        post(&app(false), BEARER, good()).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}
