//! Contract tests (task 3.4): every operation in `services/core/openapi.json` answers 401 without
//! the service token, 400 for bad input, and a 200 that matches the declared schema. The two
//! operations that need Postgres (audit append, workload verify) check their 200 in
//! `audit_events.rs` and `workload_verify.rs` with the same helper. No network, no Docker.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use ls_agent_token::AgentTokenSigner;
use ls_core_service::app::{AppState, router};
use ls_core_service::auth::ServiceToken;
use ls_core_service::checkpoint_api::{CheckpointSigner, SignFuture, Signed};
use ls_crypto::SecretKey32;
use ls_envelope::{Binding, DataKey, Header, KeyWrapper, WrapError, WrapKeyId, WrappedDek};
use secrecy::SecretString;
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{assert_matches_contract, operations};

const ORG: &str = "11111111-1111-4111-8111-111111111111";
const AGENT: &str = "22222222-2222-4222-8222-222222222222";
const POLICY: &str = "33333333-3333-4333-8333-333333333333";
const BEARER: &str = "Bearer test-token";

struct FakeSigner;
impl CheckpointSigner for FakeSigner {
    fn sign<'a>(&'a self, _message: &'a [u8]) -> SignFuture<'a> {
        Box::pin(async move {
            Ok(Signed {
                key_id: "audit-checkpoint:1".into(),
                signature: [7u8; 64],
            })
        })
    }
}

#[derive(Default)]
struct FakeKms(Mutex<HashMap<Vec<u8>, [u8; 32]>>);
impl KeyWrapper for FakeKms {
    async fn wrap(&self, dek: &DataKey, _binding: &Binding) -> Result<WrappedDek, WrapError> {
        let mut blob = Header::v1(WrapKeyId::new("gateway", 1)?.to_key_id())
            .encode()
            .to_vec();
        let mut rest = vec![0u8; 60];
        getrandom::getrandom(&mut rest).unwrap();
        blob.extend_from_slice(&rest);
        self.0.lock().unwrap().insert(blob.clone(), *dek.expose());
        WrappedDek::from_bytes(blob)
    }
    async fn unwrap(&self, w: &WrappedDek, _binding: &Binding) -> Result<SecretKey32, WrapError> {
        match self.0.lock().unwrap().get(w.as_bytes()) {
            Some(k) => Ok(SecretKey32::from_bytes(*k)),
            None => Err(WrapError::Rejected { status: 400 }),
        }
    }
}

fn app() -> axum::Router {
    use base64::Engine as _;
    let seed = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    let s = AppState::new(ServiceToken::new(SecretString::from(
        "test-token".to_owned(),
    )))
    .with_signer(Arc::new(FakeSigner))
    .with_agent_signer(Arc::new(
        AgentTokenSigner::from_base64_seed(&seed).unwrap(),
    ))
    .with_dek_kms(Arc::new(FakeKms::default()));
    router(s)
}

async fn post(path: &str, auth: Option<&str>, body: Value) -> (StatusCode, Value) {
    let mut req = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    let res = app()
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

fn binding() -> Value {
    json!({"org_id": ORG, "secret_id": AGENT, "version": 1, "purpose": "dek_wrap"})
}

/// A valid body for each operation that needs no database; `None` for the two that do.
fn good_body(path: &str) -> Option<Value> {
    Some(match path {
        "/v1/agent-tokens/mint" => json!({"agent_id": AGENT, "org_id": ORG}),
        "/v1/workload-tokens/mint" => {
            json!({"agent_id": AGENT, "org_id": ORG, "policy_id": POLICY})
        }
        "/v1/audit/checkpoints" => {
            json!({"org_id": ORG, "seq": 7, "hash": "ab".repeat(32), "at": "2025-11-17T12:00:00Z"})
        }
        "/v1/deks/wrap" => json!({"binding": binding()}),
        // verify and unwrap need a prior response; see `chained_operations_match_the_contract`.
        _ => return None,
    })
}

#[test]
fn the_contract_has_the_eight_operations() {
    assert_eq!(operations().len(), 8);
}

#[tokio::test]
async fn every_operation_rejects_a_missing_or_wrong_token_with_401() {
    for (path, id) in operations() {
        for auth in [None, Some("Bearer wrong")] {
            let body = good_body(&path).unwrap_or_else(|| json!({}));
            let (st, v) = post(&path, auth, body).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED, "{id} with {auth:?}");
            assert_matches_contract(&path, 401, &v);
        }
    }
}

#[tokio::test]
async fn every_operation_rejects_bad_input_with_400() {
    for (path, id) in operations() {
        for body in [json!({}), json!({"unexpected": 1}), json!([])] {
            let (st, v) = post(&path, Some(BEARER), body.clone()).await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{id} with {body}");
            assert_matches_contract(&path, 400, &v);
        }
    }
}

#[tokio::test]
async fn operations_without_a_database_match_the_contract_on_success() {
    for (path, id) in operations() {
        let Some(body) = good_body(&path) else {
            continue;
        };
        let (st, v) = post(&path, Some(BEARER), body).await;
        assert_eq!(st, StatusCode::OK, "{id}: {v}");
        assert_matches_contract(&path, 200, &v);
    }
}

#[tokio::test]
async fn chained_operations_match_the_contract() {
    // The shared state is rebuilt per `post`, so chain through one router.
    let app = app();
    let call = |path: &'static str, body: Value| {
        let app = app.clone();
        async move {
            let req = Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, BEARER)
                .body(Body::from(body.to_string()))
                .unwrap();
            let res = app.oneshot(req).await.unwrap();
            let st = res.status();
            let b = res.into_body().collect().await.unwrap().to_bytes();
            (st, serde_json::from_slice::<Value>(&b).unwrap())
        }
    };
    let (st, minted) = call(
        "/v1/agent-tokens/mint",
        json!({"agent_id": AGENT, "org_id": ORG}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, v) = call(
        "/v1/agent-tokens/verify",
        json!({"token": minted["token"]}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["valid"], true);
    assert_matches_contract("/v1/agent-tokens/verify", 200, &v);
    let (st, v) = call("/v1/agent-tokens/verify", json!({"token": "garbage"})).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["valid"], false);
    assert_matches_contract("/v1/agent-tokens/verify", 200, &v);

    let (st, wrapped) = call("/v1/deks/wrap", json!({"binding": binding()})).await;
    assert_eq!(st, StatusCode::OK);
    let (st, v) = call(
        "/v1/deks/unwrap",
        json!({"binding": binding(), "wrapped_dek": wrapped["wrapped_dek"]}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_matches_contract("/v1/deks/unwrap", 200, &v);
}
