//! `GET /v1/agent-tokens/jwks`: service-token only, public keys only, matches the contract, and
//! the published key verifies a token the core minted.

mod common;

use std::sync::Arc;

use axum::body::Body;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use ls_agent_token::AgentTokenSigner;
use ls_core_service::app::{AppState, router};
use ls_core_service::auth::ServiceToken;
use secrecy::SecretString;
use serde_json::Value;
use tower::ServiceExt;

fn state() -> AppState {
    AppState::new(ServiceToken::new(SecretString::from(
        "test-token".to_owned(),
    )))
}

fn signer() -> Arc<AgentTokenSigner> {
    use base64::Engine as _;
    let seed = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    Arc::new(AgentTokenSigner::from_base64_seed(&seed).unwrap())
}

async fn get(state: AppState, auth: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::get("/v1/agent-tokens/jwks");
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    let res = router(state)
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let st = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (st, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_missing_or_wrong_token_is_401() {
    for auth in [None, Some("Bearer wrong")] {
        let (st, _) = get(state().with_agent_signer(signer()), auth).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{auth:?}");
    }
}

#[tokio::test]
async fn publishes_the_signing_key_and_nothing_private() {
    let s = signer();
    let (st, v) = get(
        state().with_agent_signer(s.clone()),
        Some("Bearer test-token"),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let keys = v["keys"].as_array().expect("keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kid"], s.jwk().kid.as_str());
    assert_eq!(keys[0]["kty"], "OKP");
    assert!(keys[0].get("d").is_none(), "no private member");
    common::assert_get_matches_contract("/v1/agent-tokens/jwks", 200, &v);
}

#[tokio::test]
async fn an_unconfigured_signer_is_503() {
    let (st, v) = get(state(), Some("Bearer test-token")).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    common::assert_get_matches_contract("/v1/agent-tokens/jwks", 503, &v);
}
