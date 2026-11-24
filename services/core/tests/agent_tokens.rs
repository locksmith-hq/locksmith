//! `POST /v1/agent-tokens/{mint,verify}` (task 3.2; no network).

use std::sync::Arc;

use axum::body::Body;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use ls_agent_token::AgentTokenSigner;
use ls_core_service::app::{AppState, router};
use ls_core_service::auth::ServiceToken;
use secrecy::SecretString;
use serde_json::{Value, json};
use tower::ServiceExt;

const AGENT: &str = "11111111-1111-4111-8111-111111111111";
const ORG: &str = "22222222-2222-4222-8222-222222222222";
const AUTH: &str = "Bearer test-token";

fn seed(n: u8) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([n; 32])
}

fn app(seed_byte: Option<u8>) -> axum::Router {
    let mut s = AppState::new(ServiceToken::new(SecretString::from(
        "test-token".to_owned(),
    )));
    if let Some(n) = seed_byte {
        s = s.with_agent_signer(Arc::new(
            AgentTokenSigner::from_base64_seed(&seed(n)).unwrap(),
        ));
    }
    router(s)
}

async fn post(
    app: &axum::Router,
    path: &str,
    auth: Option<&str>,
    body: Value,
) -> (StatusCode, Option<String>, Value) {
    let mut req = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let cache = res
        .headers()
        .get(header::CACHE_CONTROL)
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        cache,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn mint(app: &axum::Router) -> String {
    let (st, cache, v) = post(
        app,
        "/v1/agent-tokens/mint",
        Some(AUTH),
        json!({"agent_id": AGENT, "org_id": ORG}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(cache.as_deref(), Some("no-store"));
    assert_eq!(v["token_type"], "Bearer");
    assert_eq!(v["expires_in"], 900);
    assert!(v["expires_at"].as_str().unwrap().ends_with('Z'));
    v["token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn minted_token_verifies_and_carries_the_ids() {
    let app = app(Some(1));
    let token = mint(&app).await;
    let (st, cache, v) = post(
        &app,
        "/v1/agent-tokens/verify",
        Some(AUTH),
        json!({ "token": token }),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(cache.as_deref(), Some("no-store"));
    assert_eq!(v["valid"], true);
    assert_eq!(v["agent_id"], AGENT);
    assert_eq!(v["org_id"], ORG);
    assert!(v.get("reason").is_none());
}

#[tokio::test]
async fn bad_tokens_are_200_with_a_coarse_reason() {
    let app = app(Some(1));
    let token = mint(&app).await;
    let foreign = {
        let other = self::app(Some(2));
        mint(&other).await
    };
    // Change one character in the middle of the signature segment (still valid base64url).
    let sig_start = token.rfind('.').unwrap() + 1;
    let mid = sig_start + 10;
    let flipped = if token.as_bytes()[mid] == b'A' {
        "B"
    } else {
        "A"
    };
    let mut tampered = token.clone();
    tampered.replace_range(mid..=mid, flipped);
    for (t, reason) in [
        ("not a jwt", "malformed"),
        (foreign.as_str(), "unknown_key"),
        (tampered.as_str(), "bad_signature"),
    ] {
        let (st, _, v) = post(
            &app,
            "/v1/agent-tokens/verify",
            Some(AUTH),
            json!({ "token": t }),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{reason}");
        assert_eq!(v["valid"], false);
        assert_eq!(v["reason"], reason);
        assert!(v.get("agent_id").is_none());
    }
}

#[tokio::test]
async fn unauthenticated_malformed_and_unconfigured_are_refused() {
    let app = app(Some(1));
    for path in ["/v1/agent-tokens/mint", "/v1/agent-tokens/verify"] {
        let (st, _, _) = post(&app, path, None, json!({})).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{path}");
        let (st, _, _) = post(&app, path, Some("Bearer wrong"), json!({})).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{path}");
        let (st, _, _) = post(&app, path, Some(AUTH), json!({"extra": 1})).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{path}");
    }
    let (st, _, _) = post(
        &app,
        "/v1/agent-tokens/mint",
        Some(AUTH),
        json!({"agent_id": "nope", "org_id": ORG}),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let none = self::app(None);
    let (st, _, _) = post(
        &none,
        "/v1/agent-tokens/mint",
        Some(AUTH),
        json!({"agent_id": AGENT, "org_id": ORG}),
    )
    .await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn workload_mint_gives_a_verifiable_agent_token() {
    let app = app(Some(1));
    let policy = "33333333-3333-4333-8333-333333333333";
    let (st, cache, v) = post(
        &app,
        "/v1/workload-tokens/mint",
        Some(AUTH),
        json!({"agent_id": AGENT, "org_id": ORG, "policy_id": policy}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(cache.as_deref(), Some("no-store"));
    assert_eq!(v["expires_in"], 900);
    let (_, _, verdict) = post(
        &app,
        "/v1/agent-tokens/verify",
        Some(AUTH),
        json!({ "token": v["token"] }),
    )
    .await;
    assert_eq!(verdict["valid"], true);
    assert_eq!(verdict["agent_id"], AGENT);
    let path = "/v1/workload-tokens/mint";
    let (st, _, _) = post(&app, path, None, json!({})).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _, _) = post(
        &app,
        path,
        Some(AUTH),
        json!({"agent_id": AGENT, "org_id": ORG}),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "policy_id is required");
    let (st, _, _) = post(
        &self::app(None),
        path,
        Some(AUTH),
        json!({"agent_id": AGENT, "org_id": ORG, "policy_id": policy}),
    )
    .await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
}
