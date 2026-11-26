//! `POST /v1/enrollment-secrets/{generate,verify}` (lead ruling B1-5; no network, no database).

use axum::body::Body;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use ls_core_service::app::{AppState, router};
use ls_core_service::auth::ServiceToken;
use secrecy::SecretString;
use serde_json::{Value, json};
use tower::ServiceExt;

const AGENT: &str = "11111111-1111-4111-8111-111111111111";
const ORG: &str = "22222222-2222-4222-8222-222222222222";
const AUTH: &str = "Bearer test-token";
const GENERATE: &str = "/v1/enrollment-secrets/generate";
const VERIFY: &str = "/v1/enrollment-secrets/verify";

fn app() -> axum::Router {
    router(AppState::new(ServiceToken::new(SecretString::from(
        "test-token".to_owned(),
    ))))
}

/// Status, `Cache-Control`, the raw body text and the body as JSON.
async fn post(
    app: &axum::Router,
    path: &str,
    auth: Option<&str>,
    body: Value,
) -> (StatusCode, Option<String>, String, Value) {
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
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let json = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, cache, text, json)
}

/// `(secret, hash)` for AGENT in ORG.
async fn generate(app: &axum::Router) -> (String, String) {
    let (st, cache, _, v) = post(
        app,
        GENERATE,
        Some(AUTH),
        json!({"org_id": ORG, "agent_id": AGENT}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(cache.as_deref(), Some("no-store"));
    let secret = v["enrollment_secret"].as_str().unwrap().to_owned();
    let hash = v["enrollment_hash"].as_str().unwrap().to_owned();
    assert!(secret.starts_with("lse_"));
    assert_eq!(secret.len(), "lse_".len() + 86);
    assert!(hash.starts_with("$argon2id$"));
    assert!(!hash.contains(&secret["lse_".len()..]));
    assert_eq!(v.as_object().unwrap().len(), 2);
    (secret, hash)
}

async fn verify(app: &axum::Router, secret: &str, hash: Value) -> (StatusCode, String, Value) {
    let (st, cache, text, v) = post(
        app,
        VERIFY,
        Some(AUTH),
        json!({"enrollment_secret": secret, "enrollment_hash": hash}),
    )
    .await;
    assert_eq!(cache.as_deref(), Some("no-store"));
    // The verdict never carries the presented secret, whole or in part.
    if let Some(body) = secret.strip_prefix("lse_").filter(|b| b.len() > 8) {
        assert!(!text.contains(body), "verify echoed the secret");
    }
    assert!(!text.contains("enrollment_secret"));
    (st, text, v)
}

#[tokio::test]
async fn generated_secret_verifies_and_carries_the_ids() {
    let app = app();
    let (secret, hash) = generate(&app).await;
    let (st, _, v) = verify(&app, &secret, json!(hash)).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["valid"], true);
    assert_eq!(v["org_id"], ORG);
    assert_eq!(v["agent_id"], AGENT);
    assert!(v.get("reason").is_none());
}

#[tokio::test]
async fn each_generate_is_a_fresh_secret() {
    let app = app();
    let (a, ha) = generate(&app).await;
    let (b, hb) = generate(&app).await;
    assert_ne!(a, b);
    assert_ne!(ha, hb);
    // One agent's old secret does not verify against its rotated hash.
    let (_, _, v) = verify(&app, &a, json!(hb)).await;
    assert_eq!(v["valid"], false);
    assert_eq!(v["reason"], "wrong_secret");
}

#[tokio::test]
async fn wrong_secret_is_200_invalid_with_the_routing_ids() {
    let app = app();
    let (secret, hash) = generate(&app).await;
    // Same ids, different random part.
    let mut raw = URL_SAFE_NO_PAD.decode(&secret["lse_".len()..]).unwrap();
    raw[40] ^= 0xff;
    let wrong = format!("lse_{}", URL_SAFE_NO_PAD.encode(&raw));
    let (st, _, v) = verify(&app, &wrong, json!(hash)).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["valid"], false);
    assert_eq!(v["reason"], "wrong_secret");
    assert_eq!(v["org_id"], ORG);
    assert_eq!(v["agent_id"], AGENT);

    // Swapping the agent id (keeping the random part) no longer verifies.
    let mut raw = URL_SAFE_NO_PAD.decode(&secret["lse_".len()..]).unwrap();
    raw[16..32].copy_from_slice(&[0x33; 16]);
    let swapped = format!("lse_{}", URL_SAFE_NO_PAD.encode(&raw));
    let (_, _, v) = verify(&app, &swapped, json!(hash)).await;
    assert_eq!(v["valid"], false);
    assert_eq!(v["reason"], "wrong_secret");
}

#[tokio::test]
async fn malformed_secret_is_200_invalid_without_ids() {
    let app = app();
    let (_, hash) = generate(&app).await;
    let short = format!("lse_{}", URL_SAFE_NO_PAD.encode([0u8; 63]));
    for bad in ["", "lse_", "lse_!!!", "lsx_AAAA", short.as_str()] {
        for h in [json!(hash), Value::Null] {
            let (st, _, v) = verify(&app, bad, h).await;
            assert_eq!(st, StatusCode::OK, "{bad}");
            assert_eq!(v["valid"], false);
            assert_eq!(v["reason"], "malformed");
            assert!(v.get("org_id").is_none());
            assert!(v.get("agent_id").is_none());
        }
    }
}

#[tokio::test]
async fn unknown_agent_runs_the_dummy_path_and_is_refused() {
    let app = app();
    let (secret, _) = generate(&app).await;
    let (st, _, v) = verify(&app, &secret, Value::Null).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["valid"], false);
    assert_eq!(v["reason"], "unknown_agent");
    assert_eq!(v["org_id"], ORG);
    assert_eq!(v["agent_id"], AGENT);
}

#[tokio::test]
async fn unauthenticated_and_malformed_requests_are_refused() {
    let app = app();
    let (secret, hash) = generate(&app).await;
    let good = [
        (GENERATE, json!({"org_id": ORG, "agent_id": AGENT})),
        (
            VERIFY,
            json!({"enrollment_secret": secret, "enrollment_hash": hash}),
        ),
    ];
    for (path, body) in good {
        let (st, _, text, _) = post(&app, path, None, body.clone()).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{path}");
        assert!(!text.contains("lse_") && !text.contains("$argon2id$"));
        let (st, _, text, _) = post(&app, path, Some("Bearer wrong"), body).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{path}");
        assert!(!text.contains("lse_") && !text.contains("$argon2id$"));
        let (st, _, _, _) = post(&app, path, Some(AUTH), json!({"extra": 1})).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{path}");
    }
    for body in [
        json!({"org_id": "nope", "agent_id": AGENT}),
        json!({"org_id": ORG}),
    ] {
        let (st, _, _, _) = post(&app, GENERATE, Some(AUTH), body).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }
    // The stored hash must be given explicitly (null for an unknown agent), and the secret is
    // a string.
    for body in [
        json!({"enrollment_secret": secret}),
        json!({"enrollment_secret": 7, "enrollment_hash": null}),
        json!({"enrollment_secret": secret, "enrollment_hash": null, "extra": 1}),
    ] {
        let (st, _, text, _) = post(&app, VERIFY, Some(AUTH), body).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(
            !text.contains(&secret["lse_".len()..]),
            "400 echoed the secret"
        );
    }
}
