//! M1 task 2.1: the hub `/mcp` route. Bearer auth against a mock issuer (wiremock JWKS): a
//! missing, expired, wrong-audience or otherwise bad token gets `401` with a `WWW-Authenticate`
//! challenge that points at the protected-resource metadata; a valid one reaches the rmcp
//! service. Needs no database.

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ls_control_plane::app::{self, AppState};
use ls_control_plane::auth::human::{HumanAuth, HumanAuthConfig};
use ls_control_plane::mcp_endpoint::McpEndpoint;
use ls_control_plane::readiness::ReadyFlag;
use p256::pkcs8::EncodePrivateKey as _;
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ISSUER: &str = "https://idp.test/realms/locksmith";
const CONSOLE_AUDIENCE: &str = "locksmith-api";
const RESOURCE: &str = "https://hub.test/mcp";
const HOST: &str = "hub.test";
const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;

struct TestKey {
    signing: p256::ecdsa::SigningKey,
}

impl TestKey {
    fn new() -> Self {
        Self {
            signing: p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap(),
        }
    }

    fn jwk(&self) -> Value {
        let point = self.signing.verifying_key().to_sec1_point(false);
        json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        })
    }

    fn mint(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("k1".to_owned());
        let der = self.signing.to_pkcs8_der().unwrap();
        jsonwebtoken::encode(&header, claims, &EncodingKey::from_ec_der(der.as_bytes())).unwrap()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn claims(aud: &str, exp: u64) -> Value {
    json!({
        "iss": ISSUER, "aud": aud, "sub": "user-1", "exp": exp,
        "email": "user-1@example.com", "email_verified": true,
    })
}

struct Fixture {
    _server: MockServer,
    key: TestKey,
    app: Router,
}

async fn start(configured: bool) -> Fixture {
    let server = MockServer::start().await;
    let key = TestKey::new();
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [key.jwk()] })))
        .mount(&server)
        .await;
    let cfg = HumanAuthConfig {
        issuer: ISSUER.to_owned(),
        audience: CONSOLE_AUDIENCE.to_owned(),
        jwks_url: format!("{}/jwks", server.uri()),
    };
    let mut state = AppState::new(
        false,
        Arc::new(ReadyFlag::new(true)),
        common::unreachable_db(),
    )
    .with_human_auth(HumanAuth::new(&cfg).unwrap());
    if configured {
        let mcp_auth = HumanAuth::with_refresh(
            &HumanAuthConfig {
                audience: RESOURCE.to_owned(),
                ..cfg.clone()
            },
            Duration::from_secs(1),
            Duration::from_secs(3600),
        )
        .unwrap();
        state = state.with_mcp(McpEndpoint::with_auth(mcp_auth, &cfg, RESOURCE).unwrap());
    }
    Fixture {
        _server: server,
        key,
        app: app::build(state),
    }
}

async fn post(app: &Router, token: Option<&str>, host: &str) -> (Response<Body>, String) {
    let mut b = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, host)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::from(INITIALIZE)).unwrap())
        .await
        .unwrap();
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    (Response::from_parts(parts, Body::empty()), text)
}

fn challenge(resp: &Response<Body>) -> String {
    resp.headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("401 carries WWW-Authenticate")
        .to_str()
        .unwrap()
        .to_owned()
}

const METADATA_URL: &str = "https://hub.test/.well-known/oauth-protected-resource/mcp";

#[tokio::test]
async fn mcp_missing_token_is_401_with_resource_metadata_challenge() {
    let f = start(true).await;
    let (resp, _) = post(&f.app, None, HOST).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        challenge(&resp),
        format!(r#"Bearer resource_metadata="{METADATA_URL}""#)
    );
}

#[tokio::test]
async fn mcp_expired_token_is_401_invalid_token() {
    let f = start(true).await;
    // Past the 60 s verifier leeway.
    let token = f.key.mint(&claims(RESOURCE, now() - 600));
    let (resp, body) = post(&f.app, Some(&token), HOST).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        challenge(&resp),
        format!(r#"Bearer error="invalid_token", resource_metadata="{METADATA_URL}""#)
    );
    assert!(!body.contains(&token), "token echoed back");
}

#[tokio::test]
async fn mcp_wrong_audience_token_is_401() {
    let f = start(true).await;
    // A console API token must not work on /mcp (no token passthrough), and vice versa.
    for aud in [CONSOLE_AUDIENCE, "https://other.test/mcp", "gateway"] {
        let token = f.key.mint(&claims(aud, now() + 600));
        let (resp, body) = post(&f.app, Some(&token), HOST).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "aud {aud}");
        assert!(challenge(&resp).contains("invalid_token"));
        assert!(!body.contains(&token), "token echoed back");
    }
}

#[tokio::test]
async fn mcp_garbage_and_non_bearer_credentials_are_401() {
    let f = start(true).await;
    let (resp, _) = post(&f.app, Some("not.a.jwt"), HOST).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, "Basic dXNlcjpwdw==")
        .body(Body::from(INITIALIZE))
        .unwrap();
    let resp = f.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(challenge(&resp).starts_with("Bearer "));
}

#[tokio::test]
async fn mcp_valid_token_reaches_the_service() {
    let f = start(true).await;
    let token = f.key.mint(&claims(RESOURCE, now() + 600));
    let (resp, body) = post(&f.app, Some(&token), HOST).await;
    assert_eq!(resp.status(), StatusCode::OK, "{body}");
    assert!(body.contains("protocolVersion"), "{body}");
    assert!(!body.contains(&token));
}

#[tokio::test]
async fn mcp_host_allowlist_refuses_other_hostnames() {
    let f = start(true).await;
    let token = f.key.mint(&claims(RESOURCE, now() + 600));
    let (resp, _) = post(&f.app, Some(&token), "evil.test").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_protected_resource_metadata_is_public_at_both_urls() {
    let f = start(true).await;
    for uri in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let resp = f
            .app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let doc: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["resource"], RESOURCE);
        assert_eq!(doc["authorization_servers"], json!([ISSUER]));
    }
}

#[tokio::test]
async fn mcp_unconfigured_fails_closed() {
    let f = start(false).await;
    let token = f.key.mint(&claims(RESOURCE, now() + 600));
    let (resp, _) = post(&f.app, Some(&token), HOST).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(challenge(&resp), "Bearer");
}
