//! `POST /v1/workload-tokens/verify` against a stub OIDC issuer and a real Postgres (task 3.2;
//! needs Docker). Every credential failure is a 200 with `valid: false`.

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ls_core_service::app::{AppState, router};
use ls_core_service::auth::ServiceToken;
use ls_oidc_verify::external::{DEFAULT_MAX_LIFETIME, ExternalVerifier};
use ls_oidc_verify::issuers::{IssuerAccess, IssuerRegistry};
use ls_oidc_verify::workload::encode_handle;
use ls_pg_test::Pg;
use p256::pkcs8::EncodePrivateKey as _;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx_core::query::query;
use sqlx_postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const AUD: &str = "https://locksmith.example";
const BEARER: &str = "Bearer test-token";

struct TestKey {
    kid: String,
    signing: p256::ecdsa::SigningKey,
}

impl TestKey {
    fn new(kid: &str, seed: u8) -> Self {
        Self {
            kid: kid.to_owned(),
            signing: p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap(),
        }
    }

    fn jwk(&self) -> Value {
        let point = self.signing.verifying_key().to_sec1_point(false);
        json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": self.kid,
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        })
    }

    fn mint(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
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

async fn stub_issuer(key: &TestKey) -> MockServer {
    let server = MockServer::start().await;
    let url = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": url, "jwks_uri": format!("{url}/jwks"),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [key.jwk()] })))
        .mount(&server)
        .await;
    server
}

fn claims(issuer: &str, git_ref: &str, jti: &str) -> Value {
    let t = now();
    json!({
        "iss": issuer, "aud": AUD, "sub": format!("repo:acme/api:ref:{git_ref}"),
        "repository": "acme/api", "ref": git_ref,
        "jti": jti, "iat": t, "nbf": t, "exp": t + 600,
    })
}

async fn post(app: &axum::Router, auth: Option<&str>, body: Value) -> (StatusCode, Value) {
    let mut req = Request::post("/v1/workload-tokens/verify")
        .header(header::CONTENT_TYPE, "application/json");
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

fn state() -> AppState {
    let registry = IssuerRegistry::new(IssuerAccess {
        allow_private_hosts: true,
    })
    .unwrap();
    AppState::new(ServiceToken::new(SecretString::from(
        "test-token".to_owned(),
    )))
    .with_workload_verifier(ExternalVerifier::new(registry, DEFAULT_MAX_LIFETIME))
}

#[tokio::test]
async fn auth_and_input_are_checked_before_anything_else() {
    let app = router(state());
    let handle = encode_handle(Uuid::now_v7(), Uuid::now_v7());
    let (s, _) = post(&app, None, json!({"policy": handle, "token": "x"})).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    for body in [
        json!({"policy": handle}),
        json!({"policy": "lsw_short", "token": "x"}),
        json!({"policy": handle, "token": "x", "extra": 1}),
    ] {
        let (s, p) = post(&app, Some(BEARER), body).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{p}");
    }
    // Valid input, no database.
    let (s, _) = post(&app, Some(BEARER), json!({"policy": handle, "token": "x"})).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn verdicts_follow_the_policy() {
    let pg = Pg::migrated().await;
    let (org, agent, policy) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    let key = TestKey::new("k1", 7);
    let issuer = stub_issuer(&key).await;
    let iss = issuer.uri();
    {
        let mut c = pg.admin().await;
        query("INSERT INTO orgs (id, name) VALUES ($1, 'wl')")
            .bind(org)
            .execute(&mut c)
            .await
            .unwrap();
        query(
            "INSERT INTO agents (id, org_id, name, enrollment_hash) \
             VALUES ($1, $2, 'a', '$argon2id$x')",
        )
        .bind(agent)
        .bind(org)
        .execute(&mut c)
        .await
        .unwrap();
        // The table only stores https issuers; the stub is plain http on loopback (test only).
        query("ALTER TABLE workload_identities DROP CONSTRAINT IF EXISTS workload_identities_issuer_check")
            .execute(&mut c)
            .await
            .unwrap();
        query(
            "INSERT INTO workload_identities \
             (id, org_id, name, issuer_kind, issuer, audience, agent_id, conditions) \
             VALUES ($1, $2, 'p', 'oidc', $3, $4, $5, $6::jsonb)",
        )
        .bind(policy)
        .bind(org)
        .bind(&iss)
        .bind(AUD)
        .bind(agent)
        .bind(json!([{"claim": "ref", "op": "eq", "value": "refs/heads/main"}]).to_string())
        .execute(&mut c)
        .await
        .unwrap();
    }
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(pg.app())
        .await
        .unwrap();
    let app = router(state().with_pool(pool));
    let handle = encode_handle(org, policy);
    let ask = |token: String| json!({"policy": handle, "token": token});

    // A good token: valid, with the policy's agent, org and policy.
    let good = key.mint(&claims(&iss, "refs/heads/main", "jti-1"));
    let (s, v) = post(&app, Some(BEARER), ask(good.clone())).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["valid"], true, "{v}");
    common::assert_matches_contract("/v1/workload-tokens/verify", 200, &v);
    assert_eq!(v["agent_id"], agent.to_string());
    assert_eq!(v["org_id"], org.to_string());
    assert_eq!(v["policy_id"], policy.to_string());
    assert!(v.get("reason").is_none());

    // The same token again is a replay.
    let (s, v) = post(&app, Some(BEARER), ask(good)).await;
    assert_eq!(
        (s, &v["valid"], &v["reason"]),
        (StatusCode::OK, &json!(false), &json!("not_trusted"))
    );

    // Claims that do not meet the policy's conditions.
    let other = key.mint(&claims(&iss, "refs/heads/dev", "jti-2"));
    let (s, v) = post(&app, Some(BEARER), ask(other)).await;
    assert_eq!(
        (s, &v["valid"], &v["reason"]),
        (StatusCode::OK, &json!(false), &json!("not_trusted"))
    );

    // Signed by a key the issuer does not publish.
    let rogue = TestKey::new("k1", 9).mint(&claims(&iss, "refs/heads/main", "jti-3"));
    let (s, v) = post(&app, Some(BEARER), ask(rogue)).await;
    assert_eq!((s, &v["valid"]), (StatusCode::OK, &json!(false)));
    let unknown_kid = TestKey::new("nope", 7).mint(&claims(&iss, "refs/heads/main", "jti-4"));
    let (_, v) = post(&app, Some(BEARER), ask(unknown_kid)).await;
    assert_eq!(v["reason"], "unknown_key");

    // Not a JWT at all.
    let (s, v) = post(&app, Some(BEARER), ask("not-a-jwt".into())).await;
    assert_eq!(
        (s, &v["valid"], &v["reason"]),
        (StatusCode::OK, &json!(false), &json!("malformed"))
    );

    // An unknown policy in the same org, and the right policy asked under another org's handle.
    let (_, v) = post(
        &app,
        Some(BEARER),
        json!({"policy": encode_handle(org, Uuid::now_v7()), "token": "x"}),
    )
    .await;
    assert_eq!(
        (&v["valid"], &v["reason"]),
        (&json!(false), &json!("not_trusted"))
    );
    let (_, v) = post(
        &app,
        Some(BEARER),
        json!({"policy": encode_handle(Uuid::now_v7(), policy), "token": "x"}),
    )
    .await;
    assert_eq!(
        (&v["valid"], &v["reason"]),
        (&json!(false), &json!("not_trusted"))
    );
}
