//! D3 task 6.2: the gateway's binding inventory. `PUT /internal/v1/gateway/bindings` stores the
//! latest snapshot per org and `GET /v1/bindings` serves it. Needs Docker (a throwaway
//! `postgres:18` container) except the auth refusals.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use ls_control_plane::app::{self, AppState};
use ls_control_plane::auth::ServiceToken;
use ls_control_plane::db::{PoolSettings, sql};
use ls_control_plane::readiness::ReadyFlag;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use tower::ServiceExt;
use uuid::Uuid;

// Test-only token value.
const TOKEN: &str = "test-only-gateway-service-token-0123456789";
// Planted strings that must never be stored or served.
const PLANTED_TEMPLATE: &str = "Bearer {secret} planted-template-value";
const PLANTED_PASSWORD: &str = "planted-pg-password-hunter2";

fn app_with(db: ls_control_plane::db::Database) -> Router {
    let s = AppState::new(true, Arc::new(ReadyFlag::new(true)), db)
        .with_service_token(ServiceToken::new(SecretString::from(TOKEN)));
    app::build(s)
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn put(app: &Router, org: Uuid, token: Option<&str>, body: Value) -> (StatusCode, String) {
    let mut b = Request::builder()
        .method("PUT")
        .uri("/internal/v1/gateway/bindings")
        .header("x-locksmith-org", org.to_string())
        .header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    send(app, b.body(Body::from(body.to_string())).unwrap()).await
}

async fn list(app: &Router, org: Uuid) -> (StatusCode, String) {
    let req = Request::builder()
        .uri("/v1/bindings")
        .header("x-locksmith-dev-org", org.to_string())
        .body(Body::empty())
        .unwrap();
    send(app, req).await
}

async fn new_org(app: &Router, name: &str) -> Uuid {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/orgs")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "name": name }).to_string()))
        .unwrap();
    let (status, body) = send(app, req).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    serde_json::from_str::<Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

fn pg_item(name: &str) -> Value {
    json!({
        "kind": "pg", "name": name, "host": "db.example.com", "port": 5432,
        "user": "app", "database": name, "tls": "verify-full"
    })
}

fn http_item() -> Value {
    json!({
        "kind": "http", "name": "https://api.example.com",
        "origin": "https://api.example.com", "header": "Authorization"
    })
}

#[tokio::test]
async fn bindings_put_without_service_token_is_refused() {
    let app = app_with(common::unreachable_db());
    let org = Uuid::now_v7();
    let (status, _) = put(&app, org, None, json!({"items": []})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = put(
        &app,
        org,
        Some("test-only-wrong-token-0123456789"),
        json!({"items": []}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bindings_snapshot_is_stored_replaced_and_isolated_per_org() {
    let pg = common::Pg::migrated().await;
    let app = app_with(pg.app_db(PoolSettings::default()));
    let org_a = new_org(&app, "a").await;
    let org_b = new_org(&app, "b").await;

    // No snapshot yet: an empty list.
    let (status, body) = list(&app, org_a).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({"items": []})
    );

    let first = json!({"items": [pg_item("one"), http_item()]});
    let (status, body) = put(&app, org_a, Some(TOKEN), first.clone()).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = list(&app, org_a).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), first);

    // Another org sees nothing, and its own snapshot does not touch org A's.
    let (_, body) = list(&app, org_b).await;
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({"items": []})
    );
    let b_snapshot = json!({"items": [pg_item("b-only")]});
    assert_eq!(
        put(&app, org_b, Some(TOKEN), b_snapshot.clone()).await.0,
        StatusCode::NO_CONTENT
    );
    let (_, body) = list(&app, org_b).await;
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), b_snapshot);
    let (_, body) = list(&app, org_a).await;
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), first);

    // A second PUT replaces the snapshot whole.
    let second = json!({"items": [pg_item("two")]});
    assert_eq!(
        put(&app, org_a, Some(TOKEN), second.clone()).await.0,
        StatusCode::NO_CONTENT
    );
    let (_, body) = list(&app, org_a).await;
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), second);
    let mut admin = pg.admin().await;
    let rows: i64 = sql::query_scalar("SELECT count(*) FROM gateway_bindings")
        .fetch_one(&mut admin)
        .await
        .unwrap();
    assert_eq!(rows, 2, "one row per org");
    admin.close().await.unwrap();
}

#[tokio::test]
async fn bindings_secret_material_is_refused_and_never_stored_or_served() {
    let pg = common::Pg::migrated().await;
    let app = app_with(pg.app_db(PoolSettings::default()));
    let org = new_org(&app, "a").await;

    // Fields the contract does not name (a password, a template, a secret id) are a 400.
    for (field, value) in [
        ("password", PLANTED_PASSWORD),
        ("template", PLANTED_TEMPLATE),
        ("secret_id", "00000000-0000-0000-0000-000000000001"),
    ] {
        let mut item = pg_item("db");
        item[field] = json!(value);
        let (status, body) = put(&app, org, Some(TOKEN), json!({"items": [item]})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{field}: {body}");
        assert!(!body.contains(value), "the refusal does not echo {field}");
    }
    let (status, body) = put(
        &app,
        org,
        Some(TOKEN),
        json!({"items": [], "template": PLANTED_TEMPLATE}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Nothing was stored, so the response and the table hold none of it.
    let (_, body) = list(&app, org).await;
    assert_eq!(body, r#"{"items":[]}"#);
    let mut admin = pg.admin().await;
    let rows: i64 = sql::query_scalar("SELECT count(*) FROM gateway_bindings")
        .fetch_one(&mut admin)
        .await
        .unwrap();
    assert_eq!(rows, 0);

    // A valid snapshot: the stored row and the response hold only the allowed fields.
    let ok = json!({"items": [pg_item("db"), http_item()]});
    assert_eq!(
        put(&app, org, Some(TOKEN), ok).await.0,
        StatusCode::NO_CONTENT
    );
    let stored: String = sql::query_scalar("SELECT items::text FROM gateway_bindings")
        .fetch_one(&mut admin)
        .await
        .unwrap();
    admin.close().await.unwrap();
    let (_, served) = list(&app, org).await;
    for text in [&stored, &served] {
        for planted in [
            PLANTED_PASSWORD,
            PLANTED_TEMPLATE,
            "{secret}",
            "secret_id",
            "password",
            "template",
        ] {
            assert!(!text.contains(planted), "{planted} in {text}");
        }
    }
}

#[tokio::test]
async fn bindings_oversized_or_nameless_snapshot_is_refused() {
    let pg = common::Pg::migrated().await;
    let app = app_with(pg.app_db(PoolSettings::default()));
    let org = new_org(&app, "a").await;
    let (status, _) = put(&app, org, Some(TOKEN), json!({"items": [pg_item(" ")]})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let long = "x".repeat(600);
    let (status, _) = put(&app, org, Some(TOKEN), json!({"items": [pg_item(&long)]})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
