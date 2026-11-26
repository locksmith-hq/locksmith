//! S3 tasks 1.1-1.2: the gateway's internal material endpoint
//! (`GET /internal/v1/secrets/{id}/versions/{n}/material`). Auth refusals need no database; the
//! org-scoping tests use a throwaway `postgres:18` container (testcontainers; needs Docker).

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http_body_util::BodyExt;
use ls_control_plane::app::{self, AppState};
use ls_control_plane::auth::ServiceToken;
use ls_control_plane::db::{Database, PoolSettings};
use ls_control_plane::readiness::ReadyFlag;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use tower::ServiceExt;
use uuid::Uuid;

// Test-only token values.
const TOKEN: &str = "test-only-gateway-service-token-0123456789";
const WRONG: &str = "test-only-gateway-service-token-0123456780";

struct Reply {
    status: StatusCode,
    body: Value,
    raw: String,
}

fn state(db: Database, token: Option<&str>) -> AppState {
    let s = AppState::new(true, Arc::new(ReadyFlag::new(true)), db);
    match token {
        Some(t) => s.with_service_token(ServiceToken::new(SecretString::from(t))),
        None => s,
    }
}

fn material_uri(secret_id: Uuid, version: impl std::fmt::Display) -> String {
    format!("/internal/v1/secrets/{secret_id}/versions/{version}/material")
}

/// `GET` with optional `Authorization` and `X-Locksmith-Org` headers, plus extra headers.
async fn get(
    app: &Router,
    uri: &str,
    authorization: Option<&str>,
    org: Option<Uuid>,
    extra: &[(&str, String)],
) -> Reply {
    let mut b = Request::builder().uri(uri);
    if let Some(a) = authorization {
        b = b.header("authorization", a);
    }
    if let Some(o) = org {
        b = b.header("x-locksmith-org", o.to_string());
    }
    for (k, v) in extra {
        b = b.header(*k, v);
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        raw: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

fn assert_problem(r: &Reply, status: StatusCode, slug: &str) {
    assert_eq!(r.status, status, "{}", r.raw);
    assert_eq!(r.body["type"], format!("urn:locksmith:problem:{slug}"));
    assert!(!r.raw.contains(TOKEN) && !r.raw.contains(WRONG));
}

fn bearer(t: &str) -> String {
    format!("Bearer {t}")
}

/// No token, a wrong token, a malformed header or no configured token are all `401` before any
/// database access (the pool here never connects).
#[tokio::test]
async fn missing_or_wrong_service_token_is_401() {
    let app = app::build(state(common::unreachable_db(), Some(TOKEN)));
    let uri = material_uri(Uuid::now_v7(), 1);
    let org = Some(Uuid::now_v7());

    let r = get(&app, &uri, None, org, &[]).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    let r = get(&app, &uri, Some(&bearer(WRONG)), org, &[]).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    for bad in [
        TOKEN.to_owned(),
        format!("Basic {TOKEN}"),
        format!("Bearer {}", &TOKEN[..TOKEN.len() - 1]),
        format!("Bearer {TOKEN}x"),
        "Bearer ".to_owned(),
    ] {
        let r = get(&app, &uri, Some(&bad), org, &[]).await;
        assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    }
    // The right token without an org (or with a malformed one) is still 401.
    let r = get(&app, &uri, Some(&bearer(TOKEN)), None, &[]).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    let r = get(
        &app,
        &uri,
        Some(&bearer(TOKEN)),
        None,
        &[("x-locksmith-org", "not-a-uuid".to_owned())],
    )
    .await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    // The dev org header (dev auth is on here) does not open internal routes.
    let r = get(
        &app,
        &uri,
        None,
        None,
        &[("x-locksmith-dev-org", Uuid::now_v7().to_string())],
    )
    .await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");

    // Fail closed: with no token configured, every token is refused.
    let closed = app::build(state(common::unreachable_db(), None));
    for auth in [None, Some(bearer(TOKEN)), Some("Bearer ".to_owned())] {
        let r = get(&closed, &uri, auth.as_deref(), org, &[]).await;
        assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    }
}

/// A database with org A's secret and one stored version (synthetic, well-formed blobs).
struct Fixture {
    app: Router,
    _pg: common::Pg,
    org_a: Uuid,
    org_b: Uuid,
    secret_id: Uuid,
    ciphertext: Vec<u8>,
    wrapped_dek: Vec<u8>,
}

impl Fixture {
    async fn start() -> Self {
        let pg = common::Pg::migrated().await;
        let app = app::build(state(pg.app_db(PoolSettings::default()), Some(TOKEN)));
        let org_a = Self::org(&app, "a").await;
        let org_b = Self::org(&app, "b").await;
        let p = Self::post(&app, "/v1/projects", org_a, json!({"name": "p"})).await;
        let e = Self::post(
            &app,
            &format!("/v1/projects/{p}/environments"),
            org_a,
            json!({"name": "dev"}),
        )
        .await;
        let s = Self::post(
            &app,
            &format!("/v1/projects/{p}/environments/{e}/secrets"),
            org_a,
            json!({"name": "K"}),
        )
        .await;
        let secret_id: Uuid = s.parse().unwrap();

        // Ciphertext and wrapped DEK are opaque here: the endpoint must return them unchanged.
        let ciphertext: Vec<u8> = (0..64u8).collect();
        let wrapped_dek: Vec<u8> = (0..80u8).map(|b| b.wrapping_mul(3)).collect();
        let mut c = pg.admin().await;
        sqlx_core::query::query(
            "INSERT INTO secret_versions (org_id, secret_id, version, ciphertext, wrapped_dek, key_id)
             VALUES ($1, $2, 1, $3, $4, 'gateway:v1')",
        )
        .bind(org_a)
        .bind(secret_id)
        .bind(&ciphertext)
        .bind(&wrapped_dek)
        .execute(&mut c)
        .await
        .unwrap();
        c.close().await.unwrap();

        Self {
            app,
            _pg: pg,
            org_a,
            org_b,
            secret_id,
            ciphertext,
            wrapped_dek,
        }
    }

    async fn org(app: &Router, name: &str) -> Uuid {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/orgs")
            .header("content-type", "application/json")
            .body(Body::from(json!({ "name": name }).to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        v["id"].as_str().unwrap().parse().unwrap()
    }

    /// `POST` as `org` via dev auth; returns the new resource's id.
    async fn post(app: &Router, uri: &str, org: Uuid, body: Value) -> String {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("x-locksmith-dev-org", org.to_string())
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        v["id"].as_str().unwrap().to_owned()
    }
}

/// With the service token and the owning org: `200` with exactly secret id, version, key id,
/// ciphertext and wrapped DEK, the blobs byte-for-byte as stored. Without the token: `401`.
#[tokio::test]
async fn material_returns_ciphertext_and_wrapped_dek_only() {
    let f = Fixture::start().await;
    let uri = material_uri(f.secret_id, 1);

    let r = get(&f.app, &uri, Some(&bearer(TOKEN)), Some(f.org_a), &[]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    let mut keys: Vec<&str> = r
        .body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "ciphertext",
            "key_id",
            "kind",
            "secret_id",
            "version",
            "wrapped_dek"
        ]
    );
    assert_eq!(r.body["secret_id"], f.secret_id.to_string());
    assert_eq!(r.body["version"], 1);
    assert_eq!(r.body["key_id"], "gateway:v1");
    assert_eq!(r.body["kind"], "standard");
    let decode = |field: &str| STANDARD.decode(r.body[field].as_str().unwrap()).unwrap();
    assert_eq!(decode("ciphertext"), f.ciphertext);
    assert_eq!(decode("wrapped_dek"), f.wrapped_dek);

    // The same existing version without a token, or with a wrong one, is 401.
    let r = get(&f.app, &uri, None, Some(f.org_a), &[]).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    let r = get(&f.app, &uri, Some(&bearer(WRONG)), Some(f.org_a), &[]).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
}

/// Org-scoped through the tenant helper: org B gets `404` for org A's version, the same body as
/// for a version or secret that does not exist.
#[tokio::test]
async fn other_orgs_material_is_404() {
    let f = Fixture::start().await;
    let auth = bearer(TOKEN);

    let missing = get(
        &f.app,
        &material_uri(Uuid::now_v7(), 1),
        Some(&auth),
        Some(f.org_a),
        &[],
    )
    .await;
    assert_problem(&missing, StatusCode::NOT_FOUND, "not-found");

    let cross = get(
        &f.app,
        &material_uri(f.secret_id, 1),
        Some(&auth),
        Some(f.org_b),
        &[],
    )
    .await;
    assert_problem(&cross, StatusCode::NOT_FOUND, "not-found");
    assert_eq!(cross.body, missing.body);
    assert!(!cross.raw.contains(&STANDARD.encode(&f.ciphertext)));

    // An org that does not exist at all is also just 404.
    let r = get(
        &f.app,
        &material_uri(f.secret_id, 1),
        Some(&auth),
        Some(Uuid::now_v7()),
        &[],
    )
    .await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not-found");

    // Versions that cannot exist, and malformed path segments, are 404 for the owner too.
    for v in ["0", "2", "-1", "4294967295", "x"] {
        let r = get(
            &f.app,
            &material_uri(f.secret_id, v),
            Some(&auth),
            Some(f.org_a),
            &[],
        )
        .await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not-found");
    }
    let r = get(
        &f.app,
        "/internal/v1/secrets/not-a-uuid/versions/1/material",
        Some(&auth),
        Some(f.org_a),
        &[],
    )
    .await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not-found");
}
