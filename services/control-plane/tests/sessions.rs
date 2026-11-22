//! T8 task 2.1: the gateway's session report endpoint (`POST /internal/v1/sessions`) and the
//! org's session list (`GET /v1/sessions`). Auth refusals need no database; the rest use a
//! throwaway `postgres:18` container (testcontainers; needs Docker).

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use ls_control_plane::app::{self, AppState};
use ls_control_plane::auth::ServiceToken;
use ls_control_plane::db::PoolSettings;
use ls_control_plane::readiness::ReadyFlag;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use tower::ServiceExt;
use uuid::Uuid;

// Test-only token value.
const TOKEN: &str = "test-only-gateway-service-token-0123456789";

struct Reply {
    status: StatusCode,
    body: Value,
    raw: String,
}

async fn call(app: &Router, req: Request<Body>) -> Reply {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        raw: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

/// An internal report as the gateway: service token plus the org header.
async fn report(app: &Router, org: Uuid, body: Value) -> Reply {
    let req = Request::builder()
        .method("POST")
        .uri("/internal/v1/sessions")
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("x-locksmith-org", org.to_string())
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    call(app, req).await
}

/// `GET` as an org member via dev auth.
async fn list(app: &Router, org: Uuid, query: &str) -> Reply {
    let req = Request::builder()
        .uri(format!("/v1/sessions{query}"))
        .header("x-locksmith-dev-org", org.to_string())
        .body(Body::empty())
        .unwrap();
    call(app, req).await
}

async fn create(app: &Router, uri: &str, org: Option<Uuid>, body: Value) -> Uuid {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(o) = org {
        b = b.header("x-locksmith-dev-org", o.to_string());
    }
    let r = call(app, b.body(Body::from(body.to_string())).unwrap()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    let id = if r.body["agent"].is_object() {
        &r.body["agent"]["id"]
    } else {
        &r.body["id"]
    };
    id.as_str().unwrap().parse().unwrap()
}

fn open_body(agent_id: Uuid, jti: Uuid, kind: &str, slug: &str) -> Value {
    json!({"event": "open", "agent_id": agent_id, "token_jti": jti, "kind": kind, "slug": slug})
}

#[tokio::test]
async fn sessions_report_without_service_token_is_401() {
    let state = AppState::new(
        true,
        Arc::new(ReadyFlag::new(true)),
        common::unreachable_db(),
    )
    .with_service_token(ServiceToken::new(SecretString::from(TOKEN)));
    let app = app::build(state);
    let req = Request::builder()
        .method("POST")
        .uri("/internal/v1/sessions")
        .header("x-locksmith-org", Uuid::now_v7().to_string())
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"event": "heartbeat", "session_id": Uuid::now_v7()}).to_string(),
        ))
        .unwrap();
    let r = call(&app, req).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.raw);
}

struct Fixture {
    app: Router,
    pg: common::Pg,
    org_a: Uuid,
    org_b: Uuid,
    agent_a: Uuid,
    agent_b: Uuid,
}

impl Fixture {
    async fn start() -> Self {
        let pg = common::Pg::migrated().await;
        let state = AppState::new(
            true,
            Arc::new(ReadyFlag::new(true)),
            pg.app_db(PoolSettings::default()),
        )
        .with_service_token(ServiceToken::new(SecretString::from(TOKEN)));
        let app = app::build(state);
        let org_a = create(&app, "/v1/orgs", None, json!({"name": "a"})).await;
        let org_b = create(&app, "/v1/orgs", None, json!({"name": "b"})).await;
        let agent_a = create(&app, "/v1/agents", Some(org_a), json!({"name": "agent-a"})).await;
        let agent_b = create(&app, "/v1/agents", Some(org_b), json!({"name": "agent-b"})).await;
        Self {
            app,
            pg,
            org_a,
            org_b,
            agent_a,
            agent_b,
        }
    }

    /// Run SQL as the owner (tests only), e.g. to age a session.
    async fn admin_sql(&self, sql: &'static str, id: Uuid) {
        let mut c = self.pg.admin().await;
        sqlx_core::query::query(sql)
            .bind(id)
            .execute(&mut c)
            .await
            .unwrap();
        c.close().await.unwrap();
    }
}

#[tokio::test]
async fn sessions_open_heartbeat_close_and_list() {
    let f = Fixture::start().await;
    let canary = Uuid::now_v7();

    let r = report(
        &f.app,
        f.org_a,
        open_body(f.agent_a, canary, "http", "github-api"),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    let id: Uuid = r.body["id"].as_str().unwrap().parse().unwrap();
    assert!(
        !r.raw.contains(&canary.to_string()),
        "open response leaks the jti"
    );

    // Listed and live; exactly the documented fields.
    let l = list(&f.app, f.org_a, "").await;
    assert_eq!(l.status, StatusCode::OK, "{}", l.raw);
    let items = l.body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    let s = &items[0];
    let mut keys: Vec<&str> = s.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "agent_id",
            "id",
            "kind",
            "last_seen_at",
            "live",
            "slug",
            "started_at"
        ]
    );
    assert_eq!(s["id"], id.to_string());
    assert_eq!(s["kind"], "http");
    assert_eq!(s["slug"], "github-api");
    assert_eq!(s["live"], true);
    // Canary: the jti never appears in any list or report response.
    assert!(
        !l.raw.contains(&canary.to_string()),
        "list leaks the jti: {}",
        l.raw
    );
    assert!(!l.raw.contains("token_jti") && !l.raw.contains("jti"));

    // Heartbeat on a stale session makes it live again.
    f.admin_sql(
        "UPDATE agent_sessions SET last_seen_at = now() - interval '20 seconds' WHERE id = $1",
        id,
    )
    .await;
    let l = list(&f.app, f.org_a, "").await;
    assert_eq!(l.body["items"][0]["live"], false, "{}", l.raw);
    let r = report(
        &f.app,
        f.org_a,
        json!({"event": "heartbeat", "session_id": id}),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.raw);
    let l = list(&f.app, f.org_a, "").await;
    assert_eq!(l.body["items"][0]["live"], true, "{}", l.raw);

    // Close: no longer live, still listed.
    let r = report(&f.app, f.org_a, json!({"event": "close", "session_id": id})).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.raw);
    let l = list(&f.app, f.org_a, "").await;
    assert_eq!(l.body["items"][0]["live"], false, "{}", l.raw);
    assert!(!l.raw.contains(&canary.to_string()));
}

#[tokio::test]
async fn sessions_revoked_and_old_rows_are_not_live_or_listed() {
    let f = Fixture::start().await;
    let r = report(
        &f.app,
        f.org_a,
        open_body(f.agent_a, Uuid::now_v7(), "mcp", ""),
    )
    .await;
    let revoked: Uuid = r.body["id"].as_str().unwrap().parse().unwrap();
    let r = report(
        &f.app,
        f.org_a,
        open_body(f.agent_a, Uuid::now_v7(), "pg", "db"),
    )
    .await;
    let old: Uuid = r.body["id"].as_str().unwrap().parse().unwrap();
    f.admin_sql(
        "UPDATE agent_sessions SET revoked_at = now() WHERE id = $1",
        revoked,
    )
    .await;
    f.admin_sql(
        "UPDATE agent_sessions SET last_seen_at = now() - interval '2 hours' WHERE id = $1",
        old,
    )
    .await;
    let l = list(&f.app, f.org_a, "").await;
    let items = l.body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{}", l.raw);
    assert_eq!(items[0]["id"], revoked.to_string());
    assert_eq!(items[0]["live"], false);
}

#[tokio::test]
async fn sessions_are_isolated_between_orgs() {
    let f = Fixture::start().await;
    let canary_b = Uuid::now_v7();
    let rb = report(
        &f.app,
        f.org_b,
        open_body(f.agent_b, canary_b, "http", "b-only"),
    )
    .await;
    assert_eq!(rb.status, StatusCode::CREATED, "{}", rb.raw);
    let b_id: Uuid = rb.body["id"].as_str().unwrap().parse().unwrap();
    report(
        &f.app,
        f.org_a,
        open_body(f.agent_a, Uuid::now_v7(), "http", "a-only"),
    )
    .await;

    let l = list(&f.app, f.org_a, "").await;
    assert_eq!(l.body["items"].as_array().unwrap().len(), 1, "{}", l.raw);
    assert!(!l.raw.contains("b-only") && !l.raw.contains(&b_id.to_string()));
    assert!(!l.raw.contains(&canary_b.to_string()));

    // Another org's agent or session is a 404 for the reporter.
    let r = report(
        &f.app,
        f.org_a,
        open_body(f.agent_b, Uuid::now_v7(), "http", "x"),
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.raw);
    for ev in ["heartbeat", "close"] {
        let r = report(&f.app, f.org_a, json!({"event": ev, "session_id": b_id})).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.raw);
    }
}

#[tokio::test]
async fn sessions_paging_and_validation() {
    let f = Fixture::start().await;
    for i in 0..3 {
        let r = report(
            &f.app,
            f.org_a,
            open_body(f.agent_a, Uuid::now_v7(), "http", &format!("s{i}")),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED);
    }
    let p1 = list(&f.app, f.org_a, "?limit=2").await;
    assert_eq!(p1.body["items"].as_array().unwrap().len(), 2, "{}", p1.raw);
    let next = p1.body["next"].as_str().unwrap();
    let p2 = list(&f.app, f.org_a, &format!("?limit=2&cursor={next}")).await;
    assert_eq!(p2.body["items"].as_array().unwrap().len(), 1, "{}", p2.raw);
    assert!(p2.body.get("next").is_none());
    assert_eq!(
        list(&f.app, f.org_a, "?limit=0").await.status,
        StatusCode::BAD_REQUEST
    );

    let long = "x".repeat(101);
    let r = report(
        &f.app,
        f.org_a,
        open_body(f.agent_a, Uuid::now_v7(), "http", &long),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.raw);
    let r = report(
        &f.app,
        f.org_a,
        open_body(f.agent_a, Uuid::now_v7(), "ssh", "x"),
    )
    .await;
    assert!(r.status.is_client_error(), "{}", r.raw);
    let mut extra = open_body(f.agent_a, Uuid::now_v7(), "http", "x");
    extra["address"] = json!("10.0.0.1");
    let r = report(&f.app, f.org_a, extra).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.raw);
}
