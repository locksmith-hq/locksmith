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
async fn bindings_mcp_rows_are_stored_and_served_with_their_tool_rules() {
    let pg = common::Pg::migrated().await;
    let app = app_with(pg.app_db(PoolSettings::default()));
    let org = new_org(&app, "mcp").await;
    let mcp = json!({
        "kind": "mcp", "name": "github", "origin": "https://api.githubcopilot.com/mcp/",
        "header": "Authorization", "default_decision": "hide",
        "tools": [
            {"name": "create_issue", "decision": "hold"},
            {"name": "delete_repository", "decision": "deny"},
            {"name": "list_issues", "decision": "allow"}
        ]
    });
    let snapshot = json!({"items": [http_item(), mcp]});
    let (status, body) = put(&app, org, Some(TOKEN), snapshot.clone()).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = list(&app, org).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), snapshot);

    // A `secret_id` or a template on an `mcp` row is refused, never stored.
    for (field, value) in [
        ("secret_id", json!(Uuid::from_u128(9).to_string())),
        ("template", json!("Bearer {secret}")),
    ] {
        let mut bad = snapshot["items"][1].clone();
        bad[field] = value;
        let (status, _) = put(&app, org, Some(TOKEN), json!({"items": [bad]})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{field}");
    }
    let (_, body) = list(&app, org).await;
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), snapshot);
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

/// `POST` as the org's dev principal; returns the created object's `id`.
async fn create(app: &Router, org: Uuid, uri: &str, body: Value) -> Uuid {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("x-locksmith-dev-org", org.to_string())
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, text) = send(app, req).await;
    assert_eq!(status, StatusCode::CREATED, "{uri}: {text}");
    let v: Value = serde_json::from_str(&text).unwrap();
    let id = if v["agent"].is_object() {
        &v["agent"]["id"]
    } else {
        &v["id"]
    };
    id.as_str().unwrap().parse().unwrap()
}

/// An org's secrets (by name) under one project and environment.
async fn secrets(app: &Router, org: Uuid, names: &[&str]) -> Vec<Uuid> {
    let p = create(app, org, "/v1/projects", json!({"name": "p"})).await;
    let e = create(
        app,
        org,
        &format!("/v1/projects/{p}/environments"),
        json!({"name": "dev"}),
    )
    .await;
    let mut out = Vec::new();
    for n in names {
        let uri = format!("/v1/projects/{p}/environments/{e}/secrets");
        out.push(create(app, org, &uri, json!({ "name": n })).await);
    }
    out
}

async fn delegate(app: &Router, org: Uuid, agent: Uuid, secret: Uuid, actions: &[&str]) {
    let body = json!({
        "secret_id": secret, "mode": "delegate",
        "scope": {"actions": actions, "resources": ["arn:aws:s3:::planted-resource-bucket/*"]}
    });
    create(app, org, &format!("/v1/agents/{agent}/grants"), body).await;
}

fn aws_item(role: &str, secret: Uuid) -> Value {
    json!({
        "kind": "aws", "name": role, "role": role, "region": "eu-west-1",
        "vend": true, "max_duration_secs": 900, "secret_id": secret
    })
}

/// d2 task 5.1 (design decision 8): an AWS row shows the action names of the org's unexpired
/// delegate grants on its secret; relay and expired grants, other orgs' grants, resources and
/// the secret id never appear, and non-AWS rows carry no actions.
#[tokio::test]
async fn bindings_aws_rows_show_allowed_actions_of_the_orgs_delegate_grants_only() {
    let pg = common::Pg::migrated().await;
    let app = app_with(pg.app_db(PoolSettings::default()));
    let org_a = new_org(&app, "a").await;
    let org_b = new_org(&app, "b").await;
    let a = secrets(&app, org_a, &["AWS_DEPLOY", "AWS_IDLE", "UPSTREAM"]).await;
    let b = secrets(&app, org_b, &["AWS_B"]).await;
    let (deploy, idle, upstream, b_secret) = (a[0], a[1], a[2], b[0]);

    let ci = create(&app, org_a, "/v1/agents", json!({"name": "ci"})).await;
    let ops = create(&app, org_a, "/v1/agents", json!({"name": "ops"})).await;
    delegate(&app, org_a, ci, deploy, &["s3:PutObject", "s3:GetObject"]).await;
    delegate(
        &app,
        org_a,
        ops,
        deploy,
        &["s3:GetObject", "sts:GetCallerIdentity"],
    )
    .await;
    create(
        &app,
        org_a,
        &format!("/v1/agents/{ci}/grants"),
        json!({"secret_id": upstream, "mode": "relay"}),
    )
    .await;
    let b_agent = create(&app, org_b, "/v1/agents", json!({"name": "b"})).await;
    delegate(&app, org_b, b_agent, b_secret, &["ec2:OrgBOnly"]).await;

    // An expired delegate grant on the idle binding does not count.
    let mut admin = pg.admin().await;
    sql::query(
        "INSERT INTO agent_grants (org_id, agent_id, secret_id, mode, scope, expires_at) \
         VALUES ($1, $2, $3, 'delegate', \
                 '{\"actions\": [\"iam:ExpiredOnly\"], \"resources\": [\"*\"]}'::jsonb, \
                 now() - interval '1 second')",
    )
    .bind(org_a)
    .bind(ops)
    .bind(idle)
    .execute(&mut admin)
    .await
    .unwrap();
    admin.close().await.unwrap();

    // Org A's snapshot even names org B's secret: RLS keeps org B's grants out.
    let snapshot = json!({"items": [
        aws_item("arn:aws:iam::1:role/deploy", deploy),
        aws_item("arn:aws:iam::1:role/idle", idle),
        aws_item("arn:aws:iam::1:role/foreign", b_secret),
        pg_item("db"),
        http_item(),
        json!({"kind": "aws", "name": "arn:aws:iam::1:role/old-gateway", "region": "eu-west-1"}),
    ]});
    let (status, body) = put(&app, org_a, Some(TOKEN), snapshot).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = list(&app, org_a).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = serde_json::from_str::<Value>(&body).unwrap()["items"].clone();
    assert_eq!(
        items[0]["allowed_actions"],
        json!(["s3:GetObject", "s3:PutObject", "sts:GetCallerIdentity"])
    );
    assert_eq!(items[1]["allowed_actions"], json!([]));
    assert_eq!(items[2]["allowed_actions"], json!([]));
    assert!(items[3].get("allowed_actions").is_none(), "{body}");
    assert!(items[4].get("allowed_actions").is_none(), "{body}");
    // An AWS row from an older gateway (no secret id): unknown, not "none".
    assert!(items[5].get("allowed_actions").is_none(), "{body}");
    for absent in [
        "secret_id",
        &deploy.to_string(),
        &b_secret.to_string(),
        "ec2:OrgBOnly",
        "iam:ExpiredOnly",
        "planted-resource-bucket",
        "resources",
    ] {
        assert!(!body.contains(absent), "{absent} in {body}");
    }

    // Org B sees its own grant on its own binding.
    let (status, body) = put(
        &app,
        org_b,
        Some(TOKEN),
        json!({"items": [aws_item("arn:aws:iam::2:role/b", b_secret)]}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, body) = list(&app, org_b).await;
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["items"][0]["allowed_actions"], json!(["ec2:OrgBOnly"]));

    // The gateway cannot publish actions itself, nor a secret id on a non-AWS row.
    let mut forged = aws_item("arn:aws:iam::1:role/deploy", deploy);
    forged["allowed_actions"] = json!(["*"]);
    let (status, _) = put(&app, org_a, Some(TOKEN), json!({"items": [forged]})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mut http = http_item();
    http["secret_id"] = json!(upstream);
    let (status, _) = put(&app, org_a, Some(TOKEN), json!({"items": [http]})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
