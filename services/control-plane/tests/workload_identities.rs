//! D4 task 1.3: workload identity trust policy routes. Uses a throwaway `postgres:18`
//! container (testcontainers; needs Docker).

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use ls_control_plane::app::{self, AppState};
use ls_control_plane::db::PoolSettings;
use ls_control_plane::readiness::ReadyFlag;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    org: Option<Uuid>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(o) = org {
        b = b.header("x-locksmith-dev-org", o.to_string());
    }
    let req = match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(v.to_string())),
        None => b.body(Body::empty()),
    }
    .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (
        parts.status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn org(app: &Router, name: &str) -> Uuid {
    let (s, b) = call(app, "POST", "/v1/orgs", None, Some(json!({ "name": name }))).await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    b["id"].as_str().unwrap().parse().unwrap()
}

async fn agent(app: &Router, org: Uuid) -> Uuid {
    let (s, b) = call(
        app,
        "POST",
        "/v1/agents",
        Some(org),
        Some(json!({ "name": "ci" })),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    b["agent"]["id"].as_str().unwrap().parse().unwrap()
}

fn policy(agent: Uuid, name: &str, conditions: Value) -> Value {
    json!({
        "name": name, "issuer_kind": "github", "audience": "https://locksmith.example",
        "agent_id": agent, "conditions": conditions,
    })
}

async fn start() -> (common::Pg, Router) {
    let pg = common::Pg::migrated().await;
    let state = AppState::new(
        true,
        Arc::new(ReadyFlag::new(true)),
        pg.app_db(PoolSettings::default()),
    );
    (pg, app::build(state))
}

#[tokio::test]
async fn workload_policy_crud_and_audit() {
    let (_pg, app) = start().await;
    let org = org(&app, "org-a").await;
    let agent = agent(&app, org).await;

    let (s, b) = call(
        &app,
        "POST",
        "/v1/workload-identities",
        Some(org),
        Some(policy(
            agent,
            "deploy",
            json!([
                {"claim": "repository", "pattern": "acme/app"},
                {"claim": "ref", "pattern": "refs/heads/rel*"},
            ]),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let id = b["id"].as_str().unwrap().to_owned();
    assert!(b["handle"].as_str().unwrap().starts_with("lsw_"));
    assert_eq!(b["issuer"], "https://token.actions.githubusercontent.com");
    assert_eq!(b["conditions"][1]["pattern"], "refs/heads/rel*");

    let (s, b) = call(
        &app,
        "GET",
        &format!("/v1/workload-identities/{id}"),
        Some(org),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["name"], "deploy");

    let (s, b) = call(&app, "GET", "/v1/workload-identities", Some(org), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["items"].as_array().unwrap().len(), 1, "{b}");

    // Duplicate name in the same org.
    let (s, _) = call(
        &app,
        "POST",
        "/v1/workload-identities",
        Some(org),
        Some(policy(
            agent,
            "deploy",
            json!([{"claim": "repository", "pattern": "acme/x"}]),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);

    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/v1/workload-identities/{id}"),
        Some(org),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(
        &app,
        "GET",
        &format!("/v1/workload-identities/{id}"),
        Some(org),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, b) = call(&app, "GET", "/v1/audit/events", Some(org), None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let kinds: Vec<&str> = b["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"workload_identity.created"), "{kinds:?}");
    assert!(kinds.contains(&"workload_identity.deleted"), "{kinds:?}");
}

#[tokio::test]
async fn workload_policy_refuses_loose_or_cross_org() {
    let (_pg, app) = start().await;
    let a = org(&app, "org-a").await;
    let b_org = org(&app, "org-b").await;
    let agent_a = agent(&app, a).await;

    // No subject pin, bare wildcard: refused.
    for conds in [
        json!([{"claim": "ref", "pattern": "refs/heads/main"}]),
        json!([{"claim": "repository", "pattern": "*"}]),
        json!([]),
    ] {
        let (s, body) = call(
            &app,
            "POST",
            "/v1/workload-identities",
            Some(a),
            Some(policy(agent_a, "p", conds)),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    }

    // Org B cannot point a policy at org A's agent.
    let (s, _) = call(
        &app,
        "POST",
        "/v1/workload-identities",
        Some(b_org),
        Some(policy(
            agent_a,
            "p",
            json!([{"claim": "repository", "pattern": "acme/app"}]),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Org B cannot read or delete org A's policy.
    let (s, body) = call(
        &app,
        "POST",
        "/v1/workload-identities",
        Some(a),
        Some(policy(
            agent_a,
            "p",
            json!([{"claim": "repository", "pattern": "acme/app"}]),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    let id = body["id"].as_str().unwrap();
    for method in ["GET", "DELETE"] {
        let (s, _) = call(
            &app,
            method,
            &format!("/v1/workload-identities/{id}"),
            Some(b_org),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }
    let (_, list) = call(&app, "GET", "/v1/workload-identities", Some(b_org), None).await;
    assert_eq!(list["items"].as_array().unwrap().len(), 0);

    // Unauthenticated.
    let (s, _) = call(&app, "GET", "/v1/workload-identities", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}
