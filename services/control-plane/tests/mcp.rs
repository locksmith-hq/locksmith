//! M1 task 1.4: MCP tool switches and clients. Needs Docker (throwaway `postgres:18`).

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use ls_control_plane::app::{self, AppState};
use ls_control_plane::db::{PoolSettings, sql};
use ls_control_plane::readiness::ReadyFlag;
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
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

struct Fixture {
    app: Router,
    pg: common::Pg,
    a: Uuid,
    b: Uuid,
}

async fn start() -> Fixture {
    let pg = common::Pg::migrated().await;
    let state = AppState::new(
        true,
        Arc::new(ReadyFlag::new(true)),
        pg.app_db(PoolSettings::default()),
    );
    let app = app::build(state);
    let mut orgs = Vec::new();
    for name in ["org-a", "org-b"] {
        let (s, b) = call(
            &app,
            "POST",
            "/v1/orgs",
            None,
            Some(json!({ "name": name })),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        orgs.push(b["id"].as_str().unwrap().parse().unwrap());
    }
    Fixture {
        app,
        pg,
        a: orgs[0],
        b: orgs[1],
    }
}

/// Seed a client row as the control plane's `initialize` will (as the superuser: the insert path
/// belongs to task 2.3).
async fn seed_client(
    f: &Fixture,
    org: Uuid,
    layer: &str,
    client_id: &str,
    principal: &str,
) -> Uuid {
    let mut c = f.pg.admin().await;
    let id: Uuid = sql::query_scalar(
        "INSERT INTO mcp_clients (org_id, layer, client_id, principal, client_name) \
         VALUES ($1, $2, $3, $4, 'Claude') RETURNING id",
    )
    .bind(org)
    .bind(layer)
    .bind(client_id)
    .bind(principal)
    .fetch_one(&mut c)
    .await
    .unwrap();
    c.close().await.unwrap();
    id
}

fn find<'a>(list: &'a Value, layer: &str, tool: &str) -> &'a Value {
    list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["layer"] == layer && t["tool"] == tool)
        .unwrap_or_else(|| panic!("{layer}/{tool} missing"))
}

#[tokio::test]
async fn tool_settings_default_to_the_registry_and_are_set_per_org() {
    let f = start().await;
    let (s, list) = call(&f.app, "GET", "/v1/mcp/tools", Some(f.a), None).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    // Defaults come from ls-mcp-server: reads on, state changes off.
    let t = find(&list, "hub", "list_projects");
    assert_eq!(
        (t["enabled"].as_bool(), t["default_enabled"].as_bool()),
        (Some(true), Some(true))
    );
    assert_eq!(t["overridden"], false);
    assert_eq!(find(&list, "hub", "revoke_grant")["enabled"], false);
    assert_eq!(
        find(&list, "agent", "issue_short_lived_credential")["enabled"],
        false
    );
    assert_eq!(find(&list, "agent", "relay_http_request")["enabled"], true);

    // Turn one on; it is reflected, marked overridden, and only for this org.
    let (s, t) = call(
        &f.app,
        "PUT",
        "/v1/mcp/tools/hub/revoke_grant",
        Some(f.a),
        Some(json!({ "enabled": true })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{t}");
    assert_eq!(
        (t["enabled"].as_bool(), t["overridden"].as_bool()),
        (Some(true), Some(true))
    );
    let (_, la) = call(&f.app, "GET", "/v1/mcp/tools", Some(f.a), None).await;
    assert_eq!(find(&la, "hub", "revoke_grant")["enabled"], true);
    let (_, lb) = call(&f.app, "GET", "/v1/mcp/tools", Some(f.b), None).await;
    assert_eq!(find(&lb, "hub", "revoke_grant")["enabled"], false);

    // Setting it back to the default is no longer an override; a second PUT updates, not inserts.
    let (_, t) = call(
        &f.app,
        "PUT",
        "/v1/mcp/tools/hub/revoke_grant",
        Some(f.a),
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(
        (t["enabled"].as_bool(), t["overridden"].as_bool()),
        (Some(false), Some(false))
    );
    let mut c = f.pg.admin().await;
    let rows: i64 = sql::query_scalar("SELECT count(*) FROM mcp_tool_settings")
        .fetch_one(&mut c)
        .await
        .unwrap();
    c.close().await.unwrap();
    assert_eq!(rows, 1);
}

#[tokio::test]
async fn tool_setting_errors() {
    let f = start().await;
    let on = Some(json!({ "enabled": true }));
    for uri in [
        "/v1/mcp/tools/hub/no_such_tool",
        "/v1/mcp/tools/agent/list_projects",
    ] {
        let (s, _) = call(&f.app, "PUT", uri, Some(f.a), on.clone()).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{uri}");
    }
    let (s, _) = call(
        &f.app,
        "PUT",
        "/v1/mcp/tools/other/list_projects",
        Some(f.a),
        on.clone(),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(
        &f.app,
        "PUT",
        "/v1/mcp/tools/hub/list_projects",
        Some(f.a),
        Some(json!({ "enabled": true, "value": "x" })),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    for (m, uri) in [("GET", "/v1/mcp/tools"), ("GET", "/v1/mcp/clients")] {
        let (s, _) = call(&f.app, m, uri, None, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{uri}");
    }
    let (s, _) = call(&f.app, "PUT", "/v1/mcp/tools/hub/list_projects", None, on).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn clients_list_and_revoke_are_org_scoped() {
    let f = start().await;
    let (s, empty) = call(&f.app, "GET", "/v1/mcp/clients", Some(f.a), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(empty["items"], json!([]));

    let hub = seed_client(&f, f.a, "hub", "claude-desktop", "user-1").await;
    let agent = seed_client(&f, f.a, "agent", "agent-7", "agent-7").await;
    let other = seed_client(&f, f.b, "hub", "claude-desktop", "user-9").await;

    let (_, list) = call(&f.app, "GET", "/v1/mcp/clients", Some(f.a), None).await;
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["id"], hub.to_string());
    assert_eq!(items[0]["client_id"], "claude-desktop");
    assert_eq!(items[0]["layer"], "hub");
    assert!(items[0].get("revoked_at").is_none());
    let mut keys: Vec<&str> = items[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "client_id",
            "client_name",
            "first_seen_at",
            "id",
            "last_seen_at",
            "layer",
            "principal"
        ]
    );

    // Paging.
    let (_, p1) = call(&f.app, "GET", "/v1/mcp/clients?limit=1", Some(f.a), None).await;
    assert_eq!(p1["items"].as_array().unwrap().len(), 1);
    let cursor = p1["next"].as_str().unwrap();
    let (_, p2) = call(
        &f.app,
        "GET",
        &format!("/v1/mcp/clients?limit=1&cursor={cursor}"),
        Some(f.a),
        None,
    )
    .await;
    assert_eq!(p2["items"][0]["id"], agent.to_string());
    assert!(p2.get("next").is_none());

    // Another org cannot see or revoke org A's client; org A cannot revoke org B's.
    let (_, lb) = call(&f.app, "GET", "/v1/mcp/clients", Some(f.b), None).await;
    assert_eq!(lb["items"].as_array().unwrap().len(), 1);
    assert_eq!(lb["items"][0]["id"], other.to_string());
    let (s, _) = call(
        &f.app,
        "POST",
        &format!("/v1/mcp/clients/{hub}/revoke"),
        Some(f.b),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(
        &f.app,
        "POST",
        &format!("/v1/mcp/clients/{other}/revoke"),
        Some(f.a),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Revoke marks revoked_at, keeps the row, and a second revoke moves the cut-off to the new time
    // (a client that signed in again after the first revoke must be cut off too).
    let (s, r1) = call(
        &f.app,
        "POST",
        &format!("/v1/mcp/clients/{hub}/revoke"),
        Some(f.a),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{r1}");
    let at = r1["revoked_at"].as_str().unwrap().to_owned();
    let (_, r2) = call(
        &f.app,
        "POST",
        &format!("/v1/mcp/clients/{hub}/revoke"),
        Some(f.a),
        None,
    )
    .await;
    let at2 = r2["revoked_at"].as_str().unwrap().to_owned();
    assert!(at2 >= at, "{at} -> {at2}");
    let (_, list) = call(&f.app, "GET", "/v1/mcp/clients", Some(f.a), None).await;
    assert_eq!(list["items"][0]["revoked_at"], at2);
    assert!(list["items"][1].get("revoked_at").is_none());
    let (_, lb) = call(&f.app, "GET", "/v1/mcp/clients", Some(f.b), None).await;
    assert!(lb["items"][0].get("revoked_at").is_none());
}

/// The app role cannot delete clients or change who they are, and a client row is unique per
/// `(org, layer, client_id, principal)`.
#[tokio::test]
async fn app_role_cannot_delete_or_rekey_clients() {
    let f = start().await;
    let id = seed_client(&f, f.a, "hub", "c1", "p1").await;
    let mut c = f.pg.admin().await;
    let dup = sql::query(
        "INSERT INTO mcp_clients (org_id, layer, client_id, principal) VALUES ($1, 'hub', 'c1', 'p1')",
    )
    .bind(f.a)
    .execute(&mut c)
    .await;
    assert!(dup.is_err(), "duplicate key must be refused");
    c.close().await.unwrap();

    let db = f.pg.app_db(PoolSettings::default());
    for stmt in [
        "DELETE FROM mcp_clients",
        "UPDATE mcp_clients SET client_id = 'other'",
        "UPDATE mcp_clients SET org_id = org_id",
        "DELETE FROM mcp_tool_settings",
    ] {
        let org = f.a;
        let res = db
            .with_org(org, move |c| {
                Box::pin(async move {
                    sql::query(stmt).execute(c).await?;
                    Ok::<_, ls_control_plane::problem::ApiError>(())
                })
            })
            .await;
        assert!(res.is_err(), "{stmt} must be denied to the app role");
    }
    let _ = id;
}
