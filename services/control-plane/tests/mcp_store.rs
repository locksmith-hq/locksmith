//! refactor-mcp-shared 2.1: the shared MCP client and settings SQL. Needs Docker (`postgres:18`).

mod common;

use ls_control_plane::db::{PoolSettings, sql};
use ls_control_plane::mcp_store;
use sqlx_core::connection::Connection;
use uuid::Uuid;

async fn org(pg: &common::Pg, name: &str) -> Uuid {
    let mut c = pg.admin().await;
    let id: Uuid = sql::query_scalar("INSERT INTO orgs (name) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(&mut c)
        .await
        .unwrap();
    c.close().await.unwrap();
    id
}

#[tokio::test]
async fn upsert_is_one_row_per_layer_with_the_latest_name_and_never_touches_revoked_at() {
    let pg = common::Pg::migrated().await;
    let db = pg.app_db(PoolSettings::default());
    let o = org(&pg, "store-org").await;

    for (layer, client, principal) in [("hub", "c1", "iss|sub"), ("agent", "a1", "a1")] {
        for name in ["first", "second"] {
            let revoked = db
                .with_org(o, |c| {
                    Box::pin(async move {
                        mcp_store::upsert_client(c, o, layer, client, principal, name).await
                    })
                })
                .await
                .unwrap();
            assert!(revoked.is_none());
        }
        // A long name is cut to 200 characters (multi-byte chars count once).
        let long = "é".repeat(300);
        db.with_org(o, |c| {
            Box::pin(async move {
                mcp_store::upsert_client(c, o, layer, client, principal, &long).await
            })
        })
        .await
        .unwrap();
    }

    let mut a = pg.admin().await;
    // Revoke the agent row as the console does, then upsert again: it stays revoked.
    sql::query("UPDATE mcp_clients SET revoked_at = now() WHERE layer = 'agent'")
        .execute(&mut a)
        .await
        .unwrap();
    let revoked = db
        .with_org(o, |c| {
            Box::pin(
                async move { mcp_store::upsert_client(c, o, "agent", "a1", "a1", "again").await },
            )
        })
        .await
        .unwrap();
    assert!(revoked.is_some());

    let rows: Vec<(String, String, bool)> = sql::query_as(
        "SELECT layer, client_name, revoked_at IS NOT NULL FROM mcp_clients \
         WHERE org_id = $1 ORDER BY layer",
    )
    .bind(o)
    .fetch_all(&mut a)
    .await
    .unwrap();
    a.close().await.unwrap();
    assert_eq!(rows.len(), 2, "one row per layer");
    assert_eq!(rows[0], ("agent".into(), "again".into(), true));
    assert_eq!(rows[1].0, "hub");
    assert_eq!(rows[1].1.chars().count(), 200);
    assert!(!rows[1].2, "hub revoked_at untouched");
}

#[tokio::test]
async fn settings_reads_are_per_org_and_per_layer() {
    let pg = common::Pg::migrated().await;
    let db = pg.app_db(PoolSettings::default());
    let (a, b) = (org(&pg, "org-a").await, org(&pg, "org-b").await);
    let mut adm = pg.admin().await;
    for (o, layer, tool, enabled) in [
        (a, "hub", "revoke_grant", true),
        (a, "agent", "relay_http_request", false),
        (a, "agent", "another", true),
        (b, "hub", "revoke_grant", false),
    ] {
        sql::query(
            "INSERT INTO mcp_tool_settings (org_id, layer, tool, enabled) VALUES ($1,$2,$3,$4)",
        )
        .bind(o)
        .bind(layer)
        .bind(tool)
        .bind(enabled)
        .execute(&mut adm)
        .await
        .unwrap();
    }
    adm.close().await.unwrap();

    let hub = db
        .with_org(a, |c| {
            Box::pin(async move { mcp_store::layer_settings(c, a, "hub").await })
        })
        .await
        .unwrap();
    assert_eq!(hub, vec![("revoke_grant".to_string(), true)]);
    let agent = db
        .with_org(a, |c| {
            Box::pin(async move { mcp_store::layer_settings(c, a, "agent").await })
        })
        .await
        .unwrap();
    assert_eq!(
        agent,
        vec![
            ("another".to_string(), true),
            ("relay_http_request".to_string(), false)
        ],
        "ordered by tool"
    );
    let all = db
        .with_org(a, |c| {
            Box::pin(async move { mcp_store::all_settings(c, a).await })
        })
        .await
        .unwrap();
    assert_eq!(all.len(), 3);
}
