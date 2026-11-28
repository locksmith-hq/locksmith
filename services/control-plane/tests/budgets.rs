//! T9 task 3.2: the daily budget lease is atomic. Needs Docker (`postgres:18`).

mod common;

use std::sync::Arc;

use ls_control_plane::budget_store;
use ls_control_plane::db::{PoolSettings, sql};
use sqlx_core::connection::Connection;
use uuid::Uuid;

async fn org_and_agent(pg: &common::Pg) -> (Uuid, Uuid) {
    let mut c = pg.admin().await;
    let org: Uuid = sql::query_scalar("INSERT INTO orgs (name) VALUES ('budget-org') RETURNING id")
        .fetch_one(&mut c)
        .await
        .unwrap();
    let agent: Uuid = sql::query_scalar(
        "INSERT INTO agents (org_id, name, enrollment_hash) \
         VALUES ($1, 'a', '$argon2id$x') RETURNING id",
    )
    .bind(org)
    .fetch_one(&mut c)
    .await
    .unwrap();
    c.close().await.unwrap();
    (org, agent)
}

/// 8 concurrent gateways lease blocks of 7 against a limit of 100: the total granted is exactly
/// 100, never more, and the counter agrees.
#[tokio::test]
async fn concurrent_leases_never_pass_the_daily_limit() {
    let pg = common::Pg::migrated().await;
    let db = Arc::new(pg.app_db(PoolSettings::default()));
    let (org, agent) = org_and_agent(&pg).await;

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let db = db.clone();
        tasks.push(tokio::spawn(async move {
            let mut total = 0;
            loop {
                let lease = db
                    .with_org(org, |c| {
                        Box::pin(
                            async move { budget_store::lease(c, org, agent, None, 100, 7).await },
                        )
                    })
                    .await
                    .unwrap();
                if lease.granted == 0 {
                    return total;
                }
                assert!(lease.granted <= 7);
                total += lease.granted;
            }
        }));
    }
    let mut granted = 0;
    for t in tasks {
        granted += t.await.unwrap();
    }
    assert_eq!(granted, 100);

    let mut a = pg.admin().await;
    let used: i32 = sql::query_scalar("SELECT used FROM agent_budget_usage WHERE agent_id = $1")
        .bind(agent)
        .fetch_one(&mut a)
        .await
        .unwrap();
    assert_eq!(used, 100);
}

/// The agent-wide counter and a grant's counter are separate rows; a lowered limit grants 0.
#[tokio::test]
async fn grant_and_agent_counters_are_separate_and_a_lowered_limit_grants_nothing() {
    let pg = common::Pg::migrated().await;
    let db = pg.app_db(PoolSettings::default());
    let (org, agent) = org_and_agent(&pg).await;
    let grant = Uuid::now_v7();

    let lease = |grant: Option<Uuid>, limit: i32, count: i32| {
        let db = &db;
        async move {
            db.with_org(org, move |c| {
                Box::pin(
                    async move { budget_store::lease(c, org, agent, grant, limit, count).await },
                )
            })
            .await
            .unwrap()
        }
    };

    assert_eq!(lease(None, 5, 10).await.granted, 5);
    assert_eq!(lease(None, 5, 10).await.granted, 0);
    assert_eq!(lease(Some(grant), 5, 3).await.granted, 3);
    assert_eq!(lease(Some(grant), 5, 3).await.granted, 2);
    // The owner lowers the limit below what is already used: nothing more is granted.
    let l = lease(None, 2, 4).await;
    assert_eq!((l.granted, l.used), (0, 5));
    assert_eq!(l.day.len(), 10);
}
