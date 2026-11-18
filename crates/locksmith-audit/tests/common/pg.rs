//! Postgres helpers for the live tests (`db.rs`, `export.rs`).

use ls_audit::SignedCheckpoint;
use ls_audit::pg;
use ls_pg_test::Pg;
use sqlx_core::connection::Connection;
use sqlx_core::query::query;
use sqlx_core::sql_str::AssertSqlSafe;
use sqlx_postgres::{PgConnection, PgPool};
use uuid::Uuid;

pub async fn create_org(app: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    let mut tx = app.begin().await.unwrap();
    pg::bind_org(&mut tx, id).await.unwrap();
    query("INSERT INTO orgs (id, name) VALUES ($1, 'audit verify test')")
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    id
}

/// Store a signed checkpoint as the owner role (bound to the org: RLS is forced on owners too).
pub async fn store_checkpoint(pg: &Pg, cp: &SignedCheckpoint) {
    let mut c = PgConnection::connect_with(&pg.owner()).await.unwrap();
    let mut tx = c.begin().await.unwrap();
    pg::bind_org(&mut tx, cp.body.org_id).await.unwrap();
    query(
        "INSERT INTO audit_checkpoints (org_id, seq, hash, at, key_id, signature)
         VALUES ($1, $2, $3, 'epoch'::timestamptz + $4 * interval '1 microsecond', $5, $6)",
    )
    .bind(cp.body.org_id)
    .bind(i64::try_from(cp.body.seq).unwrap())
    .bind(&cp.body.hash[..])
    .bind(cp.body.at_micros)
    .bind(&cp.key_id)
    .bind(&cp.signature[..])
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// Run `stmt` as the database owner bound to `org` (the tamper path).
pub async fn owner_exec(pg: &Pg, org: Uuid, stmt: &str) {
    let mut c = PgConnection::connect_with(&pg.owner()).await.unwrap();
    let mut tx = c.begin().await.unwrap();
    pg::bind_org(&mut tx, org).await.unwrap();
    query(AssertSqlSafe(stmt.to_owned()))
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}
