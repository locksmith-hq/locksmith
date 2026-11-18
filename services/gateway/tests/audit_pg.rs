//! `PgAudit` against a throwaway `postgres:18` (testcontainers; needs a Docker daemon), migrated
//! by the control plane's migrator: one row per attempt with version, caller and agent id
//! (refusals included), as `locksmith_app`, bound to the org by RLS.

use ls_control_plane::db::{Database, PoolSettings, sql};
use ls_control_plane::migrate;
use ls_gateway::audit::{AuditRecord, AuditSink, Outcome, PgAudit};
use ls_pg_test::Pg;
use uuid::Uuid;

/// `(outcome, status, version, caller, agent_id)` as read back.
type Row = (
    String,
    Option<i32>,
    Option<i32>,
    Option<String>,
    Option<Uuid>,
);

const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a1);

fn record(org: Uuid, secret: Uuid, outcome: Outcome, status: Option<u16>) -> AuditRecord {
    AuditRecord {
        org_id: org,
        agent_id: AGENT,
        secret_id: secret,
        version: 3,
        caller: "0197c1f0-0000-7000-8000-0000000000a1".to_owned(),
        method: "GET".to_owned(),
        scheme: "https".to_owned(),
        host: "api.example.com".to_owned(),
        path: "/v1/x".to_owned(),
        outcome,
        status,
        request_id: Uuid::new_v4().to_string(),
    }
}

#[tokio::test]
async fn pg_audit_appends_one_row_per_attempt() {
    let pg = Pg::start().await;
    migrate::run(pg.bootstrap()).await.expect("migrate");
    let db = Database::connect_lazy(pg.app(), PoolSettings::default());
    let org = Uuid::now_v7();
    db.with_org(org, move |c| {
        Box::pin(async move {
            sql::query("INSERT INTO orgs (id, name) VALUES ($1, 'audit-org')")
                .bind(org)
                .execute(c)
                .await
                .map(|_| ())
        })
    })
    .await
    .expect("create org");

    let audit = PgAudit::new(db.clone());
    let secret = Uuid::now_v7();
    audit
        .record(record(org, secret, Outcome::Ok, Some(200)))
        .await
        .expect("ok row");
    audit
        .record(record(org, secret, Outcome::NoGrant, None))
        .await
        .expect("no-grant denial row");
    // A row for an org that does not exist is refused (FK), not silently dropped.
    assert!(
        audit
            .record(record(Uuid::now_v7(), secret, Outcome::Ok, Some(200)))
            .await
            .is_err()
    );

    let rows: Vec<Row> = db
        .with_org(org, |c| {
            Box::pin(async move {
                sql::query_as(
                    "SELECT outcome, status, version, caller, agent_id FROM gateway_audit \
                     ORDER BY at, id",
                )
                .fetch_all(c)
                .await
            })
        })
        .await
        .unwrap();
    assert_eq!(
        rows,
        vec![
            (
                "ok".to_owned(),
                Some(200),
                Some(3),
                Some("0197c1f0-0000-7000-8000-0000000000a1".to_owned()),
                Some(AGENT)
            ),
            (
                "no_grant".to_owned(),
                None,
                Some(3),
                Some("0197c1f0-0000-7000-8000-0000000000a1".to_owned()),
                Some(AGENT)
            ),
        ]
    );
    db.close().await;
}
