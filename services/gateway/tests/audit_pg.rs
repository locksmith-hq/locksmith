//! `PgAudit` against a throwaway `postgres:18` (testcontainers; needs a Docker daemon), migrated
//! by the control plane's migrator: one row per attempt with version, caller and agent id
//! (refusals included), as `locksmith_app`, bound to the org by RLS.

use std::time::Duration;

use ls_control_plane::db::{Database, PoolSettings, sql};
use ls_control_plane::migrate;
use ls_gateway::audit::{AuditRecord, AuditSink, Outcome, PgAudit};
use sqlx_postgres::PgConnectOptions;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};
use uuid::Uuid;

// Test-only values; the container is local and discarded after the test.
const BOOTSTRAP_PASSWORD: &str = "bootstrap-test-only";
// Dev-only role password from the control plane's migrations/0001_roles.sql.
const APP_PASSWORD: &str = "locksmith-app-dev-only";

fn options(port: u16, user: &str, password: &str) -> PgConnectOptions {
    PgConnectOptions::new()
        .host("127.0.0.1")
        .port(port)
        .database("postgres")
        .username(user)
        .password(password)
}

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
    let container = GenericImage::new("postgres", "18")
        .with_exposed_port(5432.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_PASSWORD", BOOTSTRAP_PASSWORD)
        .with_startup_timeout(Duration::from_secs(120))
        .start()
        .await
        .expect("start postgres:18 (is Docker running?)");
    let port = container.get_host_port_ipv4(5432.tcp()).await.unwrap();
    // The image restarts once after init; retry until the migrator gets in.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        match migrate::run(options(port, "postgres", BOOTSTRAP_PASSWORD)).await {
            Ok(()) => break,
            Err(e) if tokio::time::Instant::now() > deadline => panic!("migrate: {e}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    }
    let db = Database::connect_lazy(
        options(port, "locksmith_app", APP_PASSWORD),
        PoolSettings::default(),
    );
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
