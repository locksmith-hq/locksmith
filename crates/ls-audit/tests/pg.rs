//! The Postgres ledger store against a throwaway `postgres:18` (testcontainers; needs a Docker
//! daemon), migrated with the control plane's migrations (S5 tasks 2.1 and 2.2).
//!
//! Run with `cargo nextest run -p ls-audit --features postgres`.
#![cfg(feature = "postgres")]

use std::collections::BTreeSet;

use ls_audit::pg::{self, PgLedger};
use ls_audit::{
    Actor, Attrs, BreakKind, Code, Event, GENESIS, Host, Target, kind, outcome, verify,
};
use ls_pg_test::Pg;
use sqlx_core::connection::Connection;
use sqlx_core::query::query;
use sqlx_core::query_scalar::query_scalar;
use sqlx_core::sql_str::AssertSqlSafe;
use sqlx_postgres::{PgConnection, PgPool, PgPoolOptions};
use uuid::Uuid;

const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a1);
const SECRET: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000b2);

fn event(n: i64) -> Event {
    Event {
        kind: kind::RELAY_ATTEMPT,
        actor: Actor::Agent(AGENT),
        target: Some(Target::Secret(SECRET)),
        outcome: outcome::PENDING,
        attrs: Attrs::new()
            .host(Code::new("host"), Host::parse("api.example.com").unwrap())
            .int(Code::new("n"), n),
    }
}

async fn app_pool(pg: &Pg, max: u32) -> PgPool {
    PgPoolOptions::new()
        .max_connections(max)
        .connect_with(pg.app())
        .await
        .unwrap()
}

/// Create an org as the app role (RLS on `orgs` admits only the bound org).
async fn create_org(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    let mut tx = pool.begin().await.unwrap();
    pg::bind_org(&mut tx, id).await.unwrap();
    query("INSERT INTO orgs (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(name)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    id
}

fn sqlstate(e: &sqlx_core::error::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
}

/// Run `stmt` as the app role bound to `org`; return the SQLSTATE of the failure, if any.
async fn app_exec(pool: &PgPool, org: Option<Uuid>, stmt: &str) -> Option<String> {
    let mut tx = pool.begin().await.unwrap();
    if let Some(org) = org {
        pg::bind_org(&mut tx, org).await.unwrap();
    }
    let r = query(AssertSqlSafe(stmt.to_owned()))
        .execute(&mut *tx)
        .await;
    tx.rollback().await.unwrap();
    r.err()
        .map(|e| sqlstate(&e).unwrap_or_else(|| e.to_string()))
}

async fn count(conn: &mut PgConnection, org: Option<Uuid>, table: &str) -> i64 {
    let mut tx = conn.begin().await.unwrap();
    if let Some(org) = org {
        pg::bind_org(&mut tx, org).await.unwrap();
    }
    let n = query_scalar(AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    n
}

/// Scenario: concurrent appends stay linear. 50 appends race on one org; the stored chain is
/// seq 1..50, each `prev_hash` is the previous hash, every recomputed hash matches, and the head
/// row points at seq 50. The walk runs over rows read back from Postgres, so `at` and `attrs`
/// round-trip exactly.
#[tokio::test]
async fn fifty_concurrent_appends_give_seq_1_to_50_with_intact_links() {
    let pg = Pg::migrated().await;
    let pool = app_pool(&pg, 20).await;
    let org = create_org(&pool, "org-concurrent").await;
    let other = create_org(&pool, "org-other").await;
    let ledger = PgLedger::new(pool.clone());

    let mut tasks = Vec::new();
    for n in 0..50 {
        let ledger = ledger.clone();
        tasks.push(tokio::spawn(async move {
            ledger.append(org, &event(n)).await.unwrap()
        }));
    }
    // Another org appends at the same time on its own chain.
    for n in 0..5 {
        ledger.append(other, &event(n)).await.unwrap();
    }
    let mut seqs = BTreeSet::new();
    for t in tasks {
        seqs.insert(t.await.unwrap().seq);
    }
    assert_eq!(seqs, (1..=50).collect::<BTreeSet<u64>>());

    let records = ledger.records(org).await.unwrap();
    assert_eq!(records.len(), 50);
    assert_eq!(records[0].prev_hash, GENESIS);
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.seq, i as u64 + 1);
        assert_eq!(r.org_id, org);
        assert_eq!(r.compute_hash(), r.hash, "seq {}", r.seq);
        if i > 0 {
            assert_eq!(r.prev_hash, records[i - 1].hash, "link at seq {}", r.seq);
        }
        assert_eq!(r.id.get_version_num(), 7, "UUIDv7 ids");
    }
    let walk = verify(records.iter().map(|r| r.link()), &[]);
    assert!(walk.ok(), "{walk:?}");
    assert_eq!((walk.rows, walk.last_seq), (50, 50));

    let mut tx = pool.begin().await.unwrap();
    pg::bind_org(&mut tx, org).await.unwrap();
    let (head_seq, head_hash): (i64, Vec<u8>) =
        sqlx_core::query_as::query_as("SELECT seq, hash FROM audit_heads WHERE org_id = $1")
            .bind(org)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(head_seq, 50);
    assert_eq!(head_hash, walk.head.to_vec());

    let other_records = ledger.records(other).await.unwrap();
    assert_eq!(
        other_records.iter().map(|r| r.seq).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5]
    );
    assert!(verify(other_records.iter().map(|r| r.link()), &[]).ok());
    pool.close().await;
}

/// Scenario: the app role cannot rewrite history. UPDATE and DELETE are refused (42501) on
/// `audit_events`, `audit_checkpoints` and `audit_verify_runs`; on `audit_heads` only seq, hash
/// and updated_at may change and rows cannot be deleted.
#[tokio::test]
async fn app_role_update_and_delete_are_refused() {
    let pg = Pg::migrated().await;
    let pool = app_pool(&pg, 2).await;
    let org = create_org(&pool, "org-a").await;
    let ledger = PgLedger::new(pool.clone());
    let appended = ledger.append(org, &event(1)).await.unwrap();

    // The app role may insert a checkpoint (the checkpoint job, task 4.2).
    let mut tx = pool.begin().await.unwrap();
    pg::bind_org(&mut tx, org).await.unwrap();
    query(
        "INSERT INTO audit_checkpoints (org_id, seq, hash, at, key_id, signature)
         VALUES ($1, 1, $2, now(), 'audit-checkpoint:1', $3)",
    )
    .bind(org)
    .bind(&appended.hash[..])
    .bind(&[7u8; 64][..])
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let refused = [
        "UPDATE audit_events SET outcome = 'ok'",
        "DELETE FROM audit_events",
        "UPDATE audit_checkpoints SET seq = 2",
        "DELETE FROM audit_checkpoints",
        "UPDATE audit_verify_runs SET ok = true",
        "DELETE FROM audit_verify_runs",
        "INSERT INTO audit_verify_runs (org_id, mode, started_at, ok, events, checkpoints)
         VALUES (current_org_id(), 'db', now(), true, 0, 0)",
        "DELETE FROM audit_heads",
        "UPDATE audit_heads SET org_id = gen_random_uuid()",
        "TRUNCATE audit_events",
    ];
    for stmt in refused {
        assert_eq!(
            app_exec(&pool, Some(org), stmt).await.as_deref(),
            Some("42501"),
            "{stmt}"
        );
    }
    // The head update that the append itself makes is allowed.
    assert_eq!(
        app_exec(
            &pool,
            Some(org),
            "UPDATE audit_heads SET updated_at = now()"
        )
        .await,
        None
    );

    // Nothing changed.
    let records = ledger.records(org).await.unwrap();
    assert_eq!(records.len(), 1);
    assert!(verify(records.iter().map(|r| r.link()), &[]).ok());
    pool.close().await;
}

/// Scenario: cross-org isolation, plus RLS and FORCE RLS on every ledger table. Org B sees none
/// of org A's events, heads, checkpoints or verify runs; with no org bound everything reads as
/// empty; a row claiming another org is refused.
#[tokio::test]
async fn rls_isolates_orgs_on_every_ledger_table() {
    let pg = Pg::migrated().await;
    let mut admin = pg.admin().await;
    let rls: Vec<(String, bool, bool, String)> = sqlx_core::query_as::query_as(
        "SELECT relname::text, relrowsecurity, relforcerowsecurity, pg_get_userbyid(relowner)::text
         FROM pg_class WHERE relname LIKE 'audit\\_%' AND relkind = 'r' ORDER BY 1",
    )
    .fetch_all(&mut admin)
    .await
    .unwrap();
    assert_eq!(
        rls.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(),
        [
            // Migration 0010: the checkpoint job's queue (org ids only); the app role reads all
            // of its rows by design and changes one only when bound to its org.
            "audit_checkpoint_jobs",
            "audit_checkpoints",
            "audit_events",
            "audit_heads",
            "audit_verify_runs"
        ]
    );
    for (name, on, force, owner) in &rls {
        assert!(*on && *force, "{name} must FORCE ROW LEVEL SECURITY");
        assert_eq!(owner, "locksmith_owner", "{name}");
    }

    let pool = app_pool(&pg, 4).await;
    let a = create_org(&pool, "org-a").await;
    let b = create_org(&pool, "org-b").await;
    let ledger = PgLedger::new(pool.clone());
    let head_a = ledger.append(a, &event(1)).await.unwrap();
    ledger.append(a, &event(2)).await.unwrap();
    ledger.append(b, &event(3)).await.unwrap();

    // A checkpoint for A (app role) and a verify run for A (verifier role, org bound).
    let mut tx = pool.begin().await.unwrap();
    pg::bind_org(&mut tx, a).await.unwrap();
    query(
        "INSERT INTO audit_checkpoints (org_id, seq, hash, at, key_id, signature)
         VALUES ($1, 1, $2, now(), 'audit-checkpoint:1', $3)",
    )
    .bind(a)
    .bind(&head_a.hash[..])
    .bind(&[7u8; 64][..])
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let mut verifier = PgConnection::connect_with(&pg.verifier()).await.unwrap();
    let mut tx = verifier.begin().await.unwrap();
    pg::bind_org(&mut tx, a).await.unwrap();
    query(
        "INSERT INTO audit_verify_runs (org_id, mode, started_at, ok, events, checkpoints)
         VALUES ($1, 'db', now(), true, 2, 1)",
    )
    .bind(a)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let mut app = pool.acquire().await.unwrap();
    for (table, in_a, in_b) in [
        ("audit_events", 2, 1),
        ("audit_heads", 1, 1),
        ("audit_checkpoints", 1, 0),
        ("audit_verify_runs", 1, 0),
    ] {
        assert_eq!(count(&mut app, Some(a), table).await, in_a, "{table} as A");
        assert_eq!(count(&mut app, Some(b), table).await, in_b, "{table} as B");
        assert_eq!(count(&mut app, None, table).await, 0, "{table} unbound");
    }
    drop(app);
    let seen_by_b = ledger.records(b).await.unwrap();
    assert!(seen_by_b.iter().all(|r| r.org_id == b));
    assert!(ledger.records(a).await.unwrap().len() == 2);
    // Bound to B, asking for A's rows returns nothing.
    let mut tx = pool.begin().await.unwrap();
    pg::bind_org(&mut tx, b).await.unwrap();
    assert!(pg::records_in_tx(&mut tx, a).await.unwrap().is_empty());
    assert!(pg::checkpoints_in_tx(&mut tx, a).await.unwrap().is_empty());
    // Appending to A's chain from a transaction bound to B is refused by RLS.
    let err = pg::append_in_tx(&mut tx, a, &event(9))
        .await
        .expect_err("cross-org append");
    assert_eq!(sqlstate(&err).as_deref(), Some("42501"), "{err}");
    tx.rollback().await.unwrap();
    // So is a raw row claiming another org, and any append with no org bound.
    assert_eq!(
        app_exec(
            &pool,
            Some(b),
            &format!(
                "INSERT INTO audit_events (org_id, seq, id, at, kind, actor, outcome, prev_hash, hash)
                 VALUES ('{a}', 99, gen_random_uuid(), now(), 'x', 'service:x', 'ok',
                         '\\x{z}'::bytea, '\\x{z}'::bytea)",
                z = "00".repeat(32)
            ),
        )
        .await
        .as_deref(),
        Some("42501")
    );
    let mut tx = pool.begin().await.unwrap();
    let err = pg::append_in_tx(&mut tx, a, &event(9))
        .await
        .expect_err("unbound append");
    assert_eq!(sqlstate(&err).as_deref(), Some("42501"), "{err}");
    tx.rollback().await.unwrap();
    pool.close().await;
}

/// The verifier role: BYPASSRLS and SELECT across orgs, INSERT on `audit_verify_runs` only.
/// The app role never has BYPASSRLS and is not a member of the verifier role.
#[tokio::test]
async fn verifier_role_reads_every_org_and_writes_only_verify_runs() {
    let pg = Pg::migrated().await;
    let mut admin = pg.admin().await;
    let (sup, bypass, login): (bool, bool, bool) = sqlx_core::query_as::query_as(
        "SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = 'audit_verifier'",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert!(!sup && bypass && login);
    let app_bypass: bool =
        query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'locksmith_app'")
            .fetch_one(&mut admin)
            .await
            .unwrap();
    assert!(!app_bypass);
    let member: bool =
        query_scalar("SELECT pg_has_role('locksmith_app', 'audit_verifier', 'USAGE')")
            .fetch_one(&mut admin)
            .await
            .unwrap();
    assert!(!member);

    let pool = app_pool(&pg, 2).await;
    let a = create_org(&pool, "org-a").await;
    let b = create_org(&pool, "org-b").await;
    let ledger = PgLedger::new(pool.clone());
    ledger.append(a, &event(1)).await.unwrap();
    ledger.append(b, &event(2)).await.unwrap();

    let mut v = PgConnection::connect_with(&pg.verifier()).await.unwrap();
    // No org bound: BYPASSRLS sees both orgs.
    assert_eq!(count(&mut v, None, "audit_events").await, 2);
    assert_eq!(count(&mut v, None, "audit_heads").await, 2);
    let records = pg::records_in_tx(&mut v, a).await.unwrap();
    assert_eq!(records.len(), 1);
    assert!(verify(records.iter().map(|r| r.link()), &[]).ok());
    for stmt in [
        "UPDATE audit_events SET outcome = 'ok'",
        "DELETE FROM audit_events",
        "INSERT INTO audit_checkpoints (org_id, seq, hash, at, key_id, signature)
         SELECT org_id, seq, hash, now(), 'k', hash || hash FROM audit_events",
        "UPDATE audit_heads SET seq = 0",
        "UPDATE audit_verify_runs SET ok = false",
        "DELETE FROM audit_verify_runs",
        "SELECT count(*) FROM agents",
    ] {
        let err = query(stmt).execute(&mut v).await.expect_err(stmt);
        assert_eq!(sqlstate(&err).as_deref(), Some("42501"), "{stmt}: {err}");
    }
    v.close().await.unwrap();
    pool.close().await;
}

/// The owner can still rewrite rows (detection, not prevention: design decision 9); the walk
/// over rows read back from Postgres reports the first broken seq.
#[tokio::test]
async fn owner_edit_is_detected_at_its_seq() {
    let pg = Pg::migrated().await;
    let pool = app_pool(&pg, 2).await;
    let org = create_org(&pool, "org-a").await;
    let ledger = PgLedger::new(pool.clone());
    for n in 0..5 {
        ledger.append(org, &event(n)).await.unwrap();
    }
    let mut owner = PgConnection::connect_with(&pg.owner()).await.unwrap();
    // FORCE RLS applies to the owner too: bind the org to reach the rows.
    let mut tx = owner.begin().await.unwrap();
    pg::bind_org(&mut tx, org).await.unwrap();
    query(
        "UPDATE audit_events SET attrs = jsonb_set(attrs, '{n,int}', '42') WHERE org_id = $1 AND seq = 3",
    )
    .bind(org)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let records = ledger.records(org).await.unwrap();
    let walk = verify(records.iter().map(|r| r.link()), &[]);
    let broken = walk.broken.expect("edit detected");
    assert_eq!((broken.seq, broken.kind), (3, BreakKind::Hash));
    owner.close().await.unwrap();
    pool.close().await;
}
