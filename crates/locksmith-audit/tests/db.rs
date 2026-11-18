//! `locksmith-audit verify --db` (S5 task 5.1) against a throwaway `postgres:18` migrated with the
//! control plane's migrations (testcontainers; needs Docker). The binary logs in as
//! `audit_verifier`; tampering runs as the owner role, as `just audit-tamper-test` will.

mod common;

use common::pg::{create_org, owner_exec, store_checkpoint};
use common::{OTHER_SEED, SEED, event, run, sign, write_config};
use ls_audit::pg::PgLedger;
use ls_pg_test::{Pg, VERIFIER_PASSWORD};
use serde_json::Value;
use sqlx_core::query_as::query_as;
use sqlx_postgres::PgPoolOptions;
use tempfile::TempDir;
use uuid::Uuid;

struct Fixture {
    pg: Pg,
    tmp: TempDir,
    a: Uuid,
    b: Uuid,
}

impl Fixture {
    /// Org `a`: 6 events, a checkpoint at 4. Org `b`: 2 events, no checkpoint.
    async fn new() -> Self {
        let pg = Pg::migrated().await;
        let app = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(pg.app())
            .await
            .unwrap();
        let ledger = PgLedger::new(app.clone());
        let a = create_org(&app).await;
        let b = create_org(&app).await;
        let mut head4 = None;
        for i in 1..=6 {
            let ap = ledger.append(a, &event(i)).await.unwrap();
            if ap.seq == 4 {
                head4 = Some(ap.hash);
            }
        }
        for i in 1..=2 {
            ledger.append(b, &event(i)).await.unwrap();
        }
        app.close().await;
        store_checkpoint(&pg.owner(), &sign(&SEED, a, 4, head4.unwrap())).await;
        let tmp = TempDir::new().unwrap();
        write_config(&tmp.path().join("verifier.json"));
        Self { pg, tmp, a, b }
    }

    fn url(&self) -> String {
        format!(
            "postgres://audit_verifier:{VERIFIER_PASSWORD}@127.0.0.1:{}/postgres",
            self.pg.port
        )
    }

    fn verify(&self) -> common::Run {
        let cfg = self.tmp.path().join("verifier.json");
        run(
            &[
                "verify",
                "--db",
                "--json",
                "--config",
                cfg.to_str().unwrap(),
            ],
            &[("LOCKSMITH_AUDIT_DATABASE_URL", &self.url())],
        )
    }

    /// `(ok, events, checkpoints, broken_seq, break_kind, truncated_at)` of org's verify runs,
    /// oldest first, read as the bootstrap superuser.
    async fn runs(
        &self,
        org: Uuid,
    ) -> Vec<(bool, i64, i64, Option<i64>, Option<String>, Option<i64>)> {
        let mut c = self.pg.admin().await;
        query_as(
            "SELECT ok, events, checkpoints, broken_seq, break_kind, truncated_at
             FROM audit_verify_runs WHERE org_id = $1 AND mode = 'db' ORDER BY finished_at, id",
        )
        .bind(org)
        .fetch_all(&mut c)
        .await
        .unwrap()
    }
}

fn org(j: &Value, org: Uuid) -> Value {
    j["orgs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["org_id"] == org.hyphenated().to_string())
        .unwrap_or_else(|| panic!("org {org} missing: {j}"))
        .clone()
}

#[tokio::test]
async fn db_verify_records_runs_and_detects_tampering() {
    let f = Fixture::new().await;

    // Intact.
    let r = f.verify();
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    assert!(!r.stdout.contains(VERIFIER_PASSWORD) && !r.stderr.contains(VERIFIER_PASSWORD));
    let j = r.json();
    assert_eq!(j["mode"], "db");
    let a = org(&j, f.a);
    assert_eq!(
        (
            a["ok"].clone(),
            a["events"].clone(),
            a["checkpoints"].clone()
        ),
        (true.into(), 6.into(), 1.into())
    );
    assert!(a["verify_run_id"].is_string());
    assert_eq!(org(&j, f.b)["events"], 2);
    assert_eq!(f.runs(f.a).await, vec![(true, 6, 1, None, None, None)]);
    assert_eq!(f.runs(f.b).await, vec![(true, 2, 0, None, None, None)]);

    // Edited field at seq 3.
    owner_exec(
        &f.pg.owner(),
        f.a,
        &format!(
            "UPDATE audit_events SET outcome = 'ok' WHERE org_id = '{}' AND seq = 3",
            f.a
        ),
    )
    .await;
    let r = f.verify();
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(
        r.stderr
            .contains(&format!("org {}: first broken seq 3", f.a.hyphenated())),
        "{}",
        r.stderr
    );
    let a = org(&r.json(), f.a);
    assert_eq!(a["break"]["kind"], "hash");
    assert!(org(&r.json(), f.b)["ok"].as_bool().unwrap());
    assert_eq!(
        f.runs(f.a).await.last().unwrap(),
        &(false, 6, 1, Some(3), Some("hash".into()), None)
    );
}

#[tokio::test]
async fn db_verify_detects_truncation_and_bad_signatures() {
    let f = Fixture::new().await;

    // Delete the tail past the checkpoint at seq 4.
    owner_exec(
        &f.pg.owner(),
        f.a,
        &format!(
            "DELETE FROM audit_events WHERE org_id = '{}' AND seq >= 3",
            f.a
        ),
    )
    .await;
    let r = f.verify();
    assert_eq!(r.code, 1, "{}", r.stdout);
    let a = org(&r.json(), f.a);
    assert_eq!(a["first_broken_seq"], 3);
    assert_eq!(a["truncated"]["checkpoint_seq"], 4);
    assert_eq!(
        f.runs(f.a).await.last().unwrap(),
        &(false, 2, 1, None, None, Some(2))
    );

    // A checkpoint for org b signed with an untrusted key.
    let head: Vec<u8> = {
        let mut c = f.pg.admin().await;
        sqlx_core::query_scalar::query_scalar(
            "SELECT hash FROM audit_events WHERE org_id = $1 AND seq = 2",
        )
        .bind(f.b)
        .fetch_one(&mut c)
        .await
        .unwrap()
    };
    store_checkpoint(
        &f.pg.owner(),
        &sign(&OTHER_SEED, f.b, 2, head.try_into().unwrap()),
    )
    .await;
    let r = f.verify();
    assert_eq!(r.code, 1);
    let b = org(&r.json(), f.b);
    assert_eq!(b["bad_checkpoints"][0]["problem"], "bad_signature");
    assert_eq!(
        f.runs(f.b).await.last().unwrap(),
        &(false, 2, 1, Some(2), Some("checkpoint".into()), None)
    );
}

#[tokio::test]
async fn db_verify_refuses_a_bad_url_without_printing_it() {
    let tmp = TempDir::new().unwrap();
    let cfg = tmp.path().join("verifier.json");
    write_config(&cfg);
    let url = "postgres://audit_verifier:do-not-print-me@127.0.0.1:1/postgres";
    let r = run(
        &["verify", "--db", "--config", cfg.to_str().unwrap()],
        &[("LOCKSMITH_AUDIT_DATABASE_URL", url)],
    );
    assert_eq!(r.code, 2);
    assert!(!r.stderr.contains("do-not-print-me") && !r.stdout.contains("do-not-print-me"));
}
