//! The audit tamper test (S5 task 5.3; `just audit-tamper-test` runs it against the compose
//! Postgres, `just ci` against a throwaway `postgres:18` container). Each case tampers with its
//! own org as the database owner, `locksmith_owner`: edit a field, delete a row, swap two seqs,
//! truncate past a checkpoint (with and without deleting its row), edit an exported line, and the
//! strongest case: rewrite one event, recompute every later hash and the head, and delete the
//! `audit_checkpoints` rows. Each must fail verify (the database-only cases under `verify --db`,
//! the cases that also delete checkpoint rows only with `--checkpoints-from` the export, the
//! export edits under `verify --dir`), and the untouched org must pass every mode.

mod common;

use std::fs;
use std::path::PathBuf;

use common::pg::{Ledger, create_org, owner_exec, store_checkpoint};
use common::{SEED, event, run, sign, write_config};
use ls_audit::pg::{self as lpg, PgLedger};
use ls_pg_test::VERIFIER_PASSWORD;
use serde_json::Value;
use sqlx_core::connection::Connection;
use sqlx_core::query::query;
use sqlx_postgres::{PgConnection, PgPoolOptions};
use tempfile::TempDir;
use uuid::Uuid;

/// Events per org; every org has a signed checkpoint at [`CHECKPOINT`].
const EVENTS: i64 = 6;
const CHECKPOINT: u64 = 4;

struct Fixture {
    db: Ledger,
    tmp: TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        write_config(&tmp.path().join("verifier.json"));
        Self {
            db: Ledger::new().await,
            tmp,
        }
    }

    /// A new org with [`EVENTS`] events and a signed checkpoint at [`CHECKPOINT`].
    async fn org(&self) -> Uuid {
        let app = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(self.db.app())
            .await
            .unwrap();
        let org = create_org(&app).await;
        let ledger = PgLedger::new(app.clone());
        for i in 1..=EVENTS {
            let ap = ledger.append(org, &event(i)).await.unwrap();
            if ap.seq == CHECKPOINT {
                store_checkpoint(&self.db.owner(), &sign(&SEED, org, ap.seq, ap.hash)).await;
            }
        }
        app.close().await;
        org
    }

    fn export_dir(&self) -> PathBuf {
        self.tmp.path().join("export")
    }

    fn run(&self, args: &[&str]) -> Value {
        let cfg = self.tmp.path().join("verifier.json");
        let mut a = args.to_vec();
        a.push("--json");
        if a[0] == "verify" {
            a.extend(["--config", cfg.to_str().unwrap()]);
        }
        let r = run(
            &a,
            &[("LOCKSMITH_AUDIT_DATABASE_URL", &self.db.verifier_url())],
        );
        assert!(
            !r.stdout.contains(VERIFIER_PASSWORD) && !r.stderr.contains(VERIFIER_PASSWORD),
            "the database password is never printed"
        );
        assert!(
            !r.stdout.is_empty(),
            "{args:?}: exit {}: {}",
            r.code,
            r.stderr
        );
        let j = r.json();
        assert_eq!(
            r.code,
            if j["ok"] == true { 0 } else { 1 },
            "{} {}",
            r.stdout,
            r.stderr
        );
        j
    }

    fn export(&self) {
        let out = self.export_dir();
        let j = self.run(&["export", "--dir", out.to_str().unwrap()]);
        assert_eq!(j["ok"], true, "{j}");
    }

    fn verify_db(&self) -> Value {
        self.run(&["verify", "--db"])
    }

    fn verify_db_with_export(&self) -> Value {
        let out = self.export_dir();
        self.run(&[
            "verify",
            "--db",
            "--checkpoints-from",
            out.to_str().unwrap(),
        ])
    }

    fn verify_dir(&self) -> Value {
        let out = self.export_dir();
        self.run(&["verify", "--dir", out.to_str().unwrap()])
    }

    fn exported_file(&self, org: Uuid, name: &str) -> PathBuf {
        self.export_dir()
            .join(org.hyphenated().to_string())
            .join(name)
    }

    /// The strongest owner edit: change `seq`'s outcome, recompute that hash and every later
    /// link and hash, move the head, and delete the org's checkpoint rows. The chain is then
    /// self-consistent and the database holds nothing that contradicts it.
    async fn rewrite_history(&self, org: Uuid, seq: u64) {
        let mut c = PgConnection::connect_with(&self.db.owner()).await.unwrap();
        let mut tx = c.begin().await.unwrap();
        lpg::bind_org(&mut tx, org).await.unwrap();
        let mut records = lpg::records_in_tx(&mut tx, org).await.unwrap();
        let start = usize::try_from(seq).unwrap() - 1;
        records[start].outcome = "ok".into();
        let mut prev = records[start].prev_hash;
        for r in &mut records[start..] {
            r.prev_hash = prev;
            r.hash = r.compute_hash();
            prev = r.hash;
            query(
                "UPDATE audit_events SET outcome = $1, prev_hash = $2, hash = $3
                 WHERE org_id = $4 AND seq = $5",
            )
            .bind(&r.outcome)
            .bind(&r.prev_hash[..])
            .bind(&r.hash[..])
            .bind(org)
            .bind(i64::try_from(r.seq).unwrap())
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        query("UPDATE audit_heads SET hash = $1 WHERE org_id = $2")
            .bind(&prev[..])
            .bind(org)
            .execute(&mut *tx)
            .await
            .unwrap();
        query("DELETE FROM audit_checkpoints WHERE org_id = $1")
            .bind(org)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        c.close().await.unwrap();
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

/// Assert `org` passed in `j`.
fn passes(j: &Value, id: Uuid, what: &str) {
    let o = org(j, id);
    assert_eq!(o["ok"], true, "{what} should pass: {o}");
}

/// Assert `org` failed in `j` with `first_broken_seq` `seq`; returns the org's result.
fn fails_at(j: &Value, id: Uuid, seq: u64, what: &str) -> Value {
    let o = org(j, id);
    assert_eq!(o["ok"], false, "{what} should fail: {o}");
    assert_eq!(o["first_broken_seq"], seq, "{what}: {o}");
    o
}

#[tokio::test]
async fn every_tamper_case_fails_verify_and_the_untouched_ledger_passes() {
    let f = Fixture::new().await;
    let intact = f.org().await;
    let edited = f.org().await;
    let deleted = f.org().await;
    let swapped = f.org().await;
    let truncated = f.org().await;
    let truncated_unpinned = f.org().await;
    let rewritten = f.org().await;
    let export_event_edited = f.org().await;
    let export_checkpoint_edited = f.org().await;
    let all = [
        intact,
        edited,
        deleted,
        swapped,
        truncated,
        truncated_unpinned,
        rewritten,
        export_event_edited,
        export_checkpoint_edited,
    ];

    // Untouched: every mode passes, and the export carries each org's checkpoint.
    f.export();
    for j in [f.verify_db(), f.verify_db_with_export(), f.verify_dir()] {
        assert_eq!(j["ok"], true, "{j}");
        for id in all {
            let o = org(&j, id);
            assert_eq!((&o["events"], &o["checkpoints"]), (&6.into(), &1.into()));
        }
    }
    assert_eq!(
        org(&f.verify_db_with_export(), intact)["exported_checkpoints"],
        1
    );

    // Tamper as the database owner.
    let owner = f.db.owner();
    owner_exec(
        &owner,
        edited,
        &format!("UPDATE audit_events SET outcome = 'ok' WHERE org_id = '{edited}' AND seq = 3"),
    )
    .await;
    owner_exec(
        &owner,
        deleted,
        &format!("DELETE FROM audit_events WHERE org_id = '{deleted}' AND seq = 3"),
    )
    .await;
    // (org_id, seq) is unique per row, so the swap goes through a free seq.
    for (from, to) in [(2, 1000), (3, 2), (1000, 3)] {
        owner_exec(
            &owner,
            swapped,
            &format!(
                "UPDATE audit_events SET seq = {to} WHERE org_id = '{swapped}' AND seq = {from}"
            ),
        )
        .await;
    }
    owner_exec(
        &owner,
        truncated,
        &format!("DELETE FROM audit_events WHERE org_id = '{truncated}' AND seq >= 3"),
    )
    .await;
    // Truncate past the checkpoint, delete its row and move the head back: the database alone
    // is then a consistent two-event ledger.
    let o = truncated_unpinned;
    for stmt in [
        format!("DELETE FROM audit_events WHERE org_id = '{o}' AND seq >= 3"),
        format!("DELETE FROM audit_checkpoints WHERE org_id = '{o}'"),
        format!(
            "UPDATE audit_heads SET seq = 2,
                 hash = (SELECT hash FROM audit_events WHERE org_id = '{o}' AND seq = 2)
             WHERE org_id = '{o}'"
        ),
    ] {
        owner_exec(&owner, o, &stmt).await;
    }
    f.rewrite_history(rewritten, 2).await;
    // Edit exported lines: an event (seq 5) and the checkpoint.
    let p = f.exported_file(export_event_edited, "events-1.jsonl");
    let text = fs::read_to_string(&p).unwrap();
    let line5 = text.lines().nth(4).unwrap();
    assert!(
        line5.contains("\"seq\":5") && line5.contains("\"pending\""),
        "{line5}"
    );
    fs::write(
        &p,
        text.replacen(line5, &line5.replacen("\"pending\"", "\"ok\"", 1), 1),
    )
    .unwrap();
    let p = f.exported_file(export_checkpoint_edited, "checkpoints.jsonl");
    let text = fs::read_to_string(&p).unwrap();
    fs::write(&p, text.replacen("\"at_micros\":1", "\"at_micros\":2", 1)).unwrap();

    // The database alone: the row edits fail; the cases that also deleted the checkpoint rows
    // pass, which is why `just audit-verify` passes `--checkpoints-from` the export.
    let j = f.verify_db();
    assert_eq!(j["ok"], false);
    passes(&j, intact, "untouched");
    assert_eq!(
        fails_at(&j, edited, 3, "edited field")["break"]["kind"],
        "hash"
    );
    assert_eq!(
        fails_at(&j, deleted, 3, "deleted row")["break"]["kind"],
        "sequence"
    );
    fails_at(&j, swapped, 2, "swapped seqs");
    let o = fails_at(&j, truncated, 3, "truncation past a checkpoint");
    assert_eq!(o["truncated"]["checkpoint_seq"], CHECKPOINT);
    passes(
        &j,
        truncated_unpinned,
        "truncation with checkpoint rows deleted (db only)",
    );
    passes(
        &j,
        rewritten,
        "rewritten history with checkpoint rows deleted (db only)",
    );
    passes(&j, export_event_edited, "edited export line (db only)");
    passes(
        &j,
        export_checkpoint_edited,
        "edited export checkpoint (db only)",
    );

    // With the export's checkpoints: every database tamper fails, including the strongest case
    // (no `audit_checkpoints` rows left for that org).
    let j = f.verify_db_with_export();
    assert_eq!(j["ok"], false);
    passes(&j, intact, "untouched");
    fails_at(&j, edited, 3, "edited field");
    fails_at(&j, deleted, 3, "deleted row");
    fails_at(&j, swapped, 2, "swapped seqs");
    fails_at(&j, truncated, 3, "truncation past a checkpoint");
    let o = fails_at(
        &j,
        truncated_unpinned,
        3,
        "truncation, checkpoint rows deleted",
    );
    assert_eq!(o["truncated"]["checkpoint_seq"], CHECKPOINT);
    assert_eq!(o["exported_checkpoints"], 1);
    let o = fails_at(
        &j,
        rewritten,
        CHECKPOINT,
        "rewrite, checkpoint rows deleted",
    );
    assert_eq!(o["break"]["kind"], "checkpoint");
    assert_eq!(
        o["checkpoints"], 1,
        "only the exported checkpoint is left: {o}"
    );
    assert_eq!(o["exported_checkpoints"], 1);
    let o = fails_at(
        &j,
        export_checkpoint_edited,
        CHECKPOINT,
        "edited export checkpoint",
    );
    assert_eq!(o["bad_checkpoints"][0]["problem"], "bad_signature");
    passes(
        &j,
        export_event_edited,
        "edited export event line (not read here)",
    );

    // Offline: the edited export lines fail; the export predates the database tampering.
    let j = f.verify_dir();
    assert_eq!(j["ok"], false);
    fails_at(&j, export_event_edited, 5, "edited export line");
    fails_at(
        &j,
        export_checkpoint_edited,
        CHECKPOINT,
        "edited export checkpoint",
    );
    for id in [
        intact,
        edited,
        deleted,
        swapped,
        truncated,
        truncated_unpinned,
        rewritten,
    ] {
        passes(&j, id, "export taken before the database tampering");
    }
}

#[tokio::test]
async fn checkpoints_from_needs_db_and_an_existing_export() {
    let tmp = TempDir::new().unwrap();
    let cfg = tmp.path().join("verifier.json");
    write_config(&cfg);
    let missing = tmp.path().join("no-such-export");
    // Only with --db.
    let r = run(
        &[
            "verify",
            "--dir",
            tmp.path().to_str().unwrap(),
            "--checkpoints-from",
            missing.to_str().unwrap(),
            "--config",
            cfg.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(r.code, 2, "{}", r.stderr);
    // A missing export directory is an error before any database access.
    let r = run(
        &[
            "verify",
            "--db",
            "--checkpoints-from",
            missing.to_str().unwrap(),
            "--config",
            cfg.to_str().unwrap(),
        ],
        &[(
            "LOCKSMITH_AUDIT_DATABASE_URL",
            "postgres://audit_verifier:do-not-print-me@127.0.0.1:1/postgres",
        )],
    );
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(r.stderr.contains("no-such-export"), "{}", r.stderr);
    assert!(!r.stderr.contains("do-not-print-me") && !r.stdout.contains("do-not-print-me"));
}
