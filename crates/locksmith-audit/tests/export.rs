//! `locksmith-audit export` (S5 task 5.2) against a throwaway `postgres:18` migrated with the
//! control plane's migrations (testcontainers; needs Docker), through the real binary: an
//! incremental export verifies offline with `verify --dir`, holds every event exactly once in
//! order, and is refused (for that org only) when the ledger no longer extends it.

mod common;

use std::fs;
use std::path::Path;

use common::pg::{create_org, owner_exec, store_checkpoint};
use common::{SEED, event, run, sign, write_config};
use ls_audit::export::{CHECKPOINTS_FILE, CURSOR_FILE, events_file_first_seq};
use ls_audit::pg::PgLedger;
use ls_pg_test::{Pg, VERIFIER_PASSWORD};
use serde_json::Value;
use sqlx_postgres::{PgPool, PgPoolOptions};
use tempfile::TempDir;
use uuid::Uuid;

struct Fixture {
    pg: Pg,
    app: PgPool,
    tmp: TempDir,
    a: Uuid,
    b: Uuid,
}

impl Fixture {
    /// Org `a`: 6 events, a checkpoint at 4. Org `b`: 2 events.
    async fn new() -> Self {
        let pg = Pg::migrated().await;
        let app = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(pg.app())
            .await
            .unwrap();
        let a = create_org(&app).await;
        let b = create_org(&app).await;
        let tmp = TempDir::new().unwrap();
        write_config(&tmp.path().join("verifier.json"));
        let f = Self { pg, app, tmp, a, b };
        f.append(a, 6, Some(4)).await;
        f.append(b, 2, None).await;
        f
    }

    /// Append `n` events to `org`, and a signed checkpoint at `checkpoint_at` if given.
    async fn append(&self, org: Uuid, n: i64, checkpoint_at: Option<u64>) {
        let ledger = PgLedger::new(self.app.clone());
        for i in 1..=n {
            let ap = ledger.append(org, &event(i)).await.unwrap();
            if Some(ap.seq) == checkpoint_at {
                store_checkpoint(&self.pg, &sign(&SEED, org, ap.seq, ap.hash)).await;
            }
        }
    }

    fn url(&self) -> String {
        format!(
            "postgres://audit_verifier:{VERIFIER_PASSWORD}@127.0.0.1:{}/postgres",
            self.pg.port
        )
    }

    fn out(&self) -> std::path::PathBuf {
        self.tmp.path().join("export")
    }

    fn export(&self, extra: &[&str]) -> common::Run {
        let out = self.out();
        let mut args = vec!["export", "--json", "--dir", out.to_str().unwrap()];
        args.extend_from_slice(extra);
        let r = run(&args, &[("LOCKSMITH_AUDIT_DATABASE_URL", &self.url())]);
        assert!(
            !r.stdout.contains(VERIFIER_PASSWORD) && !r.stderr.contains(VERIFIER_PASSWORD),
            "the database password is never printed"
        );
        r
    }

    fn verify_dir(&self) -> common::Run {
        let cfg = self.tmp.path().join("verifier.json");
        let out = self.out();
        run(
            &[
                "verify",
                "--dir",
                out.to_str().unwrap(),
                "--json",
                "--config",
                cfg.to_str().unwrap(),
            ],
            &[],
        )
    }

    fn org_dir(&self, org: Uuid) -> std::path::PathBuf {
        self.out().join(org.hyphenated().to_string())
    }

    /// `(event seqs in file order, checkpoint seqs, event file names)` of `org`'s export.
    fn exported(&self, org: Uuid) -> (Vec<u64>, Vec<u64>, Vec<String>) {
        let dir = self.org_dir(org);
        let mut files: Vec<(u64, String)> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| {
                let n = e.unwrap().file_name().into_string().unwrap();
                events_file_first_seq(&n).map(|s| (s, n))
            })
            .collect();
        files.sort();
        let seqs = files
            .iter()
            .flat_map(|(_, n)| lines(&dir.join(n)))
            .map(|v| v["seq"].as_u64().unwrap())
            .collect();
        let cps = lines(&dir.join(CHECKPOINTS_FILE))
            .iter()
            .map(|v| v["seq"].as_u64().unwrap())
            .collect();
        (seqs, cps, files.into_iter().map(|(_, n)| n).collect())
    }

    fn cursor(&self, org: Uuid) -> Value {
        serde_json::from_slice(&fs::read(self.org_dir(org).join(CURSOR_FILE)).unwrap()).unwrap()
    }
}

fn lines(p: &Path) -> Vec<Value> {
    fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
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

/// Every file under `dir` with its contents.
fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for org in fs::read_dir(dir).unwrap() {
        let org = org.unwrap();
        if !org.file_type().unwrap().is_dir() {
            continue;
        }
        for f in fs::read_dir(org.path()).unwrap() {
            let f = f.unwrap();
            out.push((
                format!(
                    "{}/{}",
                    org.file_name().to_str().unwrap(),
                    f.file_name().to_str().unwrap()
                ),
                fs::read(f.path()).unwrap(),
            ));
        }
    }
    out.sort();
    out
}

#[tokio::test]
async fn incremental_export_writes_each_event_once_and_verifies_offline() {
    let f = Fixture::new().await;

    // First export.
    let r = f.export(&[]);
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    let j = r.json();
    let a = org(&j, f.a);
    assert_eq!(
        (
            &a["events"],
            &a["checkpoints"],
            &a["first_seq"],
            &a["cursor_seq"]
        ),
        (&6.into(), &1.into(), &1.into(), &6.into())
    );
    assert_eq!(org(&j, f.b)["events"], 2);
    assert_eq!(
        f.exported(f.a),
        ((1..=6).collect(), vec![4], vec!["events-1.jsonl".into()])
    );
    let v = f.verify_dir();
    assert_eq!(v.code, 0, "{} {}", v.stdout, v.stderr);
    assert_eq!(org(&v.json(), f.a)["events"], 6);

    // Running again with nothing new writes nothing.
    let before = snapshot(&f.out());
    let r = f.export(&[]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(org(&r.json(), f.a)["events"], 0);
    assert_eq!(snapshot(&f.out()), before, "an idle export changes no file");

    // More events and a checkpoint, exported in batches of 2.
    f.append(f.a, 5, Some(9)).await;
    let r = f.export(&["--batch-size", "2"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let a = org(&r.json(), f.a);
    assert_eq!(
        (
            &a["events"],
            &a["checkpoints"],
            &a["first_seq"],
            &a["cursor_seq"]
        ),
        (&5.into(), &1.into(), &7.into(), &11.into())
    );
    assert_eq!(a["cursor_checkpoint_seq"], 9);
    let (seqs, cps, files) = f.exported(f.a);
    assert_eq!(
        seqs,
        (1..=11).collect::<Vec<_>>(),
        "every event exactly once"
    );
    assert_eq!(cps, vec![4, 9]);
    assert_eq!(
        files,
        [
            "events-1.jsonl",
            "events-7.jsonl",
            "events-9.jsonl",
            "events-11.jsonl"
        ]
    );
    assert_eq!(f.cursor(f.a)["seq"], 11);
    assert_eq!(f.exported(f.b).0, vec![1, 2], "org b unchanged");
    let v = f.verify_dir();
    assert_eq!(v.code, 0, "{} {}", v.stdout, v.stderr);
    let va = org(&v.json(), f.a);
    assert_eq!((&va["events"], &va["checkpoints"]), (&11.into(), &2.into()));

    // An edited exported line fails offline verify at that seq.
    let p = f.org_dir(f.a).join("events-7.jsonl");
    let text = fs::read_to_string(&p).unwrap();
    fs::write(&p, text.replacen("\"pending\"", "\"ok\"", 1)).unwrap();
    let v = f.verify_dir();
    assert_eq!(v.code, 1, "{}", v.stdout);
    assert_eq!(org(&v.json(), f.a)["first_broken_seq"], 7);
}

#[tokio::test]
async fn export_refuses_a_ledger_that_no_longer_extends_it() {
    let f = Fixture::new().await;
    assert_eq!(f.export(&[]).code, 0);
    let exported = f.exported(f.a);
    let cursor = f.cursor(f.a);

    // New events in both orgs; org a's first new event is edited by the database owner.
    f.append(f.a, 2, None).await;
    f.append(f.b, 1, None).await;
    owner_exec(
        &f.pg,
        f.a,
        &format!(
            "UPDATE audit_events SET outcome = 'ok' WHERE org_id = '{}' AND seq = 7",
            f.a
        ),
    )
    .await;
    let r = f.export(&[]);
    assert_eq!(r.code, 1, "{} {}", r.stdout, r.stderr);
    assert!(
        r.stderr.contains(&format!(
            "org {}: the ledger does not extend the export at seq 7 (hash)",
            f.a.hyphenated()
        )),
        "{}",
        r.stderr
    );
    let j = r.json();
    assert_eq!(org(&j, f.a)["refused"]["seq"], 7);
    assert_eq!(f.exported(f.a), exported, "org a's export is untouched");
    assert_eq!(f.cursor(f.a), cursor);
    assert_eq!(f.exported(f.b).0, vec![1, 2, 3], "org b is still exported");

    // A rewritten history: the next event links to a head other than the exported one (as after
    // the owner rewrites an exported event and recomputes every later hash), so export refuses.
    let f = Fixture::new().await;
    assert_eq!(f.export(&[]).code, 0);
    f.append(f.a, 1, None).await;
    owner_exec(
        &f.pg,
        f.a,
        &format!(
            "UPDATE audit_events SET prev_hash = '\\x{}' WHERE org_id = '{}' AND seq = 7",
            "11".repeat(32),
            f.a
        ),
    )
    .await;
    let r = f.export(&[]);
    assert_eq!(r.code, 1);
    assert_eq!(org(&r.json(), f.a)["refused"]["kind"], "link");
}

#[tokio::test]
async fn export_refuses_a_bad_url_and_a_missing_url_without_printing_it() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("export");
    let url = "postgres://audit_verifier:do-not-print-me@127.0.0.1:1/postgres";
    let r = run(
        &["export", "--dir", out.to_str().unwrap()],
        &[("LOCKSMITH_AUDIT_DATABASE_URL", url)],
    );
    assert_eq!(r.code, 2);
    assert!(!r.stderr.contains("do-not-print-me") && !r.stdout.contains("do-not-print-me"));
    let r = run(&["export", "--dir", out.to_str().unwrap()], &[]);
    assert_eq!(r.code, 2, "{}", r.stderr);
}
