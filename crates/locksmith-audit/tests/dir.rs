//! `locksmith-audit verify --dir` (S5 task 5.1): offline verification of an export directory with
//! the checkpoint public key only, through the real binary.

mod common;

use std::fs;
use std::path::Path;

use common::{KEY_ID, OTHER_SEED, SEED, ledger, run, sign, write_config};
use ls_audit::export::{CHECKPOINTS_FILE, checkpoint_line, event_line, events_file_name};
use ls_audit::{Record, SignedCheckpoint};
use serde_json::Value;
use tempfile::TempDir;
use uuid::Uuid;

const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_00000000000a);
const ORG2: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_00000000000b);

struct Export {
    tmp: TempDir,
}

impl Export {
    /// An export with ORG (10 events in two files, checkpoints at 4 and 8) and ORG2 (3 events,
    /// no checkpoint), plus a verifier config trusting the golden vector's key.
    fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        write_config(&tmp.path().join("verifier.json"));
        fs::write(tmp.path().join("cursor.json"), "{}").unwrap();
        let e = Self { tmp };
        let l = ledger(ORG, 10);
        e.write_events(ORG, &l[..5]);
        e.write_events(ORG, &l[5..]);
        e.write_checkpoints(
            ORG,
            &[
                sign(&SEED, ORG, 4, l[3].hash),
                sign(&SEED, ORG, 8, l[7].hash),
            ],
        );
        e.write_events(ORG2, &ledger(ORG2, 3));
        e
    }

    fn dir(&self) -> &Path {
        self.tmp.path()
    }

    fn org_dir(&self, org: Uuid) -> std::path::PathBuf {
        let d = self.dir().join(org.hyphenated().to_string());
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_events(&self, org: Uuid, records: &[Record]) {
        let mut text = String::new();
        for r in records {
            text.push_str(&event_line(r).to_string());
            text.push('\n');
        }
        fs::write(
            self.org_dir(org).join(events_file_name(records[0].seq)),
            text,
        )
        .unwrap();
    }

    fn write_checkpoints(&self, org: Uuid, cps: &[SignedCheckpoint]) {
        let mut text = String::new();
        for c in cps {
            text.push_str(&checkpoint_line(c).to_string());
            text.push('\n');
        }
        fs::write(self.org_dir(org).join(CHECKPOINTS_FILE), text).unwrap();
    }

    /// Rewrite the lines of one of `org`'s files.
    fn edit(&self, org: Uuid, file: &str, f: impl FnOnce(&mut Vec<String>)) {
        let p = self.org_dir(org).join(file);
        let mut lines: Vec<String> = fs::read_to_string(&p)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        f(&mut lines);
        let mut text = lines.join("\n");
        text.push('\n');
        fs::write(p, text).unwrap();
    }

    fn verify(&self) -> common::Run {
        let dir = self.dir().to_str().unwrap().to_owned();
        let cfg = self.dir().join("verifier.json");
        run(
            &[
                "verify",
                "--dir",
                &dir,
                "--config",
                cfg.to_str().unwrap(),
                "--json",
            ],
            &[],
        )
    }
}

fn org(j: &Value, org: Uuid) -> Value {
    j["orgs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["org_id"] == org.hyphenated().to_string())
        .unwrap()
        .clone()
}

fn assert_fails_at(r: &common::Run, seq: u64) -> Value {
    assert_eq!(r.code, 1, "stdout {} stderr {}", r.stdout, r.stderr);
    let j = r.json();
    assert_eq!(j["ok"], false);
    let o = org(&j, ORG);
    assert_eq!(o["ok"], false);
    assert_eq!(o["first_broken_seq"], seq, "{o}");
    assert!(
        r.stderr
            .contains(&format!("org {}: first broken seq {seq}", ORG.hyphenated())),
        "{}",
        r.stderr
    );
    assert!(
        org(&j, ORG2)["ok"].as_bool().unwrap(),
        "other org unaffected"
    );
    o
}

#[test]
fn intact_export_verifies_offline() {
    let e = Export::new();
    let r = e.verify();
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    let j = r.json();
    assert_eq!(j["mode"], "dir");
    assert_eq!(j["ok"], true);
    let o = org(&j, ORG);
    assert_eq!(o["events"], 10);
    assert_eq!(o["checkpoints"], 2);
    assert_eq!(o["latest_checkpoint_seq"], 8);
    assert_eq!(o["first_broken_seq"], Value::Null);
    assert_eq!(o["verify_run_id"], Value::Null, "offline: nothing recorded");
    assert_eq!(org(&j, ORG2)["events"], 3);

    // Text output names each org and the totals.
    let dir = e.dir().to_str().unwrap().to_owned();
    let cfg = e.dir().join("verifier.json");
    let t = run(
        &["verify", "--dir", &dir, "--config", cfg.to_str().unwrap()],
        &[],
    );
    assert_eq!(t.code, 0);
    assert!(t.stdout.contains(&format!(
        "org {}: ok, 10 events, 2 checkpoints (latest checkpoint seq 8)",
        ORG.hyphenated()
    )));
    assert!(t.stdout.ends_with("verify: ok\n"), "{}", t.stdout);
}

#[test]
fn edited_line_fails_at_its_seq() {
    let e = Export::new();
    e.edit(ORG, "events-6.jsonl", |l| {
        let mut v: Value = serde_json::from_str(&l[1]).unwrap();
        v["outcome"] = "denied".into();
        l[1] = v.to_string();
    });
    let o = assert_fails_at(&e.verify(), 7);
    assert_eq!(o["break"]["kind"], "hash");
}

#[test]
fn deleted_line_fails_at_its_seq() {
    let e = Export::new();
    e.edit(ORG, "events-1.jsonl", |l| {
        l.remove(2);
    });
    let o = assert_fails_at(&e.verify(), 3);
    assert_eq!(o["break"]["kind"], "sequence");
}

#[test]
fn swapped_lines_fail_at_the_first() {
    let e = Export::new();
    e.edit(ORG, "events-1.jsonl", |l| l.swap(1, 2));
    assert_fails_at(&e.verify(), 2);
}

#[test]
fn truncation_past_a_checkpoint_is_reported() {
    let e = Export::new();
    // Keep seqs 6 and 7; the checkpoint at 8 is now past the end.
    e.edit(ORG, "events-6.jsonl", |l| l.truncate(2));
    let o = assert_fails_at(&e.verify(), 8);
    assert_eq!(o["truncated"]["checkpoint_seq"], 8);
    assert_eq!(o["truncated"]["last_seq"], 7);
}

#[test]
fn malformed_last_line_fails() {
    let e = Export::new();
    e.edit(ORG, "events-6.jsonl", |l| {
        let last = l.last_mut().unwrap();
        last.truncate(last.len() / 2);
    });
    let r = e.verify();
    assert_eq!(r.code, 1, "{}", r.stdout);
    let o = org(&r.json(), ORG);
    assert_eq!(
        o["malformed_lines"][0]["file"],
        format!("{}/events-6.jsonl", ORG.hyphenated())
    );
    assert_eq!(o["malformed_lines"][0]["line"], 5);
}

#[test]
fn checkpoint_signed_by_another_key_fails() {
    let e = Export::new();
    let l = ledger(ORG, 10);
    // Re-export the chain with a checkpoint signed by an untrusted key over its real head.
    e.write_events(ORG, &l[..5]);
    e.write_events(ORG, &l[5..]);
    e.write_checkpoints(ORG, &[sign(&OTHER_SEED, ORG, 8, l[7].hash)]);
    let o = assert_fails_at(&e.verify(), 8);
    assert_eq!(o["bad_checkpoints"][0]["problem"], "bad_signature");
    assert_eq!(o["bad_checkpoints"][0]["key_id"], KEY_ID);
    assert_eq!(o["break"]["kind"], "checkpoint");
}

#[test]
fn edited_checkpoint_line_fails_its_signature() {
    let e = Export::new();
    e.edit(ORG, CHECKPOINTS_FILE, |l| {
        let mut v: Value = serde_json::from_str(&l[0]).unwrap();
        v["at_micros"] = (v["at_micros"].as_i64().unwrap() + 1).into();
        l[0] = v.to_string();
    });
    let o = assert_fails_at(&e.verify(), 4);
    assert_eq!(o["bad_checkpoints"][0]["problem"], "bad_signature");
}

#[test]
fn rewritten_history_fails_against_the_exported_checkpoint() {
    let e = Export::new();
    // Rewrite seq 2 and recompute every later hash: self-consistent, but the signed checkpoint
    // at 4 no longer matches.
    let mut l = ledger(ORG, 10);
    l[1].outcome = "error".into();
    let mut prev = l[0].hash;
    for r in &mut l[1..] {
        r.prev_hash = prev;
        r.hash = r.compute_hash();
        prev = r.hash;
    }
    e.write_events(ORG, &l[..5]);
    e.write_events(ORG, &l[5..]);
    let o = assert_fails_at(&e.verify(), 4);
    assert_eq!(o["break"]["kind"], "checkpoint");
}

#[test]
fn unknown_key_id_fails() {
    let e = Export::new();
    e.edit(ORG, CHECKPOINTS_FILE, |l| {
        let mut v: Value = serde_json::from_str(&l[1]).unwrap();
        v["key_id"] = "audit-checkpoint:2".into();
        l[1] = v.to_string();
    });
    let o = assert_fails_at(&e.verify(), 8);
    assert_eq!(o["bad_checkpoints"][0]["problem"], "unknown_key");
}

#[test]
fn errors_exit_2() {
    let e = Export::new();
    let dir = e.dir().to_str().unwrap().to_owned();
    // Missing config.
    let r = run(
        &["verify", "--dir", &dir, "--config", "/nonexistent/v.json"],
        &[],
    );
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(r.stderr.contains("verifier config"));
    // Missing directory.
    let cfg = e.dir().join("verifier.json");
    let r = run(
        &[
            "verify",
            "--dir",
            "/nonexistent/export",
            "--config",
            cfg.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(r.code, 2, "{}", r.stderr);
    // --db without a URL, and neither mode.
    assert_eq!(run(&["verify", "--db"], &[]).code, 2);
    assert_eq!(run(&["verify"], &[]).code, 2);
    // Config with a bad key.
    fs::write(&cfg, r#"{"checkpoint_keys":{"k:1":"AAAA"}}"#).unwrap();
    let r = run(
        &["verify", "--dir", &dir, "--config", cfg.to_str().unwrap()],
        &[],
    );
    assert_eq!(r.code, 2);
}
