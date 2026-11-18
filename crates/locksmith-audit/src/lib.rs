//! `locksmith-audit`: verify the audit ledger (S5 design decision 8, task 5.1) and export it to
//! a file sink ([`export`], [`sink`]; design decision 7, task 5.2).
//!
//! - [`verify_db`] walks every org in Postgres as the `audit_verifier` role (SELECT and
//!   BYPASSRLS) in one read-only snapshot, then records one `audit_verify_runs` row per org.
//!   With `--checkpoints-from <export>` it also trusts the export's signed checkpoints, so a
//!   rewrite or truncation is caught even after the `audit_checkpoints` rows are deleted.
//! - [`verify_dir`] reads an export directory ([`ls_audit::export`]) offline: no database and no
//!   KMS, only the checkpoint public keys.
//!
//! Both check each org with [`ls_audit::verifier::verify_org`]: `seq` contiguity, `prev_hash`
//! links, recomputed hashes, checkpoint signatures, and the trusted checkpoints present in the
//! chain (tail truncation). Output carries identifiers, counts, `seq` numbers and key ids only;
//! the database URL (which holds the role's password) is never printed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ls_audit::export::{
    CHECKPOINTS_FILE, events_file_first_seq, parse_checkpoint_line, parse_event_line,
};
use ls_audit::pg::{self, VerifyMode};
use ls_audit::verifier::{KeyRing, OrgReport, verify_org};
use ls_audit::{Break, Record, SignedCheckpoint};
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use sqlx_core::query::query;
use sqlx_postgres::{PgConnectOptions, PgConnection};
use uuid::Uuid;

pub mod export;
pub mod sink;

/// A failure to run verify or export at all (as opposed to a ledger that fails verification).
#[derive(Debug)]
pub enum Error {
    Config(String),
    Io(String),
    Db(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(m) => write!(f, "verifier config: {m}"),
            Self::Io(m) => write!(f, "export directory: {m}"),
            Self::Db(m) => write!(f, "database: {m}"),
        }
    }
}

impl std::error::Error for Error {}

pub(crate) fn db_err(context: &str) -> impl Fn(sqlx_core::error::Error) -> Error + '_ {
    // sqlx errors carry SQLSTATE messages and IO errors, never the connection password.
    move |e| Error::Db(format!("{context}: {e}"))
}

/// Load the checkpoint public keys from the verifier config that `just up` writes
/// (`scripts/audit-verifier-config.sh`): `{"checkpoint_keys": {"<key_id>": "<base64>"}}`.
pub fn load_keys(path: &Path) -> Result<KeyRing, Error> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
    parse_keys(&text).map_err(|m| Error::Config(format!("{}: {m}", path.display())))
}

/// Parse the verifier config text.
pub fn parse_keys(text: &str) -> Result<KeyRing, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    let keys = v
        .get("checkpoint_keys")
        .and_then(Value::as_object)
        .ok_or("no \"checkpoint_keys\" object")?;
    let mut ring = KeyRing::new();
    for (id, k) in keys {
        let public = k
            .as_str()
            .and_then(|s| B64.decode(s).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| format!("key {id} is not a base64 32-byte public key"))?;
        ring.insert(id.clone(), &public)
            .map_err(|e| format!("key {id}: {e}"))?;
    }
    Ok(ring)
}

/// A line of an export file that did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Malformed {
    /// The file, relative to the export directory.
    pub file: String,
    /// 1-based line number.
    pub line: u64,
    /// The line's `seq`, when it has a readable one.
    pub seq: Option<u64>,
}

/// One org's verify result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgResult {
    pub report: OrgReport,
    /// Unreadable export lines (for `--db`, only `--checkpoints-from` checkpoint lines). Any
    /// makes the org fail: a dropped line could otherwise hide an edit or a truncation.
    pub malformed: Vec<Malformed>,
    /// The `audit_verify_runs` row written for this result (`--db` only).
    pub run_id: Option<Uuid>,
    /// Checkpoints read for this org from the `--checkpoints-from` export (`--db` with that
    /// flag only; 0 when the export has none for the org).
    pub exported_checkpoints: Option<u64>,
}

impl OrgResult {
    pub fn ok(&self) -> bool {
        self.report.ok() && self.malformed.is_empty()
    }

    /// The first broken `seq` from the walk, a bad checkpoint, a truncation or a malformed line.
    pub fn first_broken_seq(&self) -> Option<u64> {
        let m = self.malformed.iter().filter_map(|m| m.seq).min();
        match (self.report.first_broken_seq(), m) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

/// The whole run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub mode: VerifyMode,
    pub orgs: Vec<OrgResult>,
}

impl Outcome {
    pub fn ok(&self) -> bool {
        self.orgs.iter().all(OrgResult::ok)
    }

    pub fn failed(&self) -> impl Iterator<Item = &OrgResult> {
        self.orgs.iter().filter(|o| !o.ok())
    }
}

/// Verify every org in the database at `url` (connect as `audit_verifier`) and record one
/// `audit_verify_runs` row per org. The ledger is read in one `REPEATABLE READ` read-only
/// snapshot, so a checkpoint written during the run cannot look like a truncation.
///
/// With `checkpoints_from` (an export directory, design decision 8), each org's exported
/// `checkpoints.jsonl` is trusted alongside its `audit_checkpoints` rows: every exported
/// checkpoint whose signature verifies must match the database chain, and the chain must not end
/// before it. This catches a database owner who rewrites history (recomputing every later hash)
/// or truncates it and then deletes the checkpoint rows. Orgs that appear only in the export are
/// verified too (with no events, so any exported checkpoint reports a truncation). The export's
/// event files are not read; `verify --dir` checks those.
pub async fn verify_db(
    url: &str,
    keys: &KeyRing,
    checkpoints_from: Option<&Path>,
) -> Result<Outcome, Error> {
    let mut exported = match checkpoints_from {
        Some(dir) => Some(exported_checkpoints(dir)?),
        None => None,
    };
    let opts = PgConnectOptions::from_str(url)
        .map_err(|_| Error::Db("the database URL does not parse".into()))?;
    let mut conn = PgConnection::connect_with(&opts)
        .await
        .map_err(db_err("connect"))?;

    let mut checked = Vec::new();
    {
        let mut tx = conn.begin().await.map_err(db_err("begin"))?;
        query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(db_err("snapshot"))?;
        let mut orgs: BTreeSet<Uuid> = pg::ledger_orgs_in_tx(&mut tx)
            .await
            .map_err(db_err("list orgs"))?
            .into_iter()
            .collect();
        if let Some(e) = &exported {
            orgs.extend(e.keys().copied());
        }
        for org in orgs {
            let started = pg::now_unix_micros();
            let records = pg::records_in_tx(&mut tx, org)
                .await
                .map_err(db_err("read events"))?;
            let mut cps = pg::signed_checkpoints_in_tx(&mut tx, org)
                .await
                .map_err(db_err("read checkpoints"))?;
            let mut malformed = Vec::new();
            let mut from_export = None;
            if let Some(e) = exported.as_mut() {
                let (ecps, bad) = e.remove(&org).unwrap_or_default();
                from_export = Some(u64::try_from(ecps.len()).unwrap_or(u64::MAX));
                // The exporter copies the database rows, so an intact pair is identical.
                for c in ecps {
                    if !cps.contains(&c) {
                        cps.push(c);
                    }
                }
                malformed = bad;
            }
            let report = verify_org(org, &records, &cps, keys);
            checked.push((started, report, malformed, from_export));
        }
        tx.commit().await.map_err(db_err("end snapshot"))?;
    }

    let mut orgs = Vec::with_capacity(checked.len());
    for (started, report, malformed, exported_checkpoints) in checked {
        let run_id = pg::record_verify_run(&mut conn, VerifyMode::Db, started, &report)
            .await
            .map_err(db_err("record verify run"))?;
        orgs.push(OrgResult {
            report,
            malformed,
            run_id: Some(run_id),
            exported_checkpoints,
        });
    }
    let _ = conn.close().await;
    Ok(Outcome {
        mode: VerifyMode::Db,
        orgs,
    })
}

/// The `<org_id>/` directories of an export directory, by org.
fn org_dirs(dir: &Path) -> Result<BTreeMap<Uuid, PathBuf>, Error> {
    let io = |p: &Path, e: std::io::Error| Error::Io(format!("{}: {e}", p.display()));
    let mut org_dirs: BTreeMap<Uuid, PathBuf> = BTreeMap::new();
    for entry in std::fs::read_dir(dir).map_err(|e| io(dir, e))? {
        let entry = entry.map_err(|e| io(dir, e))?;
        let name = entry.file_name();
        let Some(org) = name.to_str().and_then(|n| {
            Uuid::parse_str(n)
                .ok()
                .filter(|u| u.hyphenated().to_string() == n)
        }) else {
            continue;
        };
        if entry
            .file_type()
            .map_err(|e| io(&entry.path(), e))?
            .is_dir()
        {
            org_dirs.insert(org, entry.path());
        }
    }
    Ok(org_dirs)
}

/// The signed checkpoints in `<org_dir>/checkpoints.jsonl` (none when the file is missing).
/// Unreadable lines go to `malformed`.
fn read_checkpoints(
    org_dir: &Path,
    org: Uuid,
    malformed: &mut Vec<Malformed>,
) -> Result<Vec<SignedCheckpoint>, Error> {
    let mut cps = Vec::new();
    let cp_path = org_dir.join(CHECKPOINTS_FILE);
    if cp_path.exists() {
        for (n, v) in read_lines(&cp_path, org, CHECKPOINTS_FILE, malformed)? {
            match parse_checkpoint_line(&v) {
                Some(c) => cps.push(c),
                None => malformed.push(bad_line(org, CHECKPOINTS_FILE, n, &v)),
            }
        }
    }
    Ok(cps)
}

/// Every org's exported checkpoints and unreadable checkpoint lines (`--checkpoints-from`).
type ExportedCheckpoints = BTreeMap<Uuid, (Vec<SignedCheckpoint>, Vec<Malformed>)>;

fn exported_checkpoints(dir: &Path) -> Result<ExportedCheckpoints, Error> {
    let mut out = BTreeMap::new();
    for (org, path) in org_dirs(dir)? {
        let mut malformed = Vec::new();
        let cps = read_checkpoints(&path, org, &mut malformed)?;
        out.insert(org, (cps, malformed));
    }
    Ok(out)
}

/// Verify an export directory offline: every `<org_id>/` directory's event files (in
/// `first_seq` order, lines in file order) and `checkpoints.jsonl`.
pub fn verify_dir(dir: &Path, keys: &KeyRing) -> Result<Outcome, Error> {
    let io = |p: &Path, e: std::io::Error| Error::Io(format!("{}: {e}", p.display()));
    let mut orgs = Vec::new();
    for (org, path) in org_dirs(dir)? {
        let mut files: Vec<(u64, String)> = Vec::new();
        for entry in std::fs::read_dir(&path).map_err(|e| io(&path, e))? {
            let entry = entry.map_err(|e| io(&path, e))?;
            if let Some(name) = entry.file_name().to_str()
                && let Some(first) = events_file_first_seq(name)
            {
                files.push((first, name.to_owned()));
            }
        }
        files.sort();

        let mut malformed = Vec::new();
        let mut records: Vec<Record> = Vec::new();
        for (_, name) in &files {
            for (n, v) in read_lines(&path.join(name), org, name, &mut malformed)? {
                match parse_event_line(&v) {
                    Some(r) => records.push(r),
                    None => malformed.push(bad_line(org, name, n, &v)),
                }
            }
        }
        let cps = read_checkpoints(&path, org, &mut malformed)?;
        orgs.push(OrgResult {
            report: verify_org(org, &records, &cps, keys),
            malformed,
            run_id: None,
            exported_checkpoints: None,
        });
    }
    Ok(Outcome {
        mode: VerifyMode::Dir,
        orgs,
    })
}

/// The JSON values of a JSON Lines file with their 1-based line numbers. Lines that are not
/// JSON go to `malformed`; blank lines are malformed too (the exporter never writes one).
fn read_lines(
    path: &Path,
    org: Uuid,
    name: &str,
    malformed: &mut Vec<Malformed>,
) -> Result<Vec<(u64, Value)>, Error> {
    let text = std::fs::read(path).map_err(|e| Error::Io(format!("{}: {e}", path.display())))?;
    let mut out = Vec::new();
    // A trailing newline ends the last line; it does not start an empty one.
    let body = text.strip_suffix(b"\n").unwrap_or(&text);
    if body.is_empty() {
        return Ok(out);
    }
    for (i, line) in body.split(|b| *b == b'\n').enumerate() {
        let n = u64::try_from(i).unwrap_or(u64::MAX - 1) + 1;
        match serde_json::from_slice::<Value>(line) {
            Ok(v) => out.push((n, v)),
            Err(_) => malformed.push(Malformed {
                file: format!("{}/{name}", org.hyphenated()),
                line: n,
                seq: None,
            }),
        }
    }
    Ok(out)
}

fn bad_line(org: Uuid, name: &str, line: u64, v: &Value) -> Malformed {
    Malformed {
        file: format!("{}/{name}", org.hyphenated()),
        line,
        seq: v.get("seq").and_then(Value::as_u64),
    }
}

fn break_json(b: Option<Break>) -> Value {
    b.map_or(
        Value::Null,
        |b| json!({"seq": b.seq, "kind": b.kind.as_str()}),
    )
}

/// The `--json` output. Identifiers, counts, `seq` numbers and key ids only.
pub fn to_json(o: &Outcome) -> Value {
    let orgs: Vec<Value> = o
        .orgs
        .iter()
        .map(|r| {
            let rep = &r.report;
            json!({
                "org_id": rep.org_id.hyphenated().to_string(),
                "ok": r.ok(),
                "events": rep.events,
                "checkpoints": rep.checkpoints,
                "last_seq": rep.last_seq,
                "latest_checkpoint_seq": rep.latest_checkpoint_seq,
                "first_broken_seq": r.first_broken_seq(),
                "break": break_json(rep.first_break()),
                "truncated": rep.truncated.map(|t| json!({
                    "checkpoint_seq": t.checkpoint_seq,
                    "last_seq": t.last_seq,
                })),
                "bad_checkpoints": rep.bad_checkpoints.iter().map(|c| json!({
                    "seq": c.seq,
                    "key_id": c.key_id,
                    "problem": c.problem.as_str(),
                })).collect::<Vec<_>>(),
                "malformed_lines": r.malformed.iter().map(|m| json!({
                    "file": m.file,
                    "line": m.line,
                    "seq": m.seq,
                })).collect::<Vec<_>>(),
                "open_attempts": rep.open_attempts,
                "exported_checkpoints": r.exported_checkpoints,
                "verify_run_id": r.run_id.map(|id| id.hyphenated().to_string()),
            })
        })
        .collect();
    json!({
        "mode": o.mode.as_str(),
        "ok": o.ok(),
        "orgs": orgs,
    })
}

/// The human-readable output.
pub fn to_text(o: &Outcome) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "locksmith-audit verify ({}): {} org(s)",
        o.mode.as_str(),
        o.orgs.len()
    );
    for r in &o.orgs {
        let rep = &r.report;
        let status = match r.first_broken_seq() {
            None if r.ok() => "ok".to_owned(),
            None => "FAILED".to_owned(),
            Some(seq) => match rep.first_break().filter(|b| b.seq == seq) {
                Some(b) => format!("FAILED at seq {seq} ({})", b.kind.as_str()),
                None => format!("FAILED at seq {seq}"),
            },
        };
        let _ = write!(
            s,
            "org {}: {status}, {} events, {} checkpoints",
            rep.org_id.hyphenated(),
            rep.events,
            rep.checkpoints
        );
        if let Some(cp) = rep.latest_checkpoint_seq {
            let _ = write!(s, " (latest checkpoint seq {cp})");
        }
        if let Some(n) = r.exported_checkpoints {
            let _ = write!(s, ", {n} from the export");
        }
        if rep.open_attempts > 0 {
            let _ = write!(s, ", {} open attempt(s)", rep.open_attempts);
        }
        s.push('\n');
        for c in &rep.bad_checkpoints {
            let _ = writeln!(
                s,
                "  checkpoint seq {} (key {}): {}",
                c.seq,
                c.key_id,
                c.problem.as_str()
            );
        }
        if let Some(t) = rep.truncated {
            let _ = writeln!(
                s,
                "  chain ends at seq {} before checkpoint seq {}",
                t.last_seq, t.checkpoint_seq
            );
        }
        for m in &r.malformed {
            let _ = writeln!(s, "  malformed line {}:{}", m.file, m.line);
        }
    }
    let failed = o.failed().count();
    if failed == 0 {
        let _ = writeln!(s, "verify: ok");
    } else {
        let _ = writeln!(s, "verify: FAILED ({failed} of {} orgs)", o.orgs.len());
    }
    s
}
