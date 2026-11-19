//! `locksmith-audit export` (S5 design decision 7, task 5.2): copy each org's new events and
//! checkpoints from Postgres to an [`AuditSink`], resuming from the sink's cursor.
//!
//! The ledger is read as the `audit_verifier` role in one `REPEATABLE READ` read-only snapshot,
//! in batches of `batch_size` events per org. Each batch is checked against the cursor with
//! [`check_batch`] before the sink commits it: an event at or below the cursor is never written
//! again, and a database chain that no longer extends the exported head (history rewritten or
//! rows deleted since the last export) is refused for that org, leaving its export untouched.
//! Lines carry identifiers and hashes only; the database URL is never printed.

use std::str::FromStr;

use ls_audit::export::{BatchProblem, Cursor, check_batch};
use ls_audit::pg;
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use sqlx_core::query::query;
use sqlx_postgres::{PgConnectOptions, PgConnection};
use uuid::Uuid;

use crate::sink::AuditSink;
use crate::{Error, db_err};

/// Events per batch (and so at most per event file) unless `--batch-size` says otherwise.
pub const DEFAULT_BATCH_SIZE: u64 = 10_000;

/// One org's export result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgExport {
    pub org_id: Uuid,
    /// Events written by this run.
    pub events: u64,
    /// Checkpoints written by this run.
    pub checkpoints: u64,
    /// The first `seq` written by this run.
    pub first_seq: Option<u64>,
    /// The committed cursor after this run.
    pub cursor: Cursor,
    /// Why the org's next batch was refused (its export stops at `cursor`).
    pub refused: Option<BatchProblem>,
}

/// The whole run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOutcome {
    pub orgs: Vec<OrgExport>,
}

impl ExportOutcome {
    pub fn ok(&self) -> bool {
        self.orgs.iter().all(|o| o.refused.is_none())
    }
}

/// Export every org in the database at `url` (connect as `audit_verifier`) to `sink`.
pub async fn export_db(
    url: &str,
    sink: &mut impl AuditSink,
    batch_size: u64,
) -> Result<ExportOutcome, Error> {
    if batch_size == 0 {
        return Err(Error::Config("--batch-size must be at least 1".into()));
    }
    let opts = PgConnectOptions::from_str(url)
        .map_err(|_| Error::Db("the database URL does not parse".into()))?;
    let mut conn = PgConnection::connect_with(&opts)
        .await
        .map_err(db_err("connect"))?;
    let mut tx = conn.begin().await.map_err(db_err("begin"))?;
    query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(db_err("snapshot"))?;
    let mut orgs = Vec::new();
    for org in pg::ledger_orgs_in_tx(&mut tx)
        .await
        .map_err(db_err("list orgs"))?
    {
        orgs.push(export_org(&mut tx, sink, org, batch_size).await?);
    }
    tx.commit().await.map_err(db_err("end snapshot"))?;
    let _ = conn.close().await;
    Ok(ExportOutcome { orgs })
}

/// Export one org's events and checkpoints after its cursor, batch by batch.
async fn export_org(
    conn: &mut PgConnection,
    sink: &mut impl AuditSink,
    org: Uuid,
    batch_size: u64,
) -> Result<OrgExport, Error> {
    let mut out = OrgExport {
        org_id: org,
        events: 0,
        checkpoints: 0,
        first_seq: None,
        cursor: sink.cursor(org)?.unwrap_or(Cursor::start(org)),
        refused: None,
    };
    loop {
        let cursor = out.cursor;
        let events = pg::records_after_in_tx(conn, org, cursor.seq, Some(batch_size))
            .await
            .map_err(db_err("read events"))?;
        let up_to = events.last().map_or(cursor.seq, |r| r.seq);
        let cps = pg::signed_checkpoints_between_in_tx(conn, org, cursor.checkpoint_seq, up_to)
            .await
            .map_err(db_err("read checkpoints"))?;
        if events.is_empty() && cps.is_empty() {
            break;
        }
        if let Err(p) = check_batch(&cursor, &events, &cps) {
            out.refused = Some(p);
            break;
        }
        out.cursor = sink.commit(&cursor, &events, &cps)?;
        out.first_seq = out.first_seq.or(events.first().map(|r| r.seq));
        out.events += u64::try_from(events.len()).unwrap_or(u64::MAX);
        out.checkpoints += u64::try_from(cps.len()).unwrap_or(u64::MAX);
    }
    Ok(out)
}

/// The `--json` output. Identifiers, counts and `seq` numbers only.
pub fn export_json(o: &ExportOutcome) -> Value {
    let orgs: Vec<Value> = o
        .orgs
        .iter()
        .map(|r| {
            json!({
                "org_id": r.org_id.hyphenated().to_string(),
                "ok": r.refused.is_none(),
                "events": r.events,
                "checkpoints": r.checkpoints,
                "first_seq": r.first_seq,
                "cursor_seq": r.cursor.seq,
                "cursor_checkpoint_seq": r.cursor.checkpoint_seq,
                "refused": r.refused.map(|p| json!({"seq": p.seq(), "kind": p.as_str()})),
            })
        })
        .collect();
    json!({ "ok": o.ok(), "orgs": orgs })
}

/// The human-readable output.
pub fn export_text(o: &ExportOutcome) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "locksmith-audit export: {} org(s)", o.orgs.len());
    for r in &o.orgs {
        let _ = write!(s, "org {}: ", r.org_id.hyphenated());
        match r.first_seq {
            Some(first) => {
                let _ = write!(s, "{} events (seq {first}..{})", r.events, r.cursor.seq);
            }
            None => {
                let _ = write!(s, "no new events");
            }
        }
        let _ = write!(
            s,
            ", {} checkpoints; exported up to seq {}",
            r.checkpoints, r.cursor.seq
        );
        if let Some(p) = r.refused {
            let _ = write!(
                s,
                "; REFUSED at seq {} ({}): the ledger does not extend the export",
                p.seq(),
                p.as_str()
            );
        }
        s.push('\n');
    }
    let refused = o.orgs.iter().filter(|r| r.refused.is_some()).count();
    if refused == 0 {
        let _ = writeln!(s, "export: ok");
    } else {
        let _ = writeln!(s, "export: REFUSED ({refused} of {} orgs)", o.orgs.len());
    }
    s
}
