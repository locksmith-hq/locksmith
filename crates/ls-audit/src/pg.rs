//! The Postgres ledger store (feature `postgres`; S5 design decisions 1 and 2).
//!
//! An append runs in one transaction: bind `app.org_id` (transaction-local), lock the org's
//! `audit_heads` row with `SELECT ... FOR UPDATE` (creating it on the first append), compute the
//! record hash in Rust, insert the event and move the head. Concurrent appends for one org wait
//! on that row lock, so `seq` stays 1, 2, 3, ... with each `prev_hash` equal to the previous
//! hash; appends for different orgs do not contend.
//!
//! The schema and grants are in `services/control-plane/migrations/0008_audit_ledger.sql`. The
//! pool given to [`PgLedger`] logs in as `locksmith_app` (RLS applies, no UPDATE or DELETE on
//! events). Errors are sqlx errors and never carry event contents.

use std::time::{SystemTime, UNIX_EPOCH};

use sqlx_core::query::query;
use sqlx_core::query_as::query_as;
use sqlx_postgres::{PgConnection, PgPool};
use uuid::Uuid;

use crate::checkpoint::{CheckpointBody, SignedCheckpoint};
use crate::event::{Event, Record, StoredAttrs};
use crate::verifier::OrgReport;
use crate::{Checkpoint, Hash};

pub use sqlx_core::error::Error;

/// What an append stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appended {
    pub seq: u64,
    pub id: Uuid,
    pub hash: Hash,
}

/// Appends to and reads the ledger through an app-role pool.
#[derive(Clone)]
pub struct PgLedger {
    pool: PgPool,
}

impl PgLedger {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Append `event` to `org_id`'s chain in its own transaction.
    pub async fn append(&self, org_id: Uuid, event: &Event) -> Result<Appended, Error> {
        let mut tx = self.pool.begin().await?;
        bind_org(&mut tx, org_id).await?;
        let appended = append_in_tx(&mut tx, org_id, event).await?;
        tx.commit().await?;
        Ok(appended)
    }

    /// Every event of `org_id` in `seq` order.
    pub async fn records(&self, org_id: Uuid) -> Result<Vec<Record>, Error> {
        let mut tx = self.pool.begin().await?;
        bind_org(&mut tx, org_id).await?;
        let rows = records_in_tx(&mut tx, org_id).await?;
        tx.commit().await?;
        Ok(rows)
    }
}

/// Bind the transaction to `org_id` (`set_config(..., true)`: reset at commit or rollback).
pub async fn bind_org(conn: &mut PgConnection, org_id: Uuid) -> Result<(), Error> {
    query("SELECT set_config('app.org_id', $1, true)")
        .bind(org_id.to_string())
        .execute(conn)
        .await
        .map(|_| ())
}

fn now_micros() -> i64 {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970");
    i64::try_from(d.as_micros()).expect("time fits i64 microseconds")
}

fn to_hash(b: &[u8]) -> Result<Hash, Error> {
    Hash::try_from(b).map_err(|_| Error::Decode("audit hash is not 32 bytes".into()))
}

fn to_seq(s: i64) -> Result<u64, Error> {
    u64::try_from(s).map_err(|_| Error::Decode("negative audit seq".into()))
}

fn to_i64(seq: u64) -> Result<i64, Error> {
    i64::try_from(seq).map_err(|_| Error::Decode("audit seq overflows bigint".into()))
}

/// Append inside a transaction the caller has opened and bound to `org_id` with
/// [`bind_org`] (or the control plane's `Database::with_org`), so the event can commit
/// together with the change it records. Holds the org's head row lock until that transaction
/// ends.
pub async fn append_in_tx(
    conn: &mut PgConnection,
    org_id: Uuid,
    event: &Event,
) -> Result<Appended, Error> {
    let (seq, head) = lock_head(conn, org_id).await?;
    let seq = seq + 1;
    let record = Record::new(org_id, seq, Uuid::now_v7(), now_micros(), event, head);
    let attrs = record
        .attrs
        .as_ref()
        .map(StoredAttrs::to_json)
        .unwrap_or_default()
        .to_string();
    query(
        "INSERT INTO audit_events
             (org_id, seq, id, at, kind, actor, target, outcome, attrs, prev_hash, hash)
         VALUES ($1, $2, $3, 'epoch'::timestamptz + $4 * interval '1 microsecond',
                 $5, $6, $7, $8, $9::jsonb, $10, $11)",
    )
    .bind(org_id)
    .bind(to_i64(seq)?)
    .bind(record.id)
    .bind(record.at_micros)
    .bind(&record.kind)
    .bind(&record.actor)
    .bind(&record.target)
    .bind(&record.outcome)
    .bind(attrs)
    .bind(&record.prev_hash[..])
    .bind(&record.hash[..])
    .execute(&mut *conn)
    .await?;
    query("UPDATE audit_heads SET seq = $2, hash = $3, updated_at = now() WHERE org_id = $1")
        .bind(org_id)
        .bind(to_i64(seq)?)
        .bind(&record.hash[..])
        .execute(&mut *conn)
        .await?;
    Ok(Appended {
        seq,
        id: record.id,
        hash: record.hash,
    })
}

/// Lock `org_id`'s head row (creating it on the first use) until the caller's transaction
/// ends, and return the head's `(seq, hash)`. Every append takes this lock, so a caller that
/// must check the chain before appending (e.g. an idempotent append) takes it first and then
/// sees no concurrent append. Taking it again in the same transaction is a no-op.
pub async fn lock_head(conn: &mut PgConnection, org_id: Uuid) -> Result<(u64, Hash), Error> {
    // The first append creates the head; a concurrent first append waits on the unique index
    // and then does nothing.
    query("INSERT INTO audit_heads (org_id) VALUES ($1) ON CONFLICT (org_id) DO NOTHING")
        .bind(org_id)
        .execute(&mut *conn)
        .await?;
    let (seq, head): (i64, Vec<u8>) =
        query_as("SELECT seq, hash FROM audit_heads WHERE org_id = $1 FOR UPDATE")
            .bind(org_id)
            .fetch_one(&mut *conn)
            .await?;
    Ok((to_seq(seq)?, to_hash(&head)?))
}

/// `org_id`'s head `(seq, hash)` as visible in this transaction, without locking it; `None`
/// before the org's first append. The checkpoint job reads it (S5 task 4.2).
pub async fn head_in_tx(
    conn: &mut PgConnection,
    org_id: Uuid,
) -> Result<Option<(u64, Hash)>, Error> {
    let row: Option<(i64, Vec<u8>)> =
        query_as("SELECT seq, hash FROM audit_heads WHERE org_id = $1")
            .bind(org_id)
            .fetch_optional(&mut *conn)
            .await?;
    row.map(|(seq, hash)| Ok((to_seq(seq)?, to_hash(&hash)?)))
        .transpose()
}

type Row = (
    Uuid,
    i64,
    Uuid,
    i64,
    String,
    String,
    Option<String>,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
);

/// Every event of `org_id` visible in this transaction, in `seq` order. A row whose attributes
/// do not parse is returned with `attrs: None`, so verify reports it as a hash break.
pub async fn records_in_tx(conn: &mut PgConnection, org_id: Uuid) -> Result<Vec<Record>, Error> {
    records_after_in_tx(conn, org_id, 0, None).await
}

/// The events of `org_id` with `seq > after`, in `seq` order, at most `limit` of them (all when
/// `None`). The exporter reads in batches from its cursor (S5 task 5.2).
pub async fn records_after_in_tx(
    conn: &mut PgConnection,
    org_id: Uuid,
    after: u64,
    limit: Option<u64>,
) -> Result<Vec<Record>, Error> {
    let rows: Vec<Row> = query_as(
        "SELECT org_id, seq, id,
                (extract(epoch FROM at) * 1000000)::bigint,
                kind, actor, target, outcome, attrs::text, prev_hash, hash
         FROM audit_events WHERE org_id = $1 AND seq > $2 ORDER BY seq LIMIT $3",
    )
    .bind(org_id)
    .bind(to_i64(after)?)
    .bind(limit.map(to_i64).transpose()?)
    .fetch_all(conn)
    .await?;
    rows.into_iter()
        .map(
            |(org_id, seq, id, at_micros, kind, actor, target, outcome, attrs, prev, hash)| {
                Ok(Record {
                    org_id,
                    seq: to_seq(seq)?,
                    id,
                    at_micros,
                    kind,
                    actor,
                    target,
                    outcome,
                    attrs: serde_json::from_str(&attrs)
                        .ok()
                        .and_then(|v| StoredAttrs::from_json(&v)),
                    prev_hash: to_hash(&prev)?,
                    hash: to_hash(&hash)?,
                })
            },
        )
        .collect()
}

/// The checkpoints stored for `org_id` (signatures are checked by the verifier, task 5.1).
pub async fn checkpoints_in_tx(
    conn: &mut PgConnection,
    org_id: Uuid,
) -> Result<Vec<Checkpoint>, Error> {
    let rows: Vec<(i64, Vec<u8>)> =
        query_as("SELECT seq, hash FROM audit_checkpoints WHERE org_id = $1 ORDER BY seq")
            .bind(org_id)
            .fetch_all(conn)
            .await?;
    rows.into_iter()
        .map(|(seq, hash)| {
            Ok(Checkpoint {
                seq: to_seq(seq)?,
                hash: to_hash(&hash)?,
            })
        })
        .collect()
}

/// Every org with any ledger state (a head, an event or a checkpoint) visible in this
/// transaction, in id order. The verifier role (BYPASSRLS) sees all orgs.
pub async fn ledger_orgs_in_tx(conn: &mut PgConnection) -> Result<Vec<Uuid>, Error> {
    let rows: Vec<(Uuid,)> = query_as(
        "SELECT org_id FROM audit_heads
         UNION SELECT org_id FROM audit_events
         UNION SELECT org_id FROM audit_checkpoints
         ORDER BY 1",
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// `(seq, hash, at_micros, key_id, signature)` of an `audit_checkpoints` row.
type CheckpointRow = (i64, Vec<u8>, i64, String, Vec<u8>);

/// The checkpoints stored for `org_id` with their key ids and signatures, in `seq` order
/// (S5 task 5.1: the verifier checks each signature before trusting it).
pub async fn signed_checkpoints_in_tx(
    conn: &mut PgConnection,
    org_id: Uuid,
) -> Result<Vec<SignedCheckpoint>, Error> {
    signed_checkpoints_between_in_tx(conn, org_id, 0, u64::MAX).await
}

/// The signed checkpoints of `org_id` with `after < seq <= up_to`, in `seq` order (S5 task 5.2:
/// the exporter writes the checkpoints its exported events cover).
pub async fn signed_checkpoints_between_in_tx(
    conn: &mut PgConnection,
    org_id: Uuid,
    after: u64,
    up_to: u64,
) -> Result<Vec<SignedCheckpoint>, Error> {
    let rows: Vec<CheckpointRow> = query_as(
        "SELECT seq, hash, (extract(epoch FROM at) * 1000000)::bigint, key_id, signature
         FROM audit_checkpoints WHERE org_id = $1 AND seq > $2 AND seq <= $3 ORDER BY seq",
    )
    .bind(org_id)
    .bind(to_i64(after)?)
    .bind(i64::try_from(up_to).unwrap_or(i64::MAX))
    .fetch_all(conn)
    .await?;
    rows.into_iter()
        .map(|(seq, hash, at_micros, key_id, signature)| {
            Ok(SignedCheckpoint {
                body: CheckpointBody {
                    org_id,
                    seq: to_seq(seq)?,
                    hash: to_hash(&hash)?,
                    at_micros,
                },
                key_id,
                signature: <[u8; 64]>::try_from(signature.as_slice()).map_err(|_| {
                    Error::Decode("audit checkpoint signature is not 64 bytes".into())
                })?,
            })
        })
        .collect()
}

/// How a verify run read the ledger (`audit_verify_runs.mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    Db,
    Dir,
}

impl VerifyMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Db => "db",
            Self::Dir => "dir",
        }
    }
}

/// Record one org's verify result in `audit_verify_runs`, in its own transaction bound to that
/// org (the verifier role's INSERT policy admits only the bound org). `broken_seq` and
/// `break_kind` are [`OrgReport::first_break`]; `truncated_at` is the last `seq` present when
/// the chain ends before a checkpoint.
pub async fn record_verify_run(
    conn: &mut PgConnection,
    mode: VerifyMode,
    started_at_micros: i64,
    report: &OrgReport,
) -> Result<Uuid, Error> {
    use sqlx_core::connection::Connection;

    let first = report.first_break();
    let mut tx = conn.begin().await?;
    bind_org(&mut tx, report.org_id).await?;
    let (id,): (Uuid,) = query_as(
        "INSERT INTO audit_verify_runs
             (org_id, mode, started_at, ok, events, checkpoints, broken_seq, break_kind,
              truncated_at)
         VALUES ($1, $2, 'epoch'::timestamptz + $3 * interval '1 microsecond', $4, $5, $6, $7,
                 $8, $9)
         RETURNING id",
    )
    .bind(report.org_id)
    .bind(mode.as_str())
    .bind(started_at_micros)
    .bind(report.ok())
    .bind(to_i64(report.events)?)
    .bind(to_i64(report.checkpoints)?)
    .bind(first.map(|b| to_i64(b.seq)).transpose()?)
    .bind(first.map(|b| b.kind.as_str()))
    .bind(report.truncated.map(|t| to_i64(t.last_seq)).transpose()?)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// The current time in Unix microseconds (for `started_at`).
pub fn now_unix_micros() -> i64 {
    now_micros()
}
