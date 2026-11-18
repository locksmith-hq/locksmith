//! Signed audit checkpoints (S5 design decision 4, task 4.2).
//!
//! A background job checkpoints each org's chain: when an org has at least
//! [`Schedule::every`] events after its latest checkpoint, or its oldest event without one is
//! [`Schedule::max_age`] old, the job signs `ls_audit::CheckpointBody { org, seq, head hash,
//! time }` (domain tag `locksmith-checkpoint-v1`) with the OpenBao transit Ed25519 key
//! `audit-checkpoint` and stores the signature in `audit_checkpoints`. The control plane's
//! OpenBao token for this may only sign with that key; it cannot read, export or rotate it.
//!
//! Work queue (A0-2): `audit_checkpoint_jobs` (migration 0010) has one row per org with a chain.
//! A pass claims rows one at a time with `SELECT ... FOR UPDATE SKIP LOCKED`, binds the claimed
//! org to the transaction (RLS then applies to every ledger read and the checkpoint insert),
//! marks the row examined, and decides. The row lock, held until the checkpoint commits, keeps
//! two replicas from checkpointing one org at once; it is not the org's `audit_heads` lock, so
//! appends never wait on a signature. A pass examines every row once.
//!
//! Each examined org gets an `audit.checkpoint` span with the org id, the head `seq` and the
//! outcome only. Nothing here handles a secret value: the message and signature are public, and
//! the OpenBao token stays inside [`ls_envelope::TransitSigner`].

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ls_audit::CheckpointBody;
use ls_envelope::{BaoToken, TransitSigner, WrapError};
use secrecy::ExposeSecret;
use time::OffsetDateTime;
use tracing::Instrument;
use uuid::Uuid;

use crate::config::CheckpointKmsConfig;
use crate::db::sql::{self, PgConnection};
use crate::db::{Database, DbReadiness};

/// Checkpoint after this many new events (design decision 4).
pub const DEFAULT_EVERY: u64 = 1000;
/// Or once the oldest event without a checkpoint is this old (design decision 4).
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(60);
/// How often a pass runs. A checkpoint is therefore at most `max_age + tick` behind an event.
pub const DEFAULT_TICK: Duration = Duration::from_secs(5);

/// When the job checkpoints an org.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    /// Checkpoint when at least this many events follow the latest checkpoint.
    pub every: u64,
    /// Checkpoint when the oldest event after the latest checkpoint is at least this old.
    pub max_age: Duration,
    /// Time between passes ([`CheckpointJob::spawn`]).
    pub tick: Duration,
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            every: DEFAULT_EVERY,
            max_age: DEFAULT_MAX_AGE,
            tick: DEFAULT_TICK,
        }
    }
}

/// A checkpoint signature and the key that made it (`<transit key>:<version>`, the
/// `audit_checkpoints.key_id` column).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub key_id: String,
    pub signature: [u8; 64],
}

/// The future [`CheckpointSigner::sign`] returns.
pub type SignFuture<'a> = Pin<Box<dyn Future<Output = Result<Signed, WrapError>> + Send + 'a>>;

/// Signs checkpoint messages with Ed25519. Object-safe so the job holds `Arc<dyn ...>`.
pub trait CheckpointSigner: Send + Sync {
    fn sign<'a>(&'a self, message: &'a [u8]) -> SignFuture<'a>;
}

impl CheckpointSigner for TransitSigner {
    fn sign<'a>(&'a self, message: &'a [u8]) -> SignFuture<'a> {
        Box::pin(async move {
            let s = TransitSigner::sign(self, message).await?;
            let signature =
                <[u8; 64]>::try_from(s.signature.as_slice()).map_err(|_| WrapError::BadResponse)?;
            Ok(Signed {
                key_id: format!("{}:{}", self.key(), s.key_version),
                signature,
            })
        })
    }
}

/// Build the OpenBao transit checkpoint signer from configuration. The token is copied once
/// into [`BaoToken`] (zeroized on drop). Errors carry no address or token.
pub fn openbao(config: &CheckpointKmsConfig) -> Result<Arc<dyn CheckpointSigner>, WrapError> {
    let token = BaoToken::new(config.token.expose_secret().to_owned());
    Ok(Arc::new(TransitSigner::new(
        &config.addr,
        &config.key,
        token,
    )?))
}

/// What the job did for one org.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A checkpoint at this `seq` was signed and stored.
    Signed { seq: u64 },
    /// New events, but neither the count nor the age threshold is reached yet.
    Pending,
    /// No events after the latest checkpoint.
    Idle,
    /// Signing failed (OpenBao unreachable or refusing); retried on the next pass.
    SignFailed,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Signed { .. } => "signed",
            Self::Pending => "pending",
            Self::Idle => "idle",
            Self::SignFailed => "sign_failed",
        }
    }
}

/// What one pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PassReport {
    /// Orgs examined.
    pub examined: usize,
    /// Checkpoints stored.
    pub signed: usize,
    /// Orgs whose signing failed.
    pub failed: usize,
}

/// The checkpoint job over the app-role pool.
pub struct CheckpointJob {
    db: Database,
    signer: Arc<dyn CheckpointSigner>,
    schedule: Schedule,
}

impl CheckpointJob {
    pub fn new(db: Database, signer: Arc<dyn CheckpointSigner>, schedule: Schedule) -> Self {
        Self {
            db,
            signer,
            schedule,
        }
    }

    /// Examine every org with a chain once, checkpointing those that are due. Orgs another pass
    /// holds are skipped. Stops at the first database error (the next pass retries); a signing
    /// failure only skips that org.
    pub async fn run_pass(&self) -> Result<PassReport, sql::Error> {
        let pass_start: OffsetDateTime = self
            .db
            .without_org(|c| {
                Box::pin(async move {
                    sql::query_scalar("SELECT clock_timestamp()")
                        .fetch_one(c)
                        .await
                })
            })
            .await?;
        let mut report = PassReport::default();
        loop {
            let signer = self.signer.clone();
            let schedule = self.schedule;
            let done = self
                .db
                .without_org(move |c| {
                    Box::pin(
                        async move { claim_and_check(c, pass_start, &*signer, schedule).await },
                    )
                })
                .await?;
            match done {
                None => return Ok(report),
                Some(outcome) => {
                    report.examined += 1;
                    match outcome {
                        Outcome::Signed { .. } => report.signed += 1,
                        Outcome::SignFailed => report.failed += 1,
                        Outcome::Pending | Outcome::Idle => {}
                    }
                }
            }
        }
    }

    /// Run a pass every [`Schedule::tick`] once migrations are applied, until the handle is
    /// aborted.
    pub fn spawn(self, readiness: Arc<DbReadiness>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(self.schedule.tick);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if !readiness.is_migrated() {
                    continue;
                }
                if let Err(e) = self.run_pass().await {
                    tracing::warn!(error = %e, "audit checkpoint pass failed; retrying next tick");
                }
            }
        })
    }
}

/// Claim the next org not yet examined in this pass, bind it, and checkpoint it if due.
/// `None` when every org has been examined (or is held by another pass).
async fn claim_and_check(
    c: &mut PgConnection,
    pass_start: OffsetDateTime,
    signer: &dyn CheckpointSigner,
    schedule: Schedule,
) -> Result<Option<Outcome>, sql::Error> {
    let claimed: Option<Uuid> = sql::query_scalar(
        "SELECT org_id FROM audit_checkpoint_jobs WHERE checked_at < $1
         ORDER BY checked_at, org_id LIMIT 1 FOR UPDATE SKIP LOCKED",
    )
    .bind(pass_start)
    .fetch_optional(&mut *c)
    .await?;
    let Some(org_id) = claimed else {
        return Ok(None);
    };
    // Transaction-local, like Database::with_org: RLS now limits this transaction to org_id.
    ls_audit::pg::bind_org(c, org_id).await?;
    sql::query("UPDATE audit_checkpoint_jobs SET checked_at = clock_timestamp() WHERE org_id = $1")
        .bind(org_id)
        .execute(&mut *c)
        .await?;

    let span = tracing::info_span!(
        "audit.checkpoint",
        org.id = %org_id,
        audit.seq = tracing::field::Empty,
        audit.outcome = tracing::field::Empty,
    );
    let result = check_org(c, org_id, signer, schedule, &span)
        .instrument(span.clone())
        .await;
    span.record(
        "audit.outcome",
        result.as_ref().map_or("error", |o| o.as_str()),
    );
    result.map(Some)
}

async fn check_org(
    c: &mut PgConnection,
    org_id: Uuid,
    signer: &dyn CheckpointSigner,
    schedule: Schedule,
    span: &tracing::Span,
) -> Result<Outcome, sql::Error> {
    let Some((seq, hash)) = ls_audit::pg::head_in_tx(c, org_id).await? else {
        return Ok(Outcome::Idle);
    };
    // u64 seq as i64 for OTel; seqs stay far below i64::MAX.
    span.record("audit.seq", i64::try_from(seq).unwrap_or(i64::MAX));
    let last: Option<i64> =
        sql::query_scalar("SELECT max(seq) FROM audit_checkpoints WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&mut *c)
            .await?;
    let last = u64::try_from(last.unwrap_or(0))
        .map_err(|_| sql::Error::Decode("negative checkpoint seq".into()))?;
    if seq <= last {
        return Ok(Outcome::Idle);
    }
    if seq - last < schedule.every && !oldest_is_due(c, org_id, last + 1, schedule).await? {
        return Ok(Outcome::Pending);
    }

    let body = CheckpointBody {
        org_id,
        seq,
        hash,
        at_micros: now_micros(),
    };
    let signed = match signer.sign(&body.message()).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(org.id = %org_id, error = %e, "audit checkpoint signing failed");
            return Ok(Outcome::SignFailed);
        }
    };
    sql::query(
        "INSERT INTO audit_checkpoints (org_id, seq, hash, at, key_id, signature)
         VALUES ($1, $2, $3, 'epoch'::timestamptz + $4 * interval '1 microsecond', $5, $6)",
    )
    .bind(org_id)
    .bind(to_i64(seq)?)
    .bind(&hash[..])
    .bind(body.at_micros)
    .bind(&signed.key_id)
    .bind(&signed.signature[..])
    .execute(&mut *c)
    .await?;
    Ok(Outcome::Signed { seq })
}

/// Whether the event at `seq` (the oldest one after the latest checkpoint) is at least
/// `max_age` old by the database clock. A missing row counts as due, so the gap is pinned.
async fn oldest_is_due(
    c: &mut PgConnection,
    org_id: Uuid,
    seq: u64,
    schedule: Schedule,
) -> Result<bool, sql::Error> {
    let age_micros: Option<i64> = sql::query_scalar(
        "SELECT (extract(epoch FROM clock_timestamp() - at) * 1000000)::bigint
         FROM audit_events WHERE org_id = $1 AND seq = $2",
    )
    .bind(org_id)
    .bind(to_i64(seq)?)
    .fetch_optional(&mut *c)
    .await?;
    let max_age = i64::try_from(schedule.max_age.as_micros()).unwrap_or(i64::MAX);
    Ok(age_micros.is_none_or(|a| a >= max_age))
}

fn to_i64(seq: u64) -> Result<i64, sql::Error> {
    i64::try_from(seq).map_err(|_| sql::Error::Decode("audit seq overflows bigint".into()))
}

fn now_micros() -> i64 {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(d.as_micros()).unwrap_or(i64::MAX)
}
