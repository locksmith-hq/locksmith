//! S5 tasks 4.2 and 4.3: the signed checkpoint job. Signing goes through the real
//! `ls_envelope::TransitSigner` against an in-process fake of OpenBao's
//! `POST /v1/transit/sign/audit-checkpoint` (wiremock) that signs with a test-only Ed25519 key,
//! so these tests need no OpenBao; the ledger uses a throwaway `postgres:18` container
//! (testcontainers; needs Docker). Signatures are checked with `ed25519-dalek` under the
//! published (verifying) key and must fail under another key.

mod common;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ls_audit::{CheckpointBody, Record, verify};
use ls_control_plane::audit::{self, DEV_AUTH_ACTOR};
use ls_control_plane::checkpoint::{CheckpointJob, CheckpointSigner, PassReport, Schedule};
use ls_control_plane::db::{Database, PoolSettings, sql};
use ls_envelope::{BaoToken, TransitSigner};
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use sqlx_postgres::PgConnection;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

// Test-only values: a fake OpenBao token and Ed25519 seeds that are not real keys.
const SIGN_TOKEN: &str = "fake-audit-checkpoint-sign-only";
const KEY_SEED: [u8; 32] = [0x24; 32];
const OTHER_SEED: [u8; 32] = [0x25; 32];
const SIGN_PATH: &str = "/v1/transit/sign/audit-checkpoint";

/// Fake transit sign endpoint: checks the token, signs the base64 `input` with the test key and
/// answers `vault:v1:<base64 signature>` like OpenBao does for an `ed25519` key.
struct FakeSign(SigningKey);

impl Respond for FakeSign {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let token = req.headers.get("x-vault-token").map(|v| v.as_bytes());
        if token != Some(SIGN_TOKEN.as_bytes()) {
            return ResponseTemplate::new(403)
                .set_body_json(json!({"errors": ["permission denied"]}));
        }
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        let input = B64.decode(body["input"].as_str().unwrap()).unwrap();
        let sig = self.0.sign(&input);
        ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "signature": format!("vault:v1:{}", B64.encode(sig.to_bytes())),
                "key_version": 1,
            }
        }))
    }
}

/// The published key: what `just up` writes to the verifier config.
fn published_key() -> VerifyingKey {
    SigningKey::from_bytes(&KEY_SEED).verifying_key()
}

async fn fake_openbao() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(SIGN_PATH))
        .respond_with(FakeSign(SigningKey::from_bytes(&KEY_SEED)))
        .mount(&server)
        .await;
    server
}

fn signer(server: &MockServer, token: &str) -> Arc<dyn CheckpointSigner> {
    Arc::new(
        TransitSigner::new(
            &server.uri(),
            "audit-checkpoint",
            BaoToken::new(token.to_owned()),
        )
        .unwrap(),
    )
}

fn schedule(every: u64, max_age: Duration) -> Schedule {
    Schedule {
        every,
        max_age,
        tick: Duration::from_millis(50),
    }
}

struct Fixture {
    pg: common::Pg,
    db: Database,
    openbao: MockServer,
}

impl Fixture {
    async fn start() -> Self {
        let pg = common::Pg::migrated().await;
        let db = pg.app_db(PoolSettings::default());
        Self {
            pg,
            db,
            openbao: fake_openbao().await,
        }
    }

    fn job(&self, schedule: Schedule) -> CheckpointJob {
        CheckpointJob::new(self.db.clone(), signer(&self.openbao, SIGN_TOKEN), schedule)
    }

    async fn org(&self) -> Uuid {
        let id = Uuid::now_v7();
        self.db
            .with_org(id, move |c| {
                Box::pin(async move {
                    sql::query("INSERT INTO orgs (id, name) VALUES ($1, 'checkpoint-org')")
                        .bind(id)
                        .execute(c)
                        .await
                        .map(|_| ())
                })
            })
            .await
            .unwrap();
        id
    }

    /// Append `n` admin events to `org`'s chain, one transaction each.
    async fn append(&self, org: Uuid, n: usize) {
        for _ in 0..n {
            self.db
                .with_org(org, move |c| {
                    Box::pin(async move {
                        let e = audit::agent_created(DEV_AUTH_ACTOR, Uuid::now_v7());
                        audit::append(c, org, &e).await.map(|_| ())
                    })
                })
                .await
                .unwrap();
        }
    }

    /// `org`'s events and stored checkpoints, as the app role bound to `org`.
    async fn ledger(&self, org: Uuid) -> (Vec<Record>, Vec<StoredCheckpoint>) {
        let mut c = PgConnection::connect_with(&self.pg.app()).await.unwrap();
        let mut tx = c.begin().await.unwrap();
        ls_audit::pg::bind_org(&mut tx, org).await.unwrap();
        let rows = ls_audit::pg::records_in_tx(&mut tx, org).await.unwrap();
        let cps: Vec<CheckpointRow> = sql::query_as(
            "SELECT org_id, seq, hash, (extract(epoch FROM at) * 1000000)::bigint, key_id, signature
             FROM audit_checkpoints WHERE org_id = $1 ORDER BY seq",
        )
        .bind(org)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        let cps = cps
            .into_iter()
            .map(
                |(org_id, seq, hash, at_micros, key_id, sig)| StoredCheckpoint {
                    body: CheckpointBody {
                        org_id,
                        seq: u64::try_from(seq).unwrap(),
                        hash: hash.try_into().unwrap(),
                        at_micros,
                    },
                    key_id,
                    signature: Signature::from_bytes(&sig.try_into().unwrap()),
                },
            )
            .collect();
        (rows, cps)
    }
}

impl Fixture {
    /// Rows in `audit_checkpoint_jobs` as the app role with no org bound (the job's view).
    async fn job_rows(&self) -> i64 {
        self.db
            .without_org(|c| {
                Box::pin(async move {
                    sql::query_scalar("SELECT count(*) FROM audit_checkpoint_jobs")
                        .fetch_one(c)
                        .await
                })
            })
            .await
            .unwrap()
    }
}

/// `(org_id, seq, hash, at in Unix microseconds, key_id, signature)` of an `audit_checkpoints` row.
type CheckpointRow = (Uuid, i64, Vec<u8>, i64, String, Vec<u8>);

struct StoredCheckpoint {
    body: CheckpointBody,
    key_id: String,
    signature: Signature,
}

fn report(examined: usize, signed: usize, failed: usize) -> PassReport {
    PassReport {
        examined,
        signed,
        failed,
    }
}

/// Scenario "Checkpoint after threshold": below the event threshold nothing is signed; at the
/// threshold a checkpoint for the org's latest event exists, its signature verifies with
/// ed25519-dalek under the published key, fails under another key, and the chain verifies
/// against it. A further pass with no new events signs nothing.
#[tokio::test]
async fn checkpoint_at_threshold_verifies_under_the_published_key_only() {
    let f = Fixture::start().await;
    let org = f.org().await;
    let job = f.job(schedule(5, Duration::from_secs(3600)));

    f.append(org, 4).await;
    assert_eq!(job.run_pass().await.unwrap(), report(1, 0, 0));
    assert!(f.ledger(org).await.1.is_empty(), "no checkpoint below 5");

    f.append(org, 1).await;
    assert_eq!(job.run_pass().await.unwrap(), report(1, 1, 0));
    let (rows, cps) = f.ledger(org).await;
    assert_eq!(cps.len(), 1);
    let cp = &cps[0];
    assert_eq!(cp.body.org_id, org);
    assert_eq!(cp.body.seq, 5);
    assert_eq!(cp.body.hash, rows[4].hash, "head hash of the latest event");
    assert_eq!(cp.key_id, "audit-checkpoint:1");

    let message = cp.body.message();
    assert!(
        published_key()
            .verify_strict(&message, &cp.signature)
            .is_ok(),
        "verifies under the published key"
    );
    let other = SigningKey::from_bytes(&OTHER_SEED).verifying_key();
    assert!(
        other.verify_strict(&message, &cp.signature).is_err(),
        "fails under another key"
    );
    let edited = CheckpointBody {
        seq: 4,
        hash: rows[3].hash,
        ..cp.body
    };
    assert!(
        published_key()
            .verify_strict(&edited.message(), &cp.signature)
            .is_err(),
        "fails for another seq"
    );
    let walk = verify(rows.iter().map(Record::link), &[cp.body.checkpoint()]);
    assert!(walk.ok(), "{walk:?}");

    assert_eq!(job.run_pass().await.unwrap(), report(1, 0, 0), "idle");
    f.append(org, 4).await;
    assert_eq!(job.run_pass().await.unwrap(), report(1, 0, 0), "4 < 5");
    f.append(org, 1).await;
    assert_eq!(job.run_pass().await.unwrap(), report(1, 1, 0));
    let cps = f.ledger(org).await.1;
    assert_eq!(cps.iter().map(|c| c.body.seq).collect::<Vec<_>>(), [5, 10]);
}

/// The age rule: an org with fewer new events than the threshold is checkpointed once its
/// oldest new event is `max_age` old.
#[tokio::test]
async fn checkpoint_after_max_age_with_few_events() {
    let f = Fixture::start().await;
    let org = f.org().await;
    f.append(org, 2).await;
    assert_eq!(
        f.job(schedule(1000, Duration::from_secs(3600)))
            .run_pass()
            .await
            .unwrap(),
        report(1, 0, 0)
    );
    assert_eq!(
        f.job(schedule(1000, Duration::ZERO))
            .run_pass()
            .await
            .unwrap(),
        report(1, 1, 0)
    );
    let (rows, cps) = f.ledger(org).await;
    assert_eq!(cps.len(), 1);
    assert_eq!((cps[0].body.seq, cps[0].body.hash), (2, rows[1].hash));
    assert!(
        published_key()
            .verify_strict(&cps[0].body.message(), &cps[0].signature)
            .is_ok()
    );
}

/// Each org gets its own checkpoint; two passes racing (two replicas) never sign one org twice.
#[tokio::test]
async fn concurrent_passes_checkpoint_each_org_once() {
    let f = Fixture::start().await;
    let orgs = [f.org().await, f.org().await, f.org().await];
    for (i, org) in orgs.iter().enumerate() {
        f.append(*org, 3 + i).await;
    }
    let (a, b) = (
        f.job(schedule(3, Duration::from_secs(3600))),
        f.job(schedule(3, Duration::from_secs(3600))),
    );
    let (ra, rb) = tokio::join!(a.run_pass(), b.run_pass());
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!(ra.signed + rb.signed, 3, "{ra:?} {rb:?}");
    assert_eq!(ra.failed + rb.failed, 0);
    for (i, org) in orgs.iter().enumerate() {
        let (rows, cps) = f.ledger(*org).await;
        assert_eq!(cps.len(), 1, "org {i}");
        assert_eq!(cps[0].body.seq, 3 + i as u64);
        assert_eq!(cps[0].body.org_id, *org);
        assert_eq!(cps[0].body.hash, rows.last().unwrap().hash);
        assert!(
            published_key()
                .verify_strict(&cps[0].body.message(), &cps[0].signature)
                .is_ok()
        );
    }
}

/// OpenBao refusing (wrong token) or unreachable: the pass reports the failure and ends, stores
/// no checkpoint, and the next pass with a working signer catches up.
#[tokio::test]
async fn signing_failures_store_nothing_and_are_retried() {
    let f = Fixture::start().await;
    let org = f.org().await;
    f.append(org, 3).await;
    let sched = schedule(3, Duration::from_secs(3600));

    let denied = CheckpointJob::new(f.db.clone(), signer(&f.openbao, "fake-wrong-token"), sched);
    assert_eq!(denied.run_pass().await.unwrap(), report(1, 0, 1));
    let down = MockServer::start().await;
    let unreachable_uri = down.uri();
    drop(down);
    let unreachable = CheckpointJob::new(
        f.db.clone(),
        Arc::new(
            TransitSigner::new(
                &unreachable_uri,
                "audit-checkpoint",
                BaoToken::new(SIGN_TOKEN.to_owned()),
            )
            .unwrap(),
        ),
        sched,
    );
    assert_eq!(unreachable.run_pass().await.unwrap(), report(1, 0, 1));
    assert!(f.ledger(org).await.1.is_empty());

    assert_eq!(f.job(sched).run_pass().await.unwrap(), report(1, 1, 0));
    assert_eq!(f.ledger(org).await.1[0].body.seq, 3);
}

/// The spawned job checkpoints on its own once migrations are applied.
#[tokio::test]
async fn spawned_job_checkpoints_in_the_background() {
    let f = Fixture::start().await;
    let org = f.org().await;
    f.append(org, 2).await;
    let readiness = Arc::new(ls_control_plane::db::DbReadiness::new());
    readiness.set_migrated();
    let handle = f
        .job(schedule(2, Duration::from_secs(3600)))
        .spawn(readiness);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while f.ledger(org).await.1.is_empty() {
        assert!(tokio::time::Instant::now() < deadline, "no checkpoint");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    handle.abort();
    assert_eq!(f.ledger(org).await.1[0].body.seq, 2);
}

/// Migration 0010: the job table is created by the first append, the app role cannot add a row
/// for another org, cannot delete rows, and the checkpoints themselves stay isolated per org.
#[tokio::test]
async fn job_rows_follow_the_first_append_and_stay_append_only() {
    let f = Fixture::start().await;
    let (a, b) = (f.org().await, f.org().await);
    f.append(a, 1).await;
    assert_eq!(f.job_rows().await, 1, "one row, for org a only");
    f.append(a, 2).await;
    f.append(b, 1).await;
    assert_eq!(f.job_rows().await, 2);

    let other = b;
    let insert_other =
        f.db.with_org(a, move |c| {
            Box::pin(async move {
                sql::query(
                    "INSERT INTO audit_checkpoint_jobs (org_id) VALUES ($1) ON CONFLICT DO NOTHING",
                )
                .bind(other)
                .execute(c)
                .await
                .map(|_| ())
            })
        })
        .await;
    assert!(insert_other.is_err(), "row for another org refused");
    let move_other =
        f.db.with_org(a, move |c| {
            Box::pin(async move {
                sql::query("UPDATE audit_checkpoint_jobs SET checked_at = now() WHERE org_id = $1")
                    .bind(other)
                    .execute(c)
                    .await
            })
        })
        .await;
    assert!(move_other.is_err(), "update of another org's row refused");
    let delete =
        f.db.with_org(a, move |c| {
            Box::pin(async move {
                sql::query("DELETE FROM audit_checkpoint_jobs WHERE org_id = $1")
                    .bind(a)
                    .execute(c)
                    .await
            })
        })
        .await;
    assert!(delete.is_err(), "no DELETE grant");

    f.job(schedule(1, Duration::from_secs(3600)))
        .run_pass()
        .await
        .unwrap();
    let a_sees: i64 =
        f.db.with_org(a, |c| {
            Box::pin(async move {
                sql::query_scalar("SELECT count(*) FROM audit_checkpoints")
                    .fetch_one(c)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(a_sees, 1, "org a sees its own checkpoint only");
}
