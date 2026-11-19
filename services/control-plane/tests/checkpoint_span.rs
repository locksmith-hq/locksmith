//! S5 task 4.2: each org the checkpoint job examines gets one `audit.checkpoint` span carrying
//! the org id, the head seq and the outcome, and nothing from the checkpoint itself (no hash,
//! signature or key id). Runs in its own process because it installs the global tracing
//! subscriber. Signs through a fake OpenBao transit endpoint (wiremock); needs Docker for the
//! throwaway `postgres:18` container.

mod common;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ls_control_plane::audit::{self, DEV_AUTH_ACTOR};
use ls_control_plane::checkpoint::{CheckpointJob, Schedule};
use ls_control_plane::db::{PoolSettings, sql};
use ls_control_plane::telemetry::{self, Options};
use ls_envelope::{BaoToken, TransitSigner};
use opentelemetry::Value;
use opentelemetry_sdk::logs::InMemoryLogExporter;
use opentelemetry_sdk::trace::{InMemorySpanExporter, SpanData};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// Test-only fake signature (not a real key's output; nothing verifies it here).
const SIG: [u8; 64] = [0x5a; 64];

fn attr<'a>(span: &'a SpanData, key: &str) -> Option<&'a Value> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| &kv.value)
}

#[tokio::test(flavor = "multi_thread")]
async fn checkpoint_span_has_org_seq_and_outcome_only() {
    let spans = InMemorySpanExporter::default();
    let telemetry = telemetry::init_with_exporters(
        spans.clone(),
        InMemoryLogExporter::default(),
        EnvFilter::new("info"),
        common::Capture::default(),
        &Options::default(),
    )
    .unwrap();

    let openbao = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/sign/audit-checkpoint"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "signature": format!("vault:v1:{}", B64.encode(SIG)) }
        })))
        .mount(&openbao)
        .await;
    let pg = common::Pg::migrated().await;
    let db = pg.app_db(PoolSettings::default());
    let org = Uuid::now_v7();
    db.with_org(org, move |c| {
        Box::pin(async move {
            sql::query("INSERT INTO orgs (id, name) VALUES ($1, 'span-org')")
                .bind(org)
                .execute(&mut *c)
                .await?;
            for _ in 0..2 {
                audit::append(
                    c,
                    org,
                    &audit::agent_created(DEV_AUTH_ACTOR, Uuid::now_v7()),
                )
                .await?;
            }
            Ok::<_, sql::Error>(())
        })
    })
    .await
    .unwrap();
    let signer = TransitSigner::new(
        &openbao.uri(),
        "audit-checkpoint",
        BaoToken::new("fake-sign-only".to_owned()),
    )
    .unwrap();
    let job = CheckpointJob::new(
        db,
        Arc::new(signer),
        Schedule {
            every: 2,
            max_age: Duration::from_secs(3600),
            tick: Duration::from_secs(1),
        },
    );
    assert_eq!(job.run_pass().await.unwrap().signed, 1);
    assert_eq!(job.run_pass().await.unwrap().signed, 0);

    let telemetry = tokio::task::spawn_blocking(move || {
        telemetry.force_flush();
        telemetry
    })
    .await
    .unwrap();
    let finished = spans.get_finished_spans().unwrap();
    let cps: Vec<&SpanData> = finished
        .iter()
        .filter(|s| s.name == "audit.checkpoint")
        .collect();
    assert_eq!(cps.len(), 2, "one span per examined org per pass");
    let outcomes: Vec<String> = cps
        .iter()
        .map(|s| attr(s, "audit.outcome").unwrap().as_str().into_owned())
        .collect();
    assert_eq!(outcomes, ["signed", "idle"]);
    let sig_hex: String = SIG.iter().map(|b| format!("{b:02x}")).collect();
    for s in &cps {
        assert_eq!(
            attr(s, "org.id").map(Value::as_str).as_deref(),
            Some(org.to_string().as_str())
        );
        assert_eq!(attr(s, "audit.seq"), Some(&Value::I64(2)));
        for kv in &s.attributes {
            let v = kv.value.as_str();
            assert!(
                !v.contains("audit-checkpoint")
                    && !v.contains(&sig_hex)
                    && !v.contains(&B64.encode(SIG)),
                "{}: {v}",
                kv.key
            );
        }
    }
    tokio::task::spawn_blocking(move || telemetry.shutdown())
        .await
        .unwrap();
}
