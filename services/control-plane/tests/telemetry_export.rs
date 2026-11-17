//! What reaches the exporters (design decision 12): server spans named by route template with
//! method, route, status code and org id; the `locksmith-api` service resource; and no header
//! values or request bodies in spans, logs or the console. Runs in its own process because it
//! installs the global tracing subscriber.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use ls_control_plane::app::{self, AppState};
use ls_control_plane::db::PoolSettings;
use ls_control_plane::readiness::ReadyFlag;
use ls_control_plane::telemetry::{self, Options, SERVICE_NAME};
use opentelemetry::{Key, Value};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::logs::InMemoryLogExporter;
use opentelemetry_sdk::trace::{InMemorySpanExporter, SpanData, SpanExporter};
use tower::ServiceExt;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

/// In-memory span exporter that also keeps the resource the provider hands it.
#[derive(Debug, Clone, Default)]
struct SpanSpy {
    inner: InMemorySpanExporter,
    resource: Arc<Mutex<Option<Resource>>>,
}

impl SpanExporter for SpanSpy {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        self.inner.export(batch).await
    }
    fn set_resource(&mut self, resource: &Resource) {
        *self.resource.lock().unwrap() = Some(resource.clone());
    }
}

fn attr<'a>(span: &'a SpanData, key: &str) -> Option<&'a Value> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| &kv.value)
}

#[tokio::test(flavor = "multi_thread")]
async fn spans_carry_route_status_and_org_but_no_request_data() {
    let spans = SpanSpy::default();
    let logs = InMemoryLogExporter::default();
    let capture = common::Capture::default();
    let telemetry = telemetry::init_with_exporters(
        spans.clone(),
        logs.clone(),
        EnvFilter::new("info"),
        capture.clone(),
        &Options::default(),
    )
    .unwrap();

    // Postgres is unreachable, so the handler answers 503 after binding the org.
    let db = common::unreachable_db_with(PoolSettings {
        acquire_timeout: Duration::from_millis(300),
        ..PoolSettings::default()
    });
    let app = app::build(AppState::new(true, Arc::new(ReadyFlag::new(true)), db));

    let org = Uuid::new_v4();
    let project = Uuid::new_v4();
    let auth_marker = format!("AUTHMARKER{}", Uuid::new_v4().simple());
    let header_marker = format!("HEADERMARKER{}", Uuid::new_v4().simple());
    let body_marker = format!("BODYMARKER{}", Uuid::new_v4().simple());
    let res = app
        .oneshot(
            Request::patch(format!("/v1/projects/{project}"))
                .header("authorization", format!("Bearer {auth_marker}"))
                .header("x-locksmith-dev-org", org.to_string())
                .header("x-extra", &header_marker)
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"description":"{body_marker}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status().as_u16();
    // The server span closes once the response body is done.
    drop(res);

    let telemetry = tokio::task::spawn_blocking(move || {
        telemetry.force_flush();
        telemetry
    })
    .await
    .unwrap();

    let finished = spans.inner.get_finished_spans().unwrap();
    let server: Vec<&SpanData> = finished
        .iter()
        .filter(|s| attr(s, "http.route").is_some())
        .collect();
    assert_eq!(server.len(), 1, "one server span: {finished:#?}");
    let span = server[0];
    assert_eq!(span.name, "PATCH /v1/projects/{project_id}");
    assert_eq!(span.span_kind, opentelemetry::trace::SpanKind::Server);
    assert_eq!(
        attr(span, "http.route").map(Value::as_str).as_deref(),
        Some("/v1/projects/{project_id}")
    );
    assert_eq!(
        attr(span, "http.request.method")
            .map(Value::as_str)
            .as_deref(),
        Some("PATCH")
    );
    assert_eq!(
        attr(span, "http.response.status_code"),
        Some(&Value::I64(i64::from(status)))
    );
    assert_eq!(
        attr(span, "org.id").map(Value::as_str).as_deref(),
        Some(org.to_string().as_str())
    );

    let resource = spans
        .resource
        .lock()
        .unwrap()
        .clone()
        .expect("resource set");
    assert_eq!(
        resource.get(&Key::new("service.name")),
        Some(Value::from(SERVICE_NAME))
    );
    assert_eq!(SERVICE_NAME, "locksmith-api");

    let emitted = logs.get_emitted_logs().unwrap();
    assert!(
        emitted
            .iter()
            .any(|l| format!("{:?}", l.record).contains("request finished")),
        "app logs are exported"
    );
    for l in &emitted {
        assert_eq!(
            l.resource.get(&Key::new("service.name")),
            Some(Value::from(SERVICE_NAME))
        );
    }

    // The raw path, header values and body never appear anywhere we export or print.
    let exported = format!("{finished:?}\n{emitted:?}");
    let console = capture.contents();
    for (what, text) in [("exported telemetry", &exported), ("console", &console)] {
        for marker in [&auth_marker, &header_marker, &body_marker] {
            assert!(!text.contains(marker.as_str()), "{marker} in {what}");
        }
        assert!(
            !text.contains(&project.to_string()),
            "raw path (project id) in {what}"
        );
    }

    tokio::task::spawn_blocking(move || telemetry.shutdown())
        .await
        .unwrap();
}
