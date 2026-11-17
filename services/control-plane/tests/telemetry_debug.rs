//! At a `debug` filter, OTel's own diagnostics (targets such as `opentelemetry-otlp`) are
//! enabled. They must still be redacted and rate limited on the console, so the endpoint and
//! its credentials never print (design decision 12). Runs in its own process because it
//! installs the global tracing subscriber.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ls_control_plane::telemetry::{self, Options};
use tower::ServiceExt;
use tracing_subscriber::EnvFilter;

#[tokio::test(flavor = "multi_thread")]
async fn debug_filter_still_redacts_and_limits_otel_diagnostics() {
    let capture = common::Capture::default();
    let telemetry = telemetry::init(
        Some("http://user:SECRET@127.0.0.1:1?token=SECRET"),
        EnvFilter::new("debug"),
        capture.clone(),
        &Options {
            export_interval: Duration::from_millis(100),
            export_timeout: Duration::from_millis(500),
            ..Options::default()
        },
    )
    .unwrap();
    assert!(telemetry.exporting());

    let app = common::unreachable_app();
    for _ in 0..20 {
        let res = app
            .clone()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let telemetry = tokio::task::spawn_blocking(move || {
        telemetry.force_flush();
        telemetry
    })
    .await
    .unwrap();

    let out = capture.contents();
    assert!(
        out.contains("request finished"),
        "app logs still reach the console"
    );
    assert!(
        !out.contains("SECRET"),
        "endpoint credentials leaked:\n{out}"
    );
    assert!(
        !out.contains("127.0.0.1:1"),
        "exporter detail (endpoint) reached the console:\n{out}"
    );
    for target in ["reqwest", "hyper", "opentelemetry"] {
        assert!(
            !out.contains(target),
            "a {target} diagnostic bypassed redaction:\n{out}"
        );
    }
    let internal = out
        .lines()
        .filter(|l| l.contains(telemetry::EXPORT_FAILURE_MESSAGE))
        .count();
    assert!(
        internal <= 1,
        "OTel diagnostics are limited to one line a minute, got {internal}:\n{out}"
    );

    tokio::task::spawn_blocking(move || telemetry.shutdown())
        .await
        .unwrap();
}
