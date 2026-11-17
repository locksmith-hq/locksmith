//! Exporter failure must never fail a request, and export errors reach the console at most
//! once a minute, as a fixed line that never echoes the endpoint (design decision 12). Runs in its own process because it installs the
//! global tracing subscriber.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ls_control_plane::app::{self, AppState};
use ls_control_plane::db::{Database, PoolSettings, connect_options};
use ls_control_plane::readiness::ReadyFlag;
use ls_control_plane::telemetry::{self, Options};
use tower::ServiceExt;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = CaptureWriter;
    fn make_writer(&'a self) -> CaptureWriter {
        CaptureWriter(self.0.clone())
    }
}

fn app() -> axum::Router {
    let url = "postgres://nobody@127.0.0.1:1/none".to_owned().into();
    let db = Database::connect_lazy(connect_options(&url).unwrap(), PoolSettings::default());
    app::build(AppState::new(false, Arc::new(ReadyFlag::new(true)), db))
}

#[tokio::test(flavor = "multi_thread")]
async fn unreachable_otlp_endpoint_never_fails_requests_and_logs_once_without_credentials() {
    let capture = Capture::default();
    // Port 1 on loopback refuses connections immediately. The endpoint carries credentials in
    // both userinfo and the query; neither may reach the console.
    let telemetry = telemetry::init(
        Some("http://user:SECRET@127.0.0.1:1?token=SECRET"),
        EnvFilter::new("info"),
        capture.clone(),
        &Options {
            export_interval: Duration::from_millis(100),
            export_timeout: Duration::from_millis(500),
        },
    )
    .unwrap();
    assert!(telemetry.exporting());

    let app = app();
    // Spread requests over several flush intervals so many exports fail.
    for _ in 0..30 {
        let res = app
            .clone()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let out = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    let internal: Vec<&str> = out
        .lines()
        .filter(|l| l.contains(telemetry::EXPORT_FAILURE_MESSAGE))
        .collect();
    assert_eq!(
        internal.len(),
        1,
        "export failures are logged exactly once inside the window, got {}:\n{}",
        internal.len(),
        internal.join("\n")
    );
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
        "exporter error text (endpoint) reached the console:\n{out}"
    );

    tokio::task::spawn_blocking(move || telemetry.shutdown())
        .await
        .unwrap();
}
