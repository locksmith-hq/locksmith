//! Helpers shared by the integration tests. Each test file declares `mod common;` and builds
//! its own binary (some install a global tracing subscriber), so not every binary uses every
//! helper.
#![allow(dead_code)]

use std::io;
use std::ops::Deref;
use std::sync::{Arc, Mutex, OnceLock};

use ls_control_plane::app::{self, AppState};
use ls_control_plane::db::{Database, PoolSettings, connect_options};
use ls_control_plane::migrate;
use ls_control_plane::readiness::ReadyFlag;
use tracing_subscriber::fmt::MakeWriter;

/// The shared throwaway `postgres:18` container (`ls-pg-test`), migrated here with the control
/// plane's own embedded migrator.
pub struct Pg(ls_pg_test::Pg);

impl Deref for Pg {
    type Target = ls_pg_test::Pg;
    fn deref(&self) -> &ls_pg_test::Pg {
        &self.0
    }
}

impl Pg {
    /// Start the container and wait until TCP logins work. Not migrated.
    pub async fn start() -> Self {
        Self(ls_pg_test::Pg::start().await)
    }

    /// Fresh database: migrate as the bootstrap superuser, as on a first `just up`.
    pub async fn migrated() -> Self {
        let pg = Self::start().await;
        migrate::run(pg.bootstrap())
            .await
            .expect("migrations apply");
        pg
    }

    /// Lazy pool as the `locksmith_app` role.
    pub fn app_db(&self, pool: PoolSettings) -> Database {
        Database::connect_lazy(self.app(), pool)
    }
}

/// A lazy pool that never connects, for tests that touch no tenant data.
pub fn unreachable_db() -> Database {
    unreachable_db_with(PoolSettings::default())
}

pub fn unreachable_db_with(pool: PoolSettings) -> Database {
    let url = "postgres://nobody@127.0.0.1:1/none".to_owned().into();
    Database::connect_lazy(connect_options(&url).unwrap(), pool)
}

/// App with dev auth off and readiness on, backed by [`unreachable_db`].
pub fn unreachable_app() -> axum::Router {
    app::build(AppState::new(
        false,
        Arc::new(ReadyFlag::new(true)),
        unreachable_db(),
    ))
}

/// Console capture: a `MakeWriter` collecting everything the tracing subscriber prints.
#[derive(Clone, Default)]
pub struct Capture(pub Arc<Mutex<Vec<u8>>>);

pub struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Capture {
    pub fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

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

/// Process-wide log capture for tests that assert on spans and log lines.
///
/// A thread-scoped `set_default` subscriber is unreliable under the parallel test runner: a
/// callsite first hit by a test with no subscriber caches `Interest::never` for the whole
/// process, so a span can silently go unrecorded. Instead one global subscriber (TRACE, span
/// open and close events with fields) is installed once per test binary, and each test
/// scopes its reads with a unique root span.
static GLOBAL_CAPTURE: OnceLock<Capture> = OnceLock::new();

fn global_capture() -> &'static Capture {
    GLOBAL_CAPTURE.get_or_init(|| {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
            .with_ansi(false)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("no other global tracing subscriber in this test binary");
        capture
    })
}

/// One test's view of the process-wide capture. Keep it alive for the whole test (its root
/// span stays entered; tests run on the current-thread runtime).
pub struct TestCapture {
    marker: String,
    _span: tracing::span::EnteredSpan,
}

/// Install the global capture (first call only) and enter a root span with a unique id.
pub fn capture_logs() -> TestCapture {
    global_capture();
    let id = uuid::Uuid::new_v4().simple().to_string();
    let span = tracing::info_span!("test_capture", test_id = %id).entered();
    TestCapture {
        marker: format!("test_id={id}"),
        _span: span,
    }
}

impl TestCapture {
    /// Only the lines emitted inside this test's root span (use for "the span is there").
    pub fn contents(&self) -> String {
        global_capture()
            .contents()
            .lines()
            .filter(|l| l.contains(&self.marker))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Everything captured in the process so far, by any test or task. Absence checks (no
    /// token, canary or secret in any log) read this, so a leak from a concurrent task is
    /// still caught.
    pub fn all_contents(&self) -> String {
        global_capture().contents()
    }
}
