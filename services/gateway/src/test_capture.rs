//! Process-wide log capture for the tests that assert on what the gateway logs.
//!
//! A thread-scoped `set_default` subscriber is unreliable under the parallel test runner: a
//! callsite first hit by a test with no subscriber caches `Interest::never` for the whole
//! process, so events can silently go unrecorded. Instead one global subscriber is installed
//! once per test binary, and each test scopes its reads with a unique root span. Two captures
//! share it: [`Which::Plain`] (every level, no cap) and [`Which::Capped`] (the gateway's own
//! filter: `trace` plus [`crate::mcp_endpoint::cap_rmcp_logs`]).

use std::io;
use std::sync::{Arc, Mutex, OnceLock};

use tracing_subscriber::Layer;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl io::Write for Buf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Global {
    plain: Buf,
    capped: Buf,
}

static GLOBAL: OnceLock<Global> = OnceLock::new();

fn global() -> &'static Global {
    GLOBAL.get_or_init(|| {
        let plain = Buf::default();
        let capped = Buf::default();
        let (p, c) = (plain.clone(), capped.clone());
        let plain_layer = tracing_subscriber::fmt::layer()
            .with_writer(move || p.clone())
            .with_ansi(false)
            .with_filter(LevelFilter::TRACE);
        let capped_layer = tracing_subscriber::fmt::layer()
            .with_writer(move || c.clone())
            .with_ansi(false)
            .with_filter(crate::mcp_endpoint::cap_rmcp_logs(EnvFilter::new(
                "trace,rmcp::service=trace",
            )));
        tracing_subscriber::registry()
            .with(plain_layer)
            .with(capped_layer)
            .try_init()
            .expect("no other global tracing subscriber in the gateway test binary");
        Global { plain, capped }
    })
}

/// Which capture to read.
#[derive(Clone, Copy)]
pub enum Which {
    Plain,
    Capped,
}

/// One test's view of the process-wide capture. Keep it alive for the whole test: its root
/// span stays entered (tests run on the current-thread runtime).
pub struct TestCapture {
    marker: String,
    _span: tracing::span::EnteredSpan,
}

/// Install the global capture (first call only) and enter a root span with a unique id.
pub fn start() -> TestCapture {
    global();
    let id = uuid::Uuid::new_v4().simple().to_string();
    let span = tracing::info_span!("test_capture", test_id = %id).entered();
    TestCapture {
        marker: format!("test_id={id}"),
        _span: span,
    }
}

impl TestCapture {
    fn buf(which: Which) -> Vec<u8> {
        let g = global();
        let b = match which {
            Which::Plain => &g.plain,
            Which::Capped => &g.capped,
        };
        b.0.lock().unwrap().clone()
    }

    /// Only the lines emitted inside this test's root span (use for "the span is there").
    pub fn scoped(&self, which: Which) -> String {
        String::from_utf8_lossy(&Self::buf(which))
            .lines()
            .filter(|l| l.contains(&self.marker))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Everything captured in the process so far, by any test or task. Absence checks (no
    /// secret, token or credential in any log) read this, so a leak from a concurrent task is
    /// still caught.
    pub fn all(&self, which: Which) -> Vec<u8> {
        Self::buf(which)
    }
}
