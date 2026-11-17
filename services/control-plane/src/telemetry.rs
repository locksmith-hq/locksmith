//! Telemetry (design decision 12): `tracing` spans and logs exported over OTLP HTTP/protobuf.
//!
//! Export is off unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set. It can never fail or slow a
//! request: the batch processors queue on bounded channels, drop on overflow and export from
//! their own threads. Failures surface as `opentelemetry*` internal log events; those are
//! never fed back into the exporters (no feedback loop) and reach the console at most once
//! per [`INTERNAL_LOG_INTERVAL`], as the fixed line [`EXPORT_FAILURE_MESSAGE`]. Their own
//! text is never printed: HTTP client errors can embed the request URL, and the endpoint may
//! carry credentials (userinfo or a query token).
//!
//! Only method, route template, status code and org id are recorded on spans. Headers and
//! bodies are never read here.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{LogExporter, Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::{
    BatchConfigBuilder as LogBatchConfig, BatchLogProcessor, SdkLoggerProvider,
};
use opentelemetry_sdk::trace::{BatchConfigBuilder, BatchSpanProcessor, SdkTracerProvider};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_log::NormalizeEvent;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::format::{self, Writer};
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, MakeWriter};
use tracing_subscriber::layer::{Context, Filter, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry};

pub const SERVICE_NAME: &str = "locksmith-api";

/// Minimum spacing between console lines about exporter-internal failures.
pub const INTERNAL_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// The only text printed for an exporter-internal event; the event's own message and fields
/// are dropped because they can contain the endpoint URL.
pub const EXPORT_FAILURE_MESSAGE: &str = "OTLP export failed (details withheld)";

/// Tunables; the defaults are what the service runs with.
#[derive(Debug, Clone)]
pub struct Options {
    /// How often queued spans and logs are flushed.
    pub export_interval: Duration,
    /// Per-export HTTP timeout, so a black-holed endpoint cannot stall the exporter thread.
    pub export_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            export_interval: Duration::from_secs(5),
            export_timeout: Duration::from_secs(3),
        }
    }
}

/// Why telemetry could not be set up. Carries no endpoint text.
#[derive(Debug)]
pub enum TelemetryError {
    /// A global tracing subscriber was already installed.
    SubscriberInstalled,
}

impl std::fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SubscriberInstalled => f.write_str("a tracing subscriber is already installed"),
        }
    }
}

impl std::error::Error for TelemetryError {}

/// Holds the exporters; call [`Telemetry::shutdown`] to flush on exit.
#[derive(Default)]
pub struct Telemetry {
    traces: Option<SdkTracerProvider>,
    logs: Option<SdkLoggerProvider>,
}

impl Telemetry {
    /// Whether an OTLP exporter is active.
    pub fn exporting(&self) -> bool {
        self.traces.is_some()
    }

    /// Export everything queued so far. Blocking (bounded by the export timeout).
    pub fn force_flush(&self) {
        if let Some(t) = &self.traces {
            let _ = t.force_flush();
        }
        if let Some(l) = &self.logs {
            let _ = l.force_flush();
        }
    }

    /// Flush and stop the exporters. Blocking (bounded by the export timeout); run it off the
    /// async runtime.
    pub fn shutdown(self) {
        if let Some(t) = self.traces {
            let _ = t.shutdown();
        }
        if let Some(l) = self.logs {
            let _ = l.shutdown();
        }
    }
}

struct Providers {
    traces: SdkTracerProvider,
    logs: SdkLoggerProvider,
}

/// `{base}/v1/{signal}`, keeping any query string after the path.
fn signal_url(base: &str, signal: &str) -> String {
    let base = base.trim();
    let (path, query) = match base.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (base, None),
    };
    let mut url = format!("{}/v1/{signal}", path.trim_end_matches('/'));
    if let Some(q) = query {
        url.push('?');
        url.push_str(q);
    }
    url
}

fn build_otlp_providers(
    base: &str,
    opts: &Options,
) -> Result<Providers, Box<dyn std::error::Error>> {
    let span_exporter = SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(signal_url(base, "traces"))
        .with_timeout(opts.export_timeout)
        .build()?;
    let log_exporter = LogExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(signal_url(base, "logs"))
        .with_timeout(opts.export_timeout)
        .build()?;
    Ok(build_providers(span_exporter, log_exporter, opts))
}

fn build_providers<S, L>(span_exporter: S, log_exporter: L, opts: &Options) -> Providers
where
    S: opentelemetry_sdk::trace::SpanExporter + 'static,
    L: opentelemetry_sdk::logs::LogExporter + 'static,
{
    let resource = Resource::builder().with_service_name(SERVICE_NAME).build();

    let span_processor = BatchSpanProcessor::builder(span_exporter)
        .with_batch_config(
            BatchConfigBuilder::default()
                .with_scheduled_delay(opts.export_interval)
                .build(),
        )
        .build();
    let traces = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_span_processor(span_processor)
        .build();

    let log_processor = BatchLogProcessor::builder(log_exporter)
        .with_batch_config(
            LogBatchConfig::default()
                .with_scheduled_delay(opts.export_interval)
                .build(),
        )
        .build();
    let logs = SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_log_processor(log_processor)
        .build();

    Providers { traces, logs }
}

/// Targets whose events describe the exporter machinery itself. OTel's `otel_*!` macros use
/// the package name as target (`opentelemetry-otlp`), while `tracing` macros use the module
/// path (`opentelemetry_sdk::trace`), so both `-` and `_` separators count. `tower_http` is
/// the app's own request tracing (its 5xx "response failed" events), not the exporter.
fn is_internal(target: &str) -> bool {
    if target == "tower_http" || target.starts_with("tower_http::") {
        return false;
    }
    ["opentelemetry", "reqwest", "hyper", "h2", "tower"]
        .iter()
        .any(|p| {
            target.strip_prefix(p).is_some_and(|rest| {
                rest.is_empty()
                    || rest.starts_with('_')
                    || rest.starts_with('-')
                    || rest.starts_with("::")
            })
        })
}

/// Whether an event comes from the exporter machinery. Events bridged from the `log` crate
/// (reqwest, hyper) carry the target `log`; their real target is in the normalized metadata.
fn is_internal_event(event: &Event<'_>) -> bool {
    match event.normalized_metadata() {
        Some(meta) => is_internal(meta.target()),
        None => is_internal(event.metadata().target()),
    }
}

/// Keeps exporter-internal events out of the OTel layers, so export failures never loop back
/// into export.
struct NotInternal;

impl<S: Subscriber> Filter<S> for NotInternal {
    fn enabled(&self, meta: &Metadata<'_>, _cx: &Context<'_, S>) -> bool {
        !is_internal(meta.target())
    }

    fn event_enabled(&self, event: &Event<'_>, _cx: &Context<'_, S>) -> bool {
        !is_internal_event(event)
    }
}

/// Allows one event per interval; the clock is passed in so it can be tested.
pub struct RateLimiter {
    interval: Duration,
    last: Mutex<Option<Instant>>,
}

impl RateLimiter {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: Mutex::new(None),
        }
    }

    pub fn allow_at(&self, now: Instant) -> bool {
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        match *last {
            Some(prev) if now.saturating_duration_since(prev) < self.interval => false,
            _ => {
                *last = Some(now);
                true
            }
        }
    }

    pub fn allow(&self) -> bool {
        self.allow_at(Instant::now())
    }
}

/// Console filter: ordinary events pass; exporter-internal events pass only at WARN or above
/// and at most once per interval.
struct InternalLogLimiter(RateLimiter);

impl<S: Subscriber> Filter<S> for InternalLogLimiter {
    fn enabled(&self, _meta: &Metadata<'_>, _cx: &Context<'_, S>) -> bool {
        true
    }

    fn event_enabled(&self, event: &Event<'_>, _cx: &Context<'_, S>) -> bool {
        if !is_internal_event(event) {
            return true;
        }
        *event.metadata().level() <= Level::WARN && self.0.allow()
    }
}

/// Console format: ordinary events use the default format; exporter-internal events print
/// only a timestamp, their level and [`EXPORT_FAILURE_MESSAGE`].
struct RedactInternal<F>(F);

impl<S, N, F> FormatEvent<S, N> for RedactInternal<F>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
    F: FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let meta = event.metadata();
        if !is_internal_event(event) {
            return self.0.format_event(ctx, writer, event);
        }
        SystemTime.format_time(&mut writer)?;
        writeln!(
            writer,
            " {:>5} telemetry: {EXPORT_FAILURE_MESSAGE}",
            meta.level()
        )
    }
}

/// Install the global subscriber: console output to `writer`, plus OTLP export of spans and
/// logs when `endpoint` is set. A failure to build the exporter is logged and the service
/// carries on without export.
pub fn init<W>(
    endpoint: Option<&str>,
    env_filter: EnvFilter,
    writer: W,
    opts: &Options,
) -> Result<Telemetry, TelemetryError>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let built = endpoint.map(|e| build_otlp_providers(e, opts));
    let (providers, build_failed) = match built {
        Some(Ok(p)) => (Some(p), false),
        Some(Err(_)) => (None, true),
        None => (None, false),
    };
    install(providers, build_failed, env_filter, writer)
}

/// Like [`init`], but exporting to the given exporters instead of OTLP HTTP (for tests). The
/// resource, batching and filtering are the same as in production.
pub fn init_with_exporters<S, L, W>(
    span_exporter: S,
    log_exporter: L,
    env_filter: EnvFilter,
    writer: W,
    opts: &Options,
) -> Result<Telemetry, TelemetryError>
where
    S: opentelemetry_sdk::trace::SpanExporter + 'static,
    L: opentelemetry_sdk::logs::LogExporter + 'static,
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let providers = build_providers(span_exporter, log_exporter, opts);
    install(Some(providers), false, env_filter, writer)
}

fn install<W>(
    providers: Option<Providers>,
    build_failed: bool,
    env_filter: EnvFilter,
    writer: W,
) -> Result<Telemetry, TelemetryError>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let trace_layer = providers.as_ref().map(|p| {
        tracing_opentelemetry::layer()
            .with_tracer(p.traces.tracer(SERVICE_NAME))
            .with_filter(NotInternal)
    });
    let log_layer = providers
        .as_ref()
        .map(|p| OpenTelemetryTracingBridge::new(&p.logs).with_filter(NotInternal));

    Registry::default()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .event_format(RedactInternal(format::Format::default()))
                .with_filter(InternalLogLimiter(RateLimiter::new(INTERNAL_LOG_INTERVAL))),
        )
        .with(trace_layer)
        .with(log_layer)
        .try_init()
        .map_err(|_| TelemetryError::SubscriberInstalled)?;

    if build_failed {
        tracing::warn!("OTLP exporter could not be configured; telemetry export is disabled");
    }
    Ok(match providers {
        Some(p) => Telemetry {
            traces: Some(p.traces),
            logs: Some(p.logs),
        },
        None => Telemetry::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_allows_once_per_interval() {
        let l = RateLimiter::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(l.allow_at(t0));
        assert!(!l.allow_at(t0 + Duration::from_secs(1)));
        assert!(!l.allow_at(t0 + Duration::from_secs(59)));
        assert!(l.allow_at(t0 + Duration::from_secs(60)));
        assert!(!l.allow_at(t0 + Duration::from_secs(61)));
    }

    #[test]
    fn internal_targets_are_recognised() {
        assert!(is_internal("opentelemetry_sdk::trace"));
        assert!(is_internal("opentelemetry"));
        assert!(is_internal("reqwest::connect"));
        // Package-name targets used by OTel's internal-logging macros.
        assert!(is_internal("opentelemetry-otlp"));
        assert!(is_internal("opentelemetry-http"));
        assert!(is_internal("opentelemetry-appender-tracing"));
        assert!(is_internal("opentelemetry_sdk"));
        assert!(is_internal("hyper-util"));
        assert!(!is_internal("tower_http::trace::on_failure"));
        assert!(!is_internal("ls_control_plane::app"));
        assert!(!is_internal("opentelemetryish"));
    }

    #[test]
    fn signal_urls_append_path_once() {
        assert_eq!(
            signal_url("http://h:4318/", "traces"),
            "http://h:4318/v1/traces"
        );
        assert_eq!(signal_url("http://h:4318", "logs"), "http://h:4318/v1/logs");
        assert_eq!(
            signal_url("http://h:4318/otlp/?token=t", "traces"),
            "http://h:4318/otlp/v1/traces?token=t"
        );
    }
}
