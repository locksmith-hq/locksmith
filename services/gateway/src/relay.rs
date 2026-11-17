//! `POST /v1/relay` (S3 task 3.3): decrypt a bound secret inside the gateway, inject it into
//! one upstream request, return the redacted response and audit the attempt.
//!
//! Order of checks, each before the next step runs:
//! 1. caller token (constant time) -> `401`, nothing else happens and nothing is audited;
//! 2. request shape -> `400`;
//! 3. binding for the secret and the target's origin -> `403 denied`;
//! 4. DNS and address guard -> `403 denied_address` (still no fetch, no unwrap);
//! 5. fetch material, unwrap DEK (cached), open the version;
//! 6. render the binding's header template, send through a client pinned to the checked
//!    addresses that follows no redirects;
//! 7. read the response (identity encoding only, size-bounded), redact headers and body with
//!    `ls-redact` (plain, base64, URL, hex, JSON forms), re-check that nothing matches, and
//!    withhold the response with `502` if any of that fails (fail closed);
//! 8. append the audit row. If the row cannot be written for a call that reached the upstream,
//!    the response is withheld (`500`).
//!
//! The value lives in `SecretBytes` / `Zeroizing` buffers and is dropped once the header and the
//! redactor are built. Copies inside `http::HeaderValue`, hyper and rustls, and the redactor's
//! automaton, are outside the gateway's control and are not zeroized (best effort, as in
//! `ls-envelope`'s KMS client). Errors returned to the caller are fixed slugs; logs and the span
//! carry ids, host and outcome only.
//!
//! Protection level (design decision 9): containment plus prevention of direct reads. Redaction
//! is detection of the encodings `ls-redact` knows, not a proof the value cannot leave.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ls_redact::{MIN_ENCODED_LEN, Redactor, Secret};
use reqwest::header::{HeaderName, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::Instrument;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::{AuditRecord, AuditSink, Outcome};
use crate::config::{Binding, Bindings};
use crate::decrypt::{DecryptError, Decryptor, MaterialError};
use crate::egress::{self, EgressError, Resolver};

/// The caller name recorded in the audit row while S3 has one static caller token (S4 replaces
/// it with agent identity).
pub const STATIC_CALLER: &str = "static-token";

/// Label in redaction markers: `[REDACTED:SECRET]`.
pub const REDACTION_LABEL: &str = "SECRET";

/// Request headers the caller may not set: hop-by-hop, framing, encoding negotiation.
const DROPPED_REQUEST_HEADERS: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "accept-encoding",
];

/// Response headers not passed back: hop-by-hop and framing (the body length changes when
/// redacted).
const DROPPED_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
];

/// Limits and timeouts.
#[derive(Debug, Clone, Copy)]
pub struct RelayOptions {
    pub connect_timeout: Duration,
    /// Whole upstream call, including reading the body.
    pub timeout: Duration,
    /// Largest upstream request body accepted from the caller.
    pub max_request_body: usize,
    /// Largest upstream response body read; a larger one is withheld (`502`).
    pub max_response_body: usize,
}

impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            timeout: Duration::from_secs(30),
            max_request_body: 1024 * 1024,
            max_response_body: 10 * 1024 * 1024,
        }
    }
}

/// Everything the relay route needs. No `Debug`/`Clone`: it holds the caller token.
pub struct Relay {
    org_id: Uuid,
    caller_token: SecretString,
    bindings: Bindings,
    decryptor: Decryptor,
    resolver: Arc<dyn Resolver>,
    audit: Arc<dyn AuditSink>,
    options: RelayOptions,
}

impl Relay {
    pub fn new(
        caller_token: SecretString,
        bindings: Bindings,
        decryptor: Decryptor,
        resolver: Arc<dyn Resolver>,
        audit: Arc<dyn AuditSink>,
        options: RelayOptions,
    ) -> Self {
        Self {
            org_id: bindings.org_id,
            caller_token,
            bindings,
            decryptor,
            resolver,
            audit,
            options,
        }
    }

    pub fn options(&self) -> &RelayOptions {
        &self.options
    }

    fn authorized(&self, headers: &HeaderMap) -> bool {
        let Some(presented) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.as_bytes().strip_prefix(b"Bearer "))
        else {
            return false;
        };
        presented
            .ct_eq(self.caller_token.expose_secret().as_bytes())
            .into()
    }
}

/// The caller's request. Header pairs are `[name, value]`; the body is text (`body`) or bytes
/// (`body_base64`), not both.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayRequest {
    pub secret_id: Uuid,
    pub version: u32,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub body_base64: Option<String>,
}

/// The redacted upstream response. `body` when the redacted body is UTF-8, else `body_base64`.
#[derive(Serialize, Deserialize)]
pub struct RelayResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
}

/// Error body: a fixed slug and the request id. Never upstream, KMS or control-plane text.
#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    request_id: String,
}

fn error(status: StatusCode, slug: &'static str, request_id: &str) -> Response {
    let mut r = (
        status,
        Json(ErrorBody {
            error: slug,
            request_id: request_id.to_owned(),
        }),
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(request_id) {
        r.headers_mut().insert("x-request-id", v);
    }
    r
}

/// A validated caller request.
struct Parsed {
    secret_id: Uuid,
    version: u32,
    method: reqwest::Method,
    url: Url,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

fn parse(body: &[u8], max_body: usize) -> Option<Parsed> {
    let req: RelayRequest = serde_json::from_slice(body).ok()?;
    if req.version == 0 {
        return None;
    }
    let method = reqwest::Method::from_bytes(req.method.as_bytes()).ok()?;
    if method == reqwest::Method::CONNECT {
        return None;
    }
    let mut url = Url::parse(&req.url).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        return None;
    }
    url.set_fragment(None);
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in &req.headers {
        let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
        let value = HeaderValue::from_str(value).ok()?;
        if DROPPED_REQUEST_HEADERS.contains(&name.as_str()) {
            continue;
        }
        headers.append(name, value);
    }
    let body = match (req.body, req.body_base64) {
        (Some(_), Some(_)) => return None,
        (Some(t), None) => t.into_bytes(),
        (None, Some(b)) => B64.decode(b).ok()?,
        (None, None) => Vec::new(),
    };
    if body.len() > max_body {
        return None;
    }
    Some(Parsed {
        secret_id: req.secret_id,
        version: req.version,
        method,
        url,
        headers,
        body,
    })
}

/// How a relay attempt ended, before it is turned into a response.
struct Failure {
    outcome: Outcome,
    status: StatusCode,
    slug: &'static str,
    upstream_status: Option<u16>,
}

impl Failure {
    fn new(outcome: Outcome, status: StatusCode, slug: &'static str) -> Self {
        Self {
            outcome,
            status,
            slug,
            upstream_status: None,
        }
    }

    fn redaction(upstream_status: u16) -> Self {
        Self {
            upstream_status: Some(upstream_status),
            ..Self::new(
                Outcome::RedactionFailed,
                StatusCode::BAD_GATEWAY,
                "response_withheld",
            )
        }
    }
}

fn denied() -> Failure {
    Failure::new(Outcome::Denied, StatusCode::FORBIDDEN, "denied")
}

/// `host` or `host:port` when the URL names a non-default port.
fn audit_host(url: &Url) -> String {
    let host = url.host_str().unwrap_or("-");
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_owned(),
    }
}

/// The handler. See the module docs for the order of checks.
pub async fn handle(relay: Arc<Relay>, headers: HeaderMap, body: Bytes) -> Response {
    let request_id = Uuid::new_v4().to_string();
    if !relay.authorized(&headers) {
        return error(StatusCode::UNAUTHORIZED, "unauthenticated", &request_id);
    }
    let Some(req) = parse(&body, relay.options.max_request_body) else {
        return error(StatusCode::BAD_REQUEST, "bad_request", &request_id);
    };

    let host = audit_host(&req.url);
    let span = tracing::info_span!(
        "relay",
        request_id = %request_id,
        secret.id = %req.secret_id,
        secret.version = req.version,
        upstream.host = %host,
        http.request.method = %req.method,
        outcome = tracing::field::Empty,
        upstream.status = tracing::field::Empty,
    );
    let mut record = AuditRecord {
        org_id: relay.org_id,
        secret_id: req.secret_id,
        version: req.version,
        caller: STATIC_CALLER.to_owned(),
        method: req.method.as_str().to_owned(),
        scheme: req.url.scheme().to_owned(),
        host,
        path: req.url.path().to_owned(),
        outcome: Outcome::Ok,
        status: None,
        request_id: request_id.clone(),
    };

    async move {
        let result = run(&relay, req).await;
        let span = tracing::Span::current();
        match &result {
            Ok(resp) => {
                record.status = Some(resp.status);
            }
            Err(f) => {
                record.outcome = f.outcome;
                record.status = f.upstream_status;
            }
        }
        span.record("outcome", record.outcome.as_str());
        if let Some(s) = record.status {
            span.record("upstream.status", s);
        }
        let reached_upstream = record.status.is_some();
        let audited = relay.audit.record(record).await;
        if audited.is_err() {
            tracing::error!("relay audit record could not be written");
            if reached_upstream {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "audit_failed",
                    &request_id,
                );
            }
        }
        match result {
            Ok(resp) => {
                tracing::info!("relay completed");
                let mut r = (StatusCode::OK, Json(resp)).into_response();
                if let Ok(v) = HeaderValue::from_str(&request_id) {
                    r.headers_mut().insert("x-request-id", v);
                }
                r
            }
            Err(f) => {
                tracing::warn!("relay refused or failed");
                error(f.status, f.slug, &request_id)
            }
        }
    }
    .instrument(span)
    .await
}

async fn run(relay: &Relay, req: Parsed) -> Result<RelayResponse, Failure> {
    // 3. Binding and origin: refused before any lookup, fetch or unwrap.
    let binding: &Binding = relay
        .bindings
        .for_secret(req.secret_id)
        .ok_or_else(denied)?;
    // 4. Address guard (resolves once; the client is pinned to the result).
    let target = egress::check(binding, &req.url, relay.resolver.as_ref())
        .await
        .map_err(|e| match e {
            EgressError::HostNotAllowed => denied(),
            EgressError::AddressNotAllowed => Failure::new(
                Outcome::DeniedAddress,
                StatusCode::FORBIDDEN,
                "denied_address",
            ),
            EgressError::Unresolvable => Failure::new(
                Outcome::UpstreamUnreachable,
                StatusCode::BAD_GATEWAY,
                "upstream_unreachable",
            ),
        })?;
    let client = target
        .client(relay.options.connect_timeout, relay.options.timeout)
        .map_err(|_| {
            Failure::new(
                Outcome::UpstreamError,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
            )
        })?;

    // 5. Decrypt.
    let value = relay
        .decryptor
        .decrypt(req.secret_id, req.version)
        .await
        .map_err(|e| match e {
            DecryptError::Material(MaterialError::NotFound) => {
                Failure::new(Outcome::MaterialError, StatusCode::NOT_FOUND, "not_found")
            }
            DecryptError::Material(_) => Failure::new(
                Outcome::MaterialError,
                StatusCode::BAD_GATEWAY,
                "secret_unavailable",
            ),
            DecryptError::Unwrap(_) | DecryptError::Open => Failure::new(
                Outcome::DecryptFailed,
                StatusCode::BAD_GATEWAY,
                "secret_unavailable",
            ),
        })?;

    // Encoded forms of values shorter than this are not matched by ls-redact, so an echo could
    // not be caught: refuse rather than relay unscannable (fail closed).
    if value.expose().len() < MIN_ENCODED_LEN {
        return Err(Failure::new(
            Outcome::RedactionFailed,
            StatusCode::BAD_GATEWAY,
            "secret_unusable",
        ));
    }

    // 6. Inject: the redactor and the header value are built, then the value is dropped.
    let redactor = Redactor::new(&[Secret::new(REDACTION_LABEL, value.expose())]);
    let header_name = HeaderName::from_bytes(binding.header.as_bytes()).map_err(|_| {
        Failure::new(
            Outcome::InjectFailed,
            StatusCode::BAD_GATEWAY,
            "secret_unusable",
        )
    })?;
    let header_value = render(&binding.template, value.expose()).ok_or_else(|| {
        Failure::new(
            Outcome::InjectFailed,
            StatusCode::BAD_GATEWAY,
            "secret_unusable",
        )
    })?;
    drop(value);

    let mut headers = req.headers;
    headers.remove(&header_name);
    headers.insert(header_name, header_value);
    headers.insert(
        reqwest::header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    let sent = client
        .request(req.method, target.url().clone())
        .headers(headers)
        .body(req.body)
        .send()
        .await;
    let mut resp = sent.map_err(|e| upstream_failure(&e))?;
    let status = resp.status().as_u16();

    // 7. Read (bounded), refuse encodings that cannot be scanned, redact, re-check.
    let encoded = resp
        .headers()
        .get_all(reqwest::header::CONTENT_ENCODING)
        .iter()
        .any(|v| {
            v.to_str()
                .map(|s| {
                    s.split(',')
                        .any(|c| !c.trim().is_empty() && !c.trim().eq_ignore_ascii_case("identity"))
                })
                .unwrap_or(true)
        });
    if encoded {
        return Err(Failure::redaction(status));
    }
    let mut raw = Zeroizing::new(Vec::new());
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if raw.len() + chunk.len() > relay.options.max_response_body {
                    return Err(Failure::redaction(status));
                }
                raw.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                let mut f = upstream_failure(&e);
                f.upstream_status = Some(status);
                return Err(f);
            }
        }
    }
    let body = redactor.redact_all(&raw);
    drop(raw);

    let mut out_headers = Vec::new();
    for (name, value) in resp.headers() {
        if DROPPED_RESPONSE_HEADERS.contains(&name.as_str()) {
            continue;
        }
        let n = redactor.redact_all(name.as_str().as_bytes());
        let v = redactor.redact_all(value.as_bytes());
        out_headers.push((
            String::from_utf8_lossy(&n).into_owned(),
            String::from_utf8_lossy(&v).into_owned(),
        ));
    }

    // Belt and braces: nothing the redactor knows may remain.
    let leaked = !redactor.find(&body).is_empty()
        || out_headers.iter().any(|(n, v)| {
            !redactor.find(n.as_bytes()).is_empty() || !redactor.find(v.as_bytes()).is_empty()
        });
    if leaked {
        return Err(Failure::redaction(status));
    }

    let (body, body_base64) = match String::from_utf8(body) {
        Ok(text) => (Some(text), None),
        Err(e) => (None, Some(B64.encode(e.as_bytes()))),
    };
    Ok(RelayResponse {
        status,
        headers: out_headers,
        body,
        body_base64,
    })
}

/// The binding template with `{secret}` replaced by the value, as a sensitive header value.
/// `None` when the result is not a valid header value (e.g. the value has a newline).
fn render(template: &str, value: &[u8]) -> Option<HeaderValue> {
    let (prefix, suffix) = template.split_once("{secret}")?;
    let mut buf = Zeroizing::new(Vec::with_capacity(
        prefix.len() + value.len() + suffix.len(),
    ));
    buf.extend_from_slice(prefix.as_bytes());
    buf.extend_from_slice(value);
    buf.extend_from_slice(suffix.as_bytes());
    let mut v = HeaderValue::from_bytes(&buf).ok()?;
    v.set_sensitive(true);
    Some(v)
}

fn upstream_failure(e: &reqwest::Error) -> Failure {
    if e.is_timeout() {
        Failure::new(
            Outcome::UpstreamTimeout,
            StatusCode::GATEWAY_TIMEOUT,
            "upstream_timeout",
        )
    } else if e.is_connect() {
        Failure::new(
            Outcome::UpstreamUnreachable,
            StatusCode::BAD_GATEWAY,
            "upstream_unreachable",
        )
    } else {
        Failure::new(
            Outcome::UpstreamError,
            StatusCode::BAD_GATEWAY,
            "upstream_error",
        )
    }
}

/// Axum entry point: `503` until the relay is configured.
pub async fn route(
    State(state): State<crate::app::AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match state.relay() {
        Some(relay) => handle(relay, headers, body).await,
        None => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            &Uuid::new_v4().to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{self, AppState};
    use crate::audit::MemoryAudit;
    use crate::decrypt::testkit::{key, seal};
    use crate::decrypt::{CacheSettings, ControlPlane, DekCache};
    use crate::egress::testkit::StubResolver;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use http_body_util::BodyExt;
    use ls_control_plane::readiness::ReadyFlag;
    use ls_envelope::{BaoToken, OpenBaoTransit};
    use std::sync::Mutex;
    use tower::ServiceExt;
    use wiremock::matchers::{body_string_contains, header as has_header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_000000000001);
    /// Bound to the mock upstream (private address explicitly allowed).
    const SECRET: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_000000000002);
    /// Bound to a host that resolves to loopback, without allow_private_hosts.
    const INTERNAL: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_000000000003);
    /// Bound to a port where nothing listens.
    const DEAD: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_000000000004);
    /// Has material but no binding.
    const UNBOUND: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_000000000005);
    /// A canary with characters that URL-encoding changes.
    const VALUE: &[u8] = b"canary-relay-7Hk2/q+Zx9=W";
    const CALLER: &str = "caller-token-0123456789abcdef0123456789";

    fn percent(v: &[u8]) -> String {
        percent_case(v, true)
    }

    fn percent_case(v: &[u8], upper: bool) -> String {
        v.iter()
            .map(|&b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    (b as char).to_string()
                } else if upper {
                    format!("%{b:02X}")
                } else {
                    format!("%{b:02x}")
                }
            })
            .collect()
    }

    fn hex(v: &[u8]) -> String {
        v.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Every encoding the tests plant: none may reach the caller, the logs or the audit.
    fn encodings() -> Vec<String> {
        let mut out = vec![
            String::from_utf8(VALUE.to_vec()).unwrap(),
            B64.encode(VALUE),
            STANDARD_NO_PAD.encode(VALUE),
            URL_SAFE.encode(VALUE),
            URL_SAFE_NO_PAD.encode(VALUE),
            percent(VALUE),
            percent_case(VALUE, false),
            hex(VALUE),
            hex(VALUE).to_uppercase(),
        ];
        out.sort();
        out.dedup();
        out
    }

    fn assert_clean(what: &str, bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes);
        for e in encodings() {
            assert!(
                !text.contains(&e),
                "{what} contains an encoding of the canary"
            );
        }
        let oracle = Redactor::new(&[Secret::new("C", VALUE)]);
        assert!(
            oracle.find(bytes).is_empty(),
            "{what}: ls-redact still finds the canary"
        );
    }

    struct Harness {
        app: Router,
        upstream: MockServer,
        cp: MockServer,
        bao: MockServer,
        audit: Arc<MemoryAudit>,
        resolver: Arc<StubResolver>,
        dead_port: u16,
    }

    struct Setup {
        bao_ok: bool,
        audit_fails: bool,
        options: RelayOptions,
    }

    impl Default for Setup {
        fn default() -> Self {
            Self {
                bao_ok: true,
                audit_fails: false,
                options: RelayOptions {
                    connect_timeout: Duration::from_secs(2),
                    timeout: Duration::from_millis(1500),
                    max_request_body: 64 * 1024,
                    max_response_body: 64 * 1024,
                },
            }
        }
    }

    fn binding(secret_id: Uuid, origin: String, allow_private: bool) -> Binding {
        Binding {
            secret_id,
            origin,
            header: "Authorization".to_owned(),
            template: "Bearer {secret}".to_owned(),
            allow_private_hosts: allow_private,
        }
    }

    async fn harness(setup: Setup) -> Harness {
        let upstream = MockServer::start().await;
        let cp = MockServer::start().await;
        let bao = MockServer::start().await;
        let sealed = seal(ORG, SECRET, 1, VALUE);
        let unbound = seal(ORG, UNBOUND, 1, VALUE);
        let dead = seal(ORG, DEAD, 1, VALUE);
        for (id, s) in [(SECRET, &sealed), (UNBOUND, &unbound), (DEAD, &dead)] {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/internal/v1/secrets/{id}/versions/1/material"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(s.json(id, 1)))
                .mount(&cp)
                .await;
        }
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&cp)
            .await;
        for s in [&sealed, &unbound, &dead] {
            let bao_resp = if setup.bao_ok {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": { "plaintext": B64.encode(s.dek) }
                }))
            } else {
                ResponseTemplate::new(500).set_body_string("internal error")
            };
            Mock::given(method("POST"))
                .and(path("/v1/transit/decrypt/gateway"))
                .and(body_string_contains(s.transit_ciphertext()))
                .respond_with(bao_resp)
                .mount(&bao)
                .await;
        }

        let port = upstream.address().port();
        let dead_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let resolver = Arc::new(StubResolver::with(&[
            ("upstream.test", "127.0.0.1".parse().unwrap()),
            ("internal.test", "127.0.0.1".parse().unwrap()),
            ("dead.test", "127.0.0.1".parse().unwrap()),
        ]));
        let bindings = Bindings {
            org_id: ORG,
            bindings: vec![
                binding(SECRET, format!("http://upstream.test:{port}"), true),
                binding(INTERNAL, format!("http://internal.test:{port}"), false),
                binding(DEAD, format!("http://dead.test:{dead_port}"), true),
            ],
        };
        let control_plane =
            ControlPlane::new(cp.uri().parse().unwrap(), ORG, "s".repeat(32).into()).unwrap();
        let transit =
            OpenBaoTransit::new(&bao.uri(), key(), BaoToken::new("bao".to_owned())).unwrap();
        let decryptor = Decryptor::new(
            ORG,
            Arc::new(control_plane),
            Arc::new(transit),
            Arc::new(DekCache::new(CacheSettings::default())),
        );
        let audit = Arc::new(MemoryAudit {
            fail: setup.audit_fails,
            ..MemoryAudit::default()
        });
        let relay = Relay::new(
            CALLER.to_owned().into(),
            bindings,
            decryptor,
            resolver.clone(),
            audit.clone(),
            setup.options,
        );
        let app =
            app::build(AppState::new(Arc::new(ReadyFlag::new(true))).with_relay(Arc::new(relay)));
        Harness {
            app,
            upstream,
            cp,
            bao,
            audit,
            resolver,
            dead_port,
        }
    }

    impl Harness {
        fn origin(&self) -> String {
            format!("http://upstream.test:{}", self.upstream.address().port())
        }

        /// The origin bound to [`DEAD`]: a port where nothing listens.
        fn dead_origin(&self) -> String {
            format!("http://dead.test:{}", self.dead_port)
        }

        async fn call(
            &self,
            token: Option<&str>,
            body: serde_json::Value,
        ) -> (StatusCode, Vec<u8>) {
            let mut req = Request::post("/v1/relay").header("content-type", "application/json");
            if let Some(t) = token {
                req = req.header("authorization", format!("Bearer {t}"));
            }
            let resp = self
                .app
                .clone()
                .oneshot(req.body(Body::from(body.to_string())).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let mut raw = Vec::new();
            for (n, v) in resp.headers() {
                raw.extend_from_slice(n.as_str().as_bytes());
                raw.extend_from_slice(b": ");
                raw.extend_from_slice(v.as_bytes());
                raw.push(b'\n');
            }
            raw.extend_from_slice(&resp.into_body().collect().await.unwrap().to_bytes());
            (status, raw)
        }

        async fn relay_get(&self, secret: Uuid, url: &str) -> (StatusCode, Vec<u8>) {
            self.call(
                Some(CALLER),
                serde_json::json!({ "secret_id": secret, "version": 1, "method": "GET", "url": url }),
            )
            .await
        }

        async fn hits(server: &MockServer) -> usize {
            server.received_requests().await.unwrap_or_default().len()
        }

        async fn kms_calls(&self) -> usize {
            Self::hits(&self.bao).await
        }

        fn outcomes(&self) -> Vec<&'static str> {
            self.audit
                .records()
                .iter()
                .map(|r| r.outcome.as_str())
                .collect()
        }

        fn assert_audit_clean(&self) {
            let text = format!("{:?}", self.audit.records());
            assert_clean("audit records", text.as_bytes());
        }
    }

    /// The JSON body part of a raw response (after the header lines).
    fn envelope(raw: &[u8]) -> RelayResponse {
        let start = raw.iter().position(|&b| b == b'{').unwrap();
        serde_json::from_slice(&raw[start..]).unwrap()
    }

    fn injected() -> String {
        format!("Bearer {}", std::str::from_utf8(VALUE).unwrap())
    }

    #[tokio::test]
    async fn upstream_receives_the_secret_caller_does_not() {
        let h = harness(Setup::default()).await;
        Mock::given(method("POST"))
            .and(path("/v1/charge"))
            .and(has_header("authorization", injected().as_str()))
            .and(has_header("x-caller", "kept"))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header("x-upstream", "yes")
                    .set_body_string("{\"ok\":true}"),
            )
            .expect(1)
            .mount(&h.upstream)
            .await;
        let (status, raw) = h
            .call(
                Some(CALLER),
                serde_json::json!({
                    "secret_id": SECRET, "version": 1, "method": "POST",
                    "url": format!("{}/v1/charge?amount=5#frag", h.origin()),
                    "headers": [["x-caller", "kept"], ["Authorization", "Bearer caller-forged"]],
                    "body": "{\"amount\":5}",
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let env = envelope(&raw);
        assert_eq!(env.status, 201);
        assert_eq!(env.body.as_deref(), Some("{\"ok\":true}"));
        assert!(
            env.headers
                .iter()
                .any(|(n, v)| n == "x-upstream" && v == "yes")
        );
        assert_clean("caller response", &raw);
        let rec = h.audit.records();
        assert_eq!(rec.len(), 1);
        let r = &rec[0];
        assert_eq!(
            (r.outcome, r.status, r.version, r.method.as_str()),
            (Outcome::Ok, Some(201), 1, "POST")
        );
        assert_eq!(
            r.host,
            format!("upstream.test:{}", h.upstream.address().port())
        );
        assert_eq!(r.path, "/v1/charge", "no query string in the audit row");
        assert_eq!(r.caller, STATIC_CALLER);
        h.assert_audit_clean();
        // DNS was answered by the stub (the pinned path), once.
        assert_eq!(
            h.resolver.lookups.lock().unwrap().as_slice(),
            ["upstream.test"]
        );
    }

    /// Spec "Echoed secret is redacted": plain, base64 (every offset, both alphabets), URL and
    /// hex, in the body and in headers.
    #[tokio::test]
    async fn echoed_secret_is_redacted_in_every_encoding() {
        let h = harness(Setup::default()).await;
        let mut cases: Vec<(String, String)> = vec![
            ("plain".into(), format!("you sent {}", injected())),
            ("url".into(), format!("q={}", percent(VALUE))),
            (
                "url-lower".into(),
                format!("q={}", percent_case(VALUE, false)),
            ),
            ("hex".into(), format!("h={}", hex(VALUE))),
            (
                "hex-upper".into(),
                format!("h={}", hex(VALUE).to_uppercase()),
            ),
            (
                "json".into(),
                serde_json::json!({ "echo": std::str::from_utf8(VALUE).unwrap() }).to_string(),
            ),
        ];
        for prefix in ["", "x", "xy"] {
            let mut data = prefix.as_bytes().to_vec();
            data.extend_from_slice(VALUE);
            data.extend_from_slice(b"tail");
            cases.push((format!("b64-{}", prefix.len()), B64.encode(&data)));
            cases.push((
                format!("b64url-{}", prefix.len()),
                URL_SAFE_NO_PAD.encode(&data),
            ));
        }
        for (name, body) in &cases {
            Mock::given(method("GET"))
                .and(path(format!("/echo/{name}")))
                .respond_with(ResponseTemplate::new(200).set_body_string(body.clone()))
                .mount(&h.upstream)
                .await;
        }
        for (name, _) in &cases {
            let (status, raw) = h
                .relay_get(SECRET, &format!("{}/echo/{name}", h.origin()))
                .await;
            assert_eq!(status, StatusCode::OK, "{name}");
            let env = envelope(&raw);
            let body = env.body.expect("text body");
            assert!(body.contains("[REDACTED:SECRET]"), "{name}: no marker");
            assert_clean(name, &raw);
        }

        // Headers: echoed in a value (plain, base64, hex) and as a header name.
        Mock::given(method("GET"))
            .and(path("/echo-headers"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-echo-auth", injected().as_str())
                    .insert_header("x-echo-b64", B64.encode(VALUE).as_str())
                    .insert_header("x-echo-hex", hex(VALUE).as_str())
                    .insert_header("set-cookie", format!("s={}", percent(VALUE)).as_str())
                    .insert_header(format!("x-{}", hex(VALUE)).as_str(), "name-echo"),
            )
            .mount(&h.upstream)
            .await;
        let (status, raw) = h
            .relay_get(SECRET, &format!("{}/echo-headers", h.origin()))
            .await;
        assert_eq!(status, StatusCode::OK);
        let env = envelope(&raw);
        let auth = env
            .headers
            .iter()
            .find(|(n, _)| n == "x-echo-auth")
            .unwrap();
        assert_eq!(auth.1, "Bearer [REDACTED:SECRET]");
        assert_clean("echoed headers", &raw);

        // Binary body: redacted before it is base64-wrapped for the caller.
        let mut bin = vec![0xff, 0xfe, 0x00];
        bin.extend_from_slice(VALUE);
        Mock::given(method("GET"))
            .and(path("/echo-binary"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bin))
            .mount(&h.upstream)
            .await;
        let (_, raw) = h
            .relay_get(SECRET, &format!("{}/echo-binary", h.origin()))
            .await;
        let env = envelope(&raw);
        let decoded = B64.decode(env.body_base64.expect("binary body")).unwrap();
        assert_clean("binary body", &decoded);
        assert!(decoded.ends_with(b"[REDACTED:SECRET]"));
        h.assert_audit_clean();
    }

    /// Spec "Disallowed host": 403, no upstream call, no material fetch, no KMS decrypt.
    #[tokio::test]
    async fn disallowed_host_makes_no_decrypt_call() {
        let h = harness(Setup::default()).await;
        let port = h.upstream.address().port();
        for url in [
            format!("http://evil.test:{port}/x"),
            format!("https://upstream.test:{port}/x"),
            format!("http://upstream.test:{}/x", port.wrapping_add(1)),
            format!("http://user:pw@upstream.test:{port}/x"),
            format!("http://127.0.0.1:{port}/x"),
        ] {
            let (status, raw) = h.relay_get(SECRET, &url).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{url}");
            assert!(String::from_utf8_lossy(&raw).contains("\"denied\""));
        }
        // No binding at all for this secret.
        let (status, _) = h.relay_get(UNBOUND, &format!("{}/x", h.origin())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // Bound, but the host resolves to loopback without allow_private_hosts.
        let (status, raw) = h
            .relay_get(INTERNAL, &format!("http://internal.test:{port}/x"))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&raw).contains("denied_address"));

        assert_eq!(h.kms_calls().await, 0, "no KMS decrypt call");
        assert_eq!(Harness::hits(&h.cp).await, 0, "no material fetch");
        assert_eq!(Harness::hits(&h.upstream).await, 0, "no upstream call");
        let outcomes = h.outcomes();
        assert_eq!(outcomes.len(), 7, "every refused attempt is audited");
        assert_eq!(outcomes.iter().filter(|o| **o == "denied").count(), 6);
        assert_eq!(outcomes.last(), Some(&"denied_address"));
        assert!(h.audit.records().iter().all(|r| r.status.is_none()));
    }

    /// Spec "Redirect to another host": not followed, credential not resent.
    #[tokio::test]
    async fn redirect_is_not_followed() {
        let h = harness(Setup::default()).await;
        let elsewhere = MockServer::start().await;
        for code in [301, 302, 303, 307, 308] {
            Mock::given(method("GET"))
                .and(path(format!("/moved/{code}")))
                .respond_with(
                    ResponseTemplate::new(code)
                        .insert_header("location", format!("{}/stolen", elsewhere.uri()).as_str()),
                )
                .mount(&h.upstream)
                .await;
            let (status, raw) = h
                .relay_get(SECRET, &format!("{}/moved/{code}", h.origin()))
                .await;
            assert_eq!(status, StatusCode::OK);
            let env = envelope(&raw);
            assert_eq!(
                env.status, code,
                "redirect status handed back, not followed"
            );
            assert_clean("redirect response", &raw);
        }
        assert_eq!(
            Harness::hits(&elsewhere).await,
            0,
            "redirect target never contacted"
        );
        assert_eq!(
            Harness::hits(&h.upstream).await,
            5,
            "one upstream call each"
        );
    }

    /// Spec "Caller authentication": no fetch, unwrap or upstream call; nothing to audit.
    #[tokio::test]
    async fn unauthenticated_caller_is_refused_first() {
        let h = harness(Setup::default()).await;
        let body = serde_json::json!({
            "secret_id": SECRET, "version": 1, "method": "GET", "url": format!("{}/x", h.origin())
        });
        for token in [None, Some("wrong"), Some(&CALLER[..CALLER.len() - 1])] {
            let (status, _) = h.call(token, body.clone()).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        assert_eq!(h.kms_calls().await, 0);
        assert_eq!(Harness::hits(&h.cp).await, 0);
        assert_eq!(Harness::hits(&h.upstream).await, 0);
        assert!(h.audit.records().is_empty());
    }

    #[tokio::test]
    async fn malformed_requests_are_400() {
        let h = harness(Setup::default()).await;
        let o = h.origin();
        for bad in [
            serde_json::json!({}),
            serde_json::json!({ "secret_id": SECRET, "version": 0, "method": "GET", "url": format!("{o}/") }),
            serde_json::json!({ "secret_id": SECRET, "version": 1, "method": "GET", "url": "ftp://x/" }),
            serde_json::json!({ "secret_id": SECRET, "version": 1, "method": "CONNECT", "url": format!("{o}/") }),
            serde_json::json!({ "secret_id": SECRET, "version": 1, "method": "GET", "url": format!("{o}/"), "headers": [["bad header", "x"]] }),
            serde_json::json!({ "secret_id": SECRET, "version": 1, "method": "GET", "url": format!("{o}/"), "body": "a", "body_base64": "YQ==" }),
            serde_json::json!({ "secret_id": SECRET, "version": 1, "method": "GET", "url": format!("{o}/"), "extra": 1 }),
        ] {
            let (status, _) = h.call(Some(CALLER), bad).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        assert_eq!(h.kms_calls().await, 0);
    }

    /// Fail closed: an encoding the redactor cannot scan, or an oversized body, is withheld.
    #[tokio::test]
    async fn unscannable_responses_are_withheld() {
        let h = harness(Setup::default()).await;
        Mock::given(method("GET"))
            .and(path("/gzip"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(VALUE.to_vec()),
            )
            .mount(&h.upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/big"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'a'; 64 * 1024 + 1]))
            .mount(&h.upstream)
            .await;
        for p in ["gzip", "big"] {
            let (status, raw) = h.relay_get(SECRET, &format!("{}/{p}", h.origin())).await;
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{p}");
            assert!(String::from_utf8_lossy(&raw).contains("response_withheld"));
            assert_clean(p, &raw);
        }
        assert_eq!(h.outcomes(), ["redaction_failed", "redaction_failed"]);
        assert!(h.audit.records().iter().all(|r| r.status == Some(200)));
        // The relay asked for an unencoded response.
        let reqs = h.upstream.received_requests().await.unwrap();
        assert!(reqs.iter().all(|r| {
            r.headers
                .get("accept-encoding")
                .is_some_and(|v| v == "identity")
        }));
    }

    /// Spec "Failure paths do not leak": unwrap failure, unreachable upstream, upstream timeout.
    #[tokio::test]
    async fn failure_paths_leak_nothing_and_are_audited() {
        // Unwrap fails (KMS error).
        let h = harness(Setup {
            bao_ok: false,
            ..Setup::default()
        })
        .await;
        let (status, raw) = h.relay_get(SECRET, &format!("{}/x", h.origin())).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(String::from_utf8_lossy(&raw).contains("secret_unavailable"));
        assert!(
            !String::from_utf8_lossy(&raw).contains("internal error"),
            "no KMS text"
        );
        assert_eq!(Harness::hits(&h.upstream).await, 0);
        // Unknown version: 404, nothing unwrapped.
        let (status, _) = h
            .call(
                Some(CALLER),
                serde_json::json!({ "secret_id": SECRET, "version": 9, "method": "GET", "url": format!("{}/x", h.origin()) }),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(h.outcomes(), ["decrypt_failed", "material_error"]);

        let h = harness(Setup::default()).await;
        // Unreachable upstream.
        let (status, raw) = h.relay_get(DEAD, &format!("{}/x", h.dead_origin())).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(String::from_utf8_lossy(&raw).contains("upstream_unreachable"));
        assert_clean("unreachable", &raw);

        // Upstream timeout (echoing the secret, too late to matter).
        Mock::given(method("GET"))
            .and(path("/slow"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(3))
                    .set_body_bytes(VALUE.to_vec()),
            )
            .mount(&h.upstream)
            .await;
        let (status, raw) = h.relay_get(SECRET, &format!("{}/slow", h.origin())).await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_clean("timeout", &raw);
        assert_eq!(h.outcomes(), ["upstream_unreachable", "upstream_timeout"]);
        h.assert_audit_clean();
    }

    /// The response is withheld when the audit row cannot be written for a call that reached the
    /// upstream; a refusal is still a refusal.
    #[tokio::test]
    async fn audit_failure_withholds_the_response() {
        let h = harness(Setup {
            audit_fails: true,
            ..Setup::default()
        })
        .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("fine"))
            .mount(&h.upstream)
            .await;
        let (status, raw) = h.relay_get(SECRET, &format!("{}/x", h.origin())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!String::from_utf8_lossy(&raw).contains("fine"));
        let (status, _) = h.relay_get(SECRET, "http://evil.test/x").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn short_secrets_are_refused_fail_closed() {
        // A value too short for encoded-form matching is not relayed.
        let h = harness(Setup::default()).await;
        let short = seal(ORG, SECRET, 2, b"1234567");
        Mock::given(method("GET"))
            .and(path(format!(
                "/internal/v1/secrets/{SECRET}/versions/2/material"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(short.json(SECRET, 2)))
            .with_priority(1)
            .mount(&h.cp)
            .await;
        // The stub KMS returns version 1's DEK; version 2 needs its own.
        h.bao.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "plaintext": B64.encode(short.dek) }
            })))
            .mount(&h.bao)
            .await;
        let (status, _) = h
            .call(
                Some(CALLER),
                serde_json::json!({ "secret_id": SECRET, "version": 2, "method": "GET", "url": format!("{}/x", h.origin()) }),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(Harness::hits(&h.upstream).await, 0);
        assert_eq!(h.outcomes(), ["redaction_failed"]);
    }

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Trace-level logs of the success and failure paths (including reqwest/hyper) hold no
    /// encoding of the value.
    #[tokio::test]
    async fn logs_hold_no_secret() {
        let cap = Capture::default();
        let writer = cap.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let h = harness(Setup::default()).await;
        Mock::given(method("GET"))
            .and(path("/echo"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-echo", injected().as_str())
                    .set_body_string(injected()),
            )
            .mount(&h.upstream)
            .await;
        let (status, _) = h.relay_get(SECRET, &format!("{}/echo", h.origin())).await;
        assert_eq!(status, StatusCode::OK);
        h.relay_get(SECRET, "http://evil.test/x").await;
        h.relay_get(DEAD, &format!("{}/x", h.dead_origin())).await;
        let failing = harness(Setup {
            bao_ok: false,
            ..Setup::default()
        })
        .await;
        failing
            .relay_get(SECRET, &format!("{}/x", failing.origin()))
            .await;

        let logs = cap.0.lock().unwrap().clone();
        assert!(
            String::from_utf8_lossy(&logs).contains("relay"),
            "capture saw the relay span"
        );
        assert_clean("trace logs", &logs);
    }
}
