//! `POST /v1/relay` (S3 task 3.3): decrypt a bound secret inside the gateway, inject it into
//! one upstream request, return the redacted response and audit the call in the org's ledger
//! (S5 task 3.1, [`crate::audit`]).
//!
//! Order of checks, each before the next step runs:
//! 1. agent token ([`crate::auth`]: JWKS signature, audience, expiry, org) -> `401`, nothing
//!    else happens and nothing is audited;
//! 2. request shape -> `400`;
//! 3. grant (S4 task 2.2): the agent's grants (cached at most 10 s, [`crate::grants::GrantCache`])
//!    must hold an unexpired `relay` grant for the secret -> `403 no_grant`; grants that cannot
//!    be read -> `502 grants_unavailable` (fail closed);
//! 4. binding for the secret and the target's origin -> `403 denied`;
//! 5. DNS and address guard -> `403 denied_address` (still no fetch, no unwrap). Refusals in
//!    steps 3-5 append one `relay.denied` event with the agent id (the response stands even if
//!    that append fails: nothing was decrypted);
//! 6. append `relay.attempt` to the ledger; if that fails -> `503 audit_unavailable`, with no
//!    material fetch, no unwrap and no upstream call (fail closed);
//! 7. fetch material, unwrap DEK (cached), open the version. Nothing before this step touches
//!    the material or the KMS;
//! 8. render the binding's header template, send through a client pinned to the checked
//!    addresses that follows no redirects;
//! 9. read the response (identity encoding only, size-bounded), redact headers and body with
//!    `ls-redact` (plain, base64, URL, hex, JSON, base32, UTF-16 and \u-escaped forms), re-check that nothing matches, and
//!    withhold the response with `502` if any of that fails (fail closed);
//! 10. append `relay.outcome` naming the attempt, retried up to [`RelayOptions::outcome_retries`]
//!     times (idempotent on the attempt id). If it still fails, a successful response is
//!     withheld (`500 audit_failed`); the open attempt stays visible in the ledger.
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
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ls_redact::{MIN_ENCODED_LEN, Redactor, Secret};
use reqwest::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use tracing::Instrument;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::{AuditSink, EventKind, Method, Outcome, RelayEvent};
use crate::auth::AgentAuth;
use crate::config::{Binding, Bindings};
use crate::decrypt::{DecryptError, Decryptor, MaterialError};
use crate::egress::{self, EgressError, Resolver};
use crate::grants::{GrantSource, allows_relay};

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
    /// Retries of a failed `relay.outcome` append (design decision 5: 3).
    pub outcome_retries: u32,
    /// Wait before the first outcome retry; doubled for each further retry.
    pub outcome_retry_backoff: Duration,
}

impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            timeout: Duration::from_secs(30),
            max_request_body: 1024 * 1024,
            max_response_body: 10 * 1024 * 1024,
            outcome_retries: 3,
            outcome_retry_backoff: Duration::from_millis(100),
        }
    }
}

/// Everything the `/v1` routes need. No `Debug`/`Clone`: it holds the decrypt path.
pub struct Relay {
    auth: Arc<AgentAuth>,
    grants: Arc<dyn GrantSource>,
    bindings: Bindings,
    decryptor: Decryptor,
    resolver: Arc<dyn Resolver>,
    audit: Arc<dyn AuditSink>,
    options: RelayOptions,
    git: crate::git::GitState,
    /// Short-lived credentials issued over MCP (m1-remote-mcp task 3.3).
    short_lived: crate::short_lived::ShortLivedStore,
    /// The agent-layer MCP client registry (task 4.2), read before a short-lived credential is
    /// honoured so a revoke takes effect here without waiting for `/mcp` traffic.
    revoked_agents: Option<Arc<dyn crate::mcp_clients::AgentClients>>,
}

impl Relay {
    /// `auth` must verify tokens for `bindings.org_id`, the org this gateway serves.
    pub fn new(
        auth: Arc<AgentAuth>,
        grants: Arc<dyn GrantSource>,
        bindings: Bindings,
        decryptor: Decryptor,
        resolver: Arc<dyn Resolver>,
        audit: Arc<dyn AuditSink>,
        options: RelayOptions,
    ) -> Self {
        Self {
            auth,
            grants,
            bindings,
            decryptor,
            resolver,
            audit,
            options,
            git: crate::git::GitState::default(),
            short_lived: crate::short_lived::ShortLivedStore::default(),
            revoked_agents: None,
        }
    }

    /// Check short-lived credentials against the agent MCP client registry (task 4.2): a
    /// credential of a revoked agent is refused and the agent's credentials are dropped, and a
    /// registry that cannot be read refuses every short-lived credential (fail closed). In
    /// production the same cache `/mcp` reads ([`crate::mcp_clients::ClientsCache`]).
    pub fn with_revoked_agents(
        mut self,
        clients: Arc<dyn crate::mcp_clients::AgentClients>,
    ) -> Self {
        self.revoked_agents = Some(clients);
        self
    }

    /// Whether short-lived credentials of `agent_id` must be refused: its MCP access is revoked,
    /// or the registry cannot be read. Drops the agent's credentials when it is revoked.
    async fn short_lived_agent_revoked(&self, agent_id: Uuid) -> bool {
        let Some(clients) = &self.revoked_agents else {
            return false;
        };
        match clients.revoked().await {
            Ok(set) if set.contains(&agent_id) => {
                let dropped = self.short_lived.drop_agent(agent_id);
                tracing::info!(agent.id = %agent_id, dropped, "revoked MCP agent: short-lived credentials dropped");
                true
            }
            Ok(_) => false,
            Err(_) => {
                tracing::warn!("revoked MCP agents unreadable; short-lived credential refused");
                true
            }
        }
    }

    /// Replace the Git route's timeouts and token cache (D1).
    pub fn with_git(mut self, git: crate::git::GitState) -> Self {
        self.git = git;
        self
    }

    pub(crate) fn git(&self) -> &crate::git::GitState {
        &self.git
    }

    pub(crate) fn short_lived(&self) -> &crate::short_lived::ShortLivedStore {
        &self.short_lived
    }

    pub(crate) fn audit(&self) -> &dyn AuditSink {
        self.audit.as_ref()
    }

    pub(crate) fn decryptor(&self) -> &Decryptor {
        &self.decryptor
    }

    pub(crate) fn resolver(&self) -> &dyn Resolver {
        self.resolver.as_ref()
    }

    pub fn options(&self) -> &RelayOptions {
        &self.options
    }

    pub fn auth(&self) -> &AgentAuth {
        &self.auth
    }

    pub fn grants(&self) -> &dyn GrantSource {
        self.grants.as_ref()
    }

    pub fn bindings(&self) -> &Bindings {
        &self.bindings
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

pub(crate) fn error(status: StatusCode, slug: &'static str, request_id: &str) -> Response {
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

/// `host` or `host:port` when the URL names a non-default port (span attribute only).
fn span_host(url: &Url) -> String {
    let host = url.host_str().unwrap_or("-");
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_owned(),
    }
}

/// What every event of one call shares. The host is recorded only when the outcome says the
/// origin matched the binding ([`Outcome::origin_checked`]).
struct CallAudit {
    agent_id: Uuid,
    secret_id: Uuid,
    version: u32,
    method: Option<Method>,
    host: Option<String>,
    port: Option<u16>,
}

impl CallAudit {
    fn event(&self, kind: EventKind, status: Option<u16>, attempt_id: Option<Uuid>) -> RelayEvent {
        let host_ok = match kind {
            EventKind::Attempt => true,
            EventKind::Outcome(o) | EventKind::Denied(o) => o.origin_checked(),
            EventKind::GitFetch(_) | EventKind::GitPush(_) | EventKind::GitDenied(_) => true,
            EventKind::CredentialIssued => false,
        };
        RelayEvent {
            kind,
            agent_id: self.agent_id,
            secret_id: self.secret_id,
            version: self.version,
            method: self.method,
            host: self.host.clone().filter(|_| host_ok),
            port: self.port.filter(|_| host_ok),
            status,
            attempt_id,
            issued: None,
        }
    }
}

/// Append the outcome of an attempt, retrying failures that may be transient. The control
/// plane returns the stored event for a resent outcome, so a retry after a lost response does
/// not append twice. Git delegation records its outcomes through this too.
pub(crate) async fn append_outcome(relay: &Relay, ev: RelayEvent) -> bool {
    let mut wait = relay.options.outcome_retry_backoff;
    for try_no in 0..=relay.options.outcome_retries {
        match relay.audit.append(ev.clone()).await {
            Ok(_) => return true,
            Err(crate::audit::AuditError::Rejected) => {
                tracing::error!(kind = ?ev.kind, "outcome event refused by the ledger");
                return false;
            }
            Err(crate::audit::AuditError::Unavailable) => {
                tracing::warn!(kind = ?ev.kind, attempt = try_no + 1, "outcome event not appended");
                if try_no < relay.options.outcome_retries {
                    tokio::time::sleep(wait).await;
                    wait = wait.saturating_mul(2);
                }
            }
        }
    }
    false
}

/// The handler. See the module docs for the order of checks.
///
/// Besides an agent token, the bearer may be a short-lived credential the agent MCP issued
/// ([`crate::short_lived`], m1-remote-mcp task 3.3): it runs as the agent it was issued to and
/// is refused (`403 denied`, audited) for any secret but the one it is scoped to. An unknown or
/// expired one is a `401` like a bad agent token.
pub async fn handle(relay: Arc<Relay>, headers: HeaderMap, body: Bytes) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let short_lived = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| ls_control_plane::auth::bearer(v.as_bytes()))
        .and_then(|t| std::str::from_utf8(t).ok())
        .filter(|t| t.starts_with(crate::short_lived::PREFIX))
        .map(|t| {
            relay
                .short_lived
                .resolve(t, time::OffsetDateTime::now_utc())
        });
    if let Some(scope) = short_lived {
        return match scope.filter(|s| s.org_id == relay.bindings.org_id) {
            Some(s) if relay.short_lived_agent_revoked(s.agent_id).await => {
                tracing::info!(
                    reason = "short_lived_agent_revoked",
                    "relay credential refused"
                );
                error(StatusCode::UNAUTHORIZED, "unauthenticated", &request_id)
            }
            Some(s) => {
                let agent = crate::auth::AgentIdentity {
                    agent_id: s.agent_id,
                    org_id: s.org_id,
                };
                let only = Only {
                    secret_id: s.secret_id,
                    credential_id: s.credential_id,
                };
                handle_scoped(relay, agent, Some(only), request_id, body).await
            }
            None => {
                tracing::info!(
                    reason = "short_lived_unknown_or_expired",
                    "relay credential refused"
                );
                error(StatusCode::UNAUTHORIZED, "unauthenticated", &request_id)
            }
        };
    }
    let agent = match relay.auth.authenticate(&headers).await {
        Ok(a) => a,
        Err(e) => {
            tracing::info!(reason = e.as_str(), "agent token refused");
            return error(StatusCode::UNAUTHORIZED, "unauthenticated", &request_id);
        }
    };
    handle_as(relay, agent, request_id, body).await
}

/// The relay for an already authenticated agent: every check, the audit events and the
/// redaction are the ones `/v1/relay` runs. The MCP `relay_http_request` tool enters here
/// (m1-remote-mcp task 3.2) after `/mcp` verified the same agent token.
pub(crate) async fn handle_as(
    relay: Arc<Relay>,
    agent: crate::auth::AgentIdentity,
    request_id: String,
    body: Bytes,
) -> Response {
    handle_scoped(relay, agent, None, request_id, body).await
}

/// A short-lived credential's restriction: the one secret it may relay.
#[derive(Clone, Copy)]
struct Only {
    secret_id: Uuid,
    credential_id: Uuid,
}

async fn handle_scoped(
    relay: Arc<Relay>,
    agent: crate::auth::AgentIdentity,
    only: Option<Only>,
    request_id: String,
    body: Bytes,
) -> Response {
    let Some(req) = parse(&body, relay.options.max_request_body) else {
        return error(StatusCode::BAD_REQUEST, "bad_request", &request_id);
    };

    let host = span_host(&req.url);
    let span = tracing::info_span!(
        "relay",
        request_id = %request_id,
        agent.id = %agent.agent_id,
        secret.id = %req.secret_id,
        secret.version = req.version,
        upstream.host = %host,
        http.request.method = %req.method,
        outcome = tracing::field::Empty,
        upstream.status = tracing::field::Empty,
        credential.id = tracing::field::Empty,
    );
    if let Some(o) = only {
        span.record("credential.id", tracing::field::display(o.credential_id));
    }
    let call = CallAudit {
        agent_id: agent.agent_id,
        secret_id: req.secret_id,
        version: req.version,
        method: Method::from_http(&req.method),
        host: req.url.host_str().map(str::to_owned),
        port: req.url.port(),
    };

    async move {
        let mut attempt = None;
        let result = run(&relay, &call, &mut attempt, req, only).await;
        let span = tracing::Span::current();
        let (outcome, status) = match &result {
            Ok(resp) => (Outcome::Ok, Some(resp.status)),
            Err(f) => (f.outcome, f.upstream_status),
        };
        span.record("outcome", outcome.as_str());
        if let Some(s) = status {
            span.record("upstream.status", s);
        }
        let outcome_recorded = match attempt {
            Some(id) => {
                append_outcome(
                    &relay,
                    call.event(EventKind::Outcome(outcome), status, Some(id)),
                )
                .await
            }
            None if outcome == Outcome::AuditUnavailable => {
                tracing::error!("relay attempt event not appended; refused before unwrap");
                true
            }
            None if outcome.is_denial() => {
                // One try: the call is refused whether or not the event lands.
                if relay
                    .audit
                    .append(call.event(EventKind::Denied(outcome), None, None))
                    .await
                    .is_err()
                {
                    tracing::error!("relay denied event not appended");
                }
                true
            }
            None => {
                // Failed after the policy checks but before the attempt (DNS, client setup):
                // nothing was decrypted; record it as an attempt and its outcome.
                match relay
                    .audit
                    .append(call.event(EventKind::Attempt, None, None))
                    .await
                {
                    Ok(id) => {
                        append_outcome(
                            &relay,
                            call.event(EventKind::Outcome(outcome), status, Some(id)),
                        )
                        .await;
                    }
                    Err(_) => tracing::error!("relay attempt event not appended"),
                }
                true
            }
        };
        match result {
            Ok(_) if !outcome_recorded => {
                tracing::error!("relay outcome event not appended; response withheld");
                error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "audit_failed",
                    &request_id,
                )
            }
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

async fn run(
    relay: &Relay,
    call: &CallAudit,
    attempt: &mut Option<Uuid>,
    req: Parsed,
    only: Option<Only>,
) -> Result<RelayResponse, Failure> {
    let agent_id = call.agent_id;
    // A short-lived credential relays its one secret and nothing else (before any lookup).
    if only.is_some_and(|o| o.secret_id != req.secret_id) {
        return Err(denied());
    }
    // 3. Grant and its expiry: refused before the binding lookup, DNS, fetch or unwrap. The
    // expiry is re-checked here because the set may come from the cache.
    let grants = relay.grants.grants(agent_id).await.map_err(|e| {
        tracing::warn!(reason = e.as_str(), "agent grants could not be read");
        Failure::new(
            Outcome::GrantsUnavailable,
            StatusCode::BAD_GATEWAY,
            "grants_unavailable",
        )
    })?;
    if !allows_relay(&grants, req.secret_id, time::OffsetDateTime::now_utc()) {
        return Err(Failure::new(
            Outcome::NoGrant,
            StatusCode::FORBIDDEN,
            "no_grant",
        ));
    }
    drop(grants);

    // 4. Binding and origin: refused before any fetch or unwrap.
    let binding: &Binding = relay
        .bindings
        .for_secret(req.secret_id)
        .ok_or_else(denied)?;
    // 5. Address guard (resolves once; the client is pinned to the result).
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

    // 6. Attempt event before anything touches the material or the KMS (fail closed).
    let id = relay
        .audit
        .append(call.event(EventKind::Attempt, None, None))
        .await
        .map_err(|_| {
            Failure::new(
                Outcome::AuditUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
            )
        })?;
    *attempt = Some(id);

    // 7. Decrypt.
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

    // 8. Inject: the redactor and the header value are built, then the value is dropped.
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

    // 9. Read (bounded), refuse encodings that cannot be scanned, redact, re-check.
    // `Transfer-Encoding` is checked too: hyper removes only `chunked`, so `gzip, chunked`
    // with no `Content-Encoding` would hand over a compressed body the redactor cannot read.
    let encoded = names_coding_other_than(
        resp.headers(),
        reqwest::header::CONTENT_ENCODING,
        "identity",
    ) || names_coding_other_than(
        resp.headers(),
        reqwest::header::TRANSFER_ENCODING,
        "chunked",
    );
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

/// Whether any `name` header lists a coding other than `allowed` (case-insensitive), across
/// every value and comma-separated entry. A value that is not visible ASCII counts as one.
fn names_coding_other_than(
    headers: &reqwest::header::HeaderMap,
    name: HeaderName,
    allowed: &str,
) -> bool {
    headers.get_all(name).iter().any(|v| {
        v.to_str()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .any(|c| !c.is_empty() && !c.eq_ignore_ascii_case(allowed))
            })
            .unwrap_or(true)
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
    use crate::audit::{HttpAudit, MemoryAudit};
    use crate::auth::testkit::StubJwks;
    use crate::auth::{AgentAuth, JwksSettings};
    use crate::decrypt::testkit::{key, seal};
    use crate::decrypt::{CacheSettings, ControlPlane, DekCache};
    use crate::egress::testkit::StubResolver;
    use crate::grants::testkit::StubGrants;
    use crate::grants::{Grant, GrantCache, GrantCacheSettings, GrantList, GrantView};
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use http_body_util::BodyExt;
    use ls_control_plane::agent_token::{AUDIENCE, AgentClaims, AgentTokenSigner};
    use ls_control_plane::auth::ServiceToken;
    use ls_control_plane::db::{Database, PoolSettings, sql};
    use ls_control_plane::readiness::ReadyFlag;
    use ls_envelope::{BaoToken, OpenBaoTransit};
    use secrecy::SecretString;
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
    const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a1);

    /// Tasks 5.1 and 5.2 of s6-adversarial-gate-1: the G2 to G4 payloads, judged by the oracle.
    mod adversarial;

    /// Task 3.2 of m1-remote-mcp: the gateway's default-on MCP tools over the same harness.
    mod mcp;

    /// Task 4.2 of m1-remote-mcp: a revoked agent is refused on `/mcp`, calls and initialize.
    mod mcp_revoke;
    /// Task 3.3 of m1-remote-mcp: `issue_short_lived_credential` and its adversarial cases.
    mod mcp_short_lived;

    /// Task 3.4 of m1-remote-mcp: per-org tool switches and the per-call `mcp.call` event.
    mod mcp_settings;

    fn grant(secret_id: Uuid, name: &str, expires_at: Option<time::OffsetDateTime>) -> Grant {
        Grant {
            grant_id: Uuid::now_v7(),
            secret_id,
            secret_name: name.to_owned(),
            mode: "relay".to_owned(),
            expires_at,
        }
    }

    fn signer() -> AgentTokenSigner {
        AgentTokenSigner::from_seed(zeroize::Zeroizing::new([7u8; 32])).unwrap()
    }

    fn agent_claims(org: Uuid, aud: &str, exp_in: i64) -> AgentClaims {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        AgentClaims {
            sub: AGENT,
            org,
            aud: aud.to_owned(),
            jti: Uuid::now_v7(),
            iat: now,
            exp: now + exp_in,
        }
    }

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
        relay: Arc<Relay>,
        upstream: MockServer,
        cp: MockServer,
        bao: MockServer,
        audit: Arc<MemoryAudit>,
        resolver: Arc<StubResolver>,
        grants: Arc<StubGrants>,
        dead_port: u16,
        signer: AgentTokenSigner,
        /// A valid agent token for [`AGENT`] in [`ORG`].
        token: String,
    }

    struct Setup {
        bao_ok: bool,
        /// Every append fails.
        audit_fails: bool,
        /// Every `relay.attempt` append fails.
        attempt_fails: bool,
        /// The first this many `relay.outcome` appends fail.
        outcome_fails_first: usize,
        /// Replaces the in-memory sink (the ledger tests use the real control plane).
        audit: Option<Arc<dyn AuditSink>>,
        /// TTL of the gateway's grant cache in front of [`StubGrants`].
        grant_ttl: Duration,
        options: RelayOptions,
        /// The sealed secret value (the adversarial tests use the oracle's canary).
        value: Vec<u8>,
        /// MCP tool switches over the registry defaults (m1-remote-mcp task 3.3).
        mcp_tools: Vec<(&'static str, bool)>,
        /// Replaces the fixed switches with a source read on every call (task 3.4).
        settings_source: Option<Arc<dyn crate::mcp_settings::ToolSettingsSource>>,
        /// The agent-layer client registry (task 4.2); none means nobody is revoked.
        clients: Option<Arc<dyn crate::mcp_clients::AgentClients>>,
    }

    impl Default for Setup {
        fn default() -> Self {
            Self {
                bao_ok: true,
                audit_fails: false,
                attempt_fails: false,
                outcome_fails_first: 0,
                audit: None,
                grant_ttl: crate::ttl::MAX_CACHE_TTL,
                value: VALUE.to_vec(),
                mcp_tools: Vec::new(),
                settings_source: None,
                clients: None,
                options: RelayOptions {
                    connect_timeout: Duration::from_secs(2),
                    timeout: Duration::from_millis(1500),
                    max_request_body: 64 * 1024,
                    max_response_body: 64 * 1024,
                    outcome_retries: 3,
                    outcome_retry_backoff: Duration::from_millis(1),
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
        let sealed = seal(ORG, SECRET, 1, &setup.value);
        let unbound = seal(ORG, UNBOUND, 1, &setup.value);
        let dead = seal(ORG, DEAD, 1, &setup.value);
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
            git_bindings: Vec::new(),
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
            fail_attempts: setup.attempt_fails,
            fail_outcomes_first: Mutex::new(setup.outcome_fails_first),
            ..MemoryAudit::default()
        });
        let signer = signer();
        let auth = Arc::new(AgentAuth::new(
            ORG,
            Arc::new(StubJwks::with(vec![signer.jwk().clone()])),
            JwksSettings::default(),
        ));
        let token = signer.sign(&agent_claims(ORG, AUDIENCE, 600)).unwrap();
        // By default the agent may relay every test secret; tests that need fewer replace the set
        // before their first call.
        let grants = Arc::new(StubGrants::default());
        grants.set(
            AGENT,
            [SECRET, INTERNAL, DEAD, UNBOUND]
                .into_iter()
                .map(|id| grant(id, "TEST", None))
                .collect(),
        );
        let cache = GrantCache::new(
            grants.clone(),
            GrantCacheSettings {
                ttl: setup.grant_ttl,
                ..GrantCacheSettings::default()
            },
        );
        let sink: Arc<dyn AuditSink> = match setup.audit {
            Some(a) => a,
            None => audit.clone(),
        };
        let mut mcp =
            crate::mcp_endpoint::McpEndpoint::new(auth.clone(), &["gateway.test".to_owned()])
                .with_tool_settings(
                    setup
                        .mcp_tools
                        .iter()
                        .map(|(n, on)| ((*n).to_owned(), *on))
                        .collect(),
                );
        if let Some(source) = setup.settings_source {
            mcp = mcp.with_settings_source(source);
        }
        if let Some(clients) = setup.clients.clone() {
            mcp = mcp.with_clients(clients);
        }
        let mut relay = Relay::new(
            auth,
            Arc::new(cache),
            bindings,
            decryptor,
            resolver.clone(),
            sink,
            setup.options,
        );
        if let Some(clients) = setup.clients {
            relay = relay.with_revoked_agents(clients);
        }
        let relay = Arc::new(relay);
        let app = app::build(
            AppState::new(Arc::new(ReadyFlag::new(true)))
                .with_relay(relay.clone())
                .with_mcp(mcp),
        );
        Harness {
            app,
            relay,
            upstream,
            cp,
            bao,
            audit,
            resolver,
            grants,
            dead_port,
            signer,
            token,
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
                Some(self.token.as_str()),
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

        /// The final outcome of each audited call: every `relay.outcome` and `relay.denied`
        /// event, in order (attempts left out).
        fn outcomes(&self) -> Vec<&'static str> {
            self.closing().iter().map(|(o, _)| o.as_str()).collect()
        }

        /// `(outcome, event)` for every `relay.outcome` and `relay.denied` event.
        fn closing(&self) -> Vec<(Outcome, RelayEvent)> {
            self.audit
                .events()
                .into_iter()
                .filter_map(|e| match e.kind {
                    EventKind::Attempt => None,
                    EventKind::Outcome(o) | EventKind::Denied(o) => Some((o, e)),
                    EventKind::GitFetch(_)
                    | EventKind::GitPush(_)
                    | EventKind::GitDenied(_)
                    | EventKind::CredentialIssued => None,
                })
                .collect()
        }

        /// Every outcome closes the attempt before it, and every attempt is closed.
        fn assert_attempts_closed(&self) {
            let mut open = None;
            for (id, e) in self.audit.stored() {
                match e.kind {
                    EventKind::Attempt => {
                        assert!(open.is_none(), "attempt left open");
                        open = Some(id);
                    }
                    EventKind::Outcome(_) => {
                        assert_eq!(e.attempt_id, open.take(), "outcome names its attempt");
                    }
                    EventKind::Denied(o) => {
                        assert!(o.is_denial());
                        assert!(e.attempt_id.is_none());
                    }
                    EventKind::GitFetch(_)
                    | EventKind::GitPush(_)
                    | EventKind::GitDenied(_)
                    | EventKind::CredentialIssued => {}
                }
            }
            assert!(open.is_none(), "attempt left open");
        }

        fn assert_audit_clean(&self) {
            let text = format!("{:?}", self.audit.stored());
            assert_clean("audit events", text.as_bytes());
            self.assert_attempts_closed();
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
                Some(h.token.as_str()),
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
        // `relay.attempt` then `relay.outcome` naming it: ids, method, host and port, the
        // upstream status; no path, query, header or body.
        let ev = h.audit.stored();
        assert_eq!(ev.len(), 2);
        let port = Some(h.upstream.address().port());
        let host = Some("upstream.test".to_owned());
        let (attempt_id, attempt) = &ev[0];
        assert_eq!(
            attempt,
            &RelayEvent {
                kind: EventKind::Attempt,
                agent_id: AGENT,
                secret_id: SECRET,
                version: 1,
                method: Some(Method::Post),
                host: host.clone(),
                port,
                status: None,
                attempt_id: None,
                issued: None,
            }
        );
        assert_eq!(
            ev[1].1,
            RelayEvent {
                kind: EventKind::Outcome(Outcome::Ok),
                status: Some(201),
                attempt_id: Some(*attempt_id),
                ..attempt.clone()
            }
        );
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

    /// Task 4.2: base32 (RFC 4648, padded or not, both cases), UTF-16LE/BE and `\u`-escaped
    /// forms of the value never reach the caller, in the body or in a header.
    #[tokio::test]
    async fn echoed_secret_is_redacted_in_base32_utf16_and_json_u() {
        fn b32(pad: bool, lower: bool) -> Vec<u8> {
            const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let mut out = Vec::new();
            for g in VALUE.chunks(5) {
                let mut n = 0u64;
                for i in 0..5 {
                    n = (n << 8) | u64::from(*g.get(i).unwrap_or(&0));
                }
                let chars = (g.len() * 8).div_ceil(5);
                for i in 0..8 {
                    if i < chars {
                        let c = A[((n >> (35 - 5 * i)) & 31) as usize];
                        out.push(if lower { c.to_ascii_lowercase() } else { c });
                    } else if pad {
                        out.push(b'=');
                    }
                }
            }
            out
        }
        fn u16s(be: bool) -> Vec<u8> {
            VALUE
                .iter()
                .flat_map(|&b| if be { [0, b] } else { [b, 0] })
                .collect()
        }
        fn ju(upper: bool) -> Vec<u8> {
            VALUE
                .iter()
                .flat_map(|&b| {
                    if upper {
                        format!("\\u{b:04X}")
                    } else {
                        format!("\\u{b:04x}")
                    }
                    .into_bytes()
                })
                .collect()
        }
        let h = harness(Setup::default()).await;
        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("b32", b32(true, false)),
            ("b32-nopad", b32(false, false)),
            ("b32-lower", b32(true, true)),
            ("b32-lower-nopad", b32(false, true)),
            ("utf16le", u16s(false)),
            ("utf16be", u16s(true)),
            ("json-u", ju(false)),
            ("json-u-upper", ju(true)),
        ];
        for (name, enc) in &mut cases {
            let mut body = b"pre ".to_vec();
            body.append(enc);
            body.extend_from_slice(b" post");
            Mock::given(method("GET"))
                .and(path(format!("/echo/{name}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
                .mount(&h.upstream)
                .await;
            let (status, raw) = h
                .relay_get(SECRET, &format!("{}/echo/{name}", h.origin()))
                .await;
            assert_eq!(status, StatusCode::OK, "{name}");
            let env = envelope(&raw);
            let got = match (env.body, env.body_base64) {
                (Some(t), _) => t.into_bytes(),
                (None, Some(b)) => B64.decode(b).unwrap(),
                _ => panic!("{name}: no body"),
            };
            assert!(
                String::from_utf8_lossy(&got).contains("[REDACTED:SECRET]"),
                "{name}: no marker"
            );
            assert_clean(name, &got);
        }
        // Headers (ASCII forms only).
        let b32h = String::from_utf8(b32(false, true)).unwrap();
        let juh = String::from_utf8(ju(false)).unwrap();
        Mock::given(method("GET"))
            .and(path("/echo-headers-new"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-echo-b32", b32h.as_str())
                    .insert_header("x-echo-ju", juh.as_str()),
            )
            .mount(&h.upstream)
            .await;
        let (_, raw) = h
            .relay_get(SECRET, &format!("{}/echo-headers-new", h.origin()))
            .await;
        let env = envelope(&raw);
        for n in ["x-echo-b32", "x-echo-ju"] {
            let v = &env.headers.iter().find(|(k, _)| k == n).unwrap().1;
            assert_eq!(v, "[REDACTED:SECRET]", "{n}");
        }
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
        assert_eq!(outcomes.len(), 7, "every refused call is audited");
        assert_eq!(outcomes.iter().filter(|o| **o == "denied").count(), 6);
        assert_eq!(outcomes.last(), Some(&"denied_address"));
        let ev = h.audit.events();
        assert_eq!(ev.len(), 7, "a `relay.denied` event each, no attempt");
        assert!(
            ev.iter()
                .all(|e| matches!(e.kind, EventKind::Denied(_)) && e.status.is_none())
        );
        assert!(ev.iter().all(|e| e.agent_id == AGENT));
        // A host the binding did not match is caller input and is not recorded; the binding's
        // own host (refused by the address guard) is.
        assert!(ev[..6].iter().all(|e| e.host.is_none() && e.port.is_none()));
        assert_eq!(ev[6].host.as_deref(), Some("internal.test"));
        h.assert_audit_clean();
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

    /// Spec "Caller authentication" / "Expired or forged token": `401`, no fetch, unwrap or
    /// upstream call; nothing to audit.
    #[tokio::test]
    async fn unauthenticated_caller_is_refused_first() {
        let h = harness(Setup::default()).await;
        let body = serde_json::json!({
            "secret_id": SECRET, "version": 1, "method": "GET", "url": format!("{}/x", h.origin())
        });
        let other = AgentTokenSigner::from_seed(zeroize::Zeroizing::new([8u8; 32])).unwrap();
        let parts: Vec<&str> = h.token.split('.').collect();
        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&agent_claims(ORG, AUDIENCE, 3600)).unwrap()),
            parts[2]
        );
        let refused = [
            ("none", None),
            ("garbage", Some("wrong".to_owned())),
            ("truncated", Some(h.token[..h.token.len() - 1].to_owned())),
            (
                "forged (unknown key)",
                Some(other.sign(&agent_claims(ORG, AUDIENCE, 600)).unwrap()),
            ),
            ("forged (tampered payload)", Some(tampered)),
            (
                "expired",
                Some(h.signer.sign(&agent_claims(ORG, AUDIENCE, -120)).unwrap()),
            ),
            (
                "wrong audience",
                Some(
                    h.signer
                        .sign(&agent_claims(ORG, "control-plane", 600))
                        .unwrap(),
                ),
            ),
            (
                "other org",
                Some(
                    h.signer
                        .sign(&agent_claims(Uuid::now_v7(), AUDIENCE, 600))
                        .unwrap(),
                ),
            ),
        ];
        for (name, token) in &refused {
            let (status, raw) = h.call(token.as_deref(), body.clone()).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{name}");
            assert!(
                String::from_utf8_lossy(&raw).contains("\"unauthenticated\""),
                "{name}"
            );
        }
        // Lower-case scheme is the same credential (one shared bearer parser).
        let resp = h
            .app
            .clone()
            .oneshot(
                Request::post("/v1/relay")
                    .header("authorization", format!("bearer {}", h.token))
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "authenticated, bad body"
        );

        assert_eq!(h.kms_calls().await, 0, "no KMS call");
        assert_eq!(Harness::hits(&h.cp).await, 0, "no material fetch");
        assert_eq!(Harness::hits(&h.upstream).await, 0, "no upstream call");
        assert!(h.audit.events().is_empty());
    }

    async fn get_grants(h: &Harness, token: Option<&str>) -> (StatusCode, Vec<u8>) {
        let mut req = Request::get("/v1/grants");
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let resp = h
            .app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, body.to_vec())
    }

    /// `GET /v1/grants`: the calling agent's unexpired grants with the origin each may be sent
    /// to; names, ids, modes and origins only.
    #[tokio::test]
    async fn grants_lists_the_calling_agents_grants() {
        let h = harness(Setup::default()).await;
        let now = time::OffsetDateTime::now_utc();
        let later = now + time::Duration::hours(1);
        h.grants.set(
            AGENT,
            vec![
                grant(SECRET, "UPSTREAM_KEY", Some(later)),
                grant(UNBOUND, "NOT_HERE", None),
                // Expired since the control plane answered: filtered by the gateway too.
                grant(DEAD, "OLD", Some(now - time::Duration::seconds(1))),
            ],
        );
        h.grants
            .set(Uuid::now_v7(), vec![grant(INTERNAL, "OTHER_AGENT", None)]);

        let (status, body) = get_grants(&h, Some(h.token.as_str())).await;
        assert_eq!(status, StatusCode::OK);
        let list: GrantList = serde_json::from_slice(&body).unwrap();
        assert_eq!(list.agent_id, AGENT);
        let later = time::OffsetDateTime::from_unix_timestamp(later.unix_timestamp()).unwrap();
        assert_eq!(
            list.grants,
            vec![
                GrantView {
                    secret_id: SECRET,
                    secret_name: "UPSTREAM_KEY".to_owned(),
                    mode: "relay".to_owned(),
                    expires_at: list.grants[0].expires_at,
                    allowed_origin: Some(h.origin()),
                },
                GrantView {
                    secret_id: UNBOUND,
                    secret_name: "NOT_HERE".to_owned(),
                    mode: "relay".to_owned(),
                    expires_at: None,
                    allowed_origin: None,
                },
            ]
        );
        assert_eq!(
            list.grants[0].expires_at.map(|t| t.unix_timestamp()),
            Some(later.unix_timestamp())
        );
        // Only the documented fields: nothing that could carry a value.
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mut keys: Vec<&str> = v["grants"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "allowed_origin",
                "expires_at",
                "mode",
                "secret_id",
                "secret_name"
            ]
        );
        assert_clean("grants response", &body);
        assert_eq!(h.kms_calls().await, 0, "listing grants decrypts nothing");
        assert_eq!(Harness::hits(&h.cp).await, 0, "no material fetch");
    }

    #[tokio::test]
    async fn grants_requires_a_valid_agent_token() {
        let h = harness(Setup::default()).await;
        let expired = h.signer.sign(&agent_claims(ORG, AUDIENCE, -120)).unwrap();
        let wrong_aud = h
            .signer
            .sign(&agent_claims(ORG, "control-plane", 600))
            .unwrap();
        for token in [
            None,
            Some("x"),
            Some(expired.as_str()),
            Some(wrong_aud.as_str()),
        ] {
            let (status, _) = get_grants(&h, token).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        assert_eq!(h.grants.calls(), 0, "no grant lookup before authentication");
    }

    #[tokio::test]
    async fn grants_unavailable_is_a_fixed_502() {
        let h = harness(Setup::default()).await;
        let failing = StubGrants {
            fail: true,
            ..StubGrants::default()
        };
        let relay = Relay::new(
            Arc::new(AgentAuth::new(
                ORG,
                Arc::new(StubJwks::with(vec![h.signer.jwk().clone()])),
                JwksSettings::default(),
            )),
            Arc::new(failing),
            Bindings {
                org_id: ORG,
                bindings: Vec::new(),
                git_bindings: Vec::new(),
            },
            Decryptor::new(
                ORG,
                Arc::new(
                    ControlPlane::new(h.cp.uri().parse().unwrap(), ORG, "s".repeat(32).into())
                        .unwrap(),
                ),
                Arc::new(
                    OpenBaoTransit::new(&h.bao.uri(), key(), BaoToken::new("bao".to_owned()))
                        .unwrap(),
                ),
                Arc::new(DekCache::new(CacheSettings::default())),
            ),
            h.resolver.clone(),
            h.audit.clone(),
            RelayOptions::default(),
        );
        let app =
            app::build(AppState::new(Arc::new(ReadyFlag::new(true))).with_relay(Arc::new(relay)));
        let resp = app
            .clone()
            .oneshot(
                Request::get("/v1/grants")
                    .header("authorization", format!("Bearer {}", h.token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("grants_unavailable"));

        // `/v1/relay` fails closed: no fetch, no unwrap, audited with the agent.
        let resp = app
            .oneshot(
                Request::post("/v1/relay")
                    .header("authorization", format!("Bearer {}", h.token))
                    .body(Body::from(
                        serde_json::json!({
                            "secret_id": SECRET, "version": 1, "method": "GET",
                            "url": format!("{}/x", h.origin())
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("grants_unavailable"));
        assert_eq!(h.kms_calls().await, 0);
        assert_eq!(Harness::hits(&h.cp).await, 0);
        let ev = h.audit.events();
        assert_eq!(
            ev.iter().map(|e| (e.kind, e.agent_id)).collect::<Vec<_>>(),
            [(EventKind::Denied(Outcome::GrantsUnavailable), AGENT)]
        );
        assert!(ev[0].host.is_none());
    }

    /// Spec "No grant" / "Caller without a grant": `403`, no material fetch, no KMS decrypt, no
    /// DNS, no upstream call; the denial is audited with the agent id.
    #[tokio::test]
    async fn no_grant_makes_no_decrypt_call() {
        let h = harness(Setup::default()).await;
        // A grant for another secret, and one for this secret held by another agent.
        h.grants.set(AGENT, vec![grant(DEAD, "OTHER_SECRET", None)]);
        h.grants
            .set(Uuid::now_v7(), vec![grant(SECRET, "NOT_YOURS", None)]);
        let (status, raw) = h.relay_get(SECRET, &format!("{}/x", h.origin())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&raw).contains("\"no_grant\""));
        assert_clean("no-grant response", &raw);

        assert_eq!(h.kms_calls().await, 0, "no KMS decrypt call");
        assert_eq!(Harness::hits(&h.cp).await, 0, "no material fetch");
        assert_eq!(Harness::hits(&h.upstream).await, 0, "no upstream call");
        assert!(h.resolver.lookups.lock().unwrap().is_empty(), "no DNS");
        let ev = h.audit.events();
        assert_eq!(ev.len(), 1, "the denial is audited, no attempt");
        let e = &ev[0];
        assert_eq!(
            (e.kind, e.agent_id, e.secret_id, e.status, e.host.as_deref()),
            (
                EventKind::Denied(Outcome::NoGrant),
                AGENT,
                SECRET,
                None,
                None
            )
        );
        h.assert_audit_clean();
    }

    /// An expired grant is refused before unwrap, including one that expires while its set is
    /// still cached (the expiry is re-checked on every call).
    #[tokio::test]
    async fn expired_grant_is_refused_before_unwrap() {
        let h = harness(Setup::default()).await;
        let now = time::OffsetDateTime::now_utc();
        h.grants.set(
            AGENT,
            vec![grant(SECRET, "OLD", Some(now - time::Duration::seconds(1)))],
        );
        let (status, raw) = h.relay_get(SECRET, &format!("{}/x", h.origin())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&raw).contains("\"no_grant\""));
        assert_eq!(h.kms_calls().await, 0, "no KMS decrypt call");
        assert_eq!(Harness::hits(&h.cp).await, 0, "no material fetch");
        assert_eq!(h.outcomes(), ["no_grant"]);

        // Expires 1 s from now; the 10 s cache keeps serving the set, the expiry still bites.
        let h = harness(Setup::default()).await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("fine"))
            .mount(&h.upstream)
            .await;
        let soon = time::OffsetDateTime::now_utc() + time::Duration::milliseconds(1500);
        h.grants.set(AGENT, vec![grant(SECRET, "SOON", Some(soon))]);
        let (status, _) = h.relay_get(SECRET, &format!("{}/x", h.origin())).await;
        assert_eq!(status, StatusCode::OK);
        let kms_before = h.kms_calls().await;
        let wait = soon - time::OffsetDateTime::now_utc() + time::Duration::milliseconds(100);
        tokio::time::sleep(wait.try_into().unwrap_or(Duration::ZERO)).await;
        let (status, raw) = h.relay_get(SECRET, &format!("{}/x", h.origin())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_clean("expired-grant response", &raw);
        assert_eq!(h.grants.calls(), 1, "served from the cache");
        assert_eq!(h.kms_calls().await, kms_before, "no further KMS call");
        assert_eq!(
            Harness::hits(&h.upstream).await,
            1,
            "no second upstream call"
        );
        assert_eq!(h.outcomes(), ["ok", "no_grant"]);
        assert!(h.audit.events().iter().all(|e| e.agent_id == AGENT));
    }

    /// A revoked grant stops working once the cached set is older than the cache TTL, even with
    /// the data key still cached.
    #[tokio::test]
    async fn revoked_grant_stops_within_the_cache_ttl() {
        let ttl = Duration::from_millis(400);
        let h = harness(Setup {
            grant_ttl: ttl,
            ..Setup::default()
        })
        .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("fine"))
            .mount(&h.upstream)
            .await;
        let (status, _) = h.relay_get(SECRET, &format!("{}/x", h.origin())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h.grants.calls(), 1);
        let kms_before = h.kms_calls().await;
        let cp_before = Harness::hits(&h.cp).await;

        // Revoked in the control plane.
        h.grants.set(AGENT, Vec::new());
        tokio::time::sleep(ttl + Duration::from_millis(50)).await;
        let (status, raw) = h.relay_get(SECRET, &format!("{}/x", h.origin())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&raw).contains("\"no_grant\""));
        assert_eq!(h.grants.calls(), 2, "re-read after the TTL");
        assert_eq!(h.kms_calls().await, kms_before, "no KMS call");
        assert_eq!(Harness::hits(&h.cp).await, cp_before, "no material fetch");
        assert_eq!(
            Harness::hits(&h.upstream).await,
            1,
            "no second upstream call"
        );
        assert_eq!(h.outcomes(), ["ok", "no_grant"]);
        assert!(h.audit.events().iter().all(|e| e.agent_id == AGENT));
        h.assert_audit_clean();
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
            let (status, _) = h.call(Some(h.token.as_str()), bad).await;
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
        assert!(h.closing().iter().all(|(_, e)| e.status == Some(200)));
        h.assert_audit_clean();
        // The relay asked for an unencoded response.
        let reqs = h.upstream.received_requests().await.unwrap();
        assert!(reqs.iter().all(|r| {
            r.headers
                .get("accept-encoding")
                .is_some_and(|v| v == "identity")
        }));
    }

    /// A raw HTTP/1.1 upstream on `port` (wiremock's hyper would rewrite `Transfer-Encoding`):
    /// each connection gets `head` (status line and headers, no blank line) and `body`, chunked.
    fn raw_upstream(port: u16, head: &'static str, body: Vec<u8>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let mut out = format!("{head}\r\nconnection: close\r\n\r\n").into_bytes();
                out.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
                out.extend_from_slice(&body);
                out.extend_from_slice(b"\r\n0\r\n\r\n");
                let _ = stream.write_all(&out);
            }
        });
    }

    /// Adversarial case G2: a `Transfer-Encoding` coding other than `chunked` (here with no
    /// `Content-Encoding`) is withheld as `redaction_failed`, in any case, list or header split.
    #[tokio::test]
    async fn non_chunked_transfer_codings_are_withheld() {
        for head in [
            "HTTP/1.1 200 OK\r\ntransfer-encoding: gzip, chunked",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: GZip ,Chunked",
            "HTTP/1.1 200 OK\r\ntransfer-encoding: gzip\r\ntransfer-encoding: chunked",
        ] {
            let h = harness(Setup::default()).await;
            raw_upstream(h.dead_port, head, VALUE.to_vec());
            let (status, raw) = h.relay_get(DEAD, &format!("{}/x", h.dead_origin())).await;
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{head:?}");
            assert!(String::from_utf8_lossy(&raw).contains("response_withheld"));
            assert_clean("withheld response", &raw);
            assert_eq!(h.outcomes(), ["redaction_failed"], "{head:?}");
            assert!(h.closing().iter().all(|(_, e)| e.status == Some(200)));
            h.assert_audit_clean();
        }
    }

    /// A plain `Transfer-Encoding: chunked` response still relays, redacted, without the header.
    #[tokio::test]
    async fn chunked_transfer_encoding_still_relays() {
        let h = harness(Setup::default()).await;
        raw_upstream(
            h.dead_port,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\ncontent-type: text/plain",
            [b"hello ", VALUE, b" bye"].concat(),
        );
        let (status, raw) = h.relay_get(DEAD, &format!("{}/x", h.dead_origin())).await;
        assert_eq!(status, StatusCode::OK);
        assert_clean("chunked response", &raw);
        let env = envelope(&raw);
        assert_eq!(env.status, 200);
        let body = env.body.expect("text body");
        assert!(
            body.starts_with("hello ") && body.ends_with(" bye"),
            "body relayed"
        );
        assert!(body.contains("[REDACTED:SECRET]"));
        assert!(
            env.headers
                .iter()
                .all(|(n, _)| !n.eq_ignore_ascii_case("transfer-encoding")),
            "hop-by-hop header dropped"
        );
        assert_eq!(h.outcomes(), ["ok"]);
        h.assert_audit_clean();
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
                Some(h.token.as_str()),
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

    /// Spec "Ledger unavailable": the attempt cannot be appended, so the call is refused with
    /// `503` before any material fetch, unwrap or upstream call. A refusal is still a refusal.
    #[tokio::test]
    async fn attempt_append_failure_is_503_before_unwrap() {
        for setup in [
            Setup {
                attempt_fails: true,
                ..Setup::default()
            },
            Setup {
                audit_fails: true,
                ..Setup::default()
            },
        ] {
            let h = harness(setup).await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_string("fine"))
                .mount(&h.upstream)
                .await;
            let (status, raw) = h.relay_get(SECRET, &format!("{}/x", h.origin())).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(String::from_utf8_lossy(&raw).contains("\"audit_unavailable\""));
            assert_eq!(h.kms_calls().await, 0, "no KMS decrypt call");
            assert_eq!(Harness::hits(&h.cp).await, 0, "no material fetch");
            assert_eq!(Harness::hits(&h.upstream).await, 0, "no upstream call");
            assert!(
                h.audit
                    .events()
                    .iter()
                    .all(|e| e.kind != EventKind::Attempt)
            );
            let (status, _) = h.relay_get(SECRET, "http://evil.test/x").await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
    }

    /// The outcome is retried (3 times) and lands once; past the retries a successful response
    /// is withheld and the attempt stays open in the ledger.
    #[tokio::test]
    async fn outcome_append_is_retried_then_withholds() {
        let h = harness(Setup {
            outcome_fails_first: 3,
            ..Setup::default()
        })
        .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("fine"))
            .mount(&h.upstream)
            .await;
        let (status, _) = h.relay_get(SECRET, &format!("{}/x", h.origin())).await;
        assert_eq!(status, StatusCode::OK, "third retry succeeds");
        assert_eq!(
            h.audit.tries(),
            1 + 4,
            "attempt, then outcome tried 4 times"
        );
        assert_eq!(h.outcomes(), ["ok"]);
        h.assert_audit_clean();

        let h = harness(Setup {
            outcome_fails_first: 4,
            ..Setup::default()
        })
        .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("fine"))
            .mount(&h.upstream)
            .await;
        let (status, raw) = h.relay_get(SECRET, &format!("{}/x", h.origin())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(String::from_utf8_lossy(&raw).contains("audit_failed"));
        assert!(!String::from_utf8_lossy(&raw).contains("fine"));
        assert_eq!(h.audit.tries(), 1 + 4, "no fifth outcome try");
        assert_eq!(
            h.audit.events().iter().map(|e| e.kind).collect::<Vec<_>>(),
            [EventKind::Attempt],
            "the attempt stays open"
        );
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
                Some(h.token.as_str()),
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
        let no_grant = harness(Setup::default()).await;
        no_grant.grants.set(AGENT, Vec::new());
        no_grant
            .relay_get(SECRET, &format!("{}/x", no_grant.origin()))
            .await;
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

    // S5 task 3.2: the relay against the real control plane and its Postgres ledger.

    /// Test-only service token shared by the gateway and the in-process control plane.
    const SERVICE_TOKEN: &str = "test-only-gateway-service-token-0123456789";

    /// A migrated `postgres:18` (ls-pg-test; needs Docker) with [`ORG`] created, and the control
    /// plane serving it on a local port with [`SERVICE_TOKEN`].
    struct Ledger {
        pg: ls_pg_test::Pg,
        db: Database,
        url: Url,
        server: tokio::task::JoinHandle<()>,
    }

    impl Ledger {
        async fn start() -> Self {
            let pg = ls_pg_test::Pg::start().await;
            ls_control_plane::migrate::run(pg.bootstrap())
                .await
                .expect("migrate");
            let mut admin = pg.admin().await;
            sql::query("INSERT INTO orgs (id, name) VALUES ($1, 'ledger-org')")
                .bind(ORG)
                .execute(&mut admin)
                .await
                .unwrap();
            let db = Database::connect_lazy(pg.app(), PoolSettings::default());
            let state = ls_control_plane::app::AppState::new(
                false,
                Arc::new(ReadyFlag::new(true)),
                db.clone(),
            )
            .with_service_token(ServiceToken::new(SecretString::from(SERVICE_TOKEN)));
            let app = ls_control_plane::app::build(state);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/", listener.local_addr().unwrap())
                .parse()
                .unwrap();
            let server = tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            Self {
                pg,
                db,
                url,
                server,
            }
        }

        fn sink(&self) -> Arc<dyn AuditSink> {
            http_sink(self.url.clone())
        }

        /// [`ORG`]'s ledger as the app role (RLS applies).
        async fn records(&self) -> Vec<ls_audit::Record> {
            self.db
                .with_org(ORG, |c| {
                    Box::pin(async move { ls_audit::pg::records_in_tx(c, ORG).await })
                })
                .await
                .unwrap()
        }

        /// `gateway_audit` rows in every org, as the bootstrap superuser (no RLS).
        async fn legacy_rows(&self) -> i64 {
            let mut admin = self.pg.admin().await;
            sql::query_scalar("SELECT count(*) FROM gateway_audit")
                .fetch_one(&mut admin)
                .await
                .unwrap()
        }

        /// Every stored ledger row as text, as the bootstrap superuser.
        async fn ledger_text(&self) -> String {
            let mut admin = self.pg.admin().await;
            let text: Option<String> =
                sql::query_scalar("SELECT string_agg(t::text, E'\\n') FROM audit_events t")
                    .fetch_one(&mut admin)
                    .await
                    .unwrap();
            text.unwrap_or_default()
        }
    }

    impl Drop for Ledger {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    fn http_sink(base: Url) -> Arc<dyn AuditSink> {
        Arc::new(HttpAudit::new(Arc::new(
            ControlPlane::new(base, ORG, SERVICE_TOKEN.to_owned().into()).unwrap(),
        )))
    }

    fn attr<'a>(r: &'a ls_audit::Record, key: &str) -> Option<&'a str> {
        r.attrs
            .as_ref()?
            .entries()
            .iter()
            .find(|(k, _, _)| k == key)
            .map(|(_, _, v)| v.as_str())
    }

    /// Spec "Audit events per call": an allowed call appends `relay.attempt` and
    /// `relay.outcome` (`ok`), a refused call appends `relay.denied`, the chain is intact,
    /// `gateway_audit` gains no rows and no event holds the canary.
    #[tokio::test]
    async fn relay_events_land_in_the_ledger() {
        let l = Ledger::start().await;
        let h = harness(Setup {
            audit: Some(l.sink()),
            ..Setup::default()
        })
        .await;
        Mock::given(method("GET"))
            .and(path("/v1/charge"))
            .respond_with(ResponseTemplate::new(200).set_body_string(injected()))
            .mount(&h.upstream)
            .await;
        let (status, raw) = h
            .relay_get(SECRET, &format!("{}/v1/charge?q=1", h.origin()))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_clean("allowed response", &raw);
        let evil = format!("http://{}.evil.test/x", hex(VALUE));
        let (status, _) = h.relay_get(SECRET, &evil).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let rows = l.records().await;
        let got: Vec<(&str, &str)> = rows
            .iter()
            .map(|r| (r.kind.as_str(), r.outcome.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("relay.attempt", "pending"),
                ("relay.outcome", "ok"),
                ("relay.denied", "denied"),
            ]
        );
        for r in &rows {
            assert_eq!(r.actor, format!("agent:{AGENT}"));
            assert_eq!(r.target.as_deref(), Some(&*format!("secret:{SECRET}")));
            assert_eq!(attr(r, "version"), Some("1"));
            assert_eq!(attr(r, "method"), Some("get"));
        }
        let port = h.upstream.address().port().to_string();
        assert_eq!(attr(&rows[0], "host"), Some("upstream.test"));
        assert_eq!(attr(&rows[0], "port"), Some(port.as_str()));
        assert_eq!(attr(&rows[1], "status"), Some("200"));
        let attempt_id = rows[0].id.to_string();
        assert_eq!(attr(&rows[1], "attempt_id"), Some(attempt_id.as_str()));
        assert_eq!(
            attr(&rows[2], "host"),
            None,
            "a refused host is not recorded"
        );
        let walk = ls_audit::verify(rows.iter().map(ls_audit::Record::link), &[]);
        assert!(walk.ok(), "{walk:?}");

        assert_eq!(l.legacy_rows().await, 0, "no legacy rows");
        let text = l.ledger_text().await;
        assert!(
            !text.contains("evil"),
            "no caller-chosen host in the ledger"
        );
        assert_clean("ledger", text.as_bytes());
    }

    /// Spec "Ledger unavailable": the append endpoint is unreachable or answers `5xx`, so the
    /// relay is `503` with no KMS decrypt call, no material fetch and no upstream request.
    #[tokio::test]
    async fn unreachable_ledger_is_503_before_unwrap() {
        let failing = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&failing)
            .await;
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}/", l.local_addr().unwrap())
        };
        for base in [dead, failing.uri()] {
            let h = harness(Setup {
                audit: Some(http_sink(base.parse().unwrap())),
                ..Setup::default()
            })
            .await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_string("fine"))
                .mount(&h.upstream)
                .await;
            let (status, raw) = h.relay_get(SECRET, &format!("{}/x", h.origin())).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{base}");
            assert!(String::from_utf8_lossy(&raw).contains("\"audit_unavailable\""));
            assert_clean("503 response", &raw);
            assert_eq!(h.kms_calls().await, 0, "no KMS decrypt call");
            assert_eq!(Harness::hits(&h.cp).await, 0, "no material fetch");
            assert_eq!(Harness::hits(&h.upstream).await, 0, "no upstream request");
        }
        assert_eq!(
            Harness::hits(&failing).await,
            1,
            "the attempt is tried once, not retried"
        );
    }

    /// The outcome is idempotent on its attempt id through the real endpoint: a resend returns
    /// the stored event, a different outcome for the same attempt is refused, an outcome
    /// without an attempt id is refused.
    #[tokio::test]
    async fn outcome_resend_is_idempotent() {
        let l = Ledger::start().await;
        let sink = l.sink();
        let base = RelayEvent {
            kind: EventKind::Attempt,
            agent_id: AGENT,
            secret_id: SECRET,
            version: 1,
            method: Some(Method::Get),
            host: Some("upstream.test".to_owned()),
            port: None,
            status: None,
            attempt_id: None,
            issued: None,
        };
        let attempt = sink.append(base.clone()).await.unwrap();
        let outcome = RelayEvent {
            kind: EventKind::Outcome(Outcome::Ok),
            status: Some(200),
            attempt_id: Some(attempt),
            ..base.clone()
        };
        let first = sink.append(outcome.clone()).await.unwrap();
        let again = sink.append(outcome.clone()).await.unwrap();
        assert_eq!(first, again, "a resend returns the stored outcome");
        let other = RelayEvent {
            status: Some(500),
            ..outcome.clone()
        };
        assert_eq!(
            sink.append(other).await,
            Err(crate::audit::AuditError::Rejected)
        );
        let unkeyed = RelayEvent {
            attempt_id: None,
            ..outcome
        };
        assert_eq!(
            sink.append(unkeyed).await,
            Err(crate::audit::AuditError::Rejected)
        );
        assert_eq!(l.records().await.len(), 2, "one attempt, one outcome");
    }
}
