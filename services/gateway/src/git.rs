//! Git delegation over HTTPS (D1): the binding shape that says which repositories a secret may
//! be used for through `/git/{host}/{owner}/{repo}/...`, and the smart-HTTP path allow-list.
//!
//! This module holds the contract (D1 task 1.1): [`GitBinding`], [`GitService`] and the pure path
//! check [`GitBinding::authorize`]. It never touches a credential value.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use ls_proxy::github::{Credential, TokenCache, parse_credential, pat_header, upstream_token};
use ls_redact::{MIN_ENCODED_LEN, Redactor, Secret};
use reqwest::header::{HeaderName, HeaderValue};
use serde::Deserialize;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::{EventKind, Method as AuditMethod, Outcome, RelayEvent};
use crate::config::Binding;
use crate::decrypt::{DecryptError, MaterialError};
use crate::egress::{self, EgressError};
use crate::grants::allows_relay;
use crate::relay::{Relay, error};

/// What a Git operation does to the repository; a grant for one does not allow the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitService {
    /// `git-upload-pack`: clone and fetch.
    Fetch,
    /// `git-receive-pack`: push.
    Push,
}

impl GitService {
    /// The ledger event name for a completed operation.
    pub fn event(self) -> &'static str {
        match self {
            GitService::Fetch => "git.fetch",
            GitService::Push => "git.push",
        }
    }

    /// The smart-HTTP service path segment.
    fn path(self) -> &'static str {
        match self {
            GitService::Fetch => "git-upload-pack",
            GitService::Push => "git-receive-pack",
        }
    }

    /// The `info/refs` query for this service.
    fn query(self) -> &'static str {
        match self {
            GitService::Fetch => "service=git-upload-pack",
            GitService::Push => "service=git-receive-pack",
        }
    }
}

/// One allowed Git use of a secret: the host, the repositories under a prefix, the services.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitBinding {
    pub secret_id: Uuid,
    /// Exact host, lowercase, no scheme, port or path (for example `github.com`).
    pub host: String,
    /// `owner` (every repository of the owner) or `owner/repo` (exactly that repository).
    pub repo_prefix: String,
    /// Allowed services; empty is rejected by validation.
    pub services: Vec<GitService>,
    /// Permit the host to resolve to a private or loopback address (the local test fixture).
    #[serde(default)]
    pub allow_private_hosts: bool,
    /// Secret version injected (Git requests carry none). Default 1.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Upstream port; the scheme's default when unset. For a local fixture or a GHES port.
    #[serde(default)]
    pub port: Option<u16>,
    /// Call the upstream over plain `http` (only with `allow_private_hosts`: the test fixture).
    #[serde(default)]
    pub plain_http: bool,
}

fn default_version() -> u32 {
    1
}

/// Why a Git request is not allowed. Carries no request data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitDenied {
    /// Not one of the three smart-HTTP paths.
    PathNotAllowed,
    /// Host or repository is outside the binding.
    NotBound,
    /// The binding does not allow this service.
    ServiceNotAllowed,
}

/// A request that passed [`GitBinding::authorize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitTarget {
    pub owner: String,
    pub repo: String,
    pub service: GitService,
    /// `info/refs` advertisement (GET) rather than the service call (POST).
    pub advertisement: bool,
}

fn valid_segment(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

impl GitBinding {
    /// Field name of the first invalid field, for the config error.
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        let host_ok = !self.host.is_empty()
            && self.host == self.host.to_ascii_lowercase()
            && self
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'));
        if !host_ok {
            return Err("host");
        }
        let mut parts = self.repo_prefix.split('/');
        let (owner, repo) = (parts.next(), parts.next());
        let shape_ok = owner.is_some_and(valid_segment)
            && repo.is_none_or(valid_segment)
            && parts.next().is_none();
        if !shape_ok {
            return Err("repo_prefix");
        }
        if self.services.is_empty() {
            return Err("services");
        }
        if self.version == 0 {
            return Err("version");
        }
        if self.port == Some(0) || (self.plain_http && !self.allow_private_hosts) {
            return Err("port");
        }
        Ok(())
    }

    /// `scheme://host[:port]`, the origin the egress check pins the credential to.
    fn origin(&self) -> String {
        let scheme = if self.plain_http { "http" } else { "https" };
        match self.port {
            Some(p) => format!("{scheme}://{}:{p}", self.host),
            None => format!("{scheme}://{}", self.host),
        }
    }

    fn covers(&self, owner: &str, repo: &str) -> bool {
        match self.repo_prefix.split_once('/') {
            Some((o, r)) => o.eq_ignore_ascii_case(owner) && r.eq_ignore_ascii_case(repo),
            None => self.repo_prefix.eq_ignore_ascii_case(owner),
        }
    }

    /// Check a request before any credential is read. `path` is what follows
    /// `/git/{host}/` (`owner/repo[.git]/info/refs`, `.../git-upload-pack`,
    /// `.../git-receive-pack`), `query` the raw query string, `post` the method.
    pub fn authorize(
        &self,
        host: &str,
        path: &str,
        query: Option<&str>,
        post: bool,
    ) -> Result<GitTarget, GitDenied> {
        let segs: Vec<&str> = path.split('/').collect();
        let (owner, repo_raw, tail) = match segs.as_slice() {
            [o, r, rest @ ..] if !rest.is_empty() => (*o, *r, rest.join("/")),
            _ => return Err(GitDenied::PathNotAllowed),
        };
        let (service, advertisement) = match (tail.as_str(), post, query) {
            ("info/refs", false, Some("service=git-upload-pack")) => (GitService::Fetch, true),
            ("info/refs", false, Some("service=git-receive-pack")) => (GitService::Push, true),
            ("git-upload-pack", true, None) => (GitService::Fetch, false),
            ("git-receive-pack", true, None) => (GitService::Push, false),
            _ => return Err(GitDenied::PathNotAllowed),
        };
        let repo = repo_raw.strip_suffix(".git").unwrap_or(repo_raw);
        if !valid_segment(owner) || !valid_segment(repo) {
            return Err(GitDenied::PathNotAllowed);
        }
        if !host.eq_ignore_ascii_case(&self.host) || !self.covers(owner, repo) {
            return Err(GitDenied::NotBound);
        }
        if !self.services.contains(&service) {
            return Err(GitDenied::ServiceNotAllowed);
        }
        Ok(GitTarget {
            owner: owner.to_owned(),
            repo: repo.to_owned(),
            service,
            advertisement,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// The route (D1 task 2): authorize, egress-check, only then decrypt, then stream.
// ---------------------------------------------------------------------------------------------

/// Timeouts for the streamed upstream call.
#[derive(Debug, Clone, Copy)]
pub struct GitOptions {
    pub connect_timeout: Duration,
    /// Whole exchange, including the streamed bodies.
    pub total_timeout: Duration,
    /// Longest wait for the next chunk from the upstream.
    pub idle_timeout: Duration,
}

impl Default for GitOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(30 * 60),
            idle_timeout: Duration::from_secs(60),
        }
    }
}

/// Git-specific gateway state: timeouts and the GitHub App installation-token cache
/// (`ls-proxy::github`).
pub struct GitState {
    options: GitOptions,
    tokens: TokenCache,
    /// App credentials are used for `github.com` only, unless the API base is overridden (tests).
    apps_any_host: bool,
}

impl Default for GitState {
    fn default() -> Self {
        Self {
            options: GitOptions::default(),
            tokens: TokenCache::new("https://api.github.com"),
            apps_any_host: false,
        }
    }
}

impl GitState {
    pub fn with_options(mut self, options: GitOptions) -> Self {
        self.options = options;
        self
    }

    /// Mint installation tokens at `api_base` and allow App credentials for any bound host
    /// (a GitHub Enterprise API or the local test fixture).
    pub fn with_api_base(mut self, api_base: &str) -> Self {
        self.tokens = TokenCache::new(api_base);
        self.apps_any_host = true;
        self
    }
}

/// Request headers passed upstream. Everything else, `Authorization` above all (it holds the
/// agent token), is dropped.
const FORWARD_REQUEST_HEADERS: &[&str] = &[
    "content-type",
    "content-encoding",
    "accept",
    "git-protocol",
    "user-agent",
];

/// Response headers passed back.
const FORWARD_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "cache-control",
    "expires",
    "pragma",
    "content-encoding",
];

/// Pick the binding that allows this request among those the agent holds a grant for. When none
/// does, the most specific reason (service, then repository, then path) and the secret to name in
/// the denial event: the binding that refused the service, else the first the agent may use
/// (`None` when it holds no Git grant at all, so there is no secret to name).
fn select<'a>(
    bindings: &'a [GitBinding],
    granted: impl Fn(Uuid) -> bool,
    host: &str,
    path: &str,
    query: Option<&str>,
    post: bool,
) -> Result<(&'a GitBinding, GitTarget), (GitDenied, Option<Uuid>)> {
    let mut reason = GitDenied::NotBound;
    let mut path_denied = false;
    let (mut first, mut service_denied) = (None, None);
    for b in bindings.iter().filter(|b| granted(b.secret_id)) {
        first.get_or_insert(b.secret_id);
        match b.authorize(host, path, query, post) {
            Ok(t) => return Ok((b, t)),
            Err(GitDenied::PathNotAllowed) => path_denied = true,
            Err(GitDenied::ServiceNotAllowed) => {
                reason = GitDenied::ServiceNotAllowed;
                service_denied.get_or_insert(b.secret_id);
            }
            Err(GitDenied::NotBound) => {}
        }
    }
    if path_denied && reason == GitDenied::NotBound {
        reason = GitDenied::PathNotAllowed;
    }
    Err((reason, service_denied.or(first)))
}

/// Largest buffered upstream body (an error page, or any response that is not a Git stream). A
/// larger one is withheld rather than relayed unscanned.
pub(crate) const MAX_SCANNED_BODY: usize = 64 * 1024;

/// A `2xx` Git smart-HTTP stream (`application/x-git-*`): pack data and pkt-lines, relayed raw.
/// Rewriting it would break the pkt-line lengths and corrupt packs, so only the headers are
/// scanned; the upstream is the host the owner bound the credential to.
fn is_git_stream(status: StatusCode, headers: &reqwest::header::HeaderMap) -> bool {
    status.is_success()
        && headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.trim_start()
                    .to_ascii_lowercase()
                    .starts_with("application/x-git-")
            })
}

/// Every form of the upstream credential the redactor knows: the token and the
/// `Basic base64("x-access-token:" + token)` header form. `None` when the token is too short
/// for its encoded forms to be matched (an echo could not be caught: fail closed).
fn redactor_for(token: &str) -> Option<Redactor> {
    if token.len() < MIN_ENCODED_LEN {
        return None;
    }
    let mut secret = Secret::new("SECRET", token.as_bytes());
    secret.basic_auth_user = Some("x-access-token".to_owned());
    Some(Redactor::new(&[secret]))
}

/// Allow-listed upstream headers with the credential redacted, or `None` when a value still
/// matches afterwards (withhold the response).
fn scan_headers(
    redactor: &Redactor,
    headers: &reqwest::header::HeaderMap,
) -> Option<Vec<(&'static str, HeaderValue)>> {
    let mut out = Vec::new();
    for name in FORWARD_RESPONSE_HEADERS {
        for v in headers.get_all(*name) {
            let clean = redactor.redact_all(v.as_bytes());
            if !redactor.find(&clean).is_empty() {
                return None;
            }
            out.push((*name, HeaderValue::from_bytes(&clean).ok()?));
        }
    }
    Some(out)
}

/// Read an upstream body (at most [`MAX_SCANNED_BODY`]), redact it and re-check. `None` withholds.
async fn scan_body(mut resp: reqwest::Response, redactor: &Redactor) -> Option<Vec<u8>> {
    let encoded = resp
        .headers()
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));
    if encoded {
        return None;
    }
    let mut raw = Zeroizing::new(Vec::new());
    while let Ok(Some(chunk)) = resp.chunk().await {
        if raw.len() + chunk.len() > MAX_SCANNED_BODY {
            return None;
        }
        raw.extend_from_slice(&chunk);
    }
    // A failed read ends the loop early; the redacted partial body is still safe, but a
    // truncated error page helps nobody, so only a clean end is relayed.
    let clean = redactor.redact_all(&raw);
    redactor.find(&clean).is_empty().then_some(clean)
}

/// What goes back to the agent: a Git stream as it comes, or a scanned, redacted body.
enum Payload {
    Stream(reqwest::Response),
    Text(Vec<u8>),
}

/// One Git ledger event: ids, the bound host and closed codes only.
fn git_event(
    kind: EventKind,
    agent_id: Uuid,
    binding: &GitBinding,
    post: bool,
    status: Option<u16>,
) -> RelayEvent {
    RelayEvent {
        kind,
        agent_id,
        secret_id: binding.secret_id,
        version: binding.version,
        method: Some(if post {
            AuditMethod::Post
        } else {
            AuditMethod::Get
        }),
        host: Some(binding.host.clone()),
        port: binding.port,
        status,
        attempt_id: None,
        issued: None,
        connection: None,
    }
}

/// Record a refusal as `git.denied` (one try: the call is refused either way).
async fn deny(relay: &Relay, agent_id: Uuid, binding: &GitBinding, post: bool, why: Outcome) {
    let ev = git_event(EventKind::GitDenied(why), agent_id, binding, post, None);
    if relay.audit().append(ev).await.is_err() {
        tracing::error!("git denied event not appended");
    }
}

/// An admitted Git call: records its final outcome as `git.fetch` or `git.push`.
struct Call<'a> {
    relay: &'a Relay,
    agent_id: Uuid,
    binding: &'a GitBinding,
    service: GitService,
    post: bool,
}

impl Call<'_> {
    /// Record the call's final outcome, retried like a relay outcome. `false` when the ledger
    /// did not take it.
    async fn record(&self, outcome: Outcome, status: Option<u16>) -> bool {
        let kind = match self.service {
            GitService::Fetch => EventKind::GitFetch(outcome),
            GitService::Push => EventKind::GitPush(outcome),
        };
        let ev = git_event(kind, self.agent_id, self.binding, self.post, status);
        let ok = crate::relay::append_outcome(self.relay, ev).await;
        if !ok {
            tracing::error!(git.service = self.service.event(), "git event not appended");
        }
        ok
    }

    async fn deny(&self, why: Outcome) {
        deny(self.relay, self.agent_id, self.binding, self.post, why).await;
    }

    /// Record a failure and answer with its fixed error.
    async fn failed(
        &self,
        outcome: Outcome,
        status: StatusCode,
        slug: &'static str,
        request_id: &str,
    ) -> Response {
        self.record(outcome, None).await;
        fail(status, slug, request_id)
    }
}

/// Git sends the agent token as the Basic password (the credential helper's answer); accept
/// that and a plain Bearer header.
fn agent_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = headers.clone();
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
        .and_then(|(_, b64)| {
            base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .ok()
        })
        .and_then(|raw| String::from_utf8(raw).ok())
        .and_then(|up| up.split_once(':').map(|(_, pw)| pw.to_owned()));
    if let Some(token) = basic
        && let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}"))
    {
        out.insert(header::AUTHORIZATION, v);
    }
    out
}

fn fail(status: StatusCode, slug: &'static str, request_id: &str) -> Response {
    error(status, slug, request_id)
}

fn challenge(request_id: &str) -> Response {
    let mut r = error(StatusCode::UNAUTHORIZED, "unauthenticated", request_id);
    r.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"locksmith\""),
    );
    r
}

/// Axum entry point for `/git/{host}/{*rest}`: `503` until the relay is configured.
pub async fn route(
    State(state): State<crate::app::AppState>,
    Path((host, rest)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Body,
) -> Response {
    match state.relay() {
        Some(relay) => handle(relay, &host, &rest, method, headers, query, body).await,
        None => fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            &Uuid::new_v4().to_string(),
        ),
    }
}

/// Order: agent token, grants, binding and path, egress (DNS and address guard), then decrypt,
/// then the streamed call. Nothing before the decrypt touches the material or the KMS.
async fn handle(
    relay: Arc<Relay>,
    host: &str,
    rest: &str,
    method: Method,
    headers: HeaderMap,
    query: Option<String>,
    body: Body,
) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let post = match method {
        Method::GET => false,
        Method::POST => true,
        _ => return fail(StatusCode::METHOD_NOT_ALLOWED, "denied", &request_id),
    };
    let agent = match relay.auth().authenticate(&agent_headers(&headers)).await {
        Ok(a) => a,
        Err(e) => {
            tracing::info!(reason = e.as_str(), "git: agent token refused");
            return challenge(&request_id);
        }
    };
    let grants = match relay.grants().grants(agent.agent_id).await {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(reason = e.as_str(), "git: agent grants could not be read");
            return fail(StatusCode::BAD_GATEWAY, "grants_unavailable", &request_id);
        }
    };
    let now = time::OffsetDateTime::now_utc();
    let selected = select(
        &relay.bindings().git_bindings,
        |id| allows_relay(&grants, id, now),
        host,
        rest,
        query.as_deref(),
        post,
    );
    drop(grants);
    let (binding, target) = match selected {
        Ok(x) => x,
        Err((why, secret)) => {
            tracing::info!(agent.id = %agent.agent_id, reason = ?why, "git: request denied");
            // The ledger names a secret; an agent with no Git grant has none to name.
            if let Some(b) = secret.and_then(|id| relay.bindings().git_for_secret(id)) {
                deny(&relay, agent.agent_id, b, post, Outcome::Denied).await;
            }
            let slug = match why {
                GitDenied::ServiceNotAllowed => "service_denied",
                _ => "denied",
            };
            return fail(StatusCode::FORBIDDEN, slug, &request_id);
        }
    };
    let call = Call {
        relay: &relay,
        agent_id: agent.agent_id,
        binding,
        service: target.service,
        post,
    };

    // Egress: origin and address guard; the client is pinned to the checked addresses.
    let egress_binding = Binding {
        secret_id: binding.secret_id,
        origin: binding.origin(),
        header: "Authorization".to_owned(),
        template: "{secret}".to_owned(),
        allow_private_hosts: binding.allow_private_hosts,
    };
    let Ok(base) = Url::parse(&format!("{}/", binding.origin())) else {
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "internal", &request_id);
    };
    let checked = match egress::check(&egress_binding, &base, relay.resolver()).await {
        Ok(t) => t,
        Err(EgressError::HostNotAllowed) => {
            call.deny(Outcome::Denied).await;
            return fail(StatusCode::FORBIDDEN, "denied", &request_id);
        }
        Err(EgressError::AddressNotAllowed) => {
            call.deny(Outcome::DeniedAddress).await;
            return fail(StatusCode::FORBIDDEN, "denied_address", &request_id);
        }
        Err(EgressError::Unresolvable) => {
            return call
                .failed(
                    Outcome::UpstreamUnreachable,
                    StatusCode::BAD_GATEWAY,
                    "upstream_unreachable",
                    &request_id,
                )
                .await;
        }
    };
    let opts = relay.git().options;
    let Ok(client) =
        checked.streaming_client(opts.connect_timeout, opts.total_timeout, opts.idle_timeout)
    else {
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "internal", &request_id);
    };

    // Decrypt, build the header and the redactor, drop the value.
    let value = match relay
        .decryptor()
        .decrypt(binding.secret_id, binding.version)
        .await
    {
        Ok(v) => v,
        Err(DecryptError::Material(MaterialError::NotFound)) => {
            return call
                .failed(
                    Outcome::MaterialError,
                    StatusCode::NOT_FOUND,
                    "not_found",
                    &request_id,
                )
                .await;
        }
        Err(_) => {
            return call
                .failed(
                    Outcome::DecryptFailed,
                    StatusCode::BAD_GATEWAY,
                    "secret_unavailable",
                    &request_id,
                )
                .await;
        }
    };
    let Ok(cred) = parse_credential(value.expose()) else {
        return call
            .failed(
                Outcome::InjectFailed,
                StatusCode::BAD_GATEWAY,
                "secret_unusable",
                &request_id,
            )
            .await;
    };
    drop(value);
    if matches!(cred, Credential::App(_))
        && !(binding.host == "github.com" || relay.git().apps_any_host)
    {
        return call
            .failed(
                Outcome::InjectFailed,
                StatusCode::BAD_GATEWAY,
                "secret_unusable",
                &request_id,
            )
            .await;
    }
    let repo_full = format!("{}/{}", target.owner, target.repo);
    let minted = {
        let relay = relay.clone();
        let now = now.unix_timestamp();
        tokio::task::spawn_blocking(move || {
            upstream_token(&cred, &relay.git().tokens, &repo_full, now)
        })
        .await
    };
    let token = match minted {
        Ok(Ok(t)) => t,
        Ok(Err(_)) => {
            return call
                .failed(
                    Outcome::MaterialError,
                    StatusCode::BAD_GATEWAY,
                    "token_unavailable",
                    &request_id,
                )
                .await;
        }
        Err(_) => {
            return call
                .failed(
                    Outcome::InjectFailed,
                    StatusCode::BAD_GATEWAY,
                    "secret_unusable",
                    &request_id,
                )
                .await;
        }
    };
    // The redactor first: a token too short to scan for in its encoded forms is not relayed.
    let Some(redactor) = redactor_for(&token) else {
        return call
            .failed(
                Outcome::RedactionFailed,
                StatusCode::BAD_GATEWAY,
                "secret_unusable",
                &request_id,
            )
            .await;
    };
    let auth_value = HeaderValue::from_str(&pat_header(&token))
        .ok()
        .map(|mut v| {
            v.set_sensitive(true);
            v
        });
    drop(token);
    let Some(auth_value) = auth_value else {
        return call
            .failed(
                Outcome::InjectFailed,
                StatusCode::BAD_GATEWAY,
                "secret_unusable",
                &request_id,
            )
            .await;
    };

    let mut url = checked.url().clone();
    let tail = if target.advertisement {
        "info/refs"
    } else {
        target.service.path()
    };
    url.set_path(&format!("{}/{}.git/{tail}", target.owner, target.repo));
    url.set_query(target.advertisement.then(|| target.service.query()));

    let mut up_headers = reqwest::header::HeaderMap::new();
    for name in FORWARD_REQUEST_HEADERS {
        for v in headers.get_all(*name) {
            if let Ok(n) = HeaderName::from_bytes(name.as_bytes()) {
                up_headers.append(n, v.clone());
            }
        }
    }
    up_headers.insert(header::AUTHORIZATION, auth_value);
    let mut req = client.request(
        if post {
            reqwest::Method::POST
        } else {
            reqwest::Method::GET
        },
        url,
    );
    req = req.headers(up_headers);
    if post {
        req = req.body(reqwest::Body::wrap_stream(body.into_data_stream()));
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) if e.is_timeout() => {
            return call
                .failed(
                    Outcome::UpstreamTimeout,
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream_timeout",
                    &request_id,
                )
                .await;
        }
        Err(e) if e.is_connect() => {
            return call
                .failed(
                    Outcome::UpstreamUnreachable,
                    StatusCode::BAD_GATEWAY,
                    "upstream_unreachable",
                    &request_id,
                )
                .await;
        }
        Err(_) => {
            return call
                .failed(
                    Outcome::UpstreamError,
                    StatusCode::BAD_GATEWAY,
                    "upstream_error",
                    &request_id,
                )
                .await;
        }
    };
    let status = resp.status();
    tracing::info!(
        agent.id = %agent.agent_id,
        secret.id = %binding.secret_id,
        git.service = target.service.event(),
        upstream.status = status.as_u16(),
        "git request relayed"
    );
    let code = Some(status.as_u16());
    // Never follow, and never hand the agent a Location or a credential challenge.
    if status.is_redirection() || status == StatusCode::UNAUTHORIZED {
        let slug = if status.is_redirection() {
            "upstream_redirect"
        } else {
            "upstream_unauthorized"
        };
        if !call.record(Outcome::UpstreamError, code).await {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "audit_failed",
                &request_id,
            );
        }
        return fail(StatusCode::BAD_GATEWAY, slug, &request_id);
    }

    // Redact the credential in the headers passed back; fail closed when a value still matches.
    let Some(out_headers) = scan_headers(&redactor, resp.headers()) else {
        return call
            .failed(
                Outcome::RedactionFailed,
                StatusCode::BAD_GATEWAY,
                "redaction_failed",
                &request_id,
            )
            .await;
    };
    // A Git stream goes through raw; anything else (an error page above all) is read, redacted
    // and re-checked, or withheld.
    let payload = if is_git_stream(status, resp.headers()) {
        Payload::Stream(resp)
    } else {
        match scan_body(resp, &redactor).await {
            Some(b) => Payload::Text(b),
            None => {
                return call
                    .failed(
                        Outcome::RedactionFailed,
                        StatusCode::BAD_GATEWAY,
                        "redaction_failed",
                        &request_id,
                    )
                    .await;
            }
        }
    };
    // The ledger takes the event before the agent sees the answer.
    if !call.record(Outcome::Ok, code).await {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "audit_failed",
            &request_id,
        );
    }
    let mut out = Response::builder().status(status);
    for (name, v) in out_headers {
        out = out.header(name, v);
    }
    let body = match payload {
        Payload::Text(b) => Body::from(b),
        Payload::Stream(r) => Body::from_stream(r.bytes_stream()),
    };
    out.body(body)
        .unwrap_or_else(|_| fail(StatusCode::BAD_GATEWAY, "upstream_error", &request_id))
}

#[cfg(test)]
#[path = "git_fixture_tests.rs"]
mod fixture_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Bindings;

    const FIXTURE: &str = r#"
org_id = "0197c1f0-0000-7000-8000-000000000001"

[[git_binding]]
secret_id = "0197c1f0-0000-7000-8000-000000000003"
host = "github.com"
repo_prefix = "acme/widgets"
services = ["fetch"]

[[git_binding]]
secret_id = "0197c1f0-0000-7000-8000-000000000004"
host = "github.com"
repo_prefix = "acme"
services = ["fetch", "push"]
"#;

    fn bindings() -> Bindings {
        Bindings::parse(FIXTURE).expect("fixture parses")
    }

    fn id(n: u8) -> Uuid {
        Uuid::parse_str(&format!("0197c1f0-0000-7000-8000-00000000000{n}")).unwrap()
    }

    #[test]
    fn git_binding_fixture_parses() {
        let b = bindings();
        assert_eq!(b.git_bindings.len(), 2);
        assert_eq!(b.git_for_secret(id(3)).unwrap().repo_prefix, "acme/widgets");
        assert!(b.git_for_secret(id(9)).is_none());
    }

    #[test]
    fn git_binding_allows_bound_fetch_and_push() {
        let b = bindings();
        let org = b.git_for_secret(id(4)).unwrap();
        let t = org
            .authorize(
                "github.com",
                "acme/tools.git/info/refs",
                Some("service=git-receive-pack"),
                false,
            )
            .unwrap();
        assert_eq!(
            (t.repo.as_str(), t.service, t.advertisement),
            ("tools", GitService::Push, true)
        );
        let t = org
            .authorize("github.com", "acme/tools/git-upload-pack", None, true)
            .unwrap();
        assert_eq!((t.service, t.advertisement), (GitService::Fetch, false));
    }

    #[test]
    fn git_binding_denies_unbound_repo_host_and_service() {
        let b = bindings();
        let one = b.git_for_secret(id(3)).unwrap();
        let refs = "info/refs";
        let q = Some("service=git-upload-pack");
        assert_eq!(
            one.authorize("github.com", &format!("acme/other/{refs}"), q, false),
            Err(GitDenied::NotBound)
        );
        assert_eq!(
            one.authorize("gitlab.com", &format!("acme/widgets/{refs}"), q, false),
            Err(GitDenied::NotBound)
        );
        assert_eq!(
            one.authorize("github.com", "acme/widgets.git.git/info/refs", q, false),
            Err(GitDenied::NotBound)
        );
        assert_eq!(
            one.authorize("github.com", "acme/widgets/git-receive-pack", None, true),
            Err(GitDenied::ServiceNotAllowed)
        );
    }

    #[test]
    fn git_binding_denies_everything_but_the_three_paths() {
        let b = bindings();
        let org = b.git_for_secret(id(4)).unwrap();
        for (path, query, post) in [
            ("acme/widgets/objects/info/packs", None, false),
            ("acme/widgets/info/refs", None, false),
            (
                "acme/widgets/info/refs",
                Some("service=git-upload-pack"),
                true,
            ),
            ("acme/widgets/git-upload-pack", None, false),
            ("acme/widgets/git-upload-pack", Some("x=1"), true),
            (
                "acme/../widgets/info/refs",
                Some("service=git-upload-pack"),
                false,
            ),
            ("acme/widgets", None, false),
            (
                "acme/widgets/info/refs/",
                Some("service=git-upload-pack"),
                false,
            ),
            (
                "acme/%2e%2e/info/refs",
                Some("service=git-upload-pack"),
                false,
            ),
            (
                "acme/.git/info/refs",
                Some("service=git-upload-pack"),
                false,
            ),
            ("acme//info/refs", Some("service=git-upload-pack"), false),
            ("acme", None, false),
            ("api/v3/repos/acme/widgets", None, false),
        ] {
            assert!(
                org.authorize("github.com", path, query, post).is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn git_binding_rejects_duplicate_secret_id() {
        let one = "[[git_binding]]\nsecret_id = \"0197c1f0-0000-7000-8000-000000000003\"\nhost = \"github.com\"\nrepo_prefix = \"a\"\nservices = [\"fetch\"]\n";
        let toml = format!("org_id = \"0197c1f0-0000-7000-8000-000000000001\"\n{one}{one}");
        assert!(Bindings::parse(&toml).is_err());
    }

    #[test]
    fn git_binding_rejects_invalid_config() {
        for bad in [
            r#"host = "GitHub.com"
repo_prefix = "a"
services = ["fetch"]"#,
            r#"host = "github.com"
repo_prefix = "a/b/c"
services = ["fetch"]"#,
            r#"host = "github.com"
repo_prefix = "a"
services = []"#,
            r#"host = "https://github.com"
repo_prefix = "a"
services = ["fetch"]"#,
        ] {
            let toml = format!(
                "org_id = \"0197c1f0-0000-7000-8000-000000000001\"\n[[git_binding]]\nsecret_id = \"0197c1f0-0000-7000-8000-000000000003\"\n{bad}\n"
            );
            assert!(Bindings::parse(&toml).is_err(), "{bad}");
        }
    }
}
