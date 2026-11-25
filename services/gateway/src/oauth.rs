//! OAuth connect start and callback (C1 task 3.3; design decisions 4, 5, 6, 7 and 11).
//!
//! - `POST /v1/oauth/connect` `{provider, return_to}` with the person's bearer: the token is
//!   verified with [`HumanAuth`] (the control plane's issuer settings) and the person is looked up
//!   read-only through [`Database::with_login`] (never `users::resolve`, which creates users). A
//!   person of another org is refused. `return_to` must be on a configured console origin. The
//!   flow row stores the SHA-256 of a 32-byte random `state` and the PKCE S256 verifier sealed with
//!   the [`TokenVault`] (binding org ‖ flow id ‖ generation 0 ‖ `oauth-token`), and expires after
//!   10 minutes. The answer is `{flow_id, authorize_url}`; scopes come from the registry only.
//! - `GET /oauth/callback?code&state` (or `error`): the flow is consumed once (`DELETE …
//!   RETURNING`, so a replayed `state` finds nothing), the code is exchanged, the provider account
//!   read, and the token set sealed into a `pending_confirm` connection (generation 1) plus a
//!   `pending_confirm` flow row that the person confirms later (task 3.4). The answer is a `302`
//!   to `return_to` carrying only `flow=<id>` and `result=pending_confirm|<error slug>`. A failed
//!   callback appends `oauth.connect_failed` (best effort).
//! - `POST /v1/oauth/flows/{id}/confirm` with the person's bearer (task 3.4, decision 4): the
//!   `pending_confirm` flow is consumed once. Only the person who started it activates the
//!   connection (`connected`, or the person's existing connection to the same account takes the
//!   new token set as its next generation) and `oauth.connected` is appended before the commit,
//!   so a ledger that cannot take it refuses the confirm. Anyone else gets `403 wrong_person`, an
//!   expired flow `410 flow_expired`: the tokens are revoked at the provider, the connection and
//!   its material deleted, and `oauth.connect_failed` appended. An unknown flow is
//!   `404 flow_not_found`. The answer is a [`ConnectionSummary`].
//! - [`OAuth::spawn_sweeper`] revokes and deletes `pending_confirm` connections whose flow was not
//!   confirmed within 10 minutes (appending `oauth.connect_failed` `flow_expired`) and deletes
//!   expired `started` flows, which hold no token.
//! - [`OAuth::spawn_publish_providers`] upserts the enabled providers into `oauth_providers` at
//!   startup (decision 9): id, name, scopes, the public connect URL and revoke support, never a
//!   client secret.
//! - CORS on `/v1/oauth/*` for the console origins only ([`OAuth::cors`]).
//!
//! Tokens, the code, `state` and the verifier never reach a response, redirect, log, span or
//! error: failures are [`ErrorSlug`]s, and logs carry the provider, flow id and outcome only.
//! Storage goes through the gateway's own role (`locksmith_gateway`, decision 7).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ls_control_plane::auth::human::HumanAuth;
use ls_control_plane::db::{Database, sql};
use ls_envelope::{KeyWrapper, SecretBytes, WRAPPED_DEK_LEN};
use ls_oauth::{
    ConnectResponse, ConnectionStatus, ConnectionSummary, ErrorBody, ErrorSlug, OAuthClient,
    ProviderDef, ProviderEndpoints, Quirk, Tokens,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::Instrument as _;
use url::Url;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit::{AuditSink, ConnectFailure, OAuthEvent, OAuthEventKind};
use crate::config::OAuthConfig;
use crate::oauth_vault::{SealedTokenSet, TokenVault, VaultError};

pub mod refresh;
pub use refresh::{AccessError, AccessToken};

/// How long a started flow, and then an unconfirmed `pending_confirm` flow, stays valid.
pub const FLOW_TTL: Duration = Duration::from_secs(600);

/// The generation the PKCE verifier is sealed under (bound to the flow id). Token material
/// starts at generation 1 (`oauth_token_material.generation >= 1`), so the two never collide.
const VERIFIER_GENERATION: u32 = 0;

/// The generation of a freshly exchanged token set.
const FIRST_GENERATION: u32 = 1;

/// How often [`OAuth::spawn_sweeper`] looks for unconfirmed flows in the gateway binary.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Most unconfirmed connections one sweep handles (the rest wait for the next).
const SWEEP_BATCH: i64 = 100;

/// Longest accepted `return_to` (the column's limit).
const MAX_RETURN_TO: usize = 2048;

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Object-safe view of [`TokenVault`], so the endpoints do not depend on the KMS type.
pub trait Sealer: Send + Sync {
    fn seal<'a>(
        &'a self,
        org: Uuid,
        id: Uuid,
        generation: u32,
        set: &'a SecretBytes,
    ) -> BoxFut<'a, Result<SealedTokenSet, VaultError>>;

    fn open<'a>(
        &'a self,
        org: Uuid,
        id: Uuid,
        generation: u32,
        ciphertext: &'a [u8],
        wrapped_dek: &'a [u8],
    ) -> BoxFut<'a, Result<SecretBytes, VaultError>>;
}

impl<K: KeyWrapper + Send + Sync> Sealer for TokenVault<K> {
    fn seal<'a>(
        &'a self,
        org: Uuid,
        id: Uuid,
        generation: u32,
        set: &'a SecretBytes,
    ) -> BoxFut<'a, Result<SealedTokenSet, VaultError>> {
        Box::pin(TokenVault::seal(self, org, id, generation, set))
    }

    fn open<'a>(
        &'a self,
        org: Uuid,
        id: Uuid,
        generation: u32,
        ciphertext: &'a [u8],
        wrapped_dek: &'a [u8],
    ) -> BoxFut<'a, Result<SecretBytes, VaultError>> {
        Box::pin(TokenVault::open(
            self,
            org,
            id,
            generation,
            ciphertext,
            wrapped_dek,
        ))
    }
}

/// An enabled provider: its registry entry and a client for its app.
pub struct Provider {
    pub def: ProviderDef,
    pub client: OAuthClient,
}

/// The endpoints and quirks of a registry entry for [`OAuthClient`].
pub fn endpoints_for(def: &ProviderDef) -> ProviderEndpoints {
    let (quirk, authorize_params): (Quirk, &[(&str, &str)]) = match def.id.as_str() {
        "github" => (Quirk::Github, &[]),
        "slack" => (Quirk::Slack, &[]),
        // Atlassian 3LO needs the API audience and a consent prompt to issue a refresh token.
        "atlassian" => (
            Quirk::Atlassian,
            &[("audience", "api.atlassian.com"), ("prompt", "consent")],
        ),
        // Google issues a refresh token only for offline access.
        "google" => (
            Quirk::Standard,
            &[("access_type", "offline"), ("prompt", "consent")],
        ),
        _ => (Quirk::Standard, &[]),
    };
    ProviderEndpoints {
        authorize_url: def.authorize_url.clone(),
        token_url: def.token_url.clone(),
        revoke_url: def.revoke_url.clone(),
        account_url: def.account_url.clone(),
        quirk,
        authorize_params: authorize_params
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    }
}

/// Why the OAuth endpoints could not be set up. Names the part only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupError(pub &'static str);

impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "oauth setup failed: {}", self.0)
    }
}

impl std::error::Error for SetupError {}

/// The OAuth connect and callback endpoints' state.
pub struct OAuth {
    org_id: Uuid,
    db: Database,
    human: HumanAuth,
    vault: Arc<dyn Sealer>,
    providers: HashMap<String, Provider>,
    console_origins: Vec<url::Origin>,
    /// The ledger for `oauth.*` events. Without it (tests only) events are dropped.
    audit: Option<Arc<dyn AuditSink>>,
    /// The public `POST /v1/oauth/connect` URL published in `oauth_providers`.
    connect_url: Option<Url>,
}

impl OAuth {
    /// `db` connects as `locksmith_gateway`. `console_origins` must not be empty: the first is
    /// where a callback with an unknown `state` lands.
    pub fn new(
        org_id: Uuid,
        db: Database,
        human: HumanAuth,
        vault: Arc<dyn Sealer>,
        console_origins: Vec<url::Origin>,
    ) -> Self {
        assert!(!console_origins.is_empty(), "at least one console origin");
        Self {
            org_id,
            db,
            human,
            vault,
            providers: HashMap::new(),
            console_origins,
            audit: None,
            connect_url: None,
        }
    }

    /// Append `oauth.*` events to `audit` (the gateway binary always sets it).
    pub fn with_audit(mut self, audit: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// The public connect URL [`Self::publish_providers`] records.
    pub fn with_connect_url(mut self, url: Url) -> Self {
        self.connect_url = Some(url);
        self
    }

    /// Enable a provider.
    pub fn with_provider(mut self, def: ProviderDef, client: OAuthClient) -> Self {
        self.providers
            .insert(def.id.clone(), Provider { def, client });
        self
    }

    /// Build from configuration: the person verifier, the OpenBao-backed vault and one client per
    /// enabled provider over the gateway's no-redirect HTTP client.
    pub fn from_config(
        config: OAuthConfig,
        org_id: Uuid,
        db: Database,
        openbao_addr: &str,
    ) -> Result<Self, SetupError> {
        let human = HumanAuth::new(&config.human_auth).map_err(|_| SetupError("human auth"))?;
        let token = ls_envelope::BaoToken::new(config.openbao_token.expose_secret().to_owned());
        let vault = TokenVault::openbao(openbao_addr, token).map_err(|_| SetupError("vault"))?;
        let http = crate::http_client::build(Duration::from_secs(5), Duration::from_secs(20), None)
            .map_err(|_| SetupError("http client"))?;
        // Next to the callback: `https://gw.example.com/oauth/callback` gives
        // `https://gw.example.com/v1/oauth/connect` (a path prefix is kept).
        let connect_url = config
            .redirect_url
            .join("../v1/oauth/connect")
            .map_err(|_| SetupError("connect url"))?;
        let mut oauth = Self::new(org_id, db, human, Arc::new(vault), config.console_origins)
            .with_connect_url(connect_url);
        for p in config.providers {
            let client = OAuthClient::new(
                http.clone(),
                endpoints_for(&p.def),
                p.client_id,
                p.client_secret,
                config.redirect_url.as_str(),
            )
            .map_err(|_| SetupError("provider client"))?;
            oauth = oauth.with_provider(p.def, client);
        }
        Ok(oauth)
    }

    /// The enabled provider ids.
    pub fn provider_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self.providers.keys().map(String::as_str).collect();
        ids.sort_unstable();
        ids
    }

    /// CORS for `/v1/oauth/*`: the console origins only, bearer and JSON headers, no cookies.
    pub fn cors(&self) -> CorsLayer {
        let origins: Vec<HeaderValue> = self
            .console_origins
            .iter()
            .filter_map(|o| HeaderValue::from_str(&o.ascii_serialization()).ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
            .max_age(Duration::from_secs(600))
    }

    /// `return_to` parsed, when it is an absolute `http(s)` URL on a console origin with no
    /// credentials or fragment.
    pub fn allowed_return_to(&self, return_to: &str) -> Option<Url> {
        if return_to.len() > MAX_RETURN_TO || return_to.chars().any(char::is_control) {
            return None;
        }
        let url = Url::parse(return_to).ok()?;
        let ok = matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && self.console_origins.contains(&url.origin());
        ok.then_some(url)
    }

    /// Where a callback lands when the flow (and so its `return_to`) is unknown.
    fn fallback_return(&self) -> String {
        format!("{}/", self.console_origins[0].ascii_serialization())
    }
}

/// A refused connect request.
enum Refusal {
    /// No, malformed or unverified bearer, or no such person: `401`, no body.
    Unauthorized,
    /// A person of another org: `403`, no body.
    Forbidden,
    /// `400` with an error slug.
    Bad(ErrorSlug),
    /// Another status with an error slug.
    Slug(StatusCode, ErrorSlug),
    /// A body that is not `{provider, return_to}`: `400`, no body.
    Malformed,
    /// Database or KMS failure: `503`, no body.
    Unavailable,
}

impl Refusal {
    fn outcome(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::Bad(slug) | Self::Slug(_, slug) => slug.as_str(),
            Self::Malformed => "malformed",
            Self::Unavailable => "unavailable",
        }
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            Self::Forbidden => StatusCode::FORBIDDEN.into_response(),
            Self::Bad(slug) => {
                (StatusCode::BAD_REQUEST, Json(ErrorBody { error: slug })).into_response()
            }
            Self::Slug(status, slug) => (status, Json(ErrorBody { error: slug })).into_response(),
            Self::Malformed => StatusCode::BAD_REQUEST.into_response(),
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    }
}

/// The connect body. Unknown fields (for example extra scopes) are ignored: scopes come from the
/// registry only.
#[derive(Deserialize)]
pub struct ConnectBody {
    provider: String,
    return_to: String,
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token.trim())
}

fn state_hash(state: &str) -> Vec<u8> {
    Sha256::digest(state.as_bytes()).to_vec()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// `POST /v1/oauth/connect`.
pub async fn connect(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<ConnectBody>, JsonRejection>,
) -> Response {
    let Some(oauth) = state.oauth() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let span = tracing::info_span!(
        "oauth.connect",
        provider = tracing::field::Empty,
        flow_id = tracing::field::Empty,
        person = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    let result = start(&oauth, &headers, body).instrument(span.clone()).await;
    match result {
        Ok(r) => {
            span.record("outcome", "ok");
            Json(r).into_response()
        }
        Err(refusal) => {
            span.record("outcome", refusal.outcome());
            refusal.into_response()
        }
    }
}

impl OAuth {
    /// The bearer's person: verified with [`HumanAuth`], looked up read-only (an unknown identity
    /// is refused, never created here) and required to belong to this gateway's org.
    async fn person(&self, headers: &HeaderMap) -> Result<Uuid, Refusal> {
        let token = bearer(headers).ok_or(Refusal::Unauthorized)?;
        let identity = self
            .human
            .verify(token)
            .await
            .map_err(|_| Refusal::Unauthorized)?;
        let (issuer, subject) = (identity.issuer.clone(), identity.subject.clone());
        let person: Option<(Uuid, Uuid)> = self
            .db
            .with_login(&identity.issuer, &identity.subject, None, move |c| {
                Box::pin(async move {
                    sql::query_as(
                        "SELECT id, personal_org_id FROM users WHERE issuer = $1 AND subject = $2",
                    )
                    .bind(issuer)
                    .bind(subject)
                    .fetch_optional(c)
                    .await
                })
            })
            .await
            .map_err(|_| Refusal::Unavailable)?;
        let (user_id, user_org) = person.ok_or(Refusal::Unauthorized)?;
        tracing::Span::current().record("person", tracing::field::display(user_id));
        if user_org != self.org_id {
            return Err(Refusal::Forbidden);
        }
        Ok(user_id)
    }
}

async fn start(
    oauth: &OAuth,
    headers: &HeaderMap,
    body: Result<Json<ConnectBody>, JsonRejection>,
) -> Result<ConnectResponse, Refusal> {
    let user_id = oauth.person(headers).await?;

    let Json(body) = body.map_err(|_| Refusal::Malformed)?;
    let provider = oauth
        .providers
        .get(&body.provider)
        .ok_or(Refusal::Bad(ErrorSlug::UnknownProvider))?;
    tracing::Span::current().record("provider", provider.def.id.as_str());
    let return_to = oauth
        .allowed_return_to(&body.return_to)
        .ok_or(Refusal::Bad(ErrorSlug::ReturnToNotAllowed))?;

    let started = provider.client.authorize(&provider.def.default_scopes);
    let flow_id = Uuid::now_v7();
    tracing::Span::current().record("flow_id", tracing::field::display(flow_id));
    let verifier = SecretBytes::new(started.verifier.expose_secret().as_bytes().to_vec());
    let sealed = oauth
        .vault
        .seal(oauth.org_id, flow_id, VERIFIER_GENERATION, &verifier)
        .await
        .map_err(|_| Refusal::Unavailable)?;
    // `wrapped_dek` has a fixed length, so one column holds both parts.
    let mut sealed_verifier = sealed.wrapped_dek;
    sealed_verifier.extend_from_slice(&sealed.ciphertext);

    let hash = state_hash(&started.state);
    let provider_id = provider.def.id.clone();
    let return_to = return_to.to_string();
    let ttl = FLOW_TTL.as_secs_f64();
    oauth
        .db
        .with_org(oauth.org_id, move |c| {
            Box::pin(async move {
                sql::query(
                    "INSERT INTO oauth_flows (id, org_id, user_id, provider, state_hash, \
                         sealed_verifier, return_to, status, expires_at) \
                     VALUES ($1, current_org_id(), $2, $3, $4, $5, $6, 'started', \
                         now() + make_interval(secs => $7))",
                )
                .bind(flow_id)
                .bind(user_id)
                .bind(provider_id)
                .bind(hash)
                .bind(sealed_verifier)
                .bind(return_to)
                .bind(ttl)
                .execute(c)
                .await
                .map(|_| ())
            })
        })
        .await
        .map_err(|_: sql::Error| Refusal::Unavailable)?;

    Ok(ConnectResponse {
        flow_id,
        authorize_url: started.url,
    })
}

/// The callback query. Other parameters providers add (`scope`, `iss`, `session_state`) are
/// ignored.
#[derive(Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// A consumed `started` flow.
struct Flow {
    id: Uuid,
    user_id: Uuid,
    provider: String,
    state_hash: Vec<u8>,
    sealed_verifier: Vec<u8>,
    return_to: String,
    expired: bool,
}

/// `302` to `return_to` with `flow` (when known) and `result` only. No cache, no referrer: the
/// callback URL itself carried the code and `state`.
fn redirect(return_to: &str, flow: Option<Uuid>, result: &str) -> Response {
    let mut url = match Url::parse(return_to) {
        Ok(u) => u,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != "flow" && k != "result")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.set_query(None);
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in &kept {
            q.append_pair(k, v);
        }
        if let Some(id) = flow {
            q.append_pair("flow", &id.to_string());
        }
        q.append_pair("result", result);
    }
    let Ok(location) = HeaderValue::from_str(url.as_str()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, location),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("no-referrer"),
            ),
        ],
    )
        .into_response()
}

/// `GET /oauth/callback`.
pub async fn callback(
    State(state): State<AppState>,
    params: Result<Query<CallbackParams>, QueryRejection>,
) -> Response {
    let Some(oauth) = state.oauth() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let span = tracing::info_span!(
        "oauth.callback",
        provider = tracing::field::Empty,
        flow_id = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    let (return_to, flow, result) = finish(&oauth, params.ok().map(|Query(p)| p))
        .instrument(span.clone())
        .await;
    span.record("outcome", result);
    redirect(&return_to, flow, result)
}

/// Runs the callback; answers where to redirect and with what. Never fails otherwise.
async fn finish(
    oauth: &OAuth,
    params: Option<CallbackParams>,
) -> (String, Option<Uuid>, &'static str) {
    let not_found = || {
        (
            oauth.fallback_return(),
            None,
            ErrorSlug::FlowNotFound.as_str(),
        )
    };
    let Some(params) = params else {
        return not_found();
    };
    // The code is a credential from here on.
    let code = params.code.map(SecretString::from);
    let Some(state) = params.state.filter(|s| !s.is_empty() && s.len() <= 512) else {
        return not_found();
    };
    let hash = state_hash(&state);
    drop(state);

    // Single use: the row is gone for any later callback with the same `state`.
    let taken: Result<Option<Flow>, sql::Error> = oauth
        .db
        .with_org(oauth.org_id, move |c| {
            Box::pin(async move {
                type Row = (Uuid, Uuid, String, Vec<u8>, Vec<u8>, String, bool);
                let row: Option<Row> = sql::query_as(
                    "DELETE FROM oauth_flows WHERE state_hash = $1 AND status = 'started' \
                     RETURNING id, user_id, provider, state_hash, sealed_verifier, return_to, \
                         expires_at <= now()",
                )
                .bind(hash)
                .fetch_optional(c)
                .await?;
                Ok(row.map(
                    |(id, user_id, provider, state_hash, sealed_verifier, return_to, expired)| {
                        Flow {
                            id,
                            user_id,
                            provider,
                            state_hash,
                            sealed_verifier,
                            return_to,
                            expired,
                        }
                    },
                ))
            })
        })
        .await;
    let flow = match taken {
        Ok(Some(f)) => f,
        Ok(None) => return not_found(),
        Err(_) => {
            tracing::warn!("oauth callback: flow lookup failed");
            return not_found();
        }
    };
    let span = tracing::Span::current();
    span.record("flow_id", tracing::field::display(flow.id));
    span.record("provider", flow.provider.as_str());
    // Configuration may have changed since the flow started.
    let return_to = match oauth.allowed_return_to(&flow.return_to) {
        Some(u) => u.to_string(),
        None => oauth.fallback_return(),
    };
    let result = complete(oauth, &flow, code, params.error.is_some()).await;
    let slug = match result {
        Ok(()) => "pending_confirm",
        Err(slug) => {
            oauth
                .connect_failed(flow.user_id, &flow.provider, None, slug)
                .await;
            slug.as_str()
        }
    };
    (return_to, Some(flow.id), slug)
}

async fn complete(
    oauth: &OAuth,
    flow: &Flow,
    code: Option<SecretString>,
    provider_error: bool,
) -> Result<(), ErrorSlug> {
    if flow.expired {
        return Err(ErrorSlug::FlowExpired);
    }
    // The provider refused (`access_denied` and the like); its text is never echoed.
    if provider_error {
        return Err(ErrorSlug::ProviderError);
    }
    let code = code
        .filter(|c| !c.expose_secret().is_empty())
        .ok_or(ErrorSlug::ProviderError)?;
    let provider = oauth
        .providers
        .get(&flow.provider)
        .ok_or(ErrorSlug::UnknownProvider)?;

    if flow.sealed_verifier.len() <= WRAPPED_DEK_LEN {
        return Err(ErrorSlug::ExchangeFailed);
    }
    let (wrapped, ciphertext) = flow.sealed_verifier.split_at(WRAPPED_DEK_LEN);
    let verifier = oauth
        .vault
        .open(
            oauth.org_id,
            flow.id,
            VERIFIER_GENERATION,
            ciphertext,
            wrapped,
        )
        .await
        .map_err(|_| ErrorSlug::ExchangeFailed)?;
    let verifier = std::str::from_utf8(verifier.expose())
        .map(|v| SecretString::from(v.to_owned()))
        .map_err(|_| ErrorSlug::ExchangeFailed)?;

    let tokens = provider
        .client
        .exchange_code(code, verifier)
        .await
        .map_err(|e| e.slug)?;
    let account = match provider.client.account(&tokens.access).await {
        Ok(a) => a,
        Err(_) => {
            revoke_quietly(provider, &tokens).await;
            return Err(ErrorSlug::ProviderError);
        }
    };
    let scopes = if tokens.scopes.is_empty() {
        provider.def.default_scopes.clone()
    } else {
        tokens.scopes.clone()
    };

    let connection_id = Uuid::now_v7();
    let stored = store_pending(oauth, flow, connection_id, &tokens, &scopes, &account).await;
    if stored.is_err() {
        revoke_quietly(provider, &tokens).await;
        return Err(ErrorSlug::ExchangeFailed);
    }
    Ok(())
}

/// Best effort: tokens that cannot be kept are revoked at the provider.
async fn revoke_quietly(provider: &Provider, tokens: &Tokens) {
    if provider.def.revoke_url.is_some()
        && provider
            .client
            .revoke(&tokens.access, tokens.refresh.as_ref())
            .await
            .is_err()
    {
        tracing::warn!("oauth: revoking an unkept token failed");
    }
}

/// The failure of a storage step. Carries nothing.
struct StoreFailed;

impl From<sql::Error> for StoreFailed {
    fn from(_: sql::Error) -> Self {
        Self
    }
}

/// Seal the token set as generation 1 and write the `pending_confirm` connection, its material
/// and the `pending_confirm` flow (same id, `connection_id` set, a fresh 10-minute expiry) in one
/// transaction.
async fn store_pending(
    oauth: &OAuth,
    flow: &Flow,
    connection_id: Uuid,
    tokens: &Tokens,
    scopes: &[String],
    account: &ls_oauth::Account,
) -> Result<(), StoreFailed> {
    let now = now_unix();
    let expires_in = tokens.expires_in.map(|d| d.as_secs_f64());
    let set = encode_token_set(tokens, scopes, now).ok_or(StoreFailed)?;
    let sealed = oauth
        .vault
        .seal(oauth.org_id, connection_id, FIRST_GENERATION, &set)
        .await
        .map_err(|_| StoreFailed)?;
    drop(set);

    let (flow_id, user_id, provider) = (flow.id, flow.user_id, flow.provider.clone());
    let return_to = flow.return_to.clone();
    let state_hash = flow.state_hash.clone();
    let (account_id, login) = (account.id.clone(), account.login.clone());
    let scopes = scopes.to_vec();
    let ttl = FLOW_TTL.as_secs_f64();
    let generation = i32::try_from(FIRST_GENERATION).unwrap_or(1);
    oauth
        .db
        .with_org(oauth.org_id, move |c| {
            Box::pin(async move {
                sql::query(
                    "INSERT INTO oauth_connections (id, org_id, user_id, provider, account_login, \
                         account_id, scopes, status, generation, expires_at) \
                     VALUES ($1, current_org_id(), $2, $3, $4, $5, $6, 'pending_confirm', $7, \
                         now() + make_interval(secs => $8))",
                )
                .bind(connection_id)
                .bind(user_id)
                .bind(&provider)
                .bind(login)
                .bind(account_id)
                .bind(scopes)
                .bind(generation)
                .bind(expires_in)
                .execute(&mut *c)
                .await?;
                sql::query(
                    "INSERT INTO oauth_token_material (org_id, connection_id, generation, \
                         ciphertext, wrapped_dek, key_id) \
                     VALUES (current_org_id(), $1, $2, $3, $4, $5)",
                )
                .bind(connection_id)
                .bind(generation)
                .bind(sealed.ciphertext)
                .bind(sealed.wrapped_dek)
                .bind(sealed.key_id)
                .execute(&mut *c)
                .await?;
                // The verifier is spent; the `state` hash stays unique and can no longer be
                // consumed (only `started` rows are).
                sql::query(
                    "INSERT INTO oauth_flows (id, org_id, user_id, provider, state_hash, \
                         sealed_verifier, return_to, status, connection_id, expires_at) \
                     VALUES ($1, current_org_id(), $2, $3, $4, '\\x', $5, 'pending_confirm', $6, \
                         now() + make_interval(secs => $7))",
                )
                .bind(flow_id)
                .bind(user_id)
                .bind(&provider)
                .bind(state_hash)
                .bind(return_to)
                .bind(connection_id)
                .bind(ttl)
                .execute(&mut *c)
                .await?;
                Ok::<_, StoreFailed>(())
            })
        })
        .await
}

impl OAuth {
    /// Append an `oauth.*` event; `false` when the ledger did not take it. Without a ledger
    /// (tests only) nothing is appended.
    async fn append(&self, ev: OAuthEvent) -> bool {
        match &self.audit {
            Some(a) => a.append_oauth(ev).await.is_ok(),
            None => true,
        }
    }

    /// Best effort `oauth.connect_failed` for a failure `slug`; slugs that are not connect
    /// failures are not recorded.
    async fn connect_failed(
        &self,
        person: Uuid,
        provider: &str,
        connection_id: Option<Uuid>,
        slug: ErrorSlug,
    ) {
        let failure = match slug {
            ErrorSlug::WrongPerson => ConnectFailure::WrongPerson,
            ErrorSlug::FlowExpired => ConnectFailure::FlowExpired,
            ErrorSlug::ProviderError => ConnectFailure::ProviderError,
            ErrorSlug::ExchangeFailed => ConnectFailure::ExchangeFailed,
            _ => return,
        };
        let ev = OAuthEvent {
            kind: OAuthEventKind::ConnectFailed(failure),
            person,
            provider: provider.to_owned(),
            connection_id,
            agent_id: None,
        };
        if !self.append(ev).await {
            tracing::warn!(
                outcome = slug.as_str(),
                "oauth: connect_failed not recorded"
            );
        }
    }

    /// Open a sealed token set and revoke it at the provider (best effort; a provider that is
    /// no longer enabled cannot be reached).
    async fn revoke_sealed(
        &self,
        provider: &str,
        connection_id: Uuid,
        generation: i32,
        ciphertext: &[u8],
        wrapped_dek: &[u8],
    ) {
        let Some(provider) = self.providers.get(provider) else {
            tracing::warn!("oauth: provider no longer enabled, token not revoked");
            return;
        };
        let Ok(generation) = u32::try_from(generation) else {
            return;
        };
        let opened = self
            .vault
            .open(
                self.org_id,
                connection_id,
                generation,
                ciphertext,
                wrapped_dek,
            )
            .await;
        let Some(set) = opened.ok().as_ref().and_then(decode_token_set) else {
            tracing::warn!("oauth: sealed token set did not open, token not revoked");
            return;
        };
        let tokens = Tokens {
            access: set.access,
            refresh: set.refresh,
            expires_in: None,
            scopes: Vec::new(),
        };
        revoke_quietly(provider, &tokens).await;
    }

    /// The enabled providers as `oauth_providers` rows: id, name, scopes, the connect URL and
    /// revoke support. Never a client id or secret.
    fn provider_rows(&self) -> Option<Vec<ProviderRow>> {
        let connect_url = self.connect_url.as_ref()?.to_string();
        let mut rows: Vec<_> = self
            .providers
            .values()
            .map(|p| {
                (
                    p.def.id.clone(),
                    p.def.name.clone(),
                    p.def.default_scopes.clone(),
                    connect_url.clone(),
                    p.def.revoke_url.is_some(),
                )
            })
            .collect();
        rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        Some(rows)
    }

    /// Upsert the enabled providers into `oauth_providers` (decision 9). Providers that are no
    /// longer enabled keep their row (the gateway role may not delete); answers the rows written.
    pub async fn publish_providers(&self) -> Result<usize, SetupError> {
        let rows = self.provider_rows().ok_or(SetupError("connect url"))?;
        self.db
            .with_org(self.org_id, move |c| {
                Box::pin(async move {
                    let n = rows.len();
                    for (id, name, scopes, connect_url, revoke) in rows {
                        sql::query(
                            "INSERT INTO oauth_providers (org_id, provider, name, scopes, \
                                 connect_url, revoke_supported, updated_at) \
                             VALUES (current_org_id(), $1, $2, $3, $4, $5, now()) \
                             ON CONFLICT (org_id, provider) DO UPDATE SET \
                                 name = EXCLUDED.name, scopes = EXCLUDED.scopes, \
                                 connect_url = EXCLUDED.connect_url, \
                                 revoke_supported = EXCLUDED.revoke_supported, \
                                 updated_at = now()",
                        )
                        .bind(id)
                        .bind(name)
                        .bind(scopes)
                        .bind(connect_url)
                        .bind(revoke)
                        .execute(&mut *c)
                        .await?;
                    }
                    Ok::<_, sql::Error>(n)
                })
            })
            .await
            .map_err(|_| SetupError("publish providers"))
    }

    /// [`Self::publish_providers`] in the background, retried with backoff (Postgres may still
    /// be starting); a failure only logs and never blocks the gateway.
    pub fn spawn_publish_providers(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let oauth = Arc::clone(self);
        tokio::spawn(async move {
            let mut wait = Duration::from_secs(1);
            for attempt in 1..=5 {
                match oauth.publish_providers().await {
                    Ok(n) => {
                        tracing::info!(providers = n, "oauth providers published");
                        return;
                    }
                    Err(e) if attempt == 5 => {
                        tracing::warn!(error = %e, "oauth providers not published");
                    }
                    Err(_) => {
                        tokio::time::sleep(wait).await;
                        wait *= 2;
                    }
                }
            }
        })
    }

    /// Revoke and delete `pending_confirm` connections whose flow was not confirmed in time (or
    /// is gone), appending `oauth.connect_failed` `flow_expired` for each, and delete expired
    /// `started` flows (they hold no token). Answers how many connections were discarded.
    pub async fn sweep(self: &Arc<Self>) -> usize {
        let started = self
            .db
            .with_org(self.org_id, |c| {
                Box::pin(async move {
                    sql::query(
                        "DELETE FROM oauth_flows WHERE status = 'started' AND expires_at <= now()",
                    )
                    .execute(c)
                    .await
                    .map(|_| ())
                })
            })
            .await;
        if started.is_err() {
            tracing::warn!("oauth sweep: expired flows not deleted");
        }
        let stale: Result<Vec<(Uuid, Uuid, String)>, sql::Error> = self
            .db
            .with_org(self.org_id, |c| {
                Box::pin(async move {
                    sql::query_as(
                        "SELECT c.id, c.user_id, c.provider FROM oauth_connections c \
                         WHERE c.status = 'pending_confirm' AND NOT EXISTS ( \
                             SELECT 1 FROM oauth_flows f \
                             WHERE f.connection_id = c.id AND f.expires_at > now()) \
                         ORDER BY c.id LIMIT $1",
                    )
                    .bind(SWEEP_BATCH)
                    .fetch_all(c)
                    .await
                })
            })
            .await;
        let Ok(stale) = stale else {
            tracing::warn!("oauth sweep: unconfirmed connections not read");
            return 0;
        };
        let mut swept = 0;
        for (connection_id, person, provider) in stale {
            let oauth = Arc::clone(self);
            let p = provider.clone();
            let discarded = self
                .db
                .with_org(self.org_id, move |c| {
                    Box::pin(async move { discard(&oauth, c, connection_id, &p).await })
                })
                .await;
            match discarded {
                Ok(true) => {
                    swept += 1;
                    self.connect_failed(
                        person,
                        &provider,
                        Some(connection_id),
                        ErrorSlug::FlowExpired,
                    )
                    .await;
                }
                // Another replica or a confirm holds it.
                Ok(false) => {}
                Err(_) => tracing::warn!("oauth sweep: an unconfirmed connection not discarded"),
            }
        }
        if swept > 0 {
            tracing::info!(
                swept,
                "oauth sweep: unconfirmed connections revoked and deleted"
            );
        }
        swept
    }

    /// Run [`Self::sweep`] every `every` until the endpoints are dropped.
    pub fn spawn_sweeper(self: &Arc<Self>, every: Duration) -> tokio::task::JoinHandle<()> {
        let oauth = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                let Some(o) = oauth.upgrade() else { return };
                o.sweep()
                    .instrument(tracing::info_span!("oauth.sweep"))
                    .await;
            }
        })
    }
}

/// One `oauth_providers` row: id, name, scopes, connect URL, revoke support.
type ProviderRow = (String, String, Vec<String>, String, bool);

/// Revoke at the provider and delete one `pending_confirm` connection (its material and flow go
/// with it), under a row lock so one replica does it once. `false` when the connection is gone,
/// no longer pending or locked by someone else.
async fn discard(
    oauth: &OAuth,
    c: &mut sql::PgConnection,
    connection_id: Uuid,
    provider: &str,
) -> Result<bool, sql::Error> {
    type Row = (Option<i32>, Option<Vec<u8>>, Option<Vec<u8>>);
    let row: Option<Row> = sql::query_as(
        "SELECT m.generation, m.ciphertext, m.wrapped_dek FROM oauth_connections c \
         LEFT JOIN oauth_token_material m ON m.connection_id = c.id \
         WHERE c.id = $1 AND c.status = 'pending_confirm' \
         FOR UPDATE OF c SKIP LOCKED",
    )
    .bind(connection_id)
    .fetch_optional(&mut *c)
    .await?;
    let Some(material) = row else {
        return Ok(false);
    };
    if let (Some(generation), Some(ciphertext), Some(wrapped)) = material {
        oauth
            .revoke_sealed(provider, connection_id, generation, &ciphertext, &wrapped)
            .await;
    }
    sql::query("DELETE FROM oauth_connections WHERE id = $1")
        .bind(connection_id)
        .execute(&mut *c)
        .await?;
    Ok(true)
}

/// Why a confirm could not finish. Carries nothing else.
enum ConfirmError {
    /// No such `pending_confirm` flow (or its connection is gone).
    NotFound,
    /// Database, KMS or ledger failure: rolled back.
    Unavailable,
}

impl From<sql::Error> for ConfirmError {
    fn from(_: sql::Error) -> Self {
        Self::Unavailable
    }
}

/// What a consumed `pending_confirm` flow turned into.
enum Confirmed {
    Connected(ConnectionSummary),
    /// The connection was revoked and deleted.
    Failed {
        slug: ErrorSlug,
        owner: Uuid,
        provider: String,
        connection_id: Uuid,
    },
}

/// `POST /v1/oauth/flows/{id}/confirm`.
pub async fn confirm(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(oauth) = state.oauth() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let span = tracing::info_span!(
        "oauth.confirm",
        provider = tracing::field::Empty,
        flow_id = tracing::field::Empty,
        person = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    let result = confirm_flow(oauth, &headers, &id)
        .instrument(span.clone())
        .await;
    match result {
        Ok(summary) => {
            span.record("outcome", "ok");
            (
                [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
                Json(summary),
            )
                .into_response()
        }
        Err(refusal) => {
            span.record("outcome", refusal.outcome());
            refusal.into_response()
        }
    }
}

async fn confirm_flow(
    oauth: Arc<OAuth>,
    headers: &HeaderMap,
    id: &str,
) -> Result<ConnectionSummary, Refusal> {
    let not_found = || Refusal::Slug(StatusCode::NOT_FOUND, ErrorSlug::FlowNotFound);
    let user_id = oauth.person(headers).await?;
    let flow_id = Uuid::parse_str(id).map_err(|_| not_found())?;
    tracing::Span::current().record("flow_id", tracing::field::display(flow_id));
    let o = Arc::clone(&oauth);
    let done = oauth
        .db
        .with_org(oauth.org_id, move |c| {
            Box::pin(async move { consume_flow(&o, c, flow_id, user_id).await })
        })
        .await;
    match done {
        Ok(Confirmed::Connected(summary)) => {
            tracing::Span::current().record("provider", summary.provider.as_str());
            Ok(summary)
        }
        Ok(Confirmed::Failed {
            slug,
            owner,
            provider,
            connection_id,
        }) => {
            tracing::Span::current().record("provider", provider.as_str());
            oauth
                .connect_failed(owner, &provider, Some(connection_id), slug)
                .await;
            let status = match slug {
                ErrorSlug::WrongPerson => StatusCode::FORBIDDEN,
                _ => StatusCode::GONE,
            };
            Err(Refusal::Slug(status, slug))
        }
        Err(ConfirmError::NotFound) => Err(not_found()),
        Err(ConfirmError::Unavailable) => Err(Refusal::Unavailable),
    }
}

/// In one transaction: consume the flow, then activate its connection for its own person, or
/// revoke and delete it for anyone else and for an expired flow.
async fn consume_flow(
    oauth: &OAuth,
    c: &mut sql::PgConnection,
    flow_id: Uuid,
    user_id: Uuid,
) -> Result<Confirmed, ConfirmError> {
    let row: Option<(Uuid, String, Option<Uuid>, bool)> = sql::query_as(
        "DELETE FROM oauth_flows WHERE id = $1 AND status = 'pending_confirm' \
         RETURNING user_id, provider, connection_id, expires_at <= now()",
    )
    .bind(flow_id)
    .fetch_optional(&mut *c)
    .await?;
    let Some((owner, provider, Some(connection_id), expired)) = row else {
        return Err(ConfirmError::NotFound);
    };
    let failed = if owner != user_id {
        Some(ErrorSlug::WrongPerson)
    } else if expired {
        Some(ErrorSlug::FlowExpired)
    } else {
        None
    };
    if let Some(slug) = failed {
        // Locked by the sweeper means it is being discarded already.
        discard(oauth, c, connection_id, &provider).await?;
        return Ok(Confirmed::Failed {
            slug,
            owner,
            provider,
            connection_id,
        });
    }
    let id = activate(oauth, c, connection_id, user_id, &provider)
        .await?
        .ok_or(ConfirmError::NotFound)?;
    let summary = connection_summary(c, id).await?;
    // Before the commit: a ledger that cannot take it rolls the confirm back.
    let recorded = oauth
        .append(OAuthEvent {
            kind: OAuthEventKind::Connected,
            person: user_id,
            provider,
            connection_id: Some(id),
            agent_id: None,
        })
        .await;
    if !recorded {
        tracing::warn!("oauth confirm: oauth.connected not recorded, refused");
        return Err(ConfirmError::Unavailable);
    }
    Ok(Confirmed::Connected(summary))
}

/// Mark the pending connection `connected`; answers the active connection's id. When the person
/// already has a connection to the same account (a reconnect), that one keeps its id and grants,
/// takes the new token set resealed as its next generation, and the pending row is deleted.
/// `None` when the pending connection is gone.
async fn activate(
    oauth: &OAuth,
    c: &mut sql::PgConnection,
    pending_id: Uuid,
    user_id: Uuid,
    provider: &str,
) -> Result<Option<Uuid>, ConfirmError> {
    let account_id: Option<String> = sql::query_scalar(
        "SELECT account_id FROM oauth_connections \
         WHERE id = $1 AND user_id = $2 AND status = 'pending_confirm' FOR UPDATE",
    )
    .bind(pending_id)
    .bind(user_id)
    .fetch_optional(&mut *c)
    .await?;
    let Some(account_id) = account_id else {
        return Ok(None);
    };
    let existing: Option<(Uuid, i32)> = sql::query_as(
        "SELECT id, generation FROM oauth_connections \
         WHERE user_id = $1 AND provider = $2 AND account_id = $3 \
             AND status <> 'pending_confirm' FOR UPDATE",
    )
    .bind(user_id)
    .bind(provider)
    .bind(account_id)
    .fetch_optional(&mut *c)
    .await?;
    let Some((old_id, old_generation)) = existing else {
        sql::query(
            "UPDATE oauth_connections SET status = 'connected', connected_at = now() \
             WHERE id = $1",
        )
        .bind(pending_id)
        .execute(&mut *c)
        .await?;
        return Ok(Some(pending_id));
    };

    let next = old_generation
        .checked_add(1)
        .ok_or(ConfirmError::Unavailable)?;
    let (generation, ciphertext, wrapped): (i32, Vec<u8>, Vec<u8>) = sql::query_as(
        "SELECT generation, ciphertext, wrapped_dek FROM oauth_token_material \
         WHERE connection_id = $1",
    )
    .bind(pending_id)
    .fetch_one(&mut *c)
    .await?;
    let (Ok(generation), Ok(next_u32)) = (u32::try_from(generation), u32::try_from(next)) else {
        return Err(ConfirmError::Unavailable);
    };
    let set = oauth
        .vault
        .open(oauth.org_id, pending_id, generation, &ciphertext, &wrapped)
        .await
        .map_err(|_| ConfirmError::Unavailable)?;
    let sealed = oauth
        .vault
        .seal(oauth.org_id, old_id, next_u32, &set)
        .await
        .map_err(|_| ConfirmError::Unavailable)?;
    drop(set);
    sql::query(
        "INSERT INTO oauth_token_material (org_id, connection_id, generation, ciphertext, \
             wrapped_dek, key_id) \
         VALUES (current_org_id(), $1, $2, $3, $4, $5) \
         ON CONFLICT (connection_id) DO UPDATE SET generation = EXCLUDED.generation, \
             ciphertext = EXCLUDED.ciphertext, wrapped_dek = EXCLUDED.wrapped_dek, \
             key_id = EXCLUDED.key_id",
    )
    .bind(old_id)
    .bind(next)
    .bind(sealed.ciphertext)
    .bind(sealed.wrapped_dek)
    .bind(sealed.key_id)
    .execute(&mut *c)
    .await?;
    sql::query(
        "UPDATE oauth_connections o SET status = 'connected', account_login = p.account_login, \
             scopes = p.scopes, generation = $3, connected_at = now(), \
             expires_at = p.expires_at, last_refreshed_at = NULL, last_error_code = NULL \
         FROM oauth_connections p WHERE o.id = $1 AND p.id = $2",
    )
    .bind(old_id)
    .bind(pending_id)
    .bind(next)
    .execute(&mut *c)
    .await?;
    sql::query("DELETE FROM oauth_connections WHERE id = $1")
        .bind(pending_id)
        .execute(&mut *c)
        .await?;
    Ok(Some(old_id))
}

/// A connection as the console sees it (timestamps RFC 3339, UTC).
async fn connection_summary(
    c: &mut sql::PgConnection,
    id: Uuid,
) -> Result<ConnectionSummary, ConfirmError> {
    type Row = (
        Uuid,
        String,
        String,
        String,
        Vec<String>,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let row: Row = sql::query_as(
        "SELECT id, provider, account_login, account_id, scopes, status, \
             to_char(connected_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
             to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
             to_char(last_refreshed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
             last_error_code \
         FROM oauth_connections WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&mut *c)
    .await?;
    let status = match row.5.as_str() {
        "connected" => ConnectionStatus::Connected,
        "refresh_failed" => ConnectionStatus::RefreshFailed,
        "revoked" => ConnectionStatus::Revoked,
        _ => return Err(ConfirmError::Unavailable),
    };
    Ok(ConnectionSummary {
        id: row.0,
        provider: row.1,
        account_login: row.2,
        account_id: row.3,
        scopes: row.4,
        status,
        connected_at: row.6,
        expires_at: row.7,
        last_refreshed_at: row.8,
        last_error_code: row.9,
        revoked_at_provider: None,
    })
}

/// The sealed token set's plaintext form (version 1). Serialized straight into one
/// pre-sized buffer that [`SecretBytes`] zeroizes.
#[derive(Serialize)]
struct TokenSetOut<'a> {
    v: u8,
    access: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh: Option<&'a str>,
    /// Unix seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<i64>,
    scopes: &'a [String],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenSetIn {
    v: u8,
    access: String,
    #[serde(default)]
    refresh: Option<String>,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    scopes: Vec<String>,
}

/// An opened token set. No `Debug`, `Display` or `Clone`.
pub struct TokenSet {
    pub access: SecretString,
    pub refresh: Option<SecretString>,
    /// Unix seconds.
    pub expires_at: Option<i64>,
    pub scopes: Vec<String>,
}

/// Encode `tokens` for sealing; `now` is the unix time the expiry counts from.
pub fn encode_token_set(tokens: &Tokens, scopes: &[String], now: i64) -> Option<SecretBytes> {
    let access = tokens.access.expose_secret();
    let refresh = tokens.refresh.as_ref().map(|r| r.expose_secret());
    let expires_at = tokens
        .expires_in
        .map(|d| now.saturating_add(i64::try_from(d.as_secs()).unwrap_or(i64::MAX)));
    let out = TokenSetOut {
        v: 1,
        access,
        refresh,
        expires_at,
        scopes,
    };
    // Room for JSON escaping, so the buffer never reallocates and leaves a copy behind.
    let cap = 2 * (access.len() + refresh.map_or(0, str::len))
        + scopes.iter().map(|s| 2 * s.len() + 3).sum::<usize>()
        + 128;
    let mut buf = Vec::with_capacity(cap);
    if serde_json::to_writer(&mut buf, &out).is_err() {
        drop(SecretBytes::new(buf));
        return None;
    }
    Some(SecretBytes::new(buf))
}

/// Decode an opened token set. `None` when it is not a version-1 set.
pub fn decode_token_set(bytes: &SecretBytes) -> Option<TokenSet> {
    let set: TokenSetIn = serde_json::from_slice(bytes.expose()).ok()?;
    if set.v != 1 || set.access.is_empty() {
        return None;
    }
    Some(TokenSet {
        access: SecretString::from(set.access),
        refresh: set.refresh.map(SecretString::from),
        expires_at: set.expires_at,
        scopes: set.scopes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{self, AppState};
    use crate::audit::{MemoryAudit, RefreshFailure};
    use crate::oauth_vault::test_wrapper::MemWrapper;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use http_body_util::BodyExt as _;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use ls_control_plane::auth::human::HumanAuthConfig;
    use ls_control_plane::db::PoolSettings;
    use ls_control_plane::readiness::ReadyFlag;
    use ls_oauth::RefreshKind;
    use ls_oauth::testing::{ACCESS_1, ACCESS_2, CODE, FakeProvider, Kind, REFRESH_1, Refresh};
    use p256::pkcs8::EncodePrivateKey as _;
    use serde_json::{Value, json};
    use std::sync::Mutex;
    use tower::ServiceExt as _;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000c1);
    const OTHER_ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000c2);
    const ISSUER: &str = "https://idp.test/realms/acme";
    const AUDIENCE: &str = "locksmith-api";
    const CONSOLE: &str = "http://console.test";
    const RETURN_TO: &str = "http://console.test/settings/connections";
    const REDIRECT_URL: &str = "http://gateway.test/oauth/callback";

    /// A deterministic throwaway P-256 key for person tokens (test only).
    struct TestKey(p256::ecdsa::SigningKey);

    impl TestKey {
        fn new() -> Self {
            Self(p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap())
        }

        fn jwk(&self) -> Value {
            let point = self.0.verifying_key().to_sec1_point(false);
            json!({
                "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1",
                "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
            })
        }

        fn mint(&self, sub: &str) -> String {
            let mut header = Header::new(Algorithm::ES256);
            header.kid = Some("k1".to_owned());
            let der = self.0.to_pkcs8_der().unwrap();
            let claims = json!({
                "iss": ISSUER, "aud": AUDIENCE, "sub": sub, "exp": now_unix() + 600,
                "email": format!("{sub}@example.test"), "email_verified": true,
            });
            jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ec_der(der.as_bytes()))
                .unwrap()
        }
    }

    fn origins() -> Vec<url::Origin> {
        vec![Url::parse(CONSOLE).unwrap().origin()]
    }

    fn fake_def(fake: &FakeProvider) -> ProviderDef {
        ProviderDef {
            id: "fake".to_owned(),
            name: "Fake".to_owned(),
            authorize_url: format!("{}/authorize", fake.base_url()),
            token_url: fake.token_url(),
            revoke_url: fake.revoke_url(),
            account_url: fake.account_url(),
            refresh: RefreshKind::Static,
            api_hosts: vec!["api.fake.test".to_owned()],
            default_scopes: vec!["fake.read".to_owned()],
        }
    }

    const CONNECT_URL: &str = "http://gateway.test/v1/oauth/connect";

    /// A migrated `postgres:18` (ls-pg-test; needs Docker) with two orgs, alice and bob in
    /// [`ORG`] and mallory in [`OTHER_ORG`]; a JWKS issuer; a Google-shaped fake provider
    /// registered as `fake`; the gateway router with OAuth on, over the `locksmith_gateway` role,
    /// appending `oauth.*` events to a memory ledger.
    struct Harness {
        pg: ls_pg_test::Pg,
        app: Router,
        fake: FakeProvider,
        _idp: MockServer,
        key: TestKey,
        vault: Arc<TokenVault<MemWrapper>>,
        oauth: Arc<OAuth>,
        audit: Arc<MemoryAudit>,
    }

    impl Harness {
        async fn start() -> Self {
            Self::start_with(Refresh::Works).await
        }

        async fn start_with(refresh: Refresh) -> Self {
            let pg = ls_pg_test::Pg::start().await;
            ls_control_plane::migrate::run(pg.bootstrap())
                .await
                .expect("migrate");
            let mut admin = pg.admin().await;
            sql::query("INSERT INTO orgs (id, name) VALUES ($1, 'org-a'), ($2, 'org-b')")
                .bind(ORG)
                .bind(OTHER_ORG)
                .execute(&mut admin)
                .await
                .unwrap();
            for (sub, org) in [("alice", ORG), ("bob", ORG), ("mallory", OTHER_ORG)] {
                sql::query(
                    "INSERT INTO users (issuer, subject, email, email_verified, personal_org_id) \
                     VALUES ($1, $2, $3, true, $4)",
                )
                .bind(ISSUER)
                .bind(sub)
                .bind(format!("{sub}@example.test"))
                .bind(org)
                .execute(&mut admin)
                .await
                .unwrap();
            }
            let key = TestKey::new();
            let idp = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/jwks"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({ "keys": [key.jwk()] })),
                )
                .mount(&idp)
                .await;
            let human = HumanAuth::new(&HumanAuthConfig {
                issuer: ISSUER.to_owned(),
                audience: AUDIENCE.to_owned(),
                jwks_url: format!("{}/jwks", idp.uri()),
            })
            .unwrap();
            let db = Database::connect_lazy(pg.gateway(), PoolSettings::default());
            let vault = Arc::new(TokenVault::new(MemWrapper {
                check_binding: true,
            }));
            let fake = FakeProvider::start_with(Kind::Google, refresh).await;
            let def = fake_def(&fake);
            let http =
                crate::http_client::build(Duration::from_secs(5), Duration::from_secs(10), None)
                    .unwrap();
            let client = OAuthClient::new(
                http,
                endpoints_for(&def),
                "fake-client".to_owned(),
                SecretString::from("fake-client-secret"),
                REDIRECT_URL,
            )
            .unwrap();
            let audit = Arc::new(MemoryAudit::default());
            let oauth = Arc::new(
                OAuth::new(ORG, db, human, vault.clone(), origins())
                    .with_provider(def, client)
                    .with_audit(audit.clone())
                    .with_connect_url(Url::parse(CONNECT_URL).unwrap()),
            );
            let app =
                app::build(AppState::new(Arc::new(ReadyFlag::new(true))).with_oauth(oauth.clone()));
            Self {
                pg,
                app,
                fake,
                _idp: idp,
                key,
                vault,
                oauth,
                audit,
            }
        }

        /// `POST /v1/oauth/flows/{flow}/confirm` as `sub` (no bearer for `None`).
        async fn confirm(&self, sub: Option<&str>, flow: &str) -> (StatusCode, Vec<u8>) {
            let mut req =
                Request::post(format!("/v1/oauth/flows/{flow}/confirm")).header("origin", CONSOLE);
            if let Some(sub) = sub {
                req = req.header("authorization", format!("Bearer {}", self.key.mint(sub)));
            }
            let (status, _, body) = self.send(req.body(Body::empty()).unwrap()).await;
            (status, body)
        }

        /// Start a flow as alice and complete its callback: a `pending_confirm` flow.
        async fn pending_flow(&self) -> Uuid {
            let (flow_id, state) = self.start_flow().await;
            let (loc, _) = self.callback(&[("code", CODE), ("state", &state)]).await;
            assert_eq!(redirect_params(&loc).1, "pending_confirm");
            flow_id
        }

        async fn user_id(&self, sub: &str) -> Uuid {
            let mut admin = self.pg.admin().await;
            sql::query_scalar("SELECT id FROM users WHERE subject = $1")
                .bind(sub)
                .fetch_one(&mut admin)
                .await
                .unwrap()
        }

        /// The revoke calls the fake provider received, with their bodies.
        async fn revokes(&self) -> Vec<String> {
            self.fake
                .requests()
                .await
                .iter()
                .filter(|r| r.url.path() == "/revoke")
                .map(|r| String::from_utf8_lossy(&r.body).into_owned())
                .collect()
        }

        async fn send(&self, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
            let res = self.app.clone().oneshot(req).await.unwrap();
            let status = res.status();
            let headers = res.headers().clone();
            let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
            (status, headers, body)
        }

        async fn connect(&self, sub: Option<&str>, body: Value) -> (StatusCode, Vec<u8>) {
            let mut req = Request::post("/v1/oauth/connect")
                .header("content-type", "application/json")
                .header("origin", CONSOLE);
            if let Some(sub) = sub {
                req = req.header("authorization", format!("Bearer {}", self.key.mint(sub)));
            }
            let (status, _, body) = self
                .send(req.body(Body::from(body.to_string())).unwrap())
                .await;
            (status, body)
        }

        /// Start a flow as alice; answers the flow id and the authorize URL's `state`.
        async fn start_flow(&self) -> (Uuid, String) {
            let (status, body) = self
                .connect(
                    Some("alice"),
                    json!({"provider": "fake", "return_to": RETURN_TO}),
                )
                .await;
            assert_eq!(status, StatusCode::OK);
            let r: ConnectResponse = serde_json::from_slice(&body).unwrap();
            let url = Url::parse(&r.authorize_url).unwrap();
            let state = url
                .query_pairs()
                .find(|(k, _)| k == "state")
                .map(|(_, v)| v.into_owned())
                .unwrap();
            (r.flow_id, state)
        }

        /// The callback with `query`; answers the `Location` and the whole response as text.
        async fn callback(&self, query: &[(&str, &str)]) -> (Url, String) {
            let q = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(query)
                .finish();
            let (status, headers, body) = self
                .send(
                    Request::get(format!("/oauth/callback?{q}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await;
            assert_eq!(status, StatusCode::FOUND);
            assert_eq!(headers["cache-control"], "no-store");
            assert_eq!(headers["referrer-policy"], "no-referrer");
            let location = headers["location"].to_str().unwrap().to_owned();
            let text = format!("{headers:?}{}", String::from_utf8_lossy(&body));
            (Url::parse(&location).unwrap(), text)
        }

        /// A `connected` connection of alice's.
        async fn connected(&self) -> Uuid {
            let flow = self.pending_flow().await;
            let (status, body) = self.confirm(Some("alice"), &flow.to_string()).await;
            assert_eq!(status, StatusCode::OK);
            serde_json::from_slice::<ConnectionSummary>(&body)
                .unwrap()
                .id
        }

        /// Reseal the connection's token set as the next generation expiring in 10 seconds.
        async fn make_due(&self, id: Uuid) {
            let mut admin = self.pg.admin().await;
            let (generation, ciphertext, wrapped): (i32, Vec<u8>, Vec<u8>) = sql::query_as(
                "SELECT generation, ciphertext, wrapped_dek FROM oauth_token_material \
                 WHERE connection_id = $1",
            )
            .bind(id)
            .fetch_one(&mut admin)
            .await
            .unwrap();
            let g = u32::try_from(generation).unwrap();
            let opened = self
                .vault
                .open(ORG, id, g, &ciphertext, &wrapped)
                .await
                .unwrap();
            let set = decode_token_set(&opened).unwrap();
            let tokens = Tokens {
                access: set.access,
                refresh: set.refresh,
                expires_in: Some(Duration::from_secs(10)),
                scopes: set.scopes.clone(),
            };
            let plain = encode_token_set(&tokens, &set.scopes, now_unix()).unwrap();
            let sealed = self.vault.seal(ORG, id, g + 1, &plain).await.unwrap();
            sql::query(
                "UPDATE oauth_token_material SET generation = $2, ciphertext = $3, \
                     wrapped_dek = $4, key_id = $5 WHERE connection_id = $1",
            )
            .bind(id)
            .bind(generation + 1)
            .bind(sealed.ciphertext)
            .bind(sealed.wrapped_dek)
            .bind(sealed.key_id)
            .execute(&mut admin)
            .await
            .unwrap();
            sql::query("UPDATE oauth_connections SET generation = $2 WHERE id = $1")
                .bind(id)
                .bind(generation + 1)
                .execute(&mut admin)
                .await
                .unwrap();
        }

        async fn refresh_calls(&self) -> usize {
            self.fake
                .requests()
                .await
                .iter()
                .filter(|r| {
                    r.url.path() == "/token"
                        && String::from_utf8_lossy(&r.body).contains("grant_type=refresh_token")
                })
                .count()
        }

        async fn token_calls(&self) -> usize {
            self.fake
                .requests()
                .await
                .iter()
                .filter(|r| r.url.path() == "/token")
                .count()
        }

        async fn count(&self, query: &'static str) -> i64 {
            let mut admin = self.pg.admin().await;
            sql::query_scalar(query)
                .fetch_one(&mut admin)
                .await
                .unwrap()
        }
    }

    /// The `flow` and `result` of a callback redirect; asserts nothing else is in the query.
    fn redirect_params(location: &Url) -> (Option<String>, String) {
        let pairs: Vec<(String, String)> = location
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        for (k, _) in &pairs {
            assert!(k == "flow" || k == "result", "unexpected parameter {k}");
        }
        let get = |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        (get("flow"), get("result").expect("result"))
    }

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Happy path, then the same `state` replayed: one exchange, a `pending_confirm` connection
    /// with the sealed token set, a redirect with the flow id and slug only, and no token, code,
    /// `state` or verifier in any response, redirect or trace-level log line.
    #[tokio::test]
    async fn oauth_connect_and_callback_happy_path_then_replay() {
        let cap = Capture::default();
        let writer = cap.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let h = Harness::start().await;
        let (flow_id, state) = h.start_flow().await;

        // The flow row: hashed state, sealed verifier, 10-minute expiry, alice's id.
        let mut admin = h.pg.admin().await;
        let (hash, sealed, status, ttl_ok): (Vec<u8>, Vec<u8>, String, bool) = sql::query_as(
            "SELECT state_hash, sealed_verifier, status, \
                 expires_at BETWEEN now() + interval '9 minutes' AND now() + interval '10 minutes' \
             FROM oauth_flows WHERE id = $1",
        )
        .bind(flow_id)
        .fetch_one(&mut admin)
        .await
        .unwrap();
        assert_eq!(hash, Sha256::digest(state.as_bytes()).to_vec());
        assert_eq!(status, "started");
        assert!(ttl_ok, "flow expires in 10 minutes");

        let (location, response) = h.callback(&[("code", CODE), ("state", &state)]).await;
        assert_eq!(location.origin(), Url::parse(CONSOLE).unwrap().origin());
        assert_eq!(location.path(), "/settings/connections");
        let (flow, result) = redirect_params(&location);
        assert_eq!(flow, Some(flow_id.to_string()));
        assert_eq!(result, "pending_confirm");

        // The exchange sent the PKCE verifier, which is stored only sealed.
        let token_requests: Vec<String> = h
            .fake
            .requests()
            .await
            .iter()
            .filter(|r| r.url.path() == "/token")
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
            .collect();
        assert_eq!(token_requests.len(), 1);
        let verifier = url::form_urlencoded::parse(token_requests[0].as_bytes())
            .find(|(k, _)| k == "code_verifier")
            .map(|(_, v)| v.into_owned())
            .expect("PKCE verifier sent");
        assert!(verifier.len() >= 43);
        assert!(
            !sealed
                .windows(verifier.len())
                .any(|w| w == verifier.as_bytes()),
            "verifier stored in the clear"
        );

        // The pending connection, its sealed material and the pending flow.
        let (conn, status, account_id, login, scopes): (Uuid, String, String, String, Vec<String>) =
            sql::query_as(
                "SELECT c.id, c.status, c.account_id, c.account_login, c.scopes \
                 FROM oauth_flows f JOIN oauth_connections c ON c.id = f.connection_id \
                 WHERE f.id = $1 AND f.status = 'pending_confirm'",
            )
            .bind(flow_id)
            .fetch_one(&mut admin)
            .await
            .unwrap();
        assert_eq!(status, "pending_confirm");
        assert_eq!(
            (account_id.as_str(), login.as_str()),
            ("g-1001", "alice@example.test")
        );
        assert_eq!(scopes, vec!["fake.scope".to_owned()]);
        let (generation, ciphertext, wrapped): (i32, Vec<u8>, Vec<u8>) = sql::query_as(
            "SELECT generation, ciphertext, wrapped_dek FROM oauth_token_material \
             WHERE connection_id = $1",
        )
        .bind(conn)
        .fetch_one(&mut admin)
        .await
        .unwrap();
        assert_eq!(generation, 1);
        for blob in [&ciphertext, &wrapped] {
            for t in [ACCESS_1, REFRESH_1] {
                assert!(!blob.windows(t.len()).any(|w| w == t.as_bytes()));
            }
        }
        let opened = h
            .vault
            .open(ORG, conn, 1, &ciphertext, &wrapped)
            .await
            .unwrap();
        let set = decode_token_set(&opened).unwrap();
        assert!(set.access.expose_secret() == ACCESS_1);
        assert!(set.refresh.as_ref().unwrap().expose_secret() == REFRESH_1);
        assert!(set.expires_at.unwrap() > now_unix());

        // Replay: the state is spent, nothing is exchanged again.
        let (replay, replay_response) = h.callback(&[("code", CODE), ("state", &state)]).await;
        assert_eq!(
            replay.as_str(),
            "http://console.test/?result=flow_not_found"
        );
        assert_eq!(h.token_calls().await, 1);
        assert_eq!(
            h.count("SELECT count(*) FROM oauth_connections").await,
            1,
            "no second connection"
        );

        let logs = String::from_utf8_lossy(&cap.0.lock().unwrap()).into_owned();
        assert!(logs.contains("oauth.callback"), "callback span captured");
        for (what, text) in [
            ("redirect", location.as_str()),
            ("callback response", &response),
            ("replay response", &replay_response),
            ("logs", &logs),
        ] {
            for needle in [ACCESS_1, REFRESH_1, verifier.as_str()] {
                assert!(
                    !text.contains(needle),
                    "{what} leaks a token or the verifier"
                );
            }
            if what != "logs" {
                assert!(!text.contains(CODE) && !text.contains(&state), "{what}");
            }
        }
        // The callback's own log lines never carry the code or state either (the request line
        // is not logged by the gateway).
        assert!(!logs.contains(&state), "logs leak the state");
    }

    /// An expired flow, a provider `error=access_denied` and a refused code all consume the
    /// flow and redirect with their slug; only the refused code reaches the token endpoint.
    #[tokio::test]
    async fn oauth_callback_expired_denied_and_failed_exchange() {
        let h = Harness::start().await;

        let (expired_id, state) = h.start_flow().await;
        let mut admin = h.pg.admin().await;
        sql::query("UPDATE oauth_flows SET expires_at = now() - interval '1 second' WHERE id = $1")
            .bind(expired_id)
            .execute(&mut admin)
            .await
            .unwrap();
        let (loc, _) = h.callback(&[("code", CODE), ("state", &state)]).await;
        assert_eq!(
            redirect_params(&loc),
            (Some(expired_id.to_string()), "flow_expired".to_owned())
        );

        let (denied_id, state) = h.start_flow().await;
        let (loc, _) = h
            .callback(&[
                ("error", "access_denied"),
                ("error_description", "The user denied <b>access</b>"),
                ("state", &state),
            ])
            .await;
        assert_eq!(
            redirect_params(&loc),
            (Some(denied_id.to_string()), "provider_error".to_owned())
        );
        assert!(!loc.as_str().contains("denied"), "provider text not echoed");
        assert_eq!(h.token_calls().await, 0);

        let (failed_id, state) = h.start_flow().await;
        let (loc, _) = h
            .callback(&[("code", "not-the-code"), ("state", &state)])
            .await;
        assert_eq!(
            redirect_params(&loc),
            (Some(failed_id.to_string()), "exchange_failed".to_owned())
        );
        assert_eq!(h.token_calls().await, 1);

        // Each failure is in the ledger as `oauth.connect_failed`, with alice and no connection.
        let alice = h.user_id("alice").await;
        let kinds: Vec<OAuthEventKind> = h
            .audit
            .oauth_events()
            .into_iter()
            .map(|e| {
                assert_eq!((e.person, e.provider.as_str()), (alice, "fake"));
                assert_eq!((e.connection_id, e.agent_id), (None, None));
                e.kind
            })
            .collect();
        assert_eq!(
            kinds,
            [
                ConnectFailure::FlowExpired,
                ConnectFailure::ProviderError,
                ConnectFailure::ExchangeFailed
            ]
            .map(OAuthEventKind::ConnectFailed)
        );

        // Every flow was consumed and nothing was connected.
        assert_eq!(h.count("SELECT count(*) FROM oauth_flows").await, 0);
        assert_eq!(h.count("SELECT count(*) FROM oauth_connections").await, 0);
        assert_eq!(
            h.count("SELECT count(*) FROM oauth_token_material").await,
            0
        );
    }

    /// Refusals before any flow is written: no or bad bearer, an unknown person, a person of
    /// another org, an unknown provider and a `return_to` off the allow-list. Extra scopes in the
    /// body are ignored. CORS answers the console origin only.
    #[tokio::test]
    async fn oauth_connect_refusals_and_cors() {
        let h = Harness::start().await;
        let ok_body = json!({"provider": "fake", "return_to": RETURN_TO});

        assert_eq!(
            h.connect(None, ok_body.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        let (status, _, _) = h
            .send(
                Request::post("/v1/oauth/connect")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer not-a-jwt")
                    .body(Body::from(ok_body.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // A valid token for an identity with no user: refused, and no user is created.
        assert_eq!(
            h.connect(Some("nobody"), ok_body.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(h.count("SELECT count(*) FROM users").await, 3);
        assert_eq!(
            h.connect(Some("mallory"), ok_body.clone()).await.0,
            StatusCode::FORBIDDEN
        );

        let (status, body) = h
            .connect(
                Some("alice"),
                json!({"provider": "dropbox", "return_to": RETURN_TO}),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"error": "unknown_provider"})
        );

        for bad in [
            "https://evil.test/settings",
            "http://console.test.evil.test/",
            "https://console.test/settings",
            "http://console.test:8080/settings",
            "http://user@console.test/settings",
            "http://console.test/settings#frag",
            "/settings/connections",
            "javascript:alert(1)",
            "",
        ] {
            let (status, body) = h
                .connect(Some("alice"), json!({"provider": "fake", "return_to": bad}))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap(),
                json!({"error": "return_to_not_allowed"}),
                "{bad}"
            );
        }
        assert_eq!(h.count("SELECT count(*) FROM oauth_flows").await, 0);

        // Scopes come from the registry, whatever the body says.
        let (status, body) = h
            .connect(
                Some("alice"),
                json!({"provider": "fake", "return_to": RETURN_TO, "scopes": ["admin"], "scope": "admin"}),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let r: ConnectResponse = serde_json::from_slice(&body).unwrap();
        let url = Url::parse(&r.authorize_url).unwrap();
        let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(q["scope"], "fake.read");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["redirect_uri"], REDIRECT_URL);
        assert!(url.as_str().starts_with(&h.fake.base_url()));
        let state_bytes = URL_SAFE_NO_PAD.decode(&q["state"]).unwrap();
        assert_eq!(state_bytes.len(), 32, "state is 32 random bytes");
        assert_eq!(h.count("SELECT count(*) FROM oauth_flows").await, 1);

        // Unknown or missing state on the callback.
        for query in [
            vec![("code", CODE)],
            vec![("code", CODE), ("state", "forged")],
        ] {
            let (loc, _) = h.callback(&query).await;
            assert_eq!(loc.as_str(), "http://console.test/?result=flow_not_found");
        }

        // CORS: preflight from the console origin succeeds, another origin gets no grant.
        for (origin, allowed) in [(CONSOLE, true), ("https://evil.test", false)] {
            let (_, headers, _) = h
                .send(
                    Request::builder()
                        .method(Method::OPTIONS)
                        .uri("/v1/oauth/connect")
                        .header("origin", origin)
                        .header("access-control-request-method", "POST")
                        .header(
                            "access-control-request-headers",
                            "authorization,content-type",
                        )
                        .body(Body::empty())
                        .unwrap(),
                )
                .await;
            assert_eq!(
                headers.get("access-control-allow-origin").is_some(),
                allowed,
                "{origin}"
            );
            if allowed {
                assert_eq!(headers["access-control-allow-origin"], CONSOLE);
            }
        }
        // The non-OAuth routes carry no CORS grant.
        let (_, headers, _) = h
            .send(
                Request::get("/healthz")
                    .header("origin", CONSOLE)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert!(headers.get("access-control-allow-origin").is_none());
    }

    /// A person verifier that is never called.
    fn offline_human() -> HumanAuth {
        HumanAuth::new(&HumanAuthConfig {
            issuer: ISSUER.to_owned(),
            audience: AUDIENCE.to_owned(),
            jwks_url: "http://127.0.0.1:1/jwks".to_owned(),
        })
        .unwrap()
    }

    fn slug_body(body: &[u8]) -> Value {
        serde_json::from_slice(body).unwrap()
    }

    /// The person who started the flow confirms it: the connection is `connected`, the flow is
    /// spent, `oauth.connected` names alice, the provider and the connection, and the answer is a
    /// summary with no token. A second full flow to the same account (a reconnect) keeps the
    /// connection's id and reseals the new tokens as generation 2.
    #[tokio::test]
    async fn oauth_confirm_activates_for_the_person_who_started_it() {
        let h = Harness::start().await;
        let alice = h.user_id("alice").await;
        let flow_id = h.pending_flow().await;

        let (status, body) = h.confirm(Some("alice"), &flow_id.to_string()).await;
        assert_eq!(status, StatusCode::OK);
        let text = String::from_utf8_lossy(&body).into_owned();
        for t in [ACCESS_1, REFRESH_1] {
            assert!(!text.contains(t), "confirm answer leaks a token");
        }
        let summary: ConnectionSummary = serde_json::from_slice(&body).unwrap();
        assert_eq!(summary.status, ConnectionStatus::Connected);
        assert_eq!(summary.provider, "fake");
        assert_eq!(
            (summary.account_id.as_str(), summary.account_login.as_str()),
            ("g-1001", "alice@example.test")
        );
        assert_eq!(summary.scopes, vec!["fake.scope".to_owned()]);
        assert!(summary.connected_at.ends_with('Z'));
        assert!(summary.expires_at.is_some());
        assert!(summary.revoked_at_provider.is_none());
        assert_eq!(
            h.count("SELECT count(*) FROM oauth_connections WHERE status = 'connected'")
                .await,
            1
        );
        assert_eq!(h.count("SELECT count(*) FROM oauth_flows").await, 0);
        assert_eq!(
            h.audit.oauth_events(),
            vec![OAuthEvent {
                kind: OAuthEventKind::Connected,
                person: alice,
                provider: "fake".to_owned(),
                connection_id: Some(summary.id),
                agent_id: None,
            }]
        );
        assert!(h.revokes().await.is_empty(), "nothing revoked");

        // Spent: a second confirm finds nothing.
        let (status, body) = h.confirm(Some("alice"), &flow_id.to_string()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(slug_body(&body), json!({"error": "flow_not_found"}));

        // Reconnect to the same account: same connection, next generation, pending row gone.
        let again = h.pending_flow().await;
        let (status, body) = h.confirm(Some("alice"), &again.to_string()).await;
        assert_eq!(status, StatusCode::OK);
        let second: ConnectionSummary = serde_json::from_slice(&body).unwrap();
        assert_eq!(second.id, summary.id);
        assert_eq!(h.count("SELECT count(*) FROM oauth_connections").await, 1);
        let mut admin = h.pg.admin().await;
        let (generation, ciphertext, wrapped): (i32, Vec<u8>, Vec<u8>) = sql::query_as(
            "SELECT generation, ciphertext, wrapped_dek FROM oauth_token_material \
             WHERE connection_id = $1",
        )
        .bind(summary.id)
        .fetch_one(&mut admin)
        .await
        .unwrap();
        assert_eq!(generation, 2);
        let conn_generation: i32 =
            sql::query_scalar("SELECT generation FROM oauth_connections WHERE id = $1")
                .bind(summary.id)
                .fetch_one(&mut admin)
                .await
                .unwrap();
        assert_eq!(conn_generation, 2);
        let opened = h
            .vault
            .open(ORG, summary.id, 2, &ciphertext, &wrapped)
            .await
            .unwrap();
        assert!(decode_token_set(&opened).unwrap().access.expose_secret() == ACCESS_1);
        assert_eq!(h.audit.oauth_events().len(), 2);
    }

    /// Confirm by anyone but the person who started the flow: a person of another org is refused
    /// before the flow is touched; bob in the same org gets `wrong_person`, the tokens are revoked
    /// at the provider, the connection, material and flow deleted, and `oauth.connect_failed`
    /// names alice's flow. Alice cannot confirm it afterwards.
    #[tokio::test]
    async fn oauth_confirm_by_another_person_is_wrong_person_and_revokes() {
        let h = Harness::start().await;
        let alice = h.user_id("alice").await;
        let flow_id = h.pending_flow().await;
        let conn: Uuid = {
            let mut admin = h.pg.admin().await;
            sql::query_scalar("SELECT connection_id FROM oauth_flows WHERE id = $1")
                .bind(flow_id)
                .fetch_one(&mut admin)
                .await
                .unwrap()
        };

        let (status, body) = h.confirm(Some("mallory"), &flow_id.to_string()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.is_empty());
        let (status, _) = h.confirm(None, &flow_id.to_string()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(h.count("SELECT count(*) FROM oauth_flows").await, 1);

        let (status, body) = h.confirm(Some("bob"), &flow_id.to_string()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(slug_body(&body), json!({"error": "wrong_person"}));
        let revokes = h.revokes().await;
        assert_eq!(revokes.len(), 1, "revoked once at the provider");
        assert!(
            revokes[0].contains(REFRESH_1),
            "the refresh token is revoked"
        );
        for query in [
            "SELECT count(*) FROM oauth_flows",
            "SELECT count(*) FROM oauth_connections",
            "SELECT count(*) FROM oauth_token_material",
        ] {
            assert_eq!(h.count(query).await, 0, "{query}");
        }
        assert_eq!(
            h.audit.oauth_events(),
            vec![OAuthEvent {
                kind: OAuthEventKind::ConnectFailed(ConnectFailure::WrongPerson),
                person: alice,
                provider: "fake".to_owned(),
                connection_id: Some(conn),
                agent_id: None,
            }]
        );

        let (status, body) = h.confirm(Some("alice"), &flow_id.to_string()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(slug_body(&body), json!({"error": "flow_not_found"}));
    }

    /// Unknown, malformed and not-yet-called-back flows are `flow_not_found`; an expired pending
    /// flow is `flow_expired`, revoked and deleted. A ledger that cannot take `oauth.connected`
    /// refuses the confirm and leaves the flow pending.
    #[tokio::test]
    async fn oauth_confirm_expired_unknown_and_unrecorded_flows() {
        let h = Harness::start().await;
        for id in [Uuid::now_v7().to_string(), "not-a-uuid".to_owned()] {
            let (status, body) = h.confirm(Some("alice"), &id).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{id}");
            assert_eq!(slug_body(&body), json!({"error": "flow_not_found"}));
        }
        let (started, _) = h.start_flow().await;
        let (status, _) = h.confirm(Some("alice"), &started.to_string()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            h.count("SELECT count(*) FROM oauth_flows WHERE status = 'started'")
                .await,
            1,
            "a started flow is not consumed by a confirm"
        );

        let expired = h.pending_flow().await;
        let mut admin = h.pg.admin().await;
        sql::query("UPDATE oauth_flows SET expires_at = now() - interval '1 second' WHERE id = $1")
            .bind(expired)
            .execute(&mut admin)
            .await
            .unwrap();
        let (status, body) = h.confirm(Some("alice"), &expired.to_string()).await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(slug_body(&body), json!({"error": "flow_expired"}));
        assert_eq!(h.revokes().await.len(), 1);
        assert_eq!(h.count("SELECT count(*) FROM oauth_connections").await, 0);
        assert_eq!(
            h.audit
                .oauth_events()
                .iter()
                .map(|e| e.kind)
                .collect::<Vec<_>>(),
            vec![OAuthEventKind::ConnectFailed(ConnectFailure::FlowExpired)]
        );

        // The ledger refuses: nothing is activated and the flow can be confirmed later.
        let audit = Arc::new(MemoryAudit {
            fail: true,
            ..MemoryAudit::default()
        });
        let pending = h.pending_flow().await;
        let o = Arc::clone(&h.oauth);
        let pending_conn = {
            let mut admin = h.pg.admin().await;
            sql::query_scalar::<_, Uuid>("SELECT connection_id FROM oauth_flows WHERE id = $1")
                .bind(pending)
                .fetch_one(&mut admin)
                .await
                .unwrap()
        };
        let result = {
            let failing = Arc::new(
                OAuth::new(
                    ORG,
                    o.db.clone(),
                    offline_human(),
                    o.vault.clone(),
                    origins(),
                )
                .with_audit(audit),
            );
            let f = Arc::clone(&failing);
            let alice = h.user_id("alice").await;
            failing
                .db
                .with_org(ORG, move |c| {
                    Box::pin(async move { consume_flow(&f, c, pending, alice).await })
                })
                .await
        };
        assert!(matches!(result, Err(ConfirmError::Unavailable)));
        let status: String =
            sql::query_scalar("SELECT status FROM oauth_connections WHERE id = $1")
                .bind(pending_conn)
                .fetch_one(&mut admin)
                .await
                .unwrap();
        assert_eq!(status, "pending_confirm", "rolled back");
        let (status, _) = h.confirm(Some("alice"), &pending.to_string()).await;
        assert_eq!(status, StatusCode::OK, "still confirmable");
    }

    /// The sweeper revokes and deletes a `pending_confirm` connection whose flow expired (one
    /// revoke call, `oauth.connect_failed` `flow_expired`), drops expired `started` flows, and
    /// leaves flows still in time alone; a second sweep finds nothing.
    #[tokio::test]
    async fn oauth_sweep_revokes_and_deletes_unconfirmed_flows() {
        let h = Harness::start().await;
        let alice = h.user_id("alice").await;
        let stale = h.pending_flow().await;
        let fresh = h.pending_flow().await;
        let (started, _) = h.start_flow().await;
        let mut admin = h.pg.admin().await;
        sql::query(
            "UPDATE oauth_flows SET expires_at = now() - interval '1 second' \
             WHERE id = ANY($1)",
        )
        .bind(vec![stale, started])
        .execute(&mut admin)
        .await
        .unwrap();
        let stale_conn: Uuid =
            sql::query_scalar("SELECT connection_id FROM oauth_flows WHERE id = $1")
                .bind(stale)
                .fetch_one(&mut admin)
                .await
                .unwrap();

        assert_eq!(h.oauth.sweep().await, 1);
        assert_eq!(h.revokes().await.len(), 1);
        let left: Vec<Uuid> = sql::query_scalar("SELECT id FROM oauth_flows ORDER BY id")
            .fetch_all(&mut admin)
            .await
            .unwrap();
        assert_eq!(left, vec![fresh], "only the flow still in time is left");
        assert_eq!(h.count("SELECT count(*) FROM oauth_connections").await, 1);
        assert_eq!(
            h.count("SELECT count(*) FROM oauth_token_material").await,
            1
        );
        assert_eq!(
            h.audit.oauth_events(),
            vec![OAuthEvent {
                kind: OAuthEventKind::ConnectFailed(ConnectFailure::FlowExpired),
                person: alice,
                provider: "fake".to_owned(),
                connection_id: Some(stale_conn),
                agent_id: None,
            }]
        );
        assert_eq!(h.oauth.sweep().await, 0);
        assert_eq!(h.revokes().await.len(), 1);

        // The background sweeper does the same once the fresh flow expires.
        sql::query("UPDATE oauth_flows SET expires_at = now() - interval '1 second'")
            .execute(&mut admin)
            .await
            .unwrap();
        let task = h.oauth.spawn_sweeper(Duration::from_millis(20));
        for _ in 0..200 {
            if h.count("SELECT count(*) FROM oauth_connections").await == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        task.abort();
        assert_eq!(h.count("SELECT count(*) FROM oauth_connections").await, 0);
        assert_eq!(h.revokes().await.len(), 2);
    }

    /// A fresh token is returned with no provider call and no lock; one within 60 s of expiry
    /// is refreshed once: generation + 1, the new access token returned and sealed, the old
    /// refresh token kept (Google sends none), `last_refreshed_at` set and the new token
    /// reopened under the new generation only.
    #[tokio::test]
    async fn oauth_refresh_on_use_reseals_the_next_generation() {
        let h = Harness::start().await;
        let id = h.connected().await;

        let t = h.oauth.access_token(id, None).await.ok().unwrap();
        assert_eq!(t.token.expose_secret(), ACCESS_1);
        assert_eq!(h.refresh_calls().await, 0, "a fresh token is not refreshed");

        h.make_due(id).await;
        let t = h.oauth.access_token(id, None).await.ok().unwrap();
        assert_eq!(t.token.expose_secret(), ACCESS_2);
        assert_eq!(t.provider, "fake");
        assert_eq!(h.refresh_calls().await, 1);
        // Now fresh again: served without another call.
        let t = h.oauth.access_token(id, None).await.ok().unwrap();
        assert_eq!(t.token.expose_secret(), ACCESS_2);
        assert_eq!(h.refresh_calls().await, 1);

        let mut admin = h.pg.admin().await;
        let (generation, ciphertext, wrapped): (i32, Vec<u8>, Vec<u8>) = sql::query_as(
            "SELECT generation, ciphertext, wrapped_dek FROM oauth_token_material \
             WHERE connection_id = $1",
        )
        .bind(id)
        .fetch_one(&mut admin)
        .await
        .unwrap();
        assert_eq!(generation, 3, "confirm 1, make_due 2, refresh 3");
        assert!(
            h.vault
                .open(ORG, id, 2, &ciphertext, &wrapped)
                .await
                .is_err()
        );
        let opened = h
            .vault
            .open(ORG, id, 3, &ciphertext, &wrapped)
            .await
            .unwrap();
        let set = decode_token_set(&opened).unwrap();
        assert_eq!(set.access.expose_secret(), ACCESS_2);
        assert_eq!(set.refresh.unwrap().expose_secret(), REFRESH_1, "kept");
        let (conn_generation, refreshed): (i32, bool) = sql::query_as(
            "SELECT generation, last_refreshed_at IS NOT NULL FROM oauth_connections \
             WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&mut admin)
        .await
        .unwrap();
        assert_eq!((conn_generation, refreshed), (3, true));
        assert!(
            h.audit
                .oauth_events()
                .iter()
                .all(|e| !matches!(e.kind, OAuthEventKind::RefreshFailed(_)))
        );
    }

    /// Concurrent relays on a due token make exactly one provider refresh call and all get the
    /// refreshed token (the others wait on the row lock and re-read the generation).
    #[tokio::test]
    async fn oauth_refresh_concurrent_relays_make_one_provider_call() {
        let h = Harness::start().await;
        let id = h.connected().await;
        h.make_due(id).await;
        let tasks: Vec<_> = (0..6)
            .map(|_| {
                let o = Arc::clone(&h.oauth);
                tokio::spawn(async move { o.access_token(id, None).await })
            })
            .collect();
        let mut results = Vec::new();
        for t in tasks {
            results.push(t.await.unwrap());
        }
        for r in results {
            assert_eq!(r.ok().unwrap().token.expose_secret(), ACCESS_2);
        }
        assert_eq!(h.refresh_calls().await, 1);
    }

    /// `invalid_grant`: the connection becomes `refresh_failed`, `oauth.refresh_failed` names the
    /// person, connection and agent, the stored generation is unchanged, and every later use
    /// answers needs-reconnect without calling the provider again.
    #[tokio::test]
    async fn oauth_refresh_invalid_grant_needs_reconnect() {
        let h = Harness::start_with(Refresh::InvalidGrant).await;
        let alice = h.user_id("alice").await;
        let id = h.connected().await;
        h.make_due(id).await;
        let agent = Uuid::from_u128(77);

        let err = h.oauth.access_token(id, Some(agent)).await.err().unwrap();
        assert_eq!(err, AccessError::NeedsReconnect);
        assert_eq!(h.refresh_calls().await, 1);
        let mut admin = h.pg.admin().await;
        let (status, code, generation): (String, Option<String>, i32) = sql::query_as(
            "SELECT status, last_error_code, generation FROM oauth_connections WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&mut admin)
        .await
        .unwrap();
        assert_eq!(
            (status.as_str(), code.as_deref(), generation),
            ("refresh_failed", Some("invalid_grant"), 2)
        );
        let failed: Vec<_> = h
            .audit
            .oauth_events()
            .into_iter()
            .filter(|e| matches!(e.kind, OAuthEventKind::RefreshFailed(_)))
            .collect();
        assert_eq!(
            failed,
            vec![OAuthEvent {
                kind: OAuthEventKind::RefreshFailed(RefreshFailure::InvalidGrant),
                person: alice,
                provider: "fake".to_owned(),
                connection_id: Some(id),
                agent_id: Some(agent),
            }]
        );
        let again = h.oauth.access_token(id, None).await.err().unwrap();
        assert_eq!(again, AccessError::NeedsReconnect);
        assert_eq!(h.refresh_calls().await, 1, "no second provider call");
    }

    /// A transient provider failure keeps the generation and the connection `connected`; the
    /// next use, once the provider is back, refreshes. An unknown, pending or foreign-org
    /// connection id is `NotFound`.
    #[tokio::test]
    async fn oauth_refresh_transient_failure_keeps_the_generation() {
        let h = Harness::start().await;
        let id = h.connected().await;
        h.make_due(id).await;
        h.fake.fail_refresh_transiently().await;

        let err = h.oauth.access_token(id, None).await.err().unwrap();
        assert_eq!(err, AccessError::Provider);
        let mut admin = h.pg.admin().await;
        let (status, generation): (String, i32) =
            sql::query_as("SELECT status, generation FROM oauth_connections WHERE id = $1")
                .bind(id)
                .fetch_one(&mut admin)
                .await
                .unwrap();
        assert_eq!((status.as_str(), generation), ("connected", 2));
        assert!(
            h.audit
                .oauth_events()
                .iter()
                .all(|e| !matches!(e.kind, OAuthEventKind::RefreshFailed(_)))
        );

        let missing = h.oauth.access_token(Uuid::from_u128(5), None).await.err();
        assert_eq!(missing, Some(AccessError::NotFound));
        let pending = h.pending_flow().await;
        let pending_id: Uuid =
            sql::query_scalar("SELECT connection_id FROM oauth_flows WHERE id = $1")
                .bind(pending)
                .fetch_one(&mut admin)
                .await
                .unwrap();
        let err = h.oauth.access_token(pending_id, None).await.err();
        assert_eq!(err, Some(AccessError::NotFound), "pending is not usable");
    }

    /// Startup publishes the enabled providers into `oauth_providers` (decision 9): id, name,
    /// registry scopes, the connect URL and revoke support; never a client id or secret. A
    /// second publish updates the same row.
    #[tokio::test]
    async fn oauth_providers_are_published() {
        let h = Harness::start().await;
        assert_eq!(h.oauth.publish_providers().await, Ok(1));
        assert_eq!(h.oauth.publish_providers().await, Ok(1));
        let mut admin = h.pg.admin().await;
        let row: (Uuid, String, String, Vec<String>, String, bool) = sql::query_as(
            "SELECT org_id, provider, name, scopes, connect_url, revoke_supported \
             FROM oauth_providers",
        )
        .fetch_one(&mut admin)
        .await
        .unwrap();
        assert_eq!(
            row,
            (
                ORG,
                "fake".to_owned(),
                "Fake".to_owned(),
                vec!["fake.read".to_owned()],
                CONNECT_URL.to_owned(),
                true
            )
        );
        let all: String =
            sql::query_scalar("SELECT string_agg(oauth_providers::text, ',') FROM oauth_providers")
                .fetch_one(&mut admin)
                .await
                .unwrap();
        assert!(!all.contains("fake-client"), "no client id or secret");

        // Without a connect URL there is nothing to publish.
        let bare = OAuth::new(
            ORG,
            h.oauth.db.clone(),
            offline_human(),
            h.oauth.vault.clone(),
            origins(),
        );
        assert_eq!(
            bare.publish_providers().await,
            Err(SetupError("connect url"))
        );
    }

    /// Without OAuth configured the endpoints answer `503`.
    #[tokio::test]
    async fn oauth_endpoints_off_without_configuration() {
        let app = app::build(AppState::new(Arc::new(ReadyFlag::new(true))));
        for req in [
            Request::post(format!("/v1/oauth/flows/{}/confirm", Uuid::now_v7()))
                .body(Body::empty())
                .unwrap(),
            Request::post("/v1/oauth/connect")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
            Request::get("/oauth/callback?state=x")
                .body(Body::empty())
                .unwrap(),
        ] {
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    #[test]
    fn oauth_token_set_round_trips_without_debug() {
        let tokens = Tokens {
            access: SecretString::from("a-1"),
            refresh: None,
            expires_in: Some(Duration::from_secs(60)),
            scopes: vec![],
        };
        let set = encode_token_set(&tokens, &["s1".to_owned()], 1_000).unwrap();
        let back = decode_token_set(&set).unwrap();
        assert!(back.access.expose_secret() == "a-1");
        assert!(back.refresh.is_none());
        assert_eq!(back.expires_at, Some(1_060));
        assert_eq!(back.scopes, vec!["s1".to_owned()]);
        assert!(
            decode_token_set(&SecretBytes::new(b"{\"v\":2,\"access\":\"x\"}".to_vec())).is_none()
        );
    }

    #[test]
    fn oauth_redirect_carries_flow_and_result_only() {
        let id = Uuid::from_u128(1);
        let res = redirect(
            "http://console.test/c?tab=x&result=forged&flow=forged",
            Some(id),
            "pending_confirm",
        );
        assert_eq!(res.status(), StatusCode::FOUND);
        let loc = res.headers()["location"].to_str().unwrap();
        assert_eq!(
            loc,
            format!("http://console.test/c?tab=x&flow={id}&result=pending_confirm")
        );
    }

    #[test]
    fn oauth_endpoints_follow_the_provider_quirks() {
        let mut def = ProviderDef {
            id: "atlassian".to_owned(),
            name: "Atlassian".to_owned(),
            authorize_url: "https://auth.example.test/authorize".to_owned(),
            token_url: "https://auth.example.test/token".to_owned(),
            revoke_url: None,
            account_url: "https://api.example.test/me".to_owned(),
            refresh: RefreshKind::Rotating,
            api_hosts: vec!["api.example.test".to_owned()],
            default_scopes: vec!["read".to_owned()],
        };
        let e = endpoints_for(&def);
        assert_eq!(e.quirk, Quirk::Atlassian);
        assert!(e.authorize_params.iter().any(|(k, _)| k == "audience"));
        def.id = "mock".to_owned();
        let e = endpoints_for(&def);
        assert_eq!(e.quirk, Quirk::Standard);
        assert!(e.authorize_params.is_empty());
    }
}
