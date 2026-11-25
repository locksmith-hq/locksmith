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
//!   to `return_to` carrying only `flow=<id>` and `result=pending_confirm|<error slug>`.
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
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ls_control_plane::auth::human::HumanAuth;
use ls_control_plane::db::{Database, sql};
use ls_envelope::{KeyWrapper, SecretBytes, WRAPPED_DEK_LEN};
use ls_oauth::{
    ConnectResponse, ErrorBody, ErrorSlug, OAuthClient, ProviderDef, ProviderEndpoints, Quirk,
    Tokens,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::Instrument as _;
use url::Url;
use uuid::Uuid;

use crate::app::AppState;
use crate::config::OAuthConfig;
use crate::oauth_vault::{SealedTokenSet, TokenVault, VaultError};

/// How long a started flow, and then an unconfirmed `pending_confirm` flow, stays valid.
pub const FLOW_TTL: Duration = Duration::from_secs(600);

/// The generation the PKCE verifier is sealed under (bound to the flow id). Token material
/// starts at generation 1 (`oauth_token_material.generation >= 1`), so the two never collide.
const VERIFIER_GENERATION: u32 = 0;

/// The generation of a freshly exchanged token set.
const FIRST_GENERATION: u32 = 1;

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
        }
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
        let mut oauth = Self::new(org_id, db, human, Arc::new(vault), config.console_origins);
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
            Self::Bad(slug) => slug.as_str(),
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

async fn start(
    oauth: &OAuth,
    headers: &HeaderMap,
    body: Result<Json<ConnectBody>, JsonRejection>,
) -> Result<ConnectResponse, Refusal> {
    let token = bearer(headers).ok_or(Refusal::Unauthorized)?;
    let identity = oauth
        .human
        .verify(token)
        .await
        .map_err(|_| Refusal::Unauthorized)?;
    // Read-only lookup: an unknown identity is refused, never created here.
    let (issuer, subject) = (identity.issuer.clone(), identity.subject.clone());
    let person: Option<(Uuid, Uuid)> = oauth
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
    if user_org != oauth.org_id {
        return Err(Refusal::Forbidden);
    }

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
        Err(slug) => slug.as_str(),
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
        tracing::warn!("oauth callback: revoking an unkept token failed");
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
    use ls_oauth::testing::{ACCESS_1, CODE, FakeProvider, Kind, REFRESH_1};
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

    /// A migrated `postgres:18` (ls-pg-test; needs Docker) with two orgs, alice in [`ORG`] and
    /// mallory in [`OTHER_ORG`]; a JWKS issuer; a Google-shaped fake provider registered as
    /// `fake`; the gateway router with OAuth on, over the `locksmith_gateway` role.
    struct Harness {
        pg: ls_pg_test::Pg,
        app: Router,
        fake: FakeProvider,
        _idp: MockServer,
        key: TestKey,
        vault: Arc<TokenVault<MemWrapper>>,
    }

    impl Harness {
        async fn start() -> Self {
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
            for (sub, org) in [("alice", ORG), ("mallory", OTHER_ORG)] {
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
            let fake = FakeProvider::start(Kind::Google).await;
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
            let oauth =
                OAuth::new(ORG, db, human, vault.clone(), origins()).with_provider(def, client);
            let app = app::build(
                AppState::new(Arc::new(ReadyFlag::new(true))).with_oauth(Arc::new(oauth)),
            );
            Self {
                pg,
                app,
                fake,
                _idp: idp,
                key,
                vault,
            }
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
        assert_eq!(h.count("SELECT count(*) FROM users").await, 2);
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

    /// Without OAuth configured both endpoints answer `503`.
    #[tokio::test]
    async fn oauth_endpoints_off_without_configuration() {
        let app = app::build(AppState::new(Arc::new(ReadyFlag::new(true))));
        for req in [
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
