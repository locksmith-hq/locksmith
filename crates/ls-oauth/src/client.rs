//! Provider client (C1 task 2.3): authorize URL with PKCE S256 and state, code exchange, refresh,
//! revocation and account lookup, on the `oauth2` crate over a caller-supplied reqwest client.
//!
//! - The caller passes its pinned client (the gateway's: no redirects, egress guard). A redirect
//!   response is refused here as well, and every body is read through [`ls_http::read_capped`].
//! - Provider quirks live in [`Transport`], which rewrites the request and normalizes the response
//!   so `oauth2` only sees RFC 6749 shapes: GitHub (`Accept: application/json`, errors answered
//!   with `200`), Slack (`ok:false`, tokens nested under `authed_user`), Atlassian (JSON request
//!   bodies). Google refresh answers carry no new refresh token ([`Tokens::refresh`] is `None`:
//!   the caller keeps the old one); Linear is standard.
//! - Tokens are only in `secrecy` types; no type here that holds one derives `Debug`, `Display`
//!   or `Clone`. Errors are [`ErrorSlug`] plus a fixed [`Reason`]: never a response body, a
//!   provider message or a URL.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use oauth2::basic::{BasicClient, BasicErrorResponseType};
use oauth2::{
    AsyncHttpClient, AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointNotSet, EndpointSet, HttpRequest, HttpResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, RefreshToken, RequestTokenError, Scope, TokenResponse, TokenUrl,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Map, Value};

use crate::ErrorSlug;

/// Largest provider response body read, unless [`OAuthClient::with_max_body`] says otherwise.
pub const DEFAULT_MAX_BODY: usize = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(15);

/// Provider-specific behaviour. Google and Linear are [`Quirk::Standard`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quirk {
    Standard,
    Github,
    Slack,
    Atlassian,
}

/// Where a provider lives and how it deviates from RFC 6749. The caller builds it (the gateway
/// from the embedded registry, tests from a fake's URIs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEndpoints {
    pub authorize_url: String,
    pub token_url: String,
    /// `None` when the provider has no revocation endpoint (Atlassian).
    pub revoke_url: Option<String>,
    pub account_url: String,
    pub quirk: Quirk,
    /// Fixed extra authorize query parameters (Atlassian `audience`, Google `access_type`).
    pub authorize_params: Vec<(String, String)>,
}

/// Why a provider call failed. Fixed text only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The provider refused the grant or refresh token (`invalid_grant`, Slack `ok:false` on a
    /// code or refresh token, GitHub `bad_refresh_token`).
    InvalidGrant,
    /// The provider answered with another refusal.
    Rejected,
    /// The provider answered with a redirect; never followed.
    Redirect,
    /// The response body was larger than the cap.
    TooLarge,
    /// Connection, TLS or timeout failure.
    Transport,
    /// A body that is not the expected shape.
    BadResponse,
    /// The provider has no such endpoint (revocation).
    Unsupported,
    /// A URL given in the endpoints is invalid.
    Config,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidGrant => "invalid_grant",
            Self::Rejected => "rejected",
            Self::Redirect => "redirect",
            Self::TooLarge => "response_too_large",
            Self::Transport => "transport",
            Self::BadResponse => "bad_response",
            Self::Unsupported => "unsupported",
            Self::Config => "config",
        }
    }
}

/// A failed provider call: the slug the gateway answers with and a fixed reason for its
/// decisions (`refresh_failed` versus a retryable `502`). Carries nothing from the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OAuthError {
    pub slug: ErrorSlug,
    pub reason: Reason,
}

impl OAuthError {
    fn new(slug: ErrorSlug, reason: Reason) -> Self {
        Self { slug, reason }
    }

    /// A refusal the provider will repeat (as opposed to a transport failure worth retrying).
    pub fn is_permanent(self) -> bool {
        matches!(self.reason, Reason::InvalidGrant | Reason::Rejected)
    }
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.slug.as_str(), self.reason.as_str())
    }
}

impl std::error::Error for OAuthError {}

/// What the `oauth2` crate sees as the HTTP client's error.
#[derive(Debug, Clone, Copy)]
struct Fetch(Reason);

impl std::fmt::Display for Fetch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "provider request failed ({})", self.0.as_str())
    }
}

impl std::error::Error for Fetch {}

/// The tokens of one exchange or refresh. No `Debug`, `Display` or `Clone`.
pub struct Tokens {
    pub access: SecretString,
    /// `None` when the provider issued no new refresh token (Google, Linear on refresh): keep
    /// the old one.
    pub refresh: Option<SecretString>,
    pub expires_in: Option<Duration>,
    pub scopes: Vec<String>,
}

/// The provider account a token belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: String,
    pub login: String,
}

/// A started authorization: where to send the person, and what the gateway must keep. The
/// gateway stores the SHA-256 of `state` and the sealed `verifier`. No `Debug`, no `Clone`.
pub struct AuthorizeStart {
    pub url: String,
    pub state: String,
    pub verifier: SecretString,
}

type Inner = BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

/// The `oauth2` HTTP client: a caller-supplied reqwest client plus the provider's quirks.
struct Transport {
    http: reqwest::Client,
    quirk: Quirk,
    max_body: usize,
}

impl Transport {
    async fn send(&self, mut request: reqwest::Request) -> Result<(u16, Vec<u8>), Fetch> {
        *request.timeout_mut() = Some(TIMEOUT);
        let response = self
            .http
            .execute(request)
            .await
            .map_err(|_| Fetch(Reason::Transport))?;
        let status = response.status();
        if status.is_redirection() {
            return Err(Fetch(Reason::Redirect));
        }
        let body = ls_http::read_capped(response, self.max_body)
            .await
            .map_err(|e| match e {
                ls_http::CapError::TooLarge => Fetch(Reason::TooLarge),
                ls_http::CapError::Transport => Fetch(Reason::Transport),
            })?;
        Ok((status.as_u16(), body))
    }
}

impl<'c> AsyncHttpClient<'c> for Transport {
    type Error = Fetch;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Fetch>> + Send + 'c>>;

    fn call(&'c self, mut request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            request.headers_mut().insert(
                oauth2::http::header::ACCEPT,
                oauth2::http::HeaderValue::from_static("application/json"),
            );
            // Atlassian takes JSON request bodies only.
            if self.quirk == Quirk::Atlassian && !request.body().is_empty() {
                let body = form_to_json(request.body());
                *request.body_mut() = body;
                request.headers_mut().insert(
                    oauth2::http::header::CONTENT_TYPE,
                    oauth2::http::HeaderValue::from_static("application/json"),
                );
            }
            let request = reqwest::Request::try_from(request).map_err(|_| Fetch(Reason::Config))?;
            let (status, body) = self.send(request).await?;
            let (status, body) = normalize(self.quirk, status, body);
            oauth2::http::Response::builder()
                .status(status)
                .body(body)
                .map_err(|_| Fetch(Reason::BadResponse))
        })
    }
}

fn form_to_json(form: &[u8]) -> Vec<u8> {
    let map: Map<String, Value> = oauth2::url::form_urlencoded::parse(form)
        .map(|(k, v)| (k.into_owned(), Value::String(v.into_owned())))
        .collect();
    serde_json::to_vec(&map).unwrap_or_default()
}

/// Error strings that mean "the code or refresh token is no good" across the providers.
fn is_grant_error(e: &str) -> bool {
    matches!(
        e,
        "invalid_grant"
            | "bad_refresh_token"
            | "bad_verification_code"
            | "invalid_code"
            | "code_already_used"
            | "invalid_refresh_token"
            | "token_revoked"
            | "token_expired"
    )
}

fn error_body(e: &str) -> Vec<u8> {
    let e = if is_grant_error(e) {
        "invalid_grant"
    } else {
        "invalid_request"
    };
    serde_json::to_vec(&serde_json::json!({ "error": e })).unwrap_or_default()
}

/// Turn a provider's token answer into the RFC 6749 shape `oauth2` parses: a failure becomes a
/// `400` with a standard `error`, Slack's nested user token is lifted to the top level.
fn normalize(quirk: Quirk, status: u16, body: Vec<u8>) -> (u16, Vec<u8>) {
    let Ok(Value::Object(mut m)) = serde_json::from_slice::<Value>(&body) else {
        return (status, body);
    };
    if quirk == Quirk::Slack {
        if m.get("ok") == Some(&Value::Bool(false)) {
            let e = m.get("error").and_then(Value::as_str).unwrap_or_default();
            return (400, error_body(e));
        }
        if let Some(Value::Object(user)) = m.remove("authed_user") {
            m = [
                "access_token",
                "refresh_token",
                "expires_in",
                "scope",
                "token_type",
            ]
            .into_iter()
            .filter_map(|k| user.get(k).map(|v| (k.to_string(), v.clone())))
            .collect();
        }
    }
    // GitHub (and any provider) answering an error with a 2xx status.
    if (200..300).contains(&status)
        && !m.contains_key("access_token")
        && let Some(e) = m.get("error").and_then(Value::as_str)
    {
        return (400, error_body(e));
    }
    match serde_json::to_vec(&m) {
        Ok(b) => (status, b),
        Err(_) => (status, body),
    }
}

/// A provider client for one provider app.
pub struct OAuthClient {
    inner: Inner,
    transport: Transport,
    endpoints: ProviderEndpoints,
    client_id: String,
    client_secret: SecretString,
}

fn config() -> OAuthError {
    OAuthError::new(ErrorSlug::ProviderError, Reason::Config)
}

impl OAuthClient {
    /// `http` is the caller's pinned client (no redirects, egress guard).
    pub fn new(
        http: reqwest::Client,
        endpoints: ProviderEndpoints,
        client_id: String,
        client_secret: SecretString,
        redirect_url: &str,
    ) -> Result<Self, OAuthError> {
        if let Some(u) = &endpoints.revoke_url {
            reqwest::Url::parse(u).map_err(|_| config())?;
        }
        let inner = BasicClient::new(ClientId::new(client_id.clone()))
            .set_client_secret(ClientSecret::new(client_secret.expose_secret().to_owned()))
            .set_auth_uri(AuthUrl::new(endpoints.authorize_url.clone()).map_err(|_| config())?)
            .set_token_uri(TokenUrl::new(endpoints.token_url.clone()).map_err(|_| config())?)
            .set_redirect_uri(RedirectUrl::new(redirect_url.to_owned()).map_err(|_| config())?)
            // Client credentials in the request body: GitHub and Atlassian read them there.
            .set_auth_type(AuthType::RequestBody);
        Ok(Self {
            inner,
            transport: Transport {
                http,
                quirk: endpoints.quirk,
                max_body: DEFAULT_MAX_BODY,
            },
            endpoints,
            client_id,
            client_secret,
        })
    }

    pub fn with_max_body(mut self, max: usize) -> Self {
        self.transport.max_body = max;
        self
    }

    /// The authorize URL (PKCE S256, `state` of 32 random bytes) for exactly `scopes`.
    pub fn authorize(&self, scopes: &[String]) -> AuthorizeStart {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut req = self
            .inner
            .authorize_url(|| CsrfToken::new_random_len(32))
            .set_pkce_challenge(challenge);
        if self.endpoints.quirk == Quirk::Slack {
            // Slack user tokens come from `user_scope`; `scope` would request a bot token.
            req = req.add_extra_param("user_scope", scopes.join(","));
        } else {
            for s in scopes {
                req = req.add_scope(Scope::new(s.clone()));
            }
        }
        for (k, v) in &self.endpoints.authorize_params {
            req = req.add_extra_param(k.clone(), v.clone());
        }
        let (url, state) = req.url();
        AuthorizeStart {
            url: url.to_string(),
            state: state.secret().clone(),
            verifier: SecretString::from(verifier.secret().clone()),
        }
    }

    pub async fn exchange_code(
        &self,
        code: SecretString,
        verifier: SecretString,
    ) -> Result<Tokens, OAuthError> {
        let res = self
            .inner
            .exchange_code(AuthorizationCode::new(code.expose_secret().to_owned()))
            .set_pkce_verifier(PkceCodeVerifier::new(verifier.expose_secret().to_owned()))
            .request_async(&self.transport)
            .await;
        match res {
            Ok(t) => tokens(&t),
            Err(e) => Err(OAuthError::new(ErrorSlug::ExchangeFailed, token_reason(e))),
        }
    }

    /// Refresh. A provider that rotates answers a new refresh token (GitHub, Slack, Atlassian);
    /// Google and Linear answer none and [`Tokens::refresh`] is `None`.
    pub async fn refresh(&self, refresh_token: &SecretString) -> Result<Tokens, OAuthError> {
        let rt = RefreshToken::new(refresh_token.expose_secret().to_owned());
        let res = self
            .inner
            .exchange_refresh_token(&rt)
            .request_async(&self.transport)
            .await;
        match res {
            Ok(t) => tokens(&t),
            Err(e) => {
                let reason = token_reason(e);
                let slug = if reason == Reason::InvalidGrant {
                    ErrorSlug::ConnectionNeedsReconnect
                } else {
                    ErrorSlug::ProviderError
                };
                Err(OAuthError::new(slug, reason))
            }
        }
    }

    /// Revoke at the provider: RFC 7009 for Google and Linear (the refresh token when there is
    /// one), the provider's own call for GitHub and Slack. [`Reason::Unsupported`] when the
    /// provider has no endpoint.
    pub async fn revoke(
        &self,
        access: &SecretString,
        refresh: Option<&SecretString>,
    ) -> Result<(), OAuthError> {
        let fail = |r| OAuthError::new(ErrorSlug::ProviderError, r);
        let Some(url) = self.endpoints.revoke_url.as_deref() else {
            return Err(fail(Reason::Unsupported));
        };
        let http = &self.transport.http;
        match self.endpoints.quirk {
            Quirk::Github => {
                // The registry URL carries the app's client id as `{client_id}`.
                let url = url.replace("{client_id}", &self.client_id);
                let req = http
                    .delete(url)
                    .basic_auth(&self.client_id, Some(self.client_secret.expose_secret()))
                    .header("accept", "application/vnd.github+json")
                    .json(&serde_json::json!({ "access_token": access.expose_secret() }))
                    .build()
                    .map_err(|_| fail(Reason::Config))?;
                let (status, _) = self.transport.send(req).await.map_err(|f| fail(f.0))?;
                // 204 revoked; 404 means the grant is already gone.
                if matches!(status, 204 | 404) {
                    Ok(())
                } else {
                    Err(fail(Reason::Rejected))
                }
            }
            Quirk::Slack => {
                let req = http
                    .post(url)
                    .bearer_auth(access.expose_secret())
                    .build()
                    .map_err(|_| fail(Reason::Config))?;
                let (status, body) = self.transport.send(req).await.map_err(|f| fail(f.0))?;
                let ok = status == 200
                    && serde_json::from_slice::<Value>(&body)
                        .ok()
                        .is_some_and(|v| v.get("ok") == Some(&Value::Bool(true)));
                if ok {
                    Ok(())
                } else {
                    Err(fail(Reason::Rejected))
                }
            }
            Quirk::Standard | Quirk::Atlassian => {
                // RFC 7009 by hand: `oauth2` refuses a non-HTTPS revocation URL, which the
                // fakes are; registry validation (2.2) must require HTTPS for every provider endpoint except the mock.
                let (token, hint) = match refresh {
                    Some(r) => (r.expose_secret(), "refresh_token"),
                    None => (access.expose_secret(), "access_token"),
                };
                let req = http
                    .post(url)
                    .header("accept", "application/json")
                    .form(&[
                        ("token", token),
                        ("token_type_hint", hint),
                        ("client_id", self.client_id.as_str()),
                        ("client_secret", self.client_secret.expose_secret()),
                    ])
                    .build()
                    .map_err(|_| fail(Reason::Config))?;
                let (status, _) = self.transport.send(req).await.map_err(|f| fail(f.0))?;
                // 200 revoked or unknown token (RFC 7009 section 2.2).
                if status == 200 {
                    Ok(())
                } else {
                    Err(fail(Reason::Rejected))
                }
            }
        }
    }

    /// The provider account behind an access token.
    pub async fn account(&self, access: &SecretString) -> Result<Account, OAuthError> {
        let fail = |r| OAuthError::new(ErrorSlug::ProviderError, r);
        let http = &self.transport.http;
        let url = self.endpoints.account_url.as_str();
        let req = match self.endpoints.quirk {
            // Linear's only API is GraphQL.
            Quirk::Standard if url.ends_with("/graphql") => http
                .post(url)
                .json(&serde_json::json!({ "query": "{ viewer { id name } }" })),
            _ => http.get(url),
        }
        .bearer_auth(access.expose_secret())
        .header("accept", "application/json")
        .build()
        .map_err(|_| fail(Reason::Config))?;
        let (status, body) = self.transport.send(req).await.map_err(|f| fail(f.0))?;
        if !(200..300).contains(&status) {
            return Err(fail(Reason::Rejected));
        }
        let v: Value = serde_json::from_slice(&body).map_err(|_| fail(Reason::BadResponse))?;
        parse_account(self.endpoints.quirk, &v).ok_or_else(|| fail(Reason::BadResponse))
    }
}

fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The account id and a display login. Shapes: GitHub `{login,id}`, Google `{sub,email}`,
/// Slack `{ok,user:{id,name}}`, Linear `{data:{viewer:{id,name}}}`, Atlassian `{account_id,name}`.
fn parse_account(quirk: Quirk, v: &Value) -> Option<Account> {
    let (id, login) = if v.get("data").is_some() {
        let viewer = &v["data"]["viewer"];
        (text(&viewer["id"])?, text(&viewer["name"]))
    } else if quirk == Quirk::Slack {
        if v.get("ok") != Some(&Value::Bool(true)) {
            return None;
        }
        (text(&v["user"]["id"])?, text(&v["user"]["name"]))
    } else if let Some(id) = v.get("account_id") {
        (text(id)?, text(&v["name"]))
    } else if let Some(sub) = v.get("sub") {
        (text(sub)?, text(&v["email"]))
    } else {
        (text(&v["id"])?, text(&v["login"]))
    };
    Some(Account {
        login: login.unwrap_or_else(|| id.clone()),
        id,
    })
}

fn token_reason(e: RequestTokenError<Fetch, oauth2::basic::BasicErrorResponse>) -> Reason {
    match e {
        RequestTokenError::Request(f) => f.0,
        RequestTokenError::ServerResponse(r) => {
            if matches!(r.error(), BasicErrorResponseType::InvalidGrant) {
                Reason::InvalidGrant
            } else {
                Reason::Rejected
            }
        }
        // `Parse` carries the raw body: dropped here.
        RequestTokenError::Parse(..) | RequestTokenError::Other(_) => Reason::BadResponse,
    }
}

fn tokens(t: &oauth2::basic::BasicTokenResponse) -> Result<Tokens, OAuthError> {
    let access = t.access_token().secret();
    if access.is_empty() {
        return Err(OAuthError::new(
            ErrorSlug::ProviderError,
            Reason::BadResponse,
        ));
    }
    let scopes = t
        .scopes()
        .into_iter()
        .flatten()
        .flat_map(|s| {
            s.as_str()
                .split([' ', ','])
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|s| !s.is_empty())
        .collect();
    Ok(Tokens {
        access: SecretString::from(access.clone()),
        refresh: t
            .refresh_token()
            .map(|r| SecretString::from(r.secret().clone())),
        expires_in: t.expires_in(),
        scopes,
    })
}
