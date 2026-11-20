//! `smith login --user` (T1 task 6.3, design decisions 4 and 5).
//!
//! The OAuth device authorization grant (RFC 8628) against the OIDC issuer: the CLI prints a
//! verification URL and a short user code, the person approves in any browser, and the CLI polls
//! the token endpoint. The protocol is the `oauth2` crate; the tokens go straight into the OS
//! keystore (`keyring`) and are held only in `secrecy` types. Nothing here prints, logs or
//! serializes a token; errors are fixed slugs (no issuer body is echoed). The user code and the
//! verification URL are not secrets and are shown on stderr so `--json` stdout stays clean.

use std::io::Write;
use std::time::Duration;

use ls_core::ExitCode;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, ClientId, DeviceAuthorizationUrl, EndpointNotSet, EndpointSet, Scope,
    StandardDeviceAuthorizationResponse, TokenResponse, TokenUrl,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;

use crate::Fail;

const KEYSTORE_SERVICE: &str = "locksmith-cli";
const ACCESS_KEY: &str = "user-access-token";
const REFRESH_KEY: &str = "user-refresh-token";
const DEFAULT_ISSUER: &str = "http://localhost:8180/realms/locksmith";
const DEFAULT_CLIENT_ID: &str = "locksmith-cli";
/// Upper bound on the whole sign-in even if the issuer allows longer.
const MAX_WAIT: Duration = Duration::from_secs(600);

fn fail(msg: &str) -> Fail {
    Fail(ExitCode::Failure, msg.to_owned())
}

/// Access and refresh token. No Debug, Display, Clone or Serialize: only `secrecy` types.
pub struct TokenSet {
    pub access: SecretString,
    pub refresh: Option<SecretString>,
}

/// Where tokens persist. The real one is the OS keystore; tests use an in-memory store.
pub trait TokenStore {
    fn save(&self, tokens: &TokenSet) -> Result<(), Fail>;
}

pub struct KeyringTokenStore;

fn ks_err(e: keyring::Error) -> Fail {
    // keyring errors describe the platform failure, never the stored value.
    Fail(ExitCode::Failure, format!("OS keystore error: {e}"))
}

fn entry(key: &str) -> Result<keyring::Entry, Fail> {
    keyring::Entry::new(KEYSTORE_SERVICE, key).map_err(ks_err)
}

fn delete_entry(key: &str) -> Result<(), Fail> {
    match entry(key)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(ks_err(e)),
    }
}

impl TokenStore for KeyringTokenStore {
    fn save(&self, tokens: &TokenSet) -> Result<(), Fail> {
        entry(ACCESS_KEY)?
            .set_password(tokens.access.expose_secret())
            .map_err(ks_err)?;
        let refresh = match &tokens.refresh {
            Some(r) => entry(REFRESH_KEY)?
                .set_password(r.expose_secret())
                .map_err(ks_err),
            None => delete_entry(REFRESH_KEY),
        };
        if refresh.is_err() {
            // Never leave a partial set behind.
            let _ = delete_entry(ACCESS_KEY);
            let _ = delete_entry(REFRESH_KEY);
        }
        refresh
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub issuer: String,
    pub client_id: String,
}

impl Config {
    fn endpoint(&self, name: &str) -> String {
        format!("{}/protocol/openid-connect/{name}", self.issuer)
    }
}

type DeviceClient =
    BasicClient<EndpointSet, EndpointSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

fn build_client(cfg: &Config) -> Result<DeviceClient, Fail> {
    let bad = |_| fail("invalid issuer configuration");
    let c = BasicClient::new(ClientId::new(cfg.client_id.clone()))
        .set_auth_uri(AuthUrl::new(cfg.endpoint("auth")).map_err(bad)?)
        .set_token_uri(TokenUrl::new(cfg.endpoint("token")).map_err(bad)?);
    Ok(c.set_device_authorization_url(
        DeviceAuthorizationUrl::new(cfg.endpoint("auth/device")).map_err(bad)?,
    ))
}

/// `oauth2`'s own `ureq` client treats every 4xx as a transport error, which hides RFC 8628
/// answers such as `authorization_pending` and `access_denied` (the poll would then loop until
/// the timeout). This wrapper hands status responses, with their bodies, to `oauth2` to parse.
/// Redirects are not followed on issuer endpoints (RFC 6749 section 3.2 and SSRF).
struct Http(oauth2::ureq::Agent);

impl Http {
    fn new() -> Self {
        Self(
            oauth2::ureq::AgentBuilder::new()
                .redirects(0)
                .timeout(Duration::from_secs(20))
                .build(),
        )
    }
}

impl oauth2::SyncHttpClient for Http {
    type Error = oauth2::HttpClientError<oauth2::ureq::Error>;

    fn call(&self, request: oauth2::HttpRequest) -> Result<oauth2::HttpResponse, Self::Error> {
        use std::io::Read;
        let mut req = self.0.post(&request.uri().to_string());
        for (name, value) in request.headers() {
            let v = value
                .to_str()
                .map_err(|_| oauth2::HttpClientError::Other("invalid header value".into()))?;
            req = req.set(name.as_ref(), v);
        }
        let response = match req.send_bytes(request.body()) {
            Ok(r) | Err(oauth2::ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(Box::new(e).into()),
        };
        let mut builder = oauth2::http::Response::builder().status(
            oauth2::http::StatusCode::from_u16(response.status())
                .map_err(oauth2::http::Error::from)?,
        );
        if let Some(ct) = response.header("content-type") {
            builder = builder.header(
                oauth2::http::header::CONTENT_TYPE,
                oauth2::http::HeaderValue::from_str(ct).map_err(oauth2::http::Error::from)?,
            );
        }
        let mut body = Vec::new();
        // Bounded: an issuer answer is small.
        response
            .into_reader()
            .take(1 << 20)
            .read_to_end(&mut body)?;
        builder.body(body).map_err(oauth2::HttpClientError::Http)
    }
}

/// What is shown to the person: the page and the code to type. Not secrets.
pub struct Prompt<'a> {
    pub verification_uri: &'a str,
    pub verification_uri_complete: Option<&'a str>,
    pub user_code: &'a str,
}

/// Runs the grant and stores the tokens. `sleep` is injected so tests do not wait.
pub fn sign_in(
    cfg: &Config,
    store: &dyn TokenStore,
    show: &dyn Fn(&Prompt),
    sleep: &dyn Fn(Duration),
) -> Result<(), Fail> {
    let client = build_client(cfg)?;
    let http = Http::new();
    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code()
        .add_scope(Scope::new("openid".into()))
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("profile".into()))
        .request(&http)
        .map_err(|e| {
            use oauth2::RequestTokenError as E;
            match e {
                E::ServerResponse(_) => fail("the issuer refused the device sign-in request"),
                E::Request(_) => fail("the issuer is unreachable"),
                _ => fail("the issuer returned an unusable response"),
            }
        })?;
    show(&Prompt {
        verification_uri: details.verification_uri().as_str(),
        verification_uri_complete: details
            .verification_uri_complete()
            .map(|u| u.secret().as_str()),
        user_code: details.user_code().secret(),
    });
    let resp = client
        .exchange_device_access_token(&details)
        .request(&http, sleep, Some(MAX_WAIT))
        .map_err(|e| {
            use oauth2::RequestTokenError as E;
            use oauth2::basic::BasicErrorResponseType as T;
            match e {
                E::ServerResponse(r) => match r.error() {
                    oauth2::DeviceCodeErrorResponseType::AccessDenied => fail("sign-in was denied"),
                    oauth2::DeviceCodeErrorResponseType::ExpiredToken => {
                        fail("the sign-in code expired; run `smith login --user` again")
                    }
                    oauth2::DeviceCodeErrorResponseType::Basic(T::InvalidClient)
                    | oauth2::DeviceCodeErrorResponseType::Basic(T::UnauthorizedClient) => {
                        fail("the issuer client does not allow the device grant")
                    }
                    _ => fail("the issuer refused the sign-in"),
                },
                E::Request(_) => fail("the issuer is unreachable"),
                _ => fail("the issuer returned an unusable response"),
            }
        })?;
    store.save(&TokenSet {
        access: SecretString::from(resp.access_token().secret().clone()),
        refresh: resp
            .refresh_token()
            .map(|r| SecretString::from(r.secret().clone())),
    })
}

fn config(issuer: Option<String>, client_id: Option<String>) -> Result<Config, Fail> {
    let issuer = ls_connector::parse_endpoint(issuer.as_deref().unwrap_or(DEFAULT_ISSUER))?;
    let client_id = client_id.unwrap_or_else(|| DEFAULT_CLIENT_ID.to_owned());
    if client_id.trim().is_empty() {
        return Err(fail("client id must not be empty"));
    }
    Ok(Config { issuer, client_id })
}

pub fn run(
    json: bool,
    issuer: Option<String>,
    client_id: Option<String>,
) -> Result<ExitCode, Fail> {
    let cfg = config(issuer, client_id)?;
    let show = |p: &Prompt| {
        let mut e = std::io::stderr();
        let _ = writeln!(
            e,
            "To sign in, open {} and enter the code:",
            p.verification_uri
        );
        let _ = writeln!(e, "  {}", p.user_code);
        if let Some(u) = p.verification_uri_complete {
            let _ = writeln!(e, "or open {u}");
        }
        let _ = writeln!(e, "Waiting for approval...");
    };
    sign_in(&cfg, &KeyringTokenStore, &show, &std::thread::sleep)?;
    if json {
        println!("{}", json!({ "status": "logged_in", "kind": "user" }));
    } else {
        println!("logged in as a user (token stored in the OS keystore)");
    }
    Ok(ExitCode::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const BASE: &str = "/realms/locksmith/protocol/openid-connect";

    #[derive(Default)]
    struct Mem(Mutex<Option<(String, Option<String>)>>);
    impl TokenStore for Mem {
        fn save(&self, t: &TokenSet) -> Result<(), Fail> {
            *self.0.lock().unwrap() = Some((
                t.access.expose_secret().to_owned(),
                t.refresh.as_ref().map(|r| r.expose_secret().to_owned()),
            ));
            Ok(())
        }
    }

    fn cfg(server: &MockServer) -> Config {
        Config {
            issuer: format!("{}/realms/locksmith", server.uri()),
            client_id: "locksmith-cli".into(),
        }
    }

    async fn device_ok(s: &MockServer) {
        Mock::given(method("POST"))
            .and(path(format!("{BASE}/auth/device")))
            .and(body_string_contains("client_id=locksmith-cli"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_code": "DEVICE_CODE_CANARY",
                "user_code": "WDJB-MJHT",
                "verification_uri": "https://issuer.test/device",
                "verification_uri_complete": "https://issuer.test/device?user_code=WDJB-MJHT",
                "expires_in": 600,
                "interval": 1
            })))
            .mount(s)
            .await;
    }

    async fn run_sign_in(
        cfg: Config,
        store: std::sync::Arc<Mem>,
    ) -> (Result<(), Fail>, Vec<String>) {
        tokio::task::spawn_blocking(move || {
            let shown = Mutex::new(Vec::new());
            let r = sign_in(
                &cfg,
                &*store,
                &|p| {
                    shown
                        .lock()
                        .unwrap()
                        .push(format!("{} {}", p.verification_uri, p.user_code))
                },
                &|_| {},
            );
            (r, shown.into_inner().unwrap())
        })
        .await
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pending_then_approved_stores_tokens() {
        let s = MockServer::start().await;
        device_ok(&s).await;
        // First poll: authorization_pending; then the tokens.
        Mock::given(method("POST"))
            .and(path(format!("{BASE}/token")))
            .and(body_string_contains("device_code=DEVICE_CODE_CANARY"))
            .and(body_string_contains("grant_type=urn"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(json!({"error": "authorization_pending"})),
            )
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("{BASE}/token")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "ACCESS_CANARY", "refresh_token": "REFRESH_CANARY",
                "token_type": "Bearer", "expires_in": 300
            })))
            .with_priority(2)
            .mount(&s)
            .await;
        let store = std::sync::Arc::new(Mem::default());
        let (r, shown) = run_sign_in(cfg(&s), store.clone()).await;
        assert!(r.is_ok());
        assert_eq!(shown, ["https://issuer.test/device WDJB-MJHT"]);
        let saved = store.0.lock().unwrap().clone().unwrap();
        assert_eq!(saved.0, "ACCESS_CANARY");
        assert_eq!(saved.1.as_deref(), Some("REFRESH_CANARY"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn denied_stores_nothing_and_leaks_nothing() {
        let s = MockServer::start().await;
        device_ok(&s).await;
        Mock::given(method("POST"))
            .and(path(format!("{BASE}/token")))
            .respond_with(ResponseTemplate::new(400).set_body_json(
                json!({"error": "access_denied", "error_description": "BODY_CANARY"}),
            ))
            .mount(&s)
            .await;
        let store = std::sync::Arc::new(Mem::default());
        let (r, _) = run_sign_in(cfg(&s), store.clone()).await;
        let Err(Fail(code, msg)) = r else {
            panic!("expected failure")
        };
        assert_eq!(code, ExitCode::Failure);
        assert_eq!(msg, "sign-in was denied");
        assert!(store.0.lock().unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn expired_code_is_reported() {
        let s = MockServer::start().await;
        device_ok(&s).await;
        Mock::given(method("POST"))
            .and(path(format!("{BASE}/token")))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(json!({"error": "expired_token"})),
            )
            .mount(&s)
            .await;
        let store = std::sync::Arc::new(Mem::default());
        let (r, _) = run_sign_in(cfg(&s), store.clone()).await;
        let Err(Fail(_, msg)) = r else { panic!() };
        assert!(msg.contains("expired"), "{msg}");
        assert!(store.0.lock().unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn device_endpoint_refusal_does_not_echo_body() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("{BASE}/auth/device")))
            .respond_with(ResponseTemplate::new(400).set_body_json(
                json!({"error": "unauthorized_client", "error_description": "BODY_CANARY"}),
            ))
            .mount(&s)
            .await;
        let store = std::sync::Arc::new(Mem::default());
        let (r, _) = run_sign_in(cfg(&s), store.clone()).await;
        let Err(Fail(_, msg)) = r else { panic!() };
        assert!(!msg.contains("BODY_CANARY"), "{msg}");
        assert!(store.0.lock().unwrap().is_none());
    }

    #[test]
    fn issuer_must_be_https_or_loopback() {
        assert!(config(Some("http://issuer.example.com/realms/x".into()), None).is_err());
        assert!(config(Some("https://issuer.example.com/realms/x/".into()), None).is_ok());
        let Ok(c) = config(None, None) else { panic!() };
        assert_eq!(c.issuer, DEFAULT_ISSUER);
        assert_eq!(c.client_id, DEFAULT_CLIENT_ID);
    }
}
