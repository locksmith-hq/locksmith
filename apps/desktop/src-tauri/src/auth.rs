//! Human sign-in for the desktop app (T1 task 6.2, design decisions 4, 5 and 9).
//!
//! Authorization code + PKCE through the system browser with a loopback redirect
//! (`http://127.0.0.1:<ephemeral>/callback`, RFC 8252). The access and refresh tokens go
//! straight from the token endpoint into the OS keystore; they are held only in `secrecy`
//! types, never logged, and never returned to the webview (commands answer
//! [`AuthStatus`], a bool). The protocol itself is the `oauth2` crate; the keystore is `keyring`.

use oauth2::basic::BasicClient;
use oauth2::url::Url;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

const KEYSTORE_SERVICE: &str = "locksmith-desktop";
const ACCESS_KEY: &str = "access-token";
const REFRESH_KEY: &str = "refresh-token";
const CALLBACK_PATH: &str = "/callback";
/// How long the user has to finish signing in in the browser.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);

/// What the webview learns: whether a session exists. Never a token.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthStatus {
    pub signed_in: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthErrorKind {
    /// Bad callback, state mismatch, or a provider we do not allow.
    BadRequest,
    /// The user (or the issuer) refused the sign-in.
    Denied,
    /// Issuer, browser or keystore unreachable, or the sign-in timed out.
    Unavailable,
}

/// Messages here never contain a token, code, state or verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthError {
    pub kind: AuthErrorKind,
    pub message: String,
}

fn err(kind: AuthErrorKind, message: impl Into<String>) -> AuthError {
    AuthError {
        kind,
        message: message.into(),
    }
}

pub type Result<T> = std::result::Result<T, AuthError>;

/// Access and refresh token. No Debug, Display, Clone or Serialize: only `secrecy` types.
pub struct TokenSet {
    pub access: SecretString,
    pub refresh: Option<SecretString>,
}

/// Where tokens persist. The real one is the OS keystore; tests use [`MemoryTokenStore`].
pub trait TokenStore: Send + Sync {
    fn save(&self, tokens: &TokenSet) -> Result<()>;
    fn load(&self) -> Result<Option<TokenSet>>;
    /// Deletes everything; succeeds when nothing is stored.
    fn clear(&self) -> Result<()>;
}

pub struct KeyringTokenStore;

fn ks_err(e: keyring::Error) -> AuthError {
    // keyring error texts describe the platform failure, not the stored value.
    err(
        AuthErrorKind::Unavailable,
        format!("OS keystore error: {e}"),
    )
}

fn entry(key: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(KEYSTORE_SERVICE, key).map_err(ks_err)
}

fn read_entry(key: &str) -> Result<Option<SecretString>> {
    match entry(key)?.get_password() {
        Ok(v) => Ok(Some(SecretString::from(v))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(ks_err(e)),
    }
}

fn delete_entry(key: &str) -> Result<()> {
    match entry(key)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(ks_err(e)),
    }
}

impl TokenStore for KeyringTokenStore {
    fn save(&self, tokens: &TokenSet) -> Result<()> {
        entry(ACCESS_KEY)?
            .set_password(tokens.access.expose_secret())
            .map_err(ks_err)?;
        match &tokens.refresh {
            Some(r) => entry(REFRESH_KEY)?
                .set_password(r.expose_secret())
                .map_err(ks_err),
            None => delete_entry(REFRESH_KEY),
        }
    }

    fn load(&self) -> Result<Option<TokenSet>> {
        let Some(access) = read_entry(ACCESS_KEY)? else {
            return Ok(None);
        };
        Ok(Some(TokenSet {
            access,
            refresh: read_entry(REFRESH_KEY)?,
        }))
    }

    fn clear(&self) -> Result<()> {
        // Try both even if the first fails, then report the first failure.
        let a = delete_entry(ACCESS_KEY);
        let r = delete_entry(REFRESH_KEY);
        a.and(r)
    }
}

/// In-memory store for tests.
#[cfg(test)]
#[derive(Default)]
pub struct MemoryTokenStore(std::sync::Mutex<Option<(String, Option<String>)>>);

#[cfg(test)]
impl TokenStore for MemoryTokenStore {
    fn save(&self, t: &TokenSet) -> Result<()> {
        *self.0.lock().unwrap() = Some((
            t.access.expose_secret().to_string(),
            t.refresh.as_ref().map(|r| r.expose_secret().to_string()),
        ));
        Ok(())
    }
    fn load(&self) -> Result<Option<TokenSet>> {
        Ok(self.0.lock().unwrap().as_ref().map(|(a, r)| TokenSet {
            access: SecretString::from(a.clone()),
            refresh: r.clone().map(SecretString::from),
        }))
    }
    fn clear(&self) -> Result<()> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

/// Opens the authorization URL. The real one starts the system browser.
pub trait BrowserOpener {
    fn open(&self, url: &str) -> Result<()>;
}

pub struct SystemBrowser;

impl BrowserOpener for SystemBrowser {
    fn open(&self, url: &str) -> Result<()> {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(err(AuthErrorKind::BadRequest, "refusing a non-http URL"));
        }
        open::that(url).map_err(|_| err(AuthErrorKind::Unavailable, "could not open the browser"))
    }
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Realm URL, e.g. `http://localhost:8180/realms/locksmith` (Keycloak path layout).
    pub issuer: String,
    pub client_id: String,
}

impl AuthConfig {
    pub fn from_env() -> Self {
        Self {
            issuer: std::env::var("LOCKSMITH_OIDC_ISSUER")
                .unwrap_or_else(|_| "http://localhost:8180/realms/locksmith".into()),
            client_id: std::env::var("LOCKSMITH_OIDC_CLIENT_ID")
                .unwrap_or_else(|_| "locksmith-desktop".into()),
        }
    }

    fn endpoint(&self, name: &str) -> String {
        format!(
            "{}/protocol/openid-connect/{name}",
            self.issuer.trim_end_matches('/')
        )
    }
}

/// Providers the first screen can route to directly (design decision 9). Anything else is
/// refused rather than forwarded into `kc_idp_hint`.
fn idp_hint(provider: Option<&str>) -> Result<Option<&'static str>> {
    match provider {
        None | Some("email") => Ok(None),
        Some("github") => Ok(Some("github")),
        Some("google") => Ok(Some("google")),
        Some(_) => Err(err(AuthErrorKind::BadRequest, "unknown sign-in provider")),
    }
}

/// The query parameters of the redirect back to the loopback listener.
#[derive(Debug, PartialEq, Eq)]
pub enum Callback {
    Code {
        code: String,
        state: String,
    },
    /// The issuer redirected with `error=` (for example `access_denied`).
    Failed {
        error: String,
    },
}

/// Parses the request line of an HTTP request to the loopback listener. `None` for anything
/// that is not `GET /callback?...` (favicon requests and so on).
pub fn parse_callback(request: &str) -> Option<Callback> {
    let line = request.lines().next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let url = Url::parse(&format!("http://127.0.0.1{}", parts.next()?)).ok()?;
    if url.path() != CALLBACK_PATH {
        return None;
    }
    let get = |k: &str| {
        url.query_pairs()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
    };
    if let Some(error) = get("error") {
        return Some(Callback::Failed { error });
    }
    Some(Callback::Code {
        code: get("code")?,
        state: get("state")?,
    })
}

/// Constant-time-ish equality is unnecessary here (the state is not a secret against the
/// local attacker model), but a mismatch must abort before the code is used.
fn check_state(expected: &str, got: &str) -> Result<()> {
    if expected == got {
        Ok(())
    } else {
        Err(err(
            AuthErrorKind::BadRequest,
            "sign-in state mismatch; start again",
        ))
    }
}

fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let msg = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(msg.as_bytes());
}

/// Waits for the redirect on `listener`, answering unrelated requests with 404.
fn await_callback(listener: &TcpListener, timeout: Duration) -> Result<Callback> {
    let unavailable = |m: &str| err(AuthErrorKind::Unavailable, m.to_string());
    listener
        .set_nonblocking(true)
        .map_err(|_| unavailable("loopback listener failed"))?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                match parse_callback(&String::from_utf8_lossy(&buf[..n])) {
                    Some(cb) => {
                        let ok = matches!(cb, Callback::Code { .. });
                        respond(
                            &mut stream,
                            if ok { "200 OK" } else { "400 Bad Request" },
                            if ok {
                                "<!doctype html><title>Locksmith</title><p>Signed in. You can close this tab and return to Locksmith.</p>"
                            } else {
                                "<!doctype html><title>Locksmith</title><p>Sign-in was not completed. You can close this tab.</p>"
                            },
                        );
                        return Ok(cb);
                    }
                    None => respond(&mut stream, "404 Not Found", ""),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(unavailable("sign-in timed out"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return Err(unavailable("loopback listener failed")),
        }
    }
}

type Client = BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

fn build_client(cfg: &AuthConfig, redirect: &str) -> Result<Client> {
    let bad = |_| err(AuthErrorKind::BadRequest, "invalid issuer configuration");
    Ok(BasicClient::new(ClientId::new(cfg.client_id.clone()))
        .set_auth_uri(AuthUrl::new(cfg.endpoint("auth")).map_err(bad)?)
        .set_token_uri(TokenUrl::new(cfg.endpoint("token")).map_err(bad)?)
        .set_redirect_uri(RedirectUrl::new(redirect.to_string()).map_err(bad)?))
}

/// Runs the whole flow and stores the tokens. Blocks until the user finishes or it times out.
pub fn sign_in(
    cfg: &AuthConfig,
    store: &dyn TokenStore,
    opener: &dyn BrowserOpener,
    provider: Option<&str>,
) -> Result<AuthStatus> {
    sign_in_with_timeout(cfg, store, opener, provider, SIGN_IN_TIMEOUT)
}

fn sign_in_with_timeout(
    cfg: &AuthConfig,
    store: &dyn TokenStore,
    opener: &dyn BrowserOpener,
    provider: Option<&str>,
    timeout: Duration,
) -> Result<AuthStatus> {
    let hint = idp_hint(provider)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|_| err(AuthErrorKind::Unavailable, "cannot open a loopback port"))?;
    let port = listener
        .local_addr()
        .map_err(|_| err(AuthErrorKind::Unavailable, "cannot open a loopback port"))?
        .port();
    let client = build_client(cfg, &format!("http://127.0.0.1:{port}{CALLBACK_PATH}"))?;

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut req = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(challenge)
        .add_scope(Scope::new("openid".into()))
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("profile".into()));
    if let Some(h) = hint {
        req = req.add_extra_param("kc_idp_hint", h);
    }
    let (auth_url, csrf) = req.url();

    opener.open(auth_url.as_str())?;

    let (code, state) = match await_callback(&listener, timeout)? {
        Callback::Code { code, state } => (code, state),
        Callback::Failed { error } => {
            let kind = if error == "access_denied" {
                AuthErrorKind::Denied
            } else {
                AuthErrorKind::BadRequest
            };
            return Err(err(kind, format!("sign-in failed: {error}")));
        }
    };
    check_state(csrf.secret(), &state)?;
    drop(listener);

    let tokens = exchange(&client, code, verifier)?;
    store.save(&tokens)?;
    Ok(AuthStatus { signed_in: true })
}

fn exchange(client: &Client, code: String, verifier: PkceCodeVerifier) -> Result<TokenSet> {
    // Redirects are not followed on the token endpoint (RFC 6749 section 3.2 and SSRF).
    let http = oauth2::ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(20))
        .build();
    let resp = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(verifier)
        .request(&http)
        .map_err(|e| {
            use oauth2::RequestTokenError as E;
            // Only the error class: a server error body is not echoed.
            let m = match e {
                E::ServerResponse(r) => format!("token endpoint refused the code: {}", r.error()),
                E::Request(_) => "token endpoint unreachable".to_string(),
                _ => "token endpoint returned an unusable response".to_string(),
            };
            err(AuthErrorKind::Unavailable, m)
        })?;
    Ok(TokenSet {
        access: SecretString::from(resp.access_token().secret().clone()),
        refresh: resp
            .refresh_token()
            .map(|r| SecretString::from(r.secret().clone())),
    })
}

pub fn sign_out(store: &dyn TokenStore) -> Result<AuthStatus> {
    store.clear()?;
    Ok(AuthStatus { signed_in: false })
}

pub fn status(store: &dyn TokenStore) -> Result<AuthStatus> {
    Ok(AuthStatus {
        signed_in: store.load()?.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};
    use std::sync::Mutex;

    fn cfg(issuer: &str) -> AuthConfig {
        AuthConfig {
            issuer: issuer.into(),
            client_id: "locksmith-desktop".into(),
        }
    }

    fn http_get(port: u16, target: &str) -> String {
        let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        write!(s, "GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    /// Records the authorization URL and replays the browser: hits the redirect URI with the
    /// given callback query (`{state}` is replaced by the real state).
    struct FakeBrowser {
        query: &'static str,
        seen: Mutex<Option<Url>>,
    }
    impl FakeBrowser {
        fn new(query: &'static str) -> Self {
            Self {
                query,
                seen: Mutex::new(None),
            }
        }
    }
    impl BrowserOpener for FakeBrowser {
        fn open(&self, url: &str) -> Result<()> {
            let u = Url::parse(url).unwrap();
            let pair = |k: &str| {
                u.query_pairs()
                    .find(|(n, _)| n == k)
                    .map(|(_, v)| v.into_owned())
                    .unwrap()
            };
            let redirect = Url::parse(&pair("redirect_uri")).unwrap();
            let query = self.query.replace("{state}", &pair("state"));
            let port = redirect.port().unwrap();
            *self.seen.lock().unwrap() = Some(u);
            std::thread::spawn(move || {
                http_get(port, &format!("{}?{query}", redirect.path()));
            });
            Ok(())
        }
    }

    /// A one-shot token endpoint. Returns its port and the received POST body.
    fn mock_token_endpoint() -> (u16, std::thread::JoinHandle<String>) {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut data = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = s.read(&mut buf).unwrap();
                data.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&data).to_string();
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let len = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if body.len() >= len {
                        break;
                    }
                }
            }
            let json = r#"{"access_token":"at-1","refresh_token":"rt-1","token_type":"Bearer","expires_in":300}"#;
            write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
                json.len()
            )
            .unwrap();
            String::from_utf8_lossy(&data).to_string()
        });
        (port, h)
    }

    #[test]
    fn parses_loopback_callback() {
        assert_eq!(
            parse_callback(
                "GET /callback?code=abc&state=xyz&session_state=q HTTP/1.1\r\nHost: x\r\n\r\n"
            ),
            Some(Callback::Code {
                code: "abc".into(),
                state: "xyz".into()
            })
        );
        assert_eq!(
            parse_callback("GET /callback?error=access_denied&state=xyz HTTP/1.1\r\n\r\n"),
            Some(Callback::Failed {
                error: "access_denied".into()
            })
        );
        // Percent-decoding.
        assert_eq!(
            parse_callback("GET /callback?code=a%2Fb&state=s HTTP/1.1\r\n"),
            Some(Callback::Code {
                code: "a/b".into(),
                state: "s".into()
            })
        );
    }

    #[test]
    fn rejects_non_callback_requests() {
        assert_eq!(parse_callback("GET /favicon.ico HTTP/1.1\r\n"), None);
        assert_eq!(
            parse_callback("POST /callback?code=a&state=b HTTP/1.1\r\n"),
            None
        );
        assert_eq!(parse_callback("GET /callback?code=a HTTP/1.1\r\n"), None);
        assert_eq!(parse_callback("GET /callback?state=a HTTP/1.1\r\n"), None);
        assert_eq!(parse_callback(""), None);
        assert_eq!(parse_callback("garbage"), None);
    }

    #[test]
    fn state_mismatch_is_rejected() {
        assert!(check_state("a", "a").is_ok());
        let e = check_state("a", "b").unwrap_err();
        assert_eq!(e.kind, AuthErrorKind::BadRequest);
    }

    #[test]
    fn auth_url_carries_s256_pkce_and_loopback_redirect() {
        let browser = FakeBrowser::new("error=access_denied");
        let store = MemoryTokenStore::default();
        let _ = sign_in_with_timeout(
            &cfg("http://127.0.0.1:1/realms/locksmith"),
            &store,
            &browser,
            Some("github"),
            Duration::from_secs(5),
        );
        let u = browser.seen.lock().unwrap().clone().unwrap();
        assert_eq!(u.path(), "/realms/locksmith/protocol/openid-connect/auth");
        let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], "locksmith-desktop");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["kc_idp_hint"], "github");
        assert!(q["redirect_uri"].starts_with("http://127.0.0.1:"));
        assert!(q["redirect_uri"].ends_with("/callback"));
        assert!(q["scope"].contains("openid"));
        assert!(q["state"].len() >= 16);
        assert!(q["code_challenge"].len() >= 43);
    }

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let expect = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.secret().as_bytes()));
        assert_eq!(challenge.as_str(), expect);
        assert!(verifier.secret().len() >= 43);
    }

    #[test]
    fn idp_hint_allow_list() {
        assert_eq!(idp_hint(None).unwrap(), None);
        assert_eq!(idp_hint(Some("email")).unwrap(), None);
        assert_eq!(idp_hint(Some("google")).unwrap(), Some("google"));
        assert!(idp_hint(Some("evil&x=y")).is_err());
    }

    #[test]
    fn denied_sign_in_stores_nothing() {
        let store = MemoryTokenStore::default();
        let e = sign_in_with_timeout(
            &cfg("http://127.0.0.1:1/realms/locksmith"),
            &store,
            &FakeBrowser::new("error=access_denied&state={state}"),
            None,
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(e.kind, AuthErrorKind::Denied);
        assert!(!status(&store).unwrap().signed_in);
    }

    #[test]
    fn state_mismatch_aborts_before_token_exchange() {
        let store = MemoryTokenStore::default();
        // Issuer port 1 is closed: reaching the exchange would be an Unavailable error.
        let e = sign_in_with_timeout(
            &cfg("http://127.0.0.1:1/realms/locksmith"),
            &store,
            &FakeBrowser::new("code=c&state=forged"),
            None,
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(e.kind, AuthErrorKind::BadRequest);
        assert!(e.message.contains("state"));
        assert!(!status(&store).unwrap().signed_in);
    }

    #[test]
    fn times_out_when_no_redirect_arrives() {
        struct Noop;
        impl BrowserOpener for Noop {
            fn open(&self, _: &str) -> Result<()> {
                Ok(())
            }
        }
        let store = MemoryTokenStore::default();
        let e = sign_in_with_timeout(
            &cfg("http://127.0.0.1:1/realms/locksmith"),
            &store,
            &Noop,
            None,
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert_eq!(e.kind, AuthErrorKind::Unavailable);
    }

    #[test]
    fn full_flow_exchanges_code_and_stores_tokens() {
        let (port, server) = mock_token_endpoint();
        let store = MemoryTokenStore::default();
        let out = sign_in_with_timeout(
            &cfg(&format!("http://127.0.0.1:{port}/realms/locksmith")),
            &store,
            &FakeBrowser::new("code=the-code&state={state}"),
            None,
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(out.signed_in);
        let body = server.join().unwrap();
        assert!(body.starts_with("POST /realms/locksmith/protocol/openid-connect/token"));
        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("code=the-code"));
        assert!(body.contains("code_verifier="));
        let t = store.load().unwrap().unwrap();
        assert_eq!(t.access.expose_secret(), "at-1");
        assert_eq!(t.refresh.unwrap().expose_secret(), "rt-1");
        assert_eq!(
            serde_json::to_string(&out).unwrap(),
            r#"{"signed_in":true}"#
        );
    }

    #[test]
    fn sign_out_deletes_tokens_and_is_idempotent() {
        let store = MemoryTokenStore::default();
        store
            .save(&TokenSet {
                access: SecretString::from("a".to_string()),
                refresh: Some(SecretString::from("r".to_string())),
            })
            .unwrap();
        assert!(status(&store).unwrap().signed_in);
        assert!(!sign_out(&store).unwrap().signed_in);
        assert!(!status(&store).unwrap().signed_in);
        assert!(!sign_out(&store).unwrap().signed_in);
    }

    #[test]
    fn unrelated_requests_get_404_and_listener_keeps_waiting() {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || await_callback(&l, Duration::from_secs(5)));
        assert!(http_get(port, "/favicon.ico").starts_with("HTTP/1.1 404"));
        assert!(http_get(port, "/callback?code=c&state=s").starts_with("HTTP/1.1 200"));
        assert_eq!(
            h.join().unwrap().unwrap(),
            Callback::Code {
                code: "c".into(),
                state: "s".into()
            }
        );
    }
}
