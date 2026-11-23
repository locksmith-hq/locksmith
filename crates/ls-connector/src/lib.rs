//! Agent remote mode (S4), shared by `smith login --agent|grants|relay` and the `locksmith-mcp`
//! tools `list_grants` and `relay_request`.
//!
//! `smith login --agent` exchanges an enrollment secret at the control plane's
//! `POST /v1/agent-tokens` for a short-lived agent token. Only that token, its expiry and the two
//! endpoints are kept, in `agent.json` under the config dir with mode 0600. The enrollment secret
//! is never stored. Grants and relay calls go to the gateway (`GET /v1/grants`, `POST /v1/relay`)
//! with the token.
//!
//! Secrets live in `secrecy` types (no Debug, Display or Clone). Everything returned for display
//! is passed through `ls-redact` with the token as the secret, and errors are fixed slugs: no
//! server or transport text reaches the caller. Honest label: containment, not prevention (a
//! compromised agent can use its token until it expires).

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ls_redact::{Redactor, Secret};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

mod workload;
pub use workload::*;

/// Environment variable holding the enrollment secret (alternative to stdin).
pub const ENROLLMENT_ENV: &str = "LOCKSMITH_ENROLLMENT_SECRET";
/// Control plane base URL.
pub const CONTROL_PLANE_ENV: &str = "LOCKSMITH_CONTROL_PLANE_URL";
/// Gateway base URL.
pub const GATEWAY_ENV: &str = "LOCKSMITH_GATEWAY_URL";
/// State file name under the config dir.
pub const STATE_FILE: &str = "agent.json";
/// Largest response read from the gateway or control plane (gateway caps upstream at 10 MiB).
const MAX_RESPONSE: u64 = 12 * 1024 * 1024;
/// Request headers a caller may not set on a relayed request: the gateway injects the credential,
/// so a caller-supplied one is either a leak or a confused-deputy attempt.
pub const CREDENTIAL_HEADERS: &[&str] = &["authorization", "proxy-authorization", "cookie"];

/// Whether an error is the caller's input (usage) or anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Usage,
    Failure,
}

/// A fixed, value-free message. Never carries server, transport or secret text.
#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn fail(msg: &str) -> Error {
    Error {
        kind: ErrorKind::Failure,
        message: msg.to_owned(),
    }
}

fn usage(msg: &str) -> Error {
    Error {
        kind: ErrorKind::Usage,
        message: msg.to_owned(),
    }
}

/// What the state file holds: the short-lived token, its expiry and the endpoints. Nothing else.
/// No Debug or Clone (the token is a bearer credential).
pub struct State {
    token: SecretString,
    expires_at: u64,
    control_plane_url: String,
    gateway_url: String,
}

#[derive(Serialize)]
struct StateOut<'a> {
    access_token: &'a str,
    expires_at_unix: u64,
    control_plane_url: &'a str,
    gateway_url: &'a str,
}

#[derive(Deserialize)]
struct StateIn {
    access_token: String,
    expires_at_unix: u64,
    control_plane_url: String,
    gateway_url: String,
}

impl State {
    /// `<config dir>/agent.json`.
    pub fn path() -> PathBuf {
        ls_core::config_dir().join(STATE_FILE)
    }

    /// Unix expiry of the token.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Write atomically with mode 0600 (the file never exists with wider permissions).
    pub fn save(&self) -> Result<()> {
        let path = Self::path();
        let dir = path.parent().map(PathBuf::from).unwrap_or_default();
        ls_platform::fs::ensure_private_dir(&dir)
            .map_err(|_| fail("cannot create the state directory"))?;
        let mut body = Zeroizing::new(
            serde_json::to_vec(&StateOut {
                access_token: self.token.expose_secret(),
                expires_at_unix: self.expires_at,
                control_plane_url: &self.control_plane_url,
                gateway_url: &self.gateway_url,
            })
            .map_err(|_| fail("cannot encode the state file"))?,
        );
        let tmp = dir.join(format!(".{STATE_FILE}.{}.tmp", std::process::id()));
        let write = || -> std::io::Result<()> {
            let _ = std::fs::remove_file(&tmp);
            let mut f = ls_platform::fs::PrivateFile::new()
                .create_new(true)
                .open(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &path)
        };
        let r = write();
        body.zeroize();
        if r.is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(fail("cannot write the state file"));
        }
        Ok(())
    }

    /// Read the state file; refused when it is accessible to group or others.
    pub fn load() -> Result<State> {
        let path = Self::path();
        let raw = std::fs::read(&path)
            .map(Zeroizing::new)
            .map_err(|_| fail("not logged in: run `smith login --agent`"))?;
        // Unix: no group/other mode bits (0600); Windows: owner-only ACL. An unreadable ACL fails
        // closed like an open one.
        if !ls_platform::fs::is_private(&path).unwrap_or(false) {
            return Err(fail(
                "the agent state file is accessible to others (expected mode 0600 or an \
                 owner-only ACL); run `smith login --agent` again",
            ));
        }
        let s: StateIn = serde_json::from_slice(&raw)
            .map_err(|_| fail("the agent state file is unreadable: run `smith login --agent`"))?;
        Ok(State {
            token: SecretString::from(s.access_token),
            expires_at: s.expires_at_unix,
            control_plane_url: s.control_plane_url,
            gateway_url: s.gateway_url,
        })
    }

    /// Load and check the token is still valid.
    pub fn load_fresh() -> Result<State> {
        let st = Self::load()?;
        st.ensure_fresh()?;
        Ok(st)
    }

    /// Token still valid (30 s margin), else a clear instruction.
    pub fn ensure_fresh(&self) -> Result<()> {
        if now_unix() + 30 >= self.expires_at {
            return Err(fail(
                "the agent token has expired: run `smith login --agent`",
            ));
        }
        Ok(())
    }

    /// Gateway base URL (no trailing slash).
    pub fn gateway_url(&self) -> &str {
        &self.gateway_url
    }

    /// Git credential-helper answer (`username=` / `password=` lines). The only place the token
    /// leaves this crate, and only toward Git, which sends it to the gateway as the Basic password.
    pub fn git_credential_lines(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "username=locksmith-agent\npassword={}\n",
            self.token.expose_secret()
        ))
    }

    /// The agent token as a secret, for `smith db connect --gateway`: the caller puts it in a
    /// child process environment (`PGPASSWORD`) and nowhere else.
    pub fn token_secret(&self) -> SecretString {
        SecretString::from(self.token.expose_secret().to_owned())
    }

    /// Redactor for this agent's own token.
    pub fn redactor(&self) -> Redactor {
        Redactor::new(&[Secret::new("TOKEN", self.token.expose_secret().as_bytes())])
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `https`, or `http` on loopback only; no credentials, query or fragment. Returned without a
/// trailing slash.
pub fn parse_endpoint(raw: &str) -> Result<String> {
    let bad = || fail("endpoint must be an https URL (http only on localhost) without credentials");
    let url = Url::parse(raw).map_err(|_| bad())?;
    let loopback = match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(a)) => a.is_loopback(),
        Some(url::Host::Ipv6(a)) => a.is_loopback(),
        None => return Err(bad()),
    };
    let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && loopback);
    if !scheme_ok
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(bad());
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn client() -> Result<reqwest::blocking::Client> {
    let err = || fail("cannot build the HTTP client");
    ls_http::blocking_builder()
        .map_err(|_| err())?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(45))
        .build()
        .map_err(|_| err())
}

/// Bounded read of a response body into a zeroizing buffer.
fn read_body(resp: reqwest::blocking::Response) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(Vec::new());
    resp.take(MAX_RESPONSE + 1)
        .read_to_end(&mut buf)
        .map_err(|_| fail("the server response could not be read"))?;
    if buf.len() as u64 > MAX_RESPONSE {
        return Err(fail("the server response is too large"));
    }
    Ok(buf)
}

fn transport(e: &reqwest::Error) -> Error {
    fail(if e.is_timeout() {
        "request timed out"
    } else if e.is_connect() {
        "cannot connect to the server"
    } else {
        "request failed"
    })
}

/// Fixed slug from a gateway/control-plane error body (`{"error": "slug"}`); never other text.
pub fn error_slug(body: &[u8]) -> String {
    let slug = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
        .or_else(|| {
            serde_json::from_slice::<Value>(body)
                .ok()
                .and_then(|v| v.get("type").and_then(|e| e.as_str()).map(str::to_owned))
        })
        .unwrap_or_default();
    let ok = !slug.is_empty()
        && slug.len() <= 48
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if ok { slug } else { "unknown".to_owned() }
}

fn http_fail(status: reqwest::StatusCode, body: &[u8], what: &str) -> Error {
    let hint = match status.as_u16() {
        401 => " (token or enrollment secret not accepted)",
        403 => " (not granted)",
        _ => "",
    };
    Error {
        kind: ErrorKind::Failure,
        message: format!(
            "{what} failed: {} {}{hint}",
            status.as_u16(),
            error_slug(body)
        ),
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

/// Exchange an enrollment secret for an agent token and save it. Returns the saved state and the
/// token lifetime in seconds. `control_plane` and `gateway` are raw URLs (validated here).
pub fn login(
    control_plane: &str,
    gateway: &str,
    enrollment_secret: &SecretString,
) -> Result<(State, u64)> {
    let control_plane = parse_endpoint(control_plane)?;
    let gateway = parse_endpoint(gateway)?;
    let mut req = Zeroizing::new(
        serde_json::to_vec(&json!({ "enrollment_secret": enrollment_secret.expose_secret() }))
            .map_err(|_| fail("cannot encode the request"))?,
    );
    let resp = client()?
        .post(format!("{control_plane}/v1/agent-tokens"))
        .header("content-type", "application/json")
        .body(std::mem::take(&mut *req))
        .send()
        .map_err(|e| transport(&e))?;
    let status = resp.status();
    let body = read_body(resp)?;
    if !status.is_success() {
        return Err(http_fail(status, &body, "login"));
    }
    let t: TokenResponse = serde_json::from_slice(&body)
        .map_err(|_| fail("login failed: unexpected response from the control plane"))?;
    let state = State {
        token: SecretString::from(t.access_token),
        expires_at: now_unix() + t.expires_in,
        control_plane_url: control_plane,
        gateway_url: gateway,
    };
    state.save()?;
    Ok((state, t.expires_in))
}

/// `GET /v1/grants`, reduced to names, modes, hosts and expiries whatever the server sent, and
/// redacted for the token: `{"agent_id", "grants": [{secret_id, secret_name, mode, expires_at,
/// allowed_origin}]}`.
pub fn grants(st: &State) -> Result<Value> {
    let resp = client()?
        .get(format!("{}/v1/grants", st.gateway_url))
        .bearer_auth(st.token.expose_secret())
        .send()
        .map_err(|e| transport(&e))?;
    let status = resp.status();
    let body = read_body(resp)?;
    if !status.is_success() {
        return Err(http_fail(status, &body, "grants"));
    }
    let v: Value = serde_json::from_slice(&body)
        .map_err(|_| fail("grants failed: unexpected response from the gateway"))?;
    let rows: Vec<Value> = v
        .get("grants")
        .and_then(|g| g.as_array())
        .map(|g| {
            g.iter()
                .map(|r| {
                    json!({
                        "secret_id": r.get("secret_id"),
                        "secret_name": r.get("secret_name"),
                        "mode": r.get("mode"),
                        "expires_at": r.get("expires_at"),
                        "allowed_origin": r.get("allowed_origin"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let out = json!({ "agent_id": v.get("agent_id"), "grants": rows });
    // Round-trip through the redactor so the token can never appear in any field.
    let red = st.redactor();
    serde_json::from_str(&redact_str(&red, &out.to_string()))
        .map_err(|_| fail("grants failed: unexpected response from the gateway"))
}

/// Redact `s` with `r`, lossily as UTF-8.
pub fn redact_str(r: &Redactor, s: &str) -> String {
    String::from_utf8_lossy(&r.redact_all(s.as_bytes())).into_owned()
}

/// Upstream request body.
pub enum RelayBody {
    Text(String),
    Bytes(Vec<u8>),
}

/// One relayed upstream request. Carries no credential: the gateway injects it.
pub struct RelayRequest {
    pub secret_id: String,
    pub version: u32,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<RelayBody>,
}

/// The upstream response with this agent's token redacted (the gateway already redacted the vault
/// secret).
pub struct RelayOutput {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RelayOutput {
    /// `{"status", "headers", "body"}` (or `body_base64` for a non-UTF-8 body).
    pub fn to_json(&self) -> Value {
        let mut out = json!({ "status": self.status, "headers": self.headers });
        match std::str::from_utf8(&self.body) {
            Ok(s) => out["body"] = s.into(),
            Err(_) => out["body_base64"] = B64.encode(&self.body).into(),
        }
        out
    }
}

#[derive(Deserialize)]
struct RelayResp {
    status: u16,
    #[serde(default)]
    headers: Vec<(String, String)>,
    body: Option<String>,
    body_base64: Option<String>,
}

/// Refuse a caller-supplied credential header (`Authorization`, `Proxy-Authorization`,
/// `Cookie`).
pub fn reject_credential_headers(headers: &[(String, String)]) -> Result<()> {
    for (n, _) in headers {
        let n = n.trim();
        if CREDENTIAL_HEADERS.iter().any(|c| n.eq_ignore_ascii_case(c)) {
            return Err(usage(&format!(
                "header `{}` is not allowed: the gateway injects the credential",
                n.to_ascii_lowercase()
            )));
        }
    }
    Ok(())
}

/// `POST /v1/relay`. `req.secret_id` is validated as a UUID first.
pub fn relay(st: &State, req: RelayRequest) -> Result<RelayOutput> {
    let secret_id = uuid_like(&req.secret_id)?;
    let mut body = json!({
        "secret_id": secret_id,
        "version": req.version,
        "method": req.method,
        "url": req.url,
        "headers": req.headers,
    });
    match req.body {
        Some(RelayBody::Text(s)) => body["body"] = s.into(),
        Some(RelayBody::Bytes(b)) => match String::from_utf8(b) {
            Ok(s) => body["body"] = s.into(),
            Err(e) => body["body_base64"] = B64.encode(e.into_bytes()).into(),
        },
        None => {}
    }
    let resp = client()?
        .post(format!("{}/v1/relay", st.gateway_url))
        .bearer_auth(st.token.expose_secret())
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .map_err(|e| transport(&e))?;
    let status = resp.status();
    let raw = read_body(resp)?;
    if !status.is_success() {
        return Err(http_fail(status, &raw, "relay"));
    }
    let r: RelayResp = serde_json::from_slice(&raw)
        .map_err(|_| fail("relay failed: unexpected response from the gateway"))?;
    let red = st.redactor();
    // The gateway already redacted the vault secret; this pass removes the agent's own token.
    let body = match (&r.body, &r.body_base64) {
        (Some(t), _) => red.redact_all(t.as_bytes()),
        (None, Some(b)) => red.redact_all(
            &B64.decode(b)
                .map_err(|_| fail("relay failed: unexpected response from the gateway"))?,
        ),
        (None, None) => Vec::new(),
    };
    let headers = r
        .headers
        .iter()
        .map(|(n, v)| (redact_str(&red, n), redact_str(&red, v)))
        .collect();
    Ok(RelayOutput {
        status: r.status,
        headers,
        body,
    })
}

/// `POST /v1/aws/credentials` (D2): short-lived STS credentials as the AWS CLI `credential_process`
/// document `{"Version":1,"AccessKeyId","SecretAccessKey","SessionToken","Expiration"}`.
///
/// The document is the credential: it is returned in a zeroizing buffer and never logged. The
/// response is parsed and re-serialized, so nothing else the server sent can reach the output.
/// Every failure is one fixed message: no status, slug, server or transport text.
pub fn aws_credentials(st: &State, duration_secs: Option<u32>) -> Result<Zeroizing<String>> {
    const DENIED: &str = "AWS credentials were not issued (not granted, token expired or gateway \
                          unavailable); run `smith doctor` to check";
    let body = match duration_secs {
        Some(d) => json!({ "duration_secs": d }),
        None => json!({}),
    };
    let resp = client()?
        .post(format!("{}/v1/aws/credentials", st.gateway_url))
        .bearer_auth(st.token.expose_secret())
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .map_err(|_| fail(DENIED))?;
    if !resp.status().is_success() {
        return Err(fail(DENIED));
    }
    let raw = read_body(resp).map_err(|_| fail(DENIED))?;

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct In {
        version: u8,
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
        expiration: String,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct Out<'a> {
        version: u8,
        access_key_id: &'a str,
        secret_access_key: &'a str,
        session_token: &'a str,
        expiration: &'a str,
    }
    let doc: In = serde_json::from_slice(&raw).map_err(|_| fail(DENIED))?;
    let held = Zeroizing::new((
        doc.access_key_id,
        doc.secret_access_key,
        doc.session_token,
        doc.expiration,
    ));
    let (k, sk, t, e) = &*held;
    if doc.version != 1 || [k, sk, t, e].iter().any(|v| v.is_empty()) {
        return Err(fail(DENIED));
    }
    serde_json::to_string(&Out {
        version: 1,
        access_key_id: k,
        secret_access_key: sk,
        session_token: t,
        expiration: e,
    })
    .map(Zeroizing::new)
    .map_err(|_| fail(DENIED))
}

/// Canonical hyphenated UUID, lowercased, or a usage error (the id is sent verbatim to the
/// gateway).
pub fn uuid_like(s: &str) -> Result<String> {
    let ok = s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    if ok {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(usage("secret id must be a UUID"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_rules() {
        assert!(parse_endpoint("https://gw.example.com/").is_ok());
        assert!(parse_endpoint("http://127.0.0.1:8080").is_ok());
        assert!(parse_endpoint("http://localhost:8080").is_ok());
        assert!(parse_endpoint("http://gw.example.com").is_err());
        assert!(parse_endpoint("https://u:p@gw.example.com").is_err());
        assert!(parse_endpoint("https://gw.example.com/?x=1").is_err());
        assert!(parse_endpoint("ftp://gw.example.com").is_err());
        assert_eq!(
            parse_endpoint("https://gw.example.com/").ok().as_deref(),
            Some("https://gw.example.com")
        );
    }

    #[test]
    fn error_slug_is_fixed_vocabulary() {
        assert_eq!(
            error_slug(br#"{"error":"no_grant","request_id":"x"}"#),
            "no_grant"
        );
        assert_eq!(
            error_slug(br#"{"error":"has spaces and lse_SECRET"}"#),
            "unknown"
        );
        assert_eq!(error_slug(b"not json lse_SECRET"), "unknown");
    }

    #[test]
    fn uuid_validation() {
        assert!(uuid_like("0191a3b2-7c1e-7a3f-8b2d-5e6f7a8b9c0d").is_ok());
        assert_eq!(uuid_like("nope").unwrap_err().kind, ErrorKind::Usage);
    }

    #[test]
    fn credential_headers_are_refused() {
        let h = |n: &str| vec![(n.to_owned(), "x".to_owned())];
        for n in ["Authorization", "COOKIE", " proxy-authorization "] {
            let e = reject_credential_headers(&h(n)).unwrap_err();
            assert_eq!(e.kind, ErrorKind::Usage);
            assert!(e.message.contains("not allowed"), "{}", e.message);
        }
        assert!(reject_credential_headers(&h("x-api-version")).is_ok());
    }

    #[test]
    fn relay_output_json_falls_back_to_base64() {
        let o = RelayOutput {
            status: 200,
            headers: vec![],
            body: vec![0xff, 0x00],
        };
        let v = o.to_json();
        assert!(v.get("body").is_none());
        assert_eq!(v["body_base64"], "/wA=");
    }
}
