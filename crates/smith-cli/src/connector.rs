//! Remote mode (S4 task 3.1): `smith login --agent`, `smith grants`, `smith relay`.
//!
//! `login --agent` exchanges an enrollment secret (`lse_...`, from `LOCKSMITH_ENROLLMENT_SECRET`
//! or stdin, never argv) at the control plane's `POST /v1/agent-tokens` for a short-lived agent
//! token. Only that token, its expiry and the two endpoints are kept, in `agent.json` under the
//! config dir with mode 0600. The enrollment secret is never stored. `grants` and `relay` call
//! the gateway (`GET /v1/grants`, `POST /v1/relay`) with the token.
//!
//! Secrets live in `secrecy` types (no Debug, Display or Clone). Everything printed is passed
//! through `ls-redact` with the token as the secret, and errors are fixed slugs: no server or
//! transport text reaches the output. Honest label: containment, not prevention (a compromised
//! agent can use its token until it expires).

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use clap::{Args, ValueEnum};
use ls_core::ExitCode;
use ls_redact::{Redactor, Secret};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::Fail;
use crate::input;

/// Environment variable holding the enrollment secret (alternative to stdin).
pub const ENROLLMENT_ENV: &str = "LOCKSMITH_ENROLLMENT_SECRET";
const CONTROL_PLANE_ENV: &str = "LOCKSMITH_CONTROL_PLANE_URL";
const GATEWAY_ENV: &str = "LOCKSMITH_GATEWAY_URL";
/// State file name under the config dir.
const STATE_FILE: &str = "agent.json";
/// Largest response read from the gateway or control plane (gateway caps upstream at 10 MiB).
const MAX_RESPONSE: u64 = 12 * 1024 * 1024;

#[derive(Args)]
pub struct LoginArgs {
    /// Log in as an agent: exchange an enrollment secret for a short-lived token. The secret is
    /// read from $LOCKSMITH_ENROLLMENT_SECRET, else from stdin (a no-echo prompt on a terminal).
    #[arg(long, required = true)]
    pub agent: bool,
    /// Control plane base URL (`https`, or `http` on loopback only).
    #[arg(long, env = CONTROL_PLANE_ENV)]
    pub control_plane_url: String,
    /// Gateway base URL (`https`, or `http` on loopback only).
    #[arg(long, env = GATEWAY_ENV)]
    pub gateway_url: String,
}

#[derive(Args)]
pub struct RelayArgs {
    /// Secret id the gateway injects (must be granted to this agent).
    #[arg(long)]
    pub secret_id: String,
    /// Secret version to use.
    #[arg(long, default_value_t = 1)]
    pub version: u32,
    /// HTTP method of the upstream request.
    #[arg(long, short = 'X', default_value = "GET")]
    pub method: String,
    /// Extra upstream request header, `Name: value` (repeatable). Never put a credential here.
    #[arg(long = "header", short = 'H')]
    pub headers: Vec<String>,
    /// Upstream request body (text).
    #[arg(long, conflicts_with = "data_stdin")]
    pub data: Option<String>,
    /// Read the upstream request body from stdin.
    #[arg(long)]
    pub data_stdin: bool,
    /// How to show the response in human mode.
    #[arg(long, value_enum, default_value_t = Show::Body)]
    pub show: Show,
    /// Upstream URL.
    pub url: String,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Show {
    /// Status line and body.
    Body,
    /// Status line, headers and body.
    All,
}

/// What the state file holds: the short-lived token, its expiry and the endpoints. Nothing else.
/// No Debug or Clone (the token is a bearer credential).
struct State {
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
    fn path() -> PathBuf {
        ls_core::config_dir().join(STATE_FILE)
    }

    /// Write atomically with mode 0600 (the file never exists with wider permissions).
    fn save(&self) -> Result<(), Fail> {
        let path = Self::path();
        let dir = path.parent().map(PathBuf::from).unwrap_or_default();
        ls_core::ensure_private_dir(&dir).map_err(|_| fail("cannot create the state directory"))?;
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
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let _ = std::fs::remove_file(&tmp);
            let mut f = opts.open(&tmp)?;
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

    fn load() -> Result<State, Fail> {
        let path = Self::path();
        let raw = std::fs::read(&path)
            .map(Zeroizing::new)
            .map_err(|_| fail("not logged in: run `smith login --agent`"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .map(|m| m.permissions().mode())
                .unwrap_or(0);
            if mode & 0o077 != 0 {
                return Err(fail(
                    "the agent state file is accessible to others (expected mode 0600); \
                     run `smith login --agent` again",
                ));
            }
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

    /// Token still valid (30 s margin), else a clear instruction.
    fn ensure_fresh(&self) -> Result<(), Fail> {
        if now_unix() + 30 >= self.expires_at {
            return Err(fail(
                "the agent token has expired: run `smith login --agent`",
            ));
        }
        Ok(())
    }

    fn redactor(&self) -> Redactor {
        Redactor::new(&[Secret::new("TOKEN", self.token.expose_secret().as_bytes())])
    }
}

fn fail(msg: &str) -> Fail {
    Fail(ExitCode::Failure, msg.to_owned())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `https`, or `http` on loopback only; no credentials, query or fragment. Returned without a
/// trailing slash.
fn parse_endpoint(raw: &str) -> Result<String, Fail> {
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

fn client() -> Result<reqwest::blocking::Client, Fail> {
    use rustls_platform_verifier::BuilderVerifierExt as _;
    let err = || fail("cannot build the HTTP client");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| err())?
        .with_platform_verifier()
        .map_err(|_| err())?
        .with_no_client_auth();
    reqwest::blocking::Client::builder()
        .tls_backend_preconfigured(tls)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(45))
        .build()
        .map_err(|_| err())
}

/// Bounded read of a response body into a zeroizing buffer.
fn read_body(resp: reqwest::blocking::Response) -> Result<Zeroizing<Vec<u8>>, Fail> {
    let mut buf = Zeroizing::new(Vec::new());
    resp.take(MAX_RESPONSE + 1)
        .read_to_end(&mut buf)
        .map_err(|_| fail("the server response could not be read"))?;
    if buf.len() as u64 > MAX_RESPONSE {
        return Err(fail("the server response is too large"));
    }
    Ok(buf)
}

fn transport(e: &reqwest::Error) -> Fail {
    fail(if e.is_timeout() {
        "request timed out"
    } else if e.is_connect() {
        "cannot connect to the server"
    } else {
        "request failed"
    })
}

/// Fixed slug from a gateway/control-plane error body (`{"error": "slug"}`); never other text.
fn error_slug(body: &[u8]) -> String {
    let slug = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
        .or_else(|| {
            serde_json::from_slice::<serde_json::Value>(body)
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

fn http_fail(status: reqwest::StatusCode, body: &[u8], what: &str) -> Fail {
    let hint = match status.as_u16() {
        401 => " (token or enrollment secret not accepted)",
        403 => " (not granted)",
        _ => "",
    };
    Fail(
        ExitCode::Failure,
        format!(
            "{what} failed: {} {}{hint}",
            status.as_u16(),
            error_slug(body)
        ),
    )
}

fn enrollment_secret() -> Result<SecretString, Fail> {
    if let Ok(v) = std::env::var(ENROLLMENT_ENV) {
        let v = Zeroizing::new(v);
        let t = v.trim();
        if !t.is_empty() {
            return Ok(SecretString::from(t.to_owned()));
        }
    }
    let line = if std::io::stdin().is_terminal() {
        input::prompt_secret("Enrollment secret: ")?
    } else {
        input::read_line_stdin()?
    };
    let t = line.trim();
    if t.is_empty() {
        return Err(fail("no enrollment secret provided"));
    }
    Ok(SecretString::from(t.to_owned()))
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

pub fn login(json: bool, a: LoginArgs) -> Result<ExitCode, Fail> {
    let control_plane = parse_endpoint(&a.control_plane_url)?;
    let gateway = parse_endpoint(&a.gateway_url)?;
    let secret = enrollment_secret()?;
    let mut req = Zeroizing::new(
        serde_json::to_vec(&json!({ "enrollment_secret": secret.expose_secret() }))
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
    if json {
        println!(
            "{}",
            json!({ "status": "logged_in", "expires_in": t.expires_in, "expires_at_unix": state.expires_at })
        );
    } else {
        println!("logged in as agent (token valid for {} s)", t.expires_in);
    }
    Ok(ExitCode::Ok)
}

pub fn grants(json: bool) -> Result<ExitCode, Fail> {
    let st = State::load()?;
    st.ensure_fresh()?;
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
    let red = st.redactor();
    let v: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| fail("grants failed: unexpected response from the gateway"))?;
    // Names, modes, hosts and expiries only, whatever the server sent.
    let rows: Vec<serde_json::Value> = v
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
    if json {
        println!("{}", redact_str(&red, &out.to_string()));
    } else if rows.is_empty() {
        println!("no grants");
    } else {
        let s = |r: &serde_json::Value, k: &str| {
            r.get(k).and_then(|x| x.as_str()).unwrap_or("-").to_owned()
        };
        for r in &rows {
            let line = format!(
                "{}  {}  {}  host={}  expires={}",
                s(r, "secret_id"),
                s(r, "secret_name"),
                s(r, "mode"),
                s(r, "allowed_origin"),
                s(r, "expires_at"),
            );
            println!("{}", redact_str(&red, &line));
        }
    }
    Ok(ExitCode::Ok)
}

fn redact_str(r: &Redactor, s: &str) -> String {
    String::from_utf8_lossy(&r.redact_all(s.as_bytes())).into_owned()
}

#[derive(Deserialize)]
struct RelayResp {
    status: u16,
    #[serde(default)]
    headers: Vec<(String, String)>,
    body: Option<String>,
    body_base64: Option<String>,
}

pub fn relay(json: bool, a: RelayArgs) -> Result<ExitCode, Fail> {
    let st = State::load()?;
    st.ensure_fresh()?;
    let secret_id = uuid_like(&a.secret_id)?;
    let mut headers = Vec::new();
    for h in &a.headers {
        let (n, v) = h
            .split_once(':')
            .ok_or_else(|| Fail(ExitCode::Usage, "header must be `Name: value`".into()))?;
        headers.push((n.trim().to_owned(), v.trim().to_owned()));
    }
    let mut req = json!({
        "secret_id": secret_id,
        "version": a.version,
        "method": a.method,
        "url": a.url,
        "headers": headers,
    });
    if let Some(d) = a.data {
        req["body"] = d.into();
    } else if a.data_stdin {
        let mut buf = Vec::new();
        std::io::stdin()
            .lock()
            .read_to_end(&mut buf)
            .map_err(|_| fail("cannot read stdin"))?;
        match String::from_utf8(buf) {
            Ok(s) => req["body"] = s.into(),
            Err(e) => req["body_base64"] = B64.encode(e.into_bytes()).into(),
        }
    }
    let resp = client()?
        .post(format!("{}/v1/relay", st.gateway_url))
        .bearer_auth(st.token.expose_secret())
        .header("content-type", "application/json")
        .body(req.to_string())
        .send()
        .map_err(|e| transport(&e))?;
    let status = resp.status();
    let body = read_body(resp)?;
    if !status.is_success() {
        return Err(http_fail(status, &body, "relay"));
    }
    let r: RelayResp = serde_json::from_slice(&body)
        .map_err(|_| fail("relay failed: unexpected response from the gateway"))?;
    let red = st.redactor();
    // The gateway already redacted the vault secret; this pass removes the agent's own token.
    let body_bytes: Vec<u8> = match (&r.body, &r.body_base64) {
        (Some(t), _) => red.redact_all(t.as_bytes()),
        (None, Some(b)) => red.redact_all(
            &B64.decode(b)
                .map_err(|_| fail("relay failed: unexpected response from the gateway"))?,
        ),
        (None, None) => Vec::new(),
    };
    let hdrs: Vec<(String, String)> = r
        .headers
        .iter()
        .map(|(n, v)| (redact_str(&red, n), redact_str(&red, v)))
        .collect();
    if json {
        let mut out = json!({ "status": r.status, "headers": hdrs });
        match String::from_utf8(body_bytes) {
            Ok(s) => out["body"] = s.into(),
            Err(e) => out["body_base64"] = B64.encode(e.into_bytes()).into(),
        }
        println!("{out}");
    } else {
        println!("HTTP {}", r.status);
        if a.show == Show::All {
            for (n, v) in &hdrs {
                println!("{n}: {v}");
            }
            println!();
        }
        let mut so = std::io::stdout().lock();
        let _ = so.write_all(&body_bytes);
        if !body_bytes.ends_with(b"\n") {
            let _ = so.write_all(b"\n");
        }
    }
    Ok(ExitCode::Ok)
}

/// Canonical hyphenated UUID or a usage error (the id is sent verbatim to the gateway).
fn uuid_like(s: &str) -> Result<String, Fail> {
    let ok = s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    if ok {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(Fail(ExitCode::Usage, "secret id must be a UUID".into()))
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
        assert!(uuid_like("nope").is_err());
    }
}
