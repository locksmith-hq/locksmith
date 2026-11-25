//! Remote mode (S4 task 3.1): `smith login --agent`, `smith grants`, `smith relay`.
//!
//! `login --agent` exchanges an enrollment secret (`lse_...`, from `LOCKSMITH_ENROLLMENT_SECRET`
//! or stdin, never argv) at the control plane's `POST /v1/agent-tokens` for a short-lived agent
//! token. Only that token, its expiry and the two endpoints are kept, in `agent.json` under the
//! config dir with mode 0600. The enrollment secret is never stored. `grants` and `relay` call
//! the gateway (`GET /v1/grants`, `POST /v1/relay`) with the token.
//!
//! The state file, request shapes and redaction live in `ls-connector`, shared with the
//! `locksmith-mcp` tools `list_grants` and `relay_request`. This module is the CLI surface:
//! argument parsing, secret ingress and printing. Errors are fixed slugs: no server or transport
//! text reaches the output. Honest label: containment, not prevention (a compromised agent can
//! use its token until it expires).

use std::io::{IsTerminal, Read, Write};

use clap::{Args, ValueEnum};
use ls_connector::{RelayBody, RelayRequest, State};
use ls_core::ExitCode;
use secrecy::SecretString;
use serde_json::json;
use zeroize::Zeroizing;

use crate::Fail;
use crate::input;

/// Environment variable holding the enrollment secret (alternative to stdin).
pub const ENROLLMENT_ENV: &str = ls_connector::ENROLLMENT_ENV;
const CONTROL_PLANE_ENV: &str = ls_connector::CONTROL_PLANE_ENV;
const GATEWAY_ENV: &str = ls_connector::GATEWAY_ENV;

#[derive(Args)]
pub struct LoginArgs {
    /// Log in as an agent: exchange an enrollment secret for a short-lived token. The secret is
    /// read from $LOCKSMITH_ENROLLMENT_SECRET, else from stdin (a no-echo prompt on a terminal).
    #[arg(
        long,
        required_unless_present_any = ["user", "workload"],
        conflicts_with_all = ["user", "workload"]
    )]
    pub agent: bool,
    /// Log in as a human with the OAuth device grant (RFC 8628): approve in any browser; the
    /// token is kept in the OS keystore.
    #[arg(long, conflicts_with = "workload")]
    pub user: bool,
    /// Log in as a CI or cluster workload with no stored secret: fetch the runner's OIDC token
    /// (`github`: $ACTIONS_ID_TOKEN_REQUEST_URL and $ACTIONS_ID_TOKEN_REQUEST_TOKEN, needs
    /// `permissions: id-token: write`; `kubernetes`: a projected token file) and exchange it for a
    /// 15-minute agent token under the trust policy named by --policy. Only the agent token is
    /// kept, in agent.json (0600); the external token is never written or printed.
    #[arg(long, value_enum)]
    pub workload: Option<Workload>,
    /// Trust policy handle (`lsw_...`, not a secret) for `--workload`.
    #[arg(long, env = ls_connector::WORKLOAD_POLICY_ENV, requires = "workload")]
    pub policy: Option<String>,
    /// Audience to request for the external token (`--workload`; default: the control plane URL,
    /// which is the policy default). Must equal the policy's audience.
    #[arg(long, env = ls_connector::WORKLOAD_AUDIENCE_ENV, requires = "workload")]
    pub audience: Option<String>,
    /// Projected service account token file for `--workload kubernetes` (default:
    /// the pod's service account token; mount a projected token with the policy audience).
    #[arg(long, env = ls_connector::WORKLOAD_TOKEN_FILE_ENV, requires = "workload")]
    pub token_file: Option<std::path::PathBuf>,
    /// Control plane base URL (`https`, or `http` on loopback only). Agent and workload login.
    #[arg(long, env = CONTROL_PLANE_ENV)]
    pub control_plane_url: Option<String>,
    /// Gateway base URL (`https`, or `http` on loopback only). Agent and workload login.
    #[arg(long, env = GATEWAY_ENV)]
    pub gateway_url: Option<String>,
    /// OIDC issuer URL for `--user` (Keycloak realm layout; `https`, or `http` on loopback).
    #[arg(long, env = "LOCKSMITH_OIDC_ISSUER", requires = "user")]
    pub issuer: Option<String>,
    /// OAuth client id for `--user` (the issuer client must allow the device grant).
    #[arg(long, env = "LOCKSMITH_OIDC_CLIENT_ID", requires = "user")]
    pub client_id: Option<String>,
}

/// Where the external identity token comes from.
#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Workload {
    /// GitHub Actions OIDC (runner request variables).
    Github,
    /// Kubernetes projected service account token file.
    Kubernetes,
}

#[derive(Args)]
pub struct RelayArgs {
    /// Secret id the gateway injects (must be granted to this agent).
    #[arg(
        long,
        required_unless_present = "connection",
        conflicts_with = "connection"
    )]
    pub secret_id: Option<String>,
    /// A person's OAuth connection id (from `smith grants`) instead of a secret.
    #[arg(long)]
    pub connection: Option<String>,
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

impl From<ls_connector::Error> for Fail {
    fn from(e: ls_connector::Error) -> Self {
        let code = match e.kind {
            ls_connector::ErrorKind::Usage => ExitCode::Usage,
            ls_connector::ErrorKind::Failure => ExitCode::Failure,
        };
        Fail(code, e.message)
    }
}

fn fail(msg: &str) -> Fail {
    Fail(ExitCode::Failure, msg.to_owned())
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

pub fn login(json: bool, a: LoginArgs) -> Result<ExitCode, Fail> {
    if a.user {
        return crate::user_login::run(json, a.issuer, a.client_id);
    }
    let (Some(control_plane_url), Some(gateway_url)) = (&a.control_plane_url, &a.gateway_url)
    else {
        return Err(Fail(
            ExitCode::Usage,
            "--control-plane-url and --gateway-url are required".into(),
        ));
    };
    if let Some(kind) = a.workload {
        return workload_login(json, kind, &a, control_plane_url, gateway_url);
    }
    // Validate both endpoints before asking for the secret.
    ls_connector::parse_endpoint(control_plane_url)?;
    ls_connector::parse_endpoint(gateway_url)?;
    let secret = enrollment_secret()?;
    let (state, expires_in) = ls_connector::login(control_plane_url, gateway_url, &secret)?;
    if json {
        println!(
            "{}",
            json!({ "status": "logged_in", "expires_in": expires_in, "expires_at_unix": state.expires_at() })
        );
    } else {
        println!("logged in as agent (token valid for {expires_in} s)");
    }
    Ok(ExitCode::Ok)
}

fn workload_login(
    json: bool,
    kind: Workload,
    a: &LoginArgs,
    control_plane_url: &str,
    gateway_url: &str,
) -> Result<ExitCode, Fail> {
    let usage = |m: &str| Fail(ExitCode::Usage, m.to_owned());
    // Validate everything that needs no secret before reading any token.
    let cp = ls_connector::parse_endpoint(control_plane_url)?;
    ls_connector::parse_endpoint(gateway_url)?;
    let policy = a
        .policy
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            usage("--policy or $LOCKSMITH_WORKLOAD_POLICY is required for --workload")
        })?;
    if !ls_connector::valid_policy_handle(policy) {
        return Err(usage(
            "the workload policy handle is not valid (expected lsw_...)",
        ));
    }
    let audience = a.audience.clone().unwrap_or(cp);
    let external = match kind {
        Workload::Github => {
            let url = std::env::var(ls_connector::GITHUB_REQUEST_URL_ENV).map_err(|_| {
                fail(
                    "not running in GitHub Actions with OIDC: add `permissions: id-token: write` to the job",
                )
            })?;
            let tok = Zeroizing::new(
                std::env::var(ls_connector::GITHUB_REQUEST_TOKEN_ENV)
                    .map_err(|_| fail("the runner did not provide a token request token"))?,
            );
            let tok = SecretString::from(tok.to_string());
            ls_connector::fetch_github_token(&url, &tok, &audience)?
        }
        Workload::Kubernetes => {
            let default = std::path::PathBuf::from(ls_connector::KUBERNETES_DEFAULT_TOKEN_FILE);
            ls_connector::read_token_file(a.token_file.as_ref().unwrap_or(&default))?
        }
    };
    let (state, expires_in) =
        ls_connector::login_workload(control_plane_url, gateway_url, policy, &external)?;
    if json {
        println!(
            "{}",
            json!({ "status": "logged_in", "expires_in": expires_in, "expires_at_unix": state.expires_at() })
        );
    } else {
        println!("logged in as workload agent (token valid for {expires_in} s)");
    }
    Ok(ExitCode::Ok)
}

pub fn grants(json: bool) -> Result<ExitCode, Fail> {
    let st = State::load_fresh()?;
    // Names, modes, hosts and expiries only, already redacted for the token.
    let out = ls_connector::grants(&st)?;
    let red = st.redactor();
    let empty = Vec::new();
    let rows = out["grants"].as_array().unwrap_or(&empty);
    let conns = out["connection_grants"].as_array().unwrap_or(&empty);
    if json {
        println!("{}", ls_connector::redact_str(&red, &out.to_string()));
    } else if rows.is_empty() && conns.is_empty() {
        println!("no grants");
    } else {
        let s = |r: &serde_json::Value, k: &str| {
            r.get(k).and_then(|x| x.as_str()).unwrap_or("-").to_owned()
        };
        for r in rows {
            let line = format!(
                "{}  {}  {}  host={}  expires={}",
                s(r, "secret_id"),
                s(r, "secret_name"),
                s(r, "mode"),
                s(r, "allowed_origin"),
                s(r, "expires_at"),
            );
            println!("{}", ls_connector::redact_str(&red, &line));
        }
        for r in conns {
            let line = format!(
                "{}  {}  connection  person={}  expires={}",
                s(r, "connection_id"),
                s(r, "provider"),
                s(r, "person_name"),
                s(r, "expires_at"),
            );
            println!("{}", ls_connector::redact_str(&red, &line));
        }
    }
    Ok(ExitCode::Ok)
}

pub fn relay(json: bool, a: RelayArgs) -> Result<ExitCode, Fail> {
    let st = State::load_fresh()?;
    if let Some(id) = &a.secret_id {
        ls_connector::uuid_like(id)?;
    }
    let mut headers = Vec::new();
    for h in &a.headers {
        let (n, v) = h
            .split_once(':')
            .ok_or_else(|| Fail(ExitCode::Usage, "header must be `Name: value`".into()))?;
        headers.push((n.trim().to_owned(), v.trim().to_owned()));
    }
    ls_connector::reject_credential_headers(&headers)?;
    let body = if let Some(d) = a.data {
        Some(RelayBody::Text(d))
    } else if a.data_stdin {
        let mut buf = Vec::new();
        std::io::stdin()
            .lock()
            .read_to_end(&mut buf)
            .map_err(|_| fail("cannot read stdin"))?;
        Some(RelayBody::Bytes(buf))
    } else {
        None
    };
    let r = ls_connector::relay(
        &st,
        RelayRequest {
            secret_id: a.secret_id,
            connection_id: a.connection,
            version: a.version,
            method: a.method,
            url: a.url,
            headers,
            body,
        },
    )?;
    if json {
        println!("{}", r.to_json());
    } else {
        println!("HTTP {}", r.status);
        if a.show == Show::All {
            for (n, v) in &r.headers {
                println!("{n}: {v}");
            }
            println!();
        }
        let mut so = std::io::stdout().lock();
        let _ = so.write_all(&r.body);
        if !r.body.ends_with(b"\n") {
            let _ = so.write_all(b"\n");
        }
    }
    Ok(ExitCode::Ok)
}
