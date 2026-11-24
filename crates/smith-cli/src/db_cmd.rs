//! `smith db connect <name> [-- cmd args]` (M6): ask the daemon for this session's password-less
//! local endpoint for `[db.<name>]`, then print it or run `cmd` with the client environment set.
//! The password never passes through here: the daemon's relay authenticates upstream.
//!
//! With `--gateway <url>` (D3) the target is the hosted gateway's Postgres listener instead: the
//! child gets `PG*` variables with `PGPASSWORD` set to the agent token (the gateway authenticates
//! upstream with the stored password, which never reaches this machine). Nothing is written to disk
//! and the token is never printed.

use crate::session::{call, connect, exit_of};
use crate::{Fail, binding};
use clap::{Args, Subcommand};
use ls_core::ExitCode;
use ls_ipc::{Request, Response};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;

#[derive(Subcommand)]
pub enum DbCmd {
    /// Open a password-less local endpoint for `[db.<name>]` (inside a session) and print its
    /// URL, or run a command with PG*/MYSQL_*/REDIS_URL and DATABASE_URL pointing at it.
    ///
    /// With `--gateway`, `<name>` is a Postgres binding on the hosted gateway: the command runs
    /// with PGHOST, PGPORT, PGDATABASE, PGSSLMODE and PGPASSWORD (your agent token, in that
    /// command's environment only; the database password never leaves the gateway). Run
    /// `smith login --agent` first. Bind a least-privilege database role: the agent can run
    /// whatever that role may.
    Connect(ConnectArgs),
}

#[derive(Args)]
pub struct ConnectArgs {
    /// Target name from `.locksmith.toml` (`[db.<name>]`), or with `--gateway` the gateway's
    /// `[[pg]]` binding name (sent as the database).
    name: String,
    /// Hosted gateway Postgres listener, `host[:port]` or `https://host[:port]` (default port
    /// 5432). The token goes only to this host, over TLS.
    #[arg(long, value_name = "URL", env = "LOCKSMITH_DB_GATEWAY")]
    gateway: Option<String>,
    /// With `--gateway`: PGSSLMODE for the child, `verify-full` (default) or `require` (encrypts
    /// but does not check the server certificate; prints a warning).
    #[arg(long, value_enum, default_value = "verify-full", requires = "gateway")]
    sslmode: GatewaySslMode,
    /// With `--gateway`: PEM file with the CA that signed the gateway certificate
    /// (PGSSLROOTCERT).
    #[arg(long, value_name = "FILE", requires = "gateway")]
    ca_cert: Option<std::path::PathBuf>,
    /// Command to run with the endpoint in its environment.
    #[arg(last = true)]
    cmd: Vec<String>,
}

#[derive(clap::ValueEnum, Clone, Copy, PartialEq, Eq)]
enum GatewaySslMode {
    #[value(name = "verify-full")]
    VerifyFull,
    #[value(name = "require")]
    Require,
}

impl GatewaySslMode {
    fn as_str(self) -> &'static str {
        match self {
            GatewaySslMode::VerifyFull => "verify-full",
            GatewaySslMode::Require => "require",
        }
    }
}

/// Host and port of the gateway's Postgres listener.
#[derive(Debug, PartialEq, Eq)]
pub struct GatewayTarget {
    pub host: String,
    pub port: u16,
}

impl GatewayTarget {
    /// `host`, `host:port`, `[v6]:port` or a `https`/`postgres(ql)` URL; no credentials, path,
    /// query or fragment (the token must not travel in a URL).
    pub fn parse(raw: &str) -> Result<GatewayTarget, String> {
        let bad = || {
            "gateway must be host[:port] or an https URL without credentials, path or query"
                .to_string()
        };
        let raw = raw.trim();
        let full = if raw.contains("://") {
            raw.to_string()
        } else {
            format!("postgres://{raw}")
        };
        let u = url::Url::parse(&full).map_err(|_| bad())?;
        if !matches!(u.scheme(), "https" | "postgres" | "postgresql")
            || !u.username().is_empty()
            || u.password().is_some()
            || u.query().is_some()
            || u.fragment().is_some()
            || !matches!(u.path(), "" | "/")
        {
            return Err(bad());
        }
        let host = match u.host().ok_or_else(bad)? {
            url::Host::Domain(d) => d.to_string(),
            url::Host::Ipv4(a) => a.to_string(),
            url::Host::Ipv6(a) => a.to_string(),
        };
        // `https://host` means the gateway's Postgres port, not 443: the HTTP and pgwire
        // listeners differ, so only an explicit port overrides 5432.
        Ok(GatewayTarget {
            host,
            port: u.port().unwrap_or(5432),
        })
    }
}

/// The child environment without the password.
fn gateway_env(
    t: &GatewayTarget,
    binding: &str,
    mode: GatewaySslMode,
    root_cert: Option<&std::path::Path>,
) -> Vec<(String, String)> {
    let mut v = vec![
        ("PGHOST".to_string(), t.host.clone()),
        ("PGPORT".to_string(), t.port.to_string()),
        ("PGDATABASE".to_string(), binding.to_string()),
        ("PGSSLMODE".to_string(), mode.as_str().to_string()),
    ];
    if let Some(p) = root_cert {
        v.push(("PGSSLROOTCERT".to_string(), p.display().to_string()));
    }
    v
}

/// The command to run: the non-secret variables plus `PGPASSWORD` (the agent token). Variables
/// that could redirect libpq to another credential source or host are cleared.
fn gateway_command(
    cmd: &[String],
    env: &[(String, String)],
    token: &SecretString,
) -> std::process::Command {
    let mut c = std::process::Command::new(&cmd[0]);
    c.args(&cmd[1..]);
    for k in [
        "PGPASSFILE",
        "PGSERVICE",
        "PGSERVICEFILE",
        "PGHOSTADDR",
        "PGOPTIONS",
    ] {
        c.env_remove(k);
    }
    c.envs(env.iter().map(|(k, v)| (k, v)));
    c.env("PGPASSWORD", token.expose_secret());
    c
}

fn run_gateway(json: bool, a: ConnectArgs, gw: &str) -> Result<ExitCode, Fail> {
    let target = GatewayTarget::parse(gw).map_err(|m| fail(ExitCode::Usage, m))?;
    if let Some(p) = &a.ca_cert
        && !p.is_file()
    {
        return Err(fail(
            ExitCode::NotFound,
            format!("--ca-cert {} is not a readable file", p.display()),
        ));
    }
    if a.sslmode == GatewaySslMode::Require {
        eprintln!(
            "warning: PGSSLMODE=require encrypts the connection but does not verify the gateway's \
             certificate, so a network attacker could capture your agent token; use verify-full \
             with --ca-cert when the gateway uses a private CA"
        );
    }
    let st =
        ls_connector::State::load_fresh().map_err(|e| fail(ExitCode::Locked, e.to_string()))?;
    let env = gateway_env(&target, &a.name, a.sslmode, a.ca_cert.as_deref());
    if !a.cmd.is_empty() {
        let token = st.token_secret();
        drop(st);
        let mut c = gateway_command(&a.cmd, &env, &token);
        // exec on Unix: the command replaces smith, so the token lives only in its environment.
        #[cfg(unix)]
        let e = std::os::unix::process::CommandExt::exec(&mut c);
        #[cfg(not(unix))]
        let e = match c.status() {
            Ok(st) => std::process::exit(crate::run_cmd::exit_code(st)),
            Err(e) => e,
        };
        return Err(fail(
            if e.kind() == std::io::ErrorKind::NotFound {
                ExitCode::NotFound
            } else {
                ExitCode::Failure
            },
            format!("cannot run {}: {e}", a.cmd[0]),
        ));
    }
    // No command: print the non-secret variables only. The token is never printed.
    if json {
        let m: serde_json::Map<String, serde_json::Value> =
            env.into_iter().map(|(k, v)| (k, v.into())).collect();
        println!(
            "{}",
            json!({"name": a.name, "gateway": {"host": target.host, "port": target.port},
                   "env": m, "password": "set PGPASSWORD to your agent token (not printed)"})
        );
    } else {
        for (k, v) in env {
            println!("{k}={v}");
        }
        eprintln!(
            "PGPASSWORD is your agent token and is not printed; run `smith db connect {} \
             --gateway {gw} -- psql` to use it",
            a.name
        );
    }
    Ok(ExitCode::Ok)
}

pub struct Endpoint {
    pub kind: String,
    pub port: u16,
    pub user: String,
    pub database: Option<String>,
}

const HOST: &str = "127.0.0.1";

/// Percent-encode a URL userinfo or path component.
fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

impl Endpoint {
    /// A connection URL without any password.
    pub fn url(&self) -> String {
        let user = if self.user.is_empty() {
            String::new()
        } else {
            format!("{}@", enc(&self.user))
        };
        let db = self.database.as_deref().map(enc).unwrap_or_default();
        match self.kind.as_str() {
            "postgres" => format!("postgres://{user}{HOST}:{}/{db}?sslmode=disable", self.port),
            "mysql" => format!("mysql://{user}{HOST}:{}/{db}", self.port),
            _ => format!("redis://{HOST}:{}", self.port),
        }
    }

    /// Client environment variables (no password).
    pub fn env(&self) -> Vec<(String, String)> {
        let port = self.port.to_string();
        let db = self.database.clone().unwrap_or_default();
        let mut v: Vec<(&str, String)> = match self.kind.as_str() {
            "postgres" => vec![
                ("PGHOST", HOST.into()),
                ("PGPORT", port),
                ("PGUSER", self.user.clone()),
                ("PGDATABASE", db),
                ("PGSSLMODE", "disable".into()),
            ],
            "mysql" => vec![
                ("MYSQL_HOST", HOST.into()),
                ("MYSQL_TCP_PORT", port),
                ("MYSQL_USER", self.user.clone()),
                ("MYSQL_DATABASE", db),
            ],
            _ => vec![("REDIS_URL", self.url())],
        };
        v.retain(|(_, val)| !val.is_empty());
        v.push(("DATABASE_URL", self.url()));
        v.into_iter().map(|(k, val)| (k.to_string(), val)).collect()
    }
}

fn fail(c: ExitCode, m: impl Into<String>) -> Fail {
    Fail(c, m.into())
}

pub fn run(json: bool, cmd: DbCmd) -> Result<ExitCode, Fail> {
    let DbCmd::Connect(a) = cmd;
    if let Some(gw) = a.gateway.clone() {
        return run_gateway(json, a, &gw);
    }
    let cwd = std::env::current_dir().map_err(|e| fail(ExitCode::Failure, e.to_string()))?;
    let binding = match binding::find(&cwd) {
        Some(p) => Some(binding::load(&p)?.1),
        None => {
            return Err(fail(
                ExitCode::NotFound,
                "no .locksmith.toml here or above; add a [db.<name>] target",
            ));
        }
    };
    let mut c = connect(false).map_err(|Fail(_, m)| {
        fail(
            ExitCode::Locked,
            format!("{m}; start a session with `smith session start`"),
        )
    })?;
    let ep = match call(
        &mut c,
        &Request::DbConnect {
            name: a.name.clone(),
            binding,
        },
    )? {
        Response::DbEndpoint {
            kind,
            port,
            user,
            database,
        } => Endpoint {
            kind,
            port,
            user,
            database,
        },
        Response::Error { code, message } => return Err(fail(exit_of(code), message)),
        _ => return Err(fail(ExitCode::Failure, "unexpected daemon reply")),
    };
    drop(c);
    if !a.cmd.is_empty() {
        let mut c = std::process::Command::new(&a.cmd[0]);
        c.args(&a.cmd[1..]).envs(ep.env());
        // exec: the command replaces smith, so it stays inside the session tree.
        #[cfg(unix)]
        let e = std::os::unix::process::CommandExt::exec(&mut c);
        // No exec on Windows: run it as our child (still inside the session tree) and pass its
        // exit code on.
        #[cfg(not(unix))]
        let e = match c.status() {
            Ok(st) => std::process::exit(crate::run_cmd::exit_code(st)),
            Err(e) => e,
        };
        return Err(fail(
            if e.kind() == std::io::ErrorKind::NotFound {
                ExitCode::NotFound
            } else {
                ExitCode::Failure
            },
            format!("cannot run {}: {e}", a.cmd[0]),
        ));
    }
    if json {
        let env: serde_json::Map<String, serde_json::Value> =
            ep.env().into_iter().map(|(k, v)| (k, v.into())).collect();
        println!(
            "{}",
            json!({"name": a.name, "kind": ep.kind, "host": HOST, "port": ep.port,
                   "user": ep.user, "database": ep.database, "url": ep.url(), "env": env})
        );
    } else {
        println!("{}", ep.url());
        for (k, v) in ep.env() {
            if k != "DATABASE_URL" {
                println!("{k}={v}");
            }
        }
    }
    Ok(ExitCode::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(kind: &str, user: &str, db: Option<&str>) -> Endpoint {
        Endpoint {
            kind: kind.into(),
            port: 5555,
            user: user.into(),
            database: db.map(String::from),
        }
    }

    #[test]
    fn urls_and_env_carry_no_password() {
        let p = ep("postgres", "app user", Some("app/db"));
        assert_eq!(
            p.url(),
            "postgres://app%20user@127.0.0.1:5555/app%2Fdb?sslmode=disable"
        );
        let env = p.env();
        assert!(env.contains(&("PGPORT".into(), "5555".into())));
        assert!(env.contains(&("PGSSLMODE".into(), "disable".into())));
        assert!(
            env.iter()
                .all(|(k, _)| !k.contains("PASS") && k != "MYSQL_PWD")
        );
        assert_eq!(
            ep("mysql", "app", None).url(),
            "mysql://app@127.0.0.1:5555/"
        );
        assert!(
            !ep("mysql", "app", None)
                .env()
                .iter()
                .any(|(k, _)| k == "MYSQL_DATABASE")
        );
        assert_eq!(ep("redis", "", None).url(), "redis://127.0.0.1:5555");
        assert!(
            ep("redis", "", None)
                .env()
                .contains(&("REDIS_URL".into(), "redis://127.0.0.1:5555".into()))
        );
    }

    #[test]
    fn gateway_target_parsing() {
        let t = |s: &str| GatewayTarget::parse(s);
        let g = |h: &str, p: u16| {
            Ok(GatewayTarget {
                host: h.into(),
                port: p,
            })
        };
        assert_eq!(t("gw.example.com"), g("gw.example.com", 5432));
        assert_eq!(t("gw.example.com:6432"), g("gw.example.com", 6432));
        assert_eq!(t("https://gw.example.com:6432/"), g("gw.example.com", 6432));
        assert_eq!(t("https://gw.example.com"), g("gw.example.com", 5432));
        assert_eq!(t("postgres://127.0.0.1:5433"), g("127.0.0.1", 5433));
        assert_eq!(t("[::1]:5433"), g("::1", 5433));
        for bad in [
            "https://user:pw@gw.example.com",
            "https://gw.example.com/x",
            "https://gw.example.com?token=x",
            "http://gw.example.com",
            "ftp://gw.example.com",
            "",
        ] {
            assert!(t(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn gateway_env_has_no_password() {
        let t = GatewayTarget {
            host: "gw.example.com".into(),
            port: 5433,
        };
        let env = gateway_env(
            &t,
            "app",
            GatewaySslMode::VerifyFull,
            Some(std::path::Path::new("/etc/ca.pem")),
        );
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("PGHOST"), Some("gw.example.com"));
        assert_eq!(get("PGPORT"), Some("5433"));
        assert_eq!(get("PGDATABASE"), Some("app"));
        assert_eq!(get("PGSSLMODE"), Some("verify-full"));
        assert_eq!(get("PGSSLROOTCERT"), Some("/etc/ca.pem"));
        assert!(env.iter().all(|(k, _)| !k.contains("PASS")));
        let r = gateway_env(&t, "app", GatewaySslMode::Require, None);
        assert!(r.iter().any(|(k, v)| k == "PGSSLMODE" && v == "require"));
        assert!(r.iter().all(|(k, _)| k != "PGSSLROOTCERT"));
    }

    #[cfg(unix)]
    #[test]
    fn token_reaches_only_the_child_environment() {
        let t = GatewayTarget {
            host: "gw.example.com".into(),
            port: 5433,
        };
        let env = gateway_env(&t, "app", GatewaySslMode::VerifyFull, None);
        let token = SecretString::from("agent-token-canary-123".to_string());
        let cmd: Vec<String> = ["sh", "-c", "printf '%s|%s' \"$PGPASSWORD\" \"$PGDATABASE\""]
            .map(String::from)
            .to_vec();
        let mut c = gateway_command(&cmd, &env, &token);
        // Credential-source overrides are cleared for the child.
        assert!(c.get_envs().any(|(k, v)| k == "PGPASSFILE" && v.is_none()));
        let out = c.output().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "agent-token-canary-123|app"
        );
        // The non-secret variable list that is printed never holds the token.
        assert!(env.iter().all(|(_, v)| !v.contains("canary")));
    }
}
