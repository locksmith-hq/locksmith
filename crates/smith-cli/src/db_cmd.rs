//! `smith db connect <name> [-- cmd args]` (M6): ask the daemon for this session's password-less
//! local endpoint for `[db.<name>]`, then print it or run `cmd` with the client environment set.
//! The password never passes through here: the daemon's relay authenticates upstream.

use crate::session::{call, connect, exit_of};
use crate::{Fail, binding};
use clap::{Args, Subcommand};
use ls_core::ExitCode;
use ls_ipc::{Request, Response};
use serde_json::json;

#[derive(Subcommand)]
pub enum DbCmd {
    /// Open a password-less local endpoint for `[db.<name>]` (inside a session) and print its
    /// URL, or run a command with PG*/MYSQL_*/REDIS_URL and DATABASE_URL pointing at it.
    Connect(ConnectArgs),
}

#[derive(Args)]
pub struct ConnectArgs {
    /// Target name from `.locksmith.toml` (`[db.<name>]`).
    name: String,
    /// Command to run with the endpoint in its environment.
    #[arg(last = true)]
    cmd: Vec<String>,
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
}
