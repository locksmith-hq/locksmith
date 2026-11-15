//! Doctor checks for M6 database relays: `db.relay.<name>` per `[db.<name>]` target (or one
//! `db.relay` skip when none is configured). Pure over explicit facts, like `doctor_m5`; the
//! wrapper gathers the binding, vault key names (never values) and a TCP reachability probe.

use crate::binding;
use ls_diag::{CheckSet, Outcome};
use ls_ipc::{Client, ErrorCode, Request, Response};
use ls_redact::binding::Binding;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub enum Vault {
    Locked,
    /// The daemon is down or could not list key names.
    Unavailable,
    Names(Vec<String>),
}

fn default_port(kind: &str) -> u16 {
    match kind.to_ascii_lowercase().as_str() {
        "mysql" => 3306,
        "redis" => 6379,
        _ => 5432,
    }
}

/// `db.relay.<name>` with the name reduced to what `docs/schemas/doctor.v1.json` allows in an id
/// segment (`[a-z0-9_-]`): TOML table names are free-form (`[db."Prod RO"]`).
pub fn check_id(name: &str) -> String {
    let seg: String = name
        .chars()
        .map(|c| match c.to_ascii_lowercase() {
            c @ ('a'..='z' | '0'..='9' | '_' | '-') => c,
            _ => '_',
        })
        .collect();
    format!("db.relay.{}", if seg.is_empty() { "_" } else { &seg })
}

/// One outcome per target. `reach` probes TCP reachability of `host:port`.
pub fn outcomes(
    b: Option<&Binding>,
    vault: &Vault,
    reach: &dyn Fn(&str, u16) -> Result<(), String>,
) -> Vec<(String, Outcome)> {
    let Some(b) = b.filter(|b| !b.db.is_empty()) else {
        return vec![(
            "db.relay".into(),
            Outcome::skip("no [db.<name>] targets in .locksmith.toml"),
        )];
    };
    b.db.iter()
        .map(|(name, t)| {
            let id = check_id(name);
            if let Err(e) = t.check() {
                return (
                    id,
                    Outcome::fail(
                        format!("invalid [db.{name}]: {e}"),
                        format!("edit [db.{name}] in .locksmith.toml"),
                    ),
                );
            }
            let keys = t.keys();
            let key_note = match vault {
                Vault::Names(have) => {
                    let missing: Vec<&str> = keys
                        .iter()
                        .filter(|k| !have.contains(k))
                        .map(String::as_str)
                        .collect();
                    if !missing.is_empty() {
                        let fix: Vec<String> =
                            missing.iter().map(|k| format!("smith add {k}")).collect();
                        return (
                            id,
                            Outcome::warn(
                                format!("vault key(s) missing: {}", missing.join(", ")),
                                fix.join("; "),
                            ),
                        );
                    }
                    if keys.is_empty() {
                        "no credential configured".to_string()
                    } else {
                        format!("key(s) {} present", keys.join(", "))
                    }
                }
                Vault::Locked => "vault locked, keys not checked".into(),
                Vault::Unavailable => "locksmithd not running, keys not checked".into(),
            };
            let port = t.port.unwrap_or(default_port(&t.kind));
            let host = t.host.trim();
            if let Err(e) = reach(host, port) {
                return (
                    id,
                    Outcome::warn(
                        format!("{host}:{port} is unreachable ({e})"),
                        format!("check host and port in [db.{name}] and the network"),
                    ),
                );
            }
            let user = t
                .user
                .as_deref()
                .map(|u| format!("{u}@"))
                .unwrap_or_default();
            (
                id,
                Outcome::ok(format!(
                    "{} {user}{host}:{port} reachable; {key_note}",
                    t.kind.to_ascii_lowercase()
                )),
            )
        })
        .collect()
}

fn probe(host: &str, port: u16) -> Result<(), String> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .collect();
    let mut last = "host did not resolve".to_string();
    for a in addrs {
        match TcpStream::connect_timeout(&a, Duration::from_secs(2)) {
            Ok(_) => return Ok(()),
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
}

fn run() -> Vec<(String, Outcome)> {
    let b = std::env::current_dir()
        .ok()
        .and_then(|d| binding::find(&d))
        .and_then(|f| binding::load(&f).ok())
        .map(|(b, _)| b);
    let vault = match &b {
        Some(b) if !b.db.is_empty() => {
            let req = Request::KeyNames {
                project: b.project.clone().unwrap_or("default".into()),
                env: b.env.clone().unwrap_or("development".into()),
            };
            match Client::connect_default().and_then(|mut c| c.call(&req)) {
                Ok(Response::Keys { keys }) => Vault::Names(keys),
                Ok(Response::Error {
                    code: ErrorCode::Locked,
                    ..
                }) => Vault::Locked,
                _ => Vault::Unavailable,
            }
        }
        _ => Vault::Unavailable,
    };
    outcomes(b.as_ref(), &vault, &probe)
}

inventory::submit! { CheckSet { prefix: "db.relay", run } }

#[cfg(test)]
mod tests {
    use super::*;
    use ls_diag::Status;

    fn binding(toml: &str) -> Binding {
        ls_redact::binding::parse(toml.as_bytes()).unwrap()
    }

    #[track_caller]
    fn expect(o: &(String, Outcome), id: &str, status: Status, summary: &str, fix: Option<&str>) {
        assert_eq!(o.0, id);
        assert_eq!(o.1.status, status, "{}", o.1.summary);
        assert_eq!(o.1.summary, summary);
        assert_eq!(o.1.remediation.as_deref(), fix);
    }

    const TOML: &str = "[db.main]\nkind = \"postgres\"\nhost = \"db.example.com\"\nuser = \"app\"\npassword_key = \"PG_PASSWORD\"\n[db.cache]\nkind = \"redis\"\nhost = \"127.0.0.1\"\nport = 7000\n[db.bad]\nkind = \"mongo\"\nhost = \"h\"\n";

    #[test]
    fn ids_fit_the_schema() {
        assert_eq!(check_id("main"), "db.relay.main");
        assert_eq!(check_id("prod-ro"), "db.relay.prod-ro");
        assert_eq!(check_id("Prod RO.v2"), "db.relay.prod_ro_v2");
        assert_eq!(check_id("é"), "db.relay._");
        assert_eq!(check_id(""), "db.relay._");
    }

    #[test]
    fn db_relay_branches() {
        let up = |_: &str, _: u16| Ok(());
        let down = |_: &str, _: u16| Err("connection refused".to_string());
        let names = |v: &[&str]| Vault::Names(v.iter().map(|s| s.to_string()).collect());

        let none = outcomes(None, &Vault::Unavailable, &up);
        expect(
            &none[0],
            "db.relay",
            Status::Skip,
            "no [db.<name>] targets in .locksmith.toml",
            None,
        );
        let b = binding(TOML);
        let o = outcomes(Some(&b), &names(&["PG_PASSWORD"]), &up);
        // BTreeMap order: bad, cache, main.
        expect(
            &o[0],
            "db.relay.bad",
            Status::Fail,
            "invalid [db.bad]: kind \"mongo\" is not one of postgres, mysql, redis",
            Some("edit [db.bad] in .locksmith.toml"),
        );
        expect(
            &o[1],
            "db.relay.cache",
            Status::Ok,
            "redis 127.0.0.1:7000 reachable; no credential configured",
            None,
        );
        expect(
            &o[2],
            "db.relay.main",
            Status::Ok,
            "postgres app@db.example.com:5432 reachable; key(s) PG_PASSWORD present",
            None,
        );
        let o = outcomes(Some(&b), &names(&[]), &up);
        expect(
            &o[2],
            "db.relay.main",
            Status::Warn,
            "vault key(s) missing: PG_PASSWORD",
            Some("smith add PG_PASSWORD"),
        );
        let o = outcomes(Some(&b), &Vault::Locked, &down);
        expect(
            &o[2],
            "db.relay.main",
            Status::Warn,
            "db.example.com:5432 is unreachable (connection refused)",
            Some("check host and port in [db.main] and the network"),
        );
        let o = outcomes(Some(&b), &Vault::Unavailable, &up);
        expect(
            &o[2],
            "db.relay.main",
            Status::Ok,
            "postgres app@db.example.com:5432 reachable; locksmithd not running, keys not checked",
            None,
        );
    }
}
