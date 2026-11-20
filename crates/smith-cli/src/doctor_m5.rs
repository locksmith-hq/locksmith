//! Doctor checks for M5 Git delegation: `git.forwarder`, `git.insteadof`, `git.upstream_auth`.
//! Each branch is a pure function over explicit facts, so the tests need no daemon or Git config.
//! The `run` wrappers only gather the facts. Key values are never read, only names.

use crate::{binding, git_cmd};
use ls_diag::{Check, Outcome};
use ls_ipc::{Client, Request, Response};
use ls_redact::binding::Binding;
use std::path::Path;
use std::process::Command;

const SETUP: &str = "smith git setup";
const REWRITE: &str = "insteadOf = https://github.com/";

/// `reply`: `None` when the daemon is not running.
fn forwarder_outcome(reply: Option<std::io::Result<Response>>) -> Outcome {
    match reply {
        None => Outcome::skip("locksmithd is not running"),
        Some(Ok(Response::GitInfo { port, .. })) => {
            Outcome::ok(format!("listening on 127.0.0.1:{port}"))
        }
        Some(Ok(Response::Error { message, .. })) => Outcome::fail(message, "smith daemon status"),
        Some(Ok(_)) => Outcome::fail("unexpected daemon reply", "smith daemon status"),
        Some(Err(e)) => Outcome::fail(format!("daemon did not answer: {e}"), "smith daemon status"),
    }
}

/// `include_listed`: the include file is in Git's `include.path`. `file`: its contents, if readable.
fn insteadof_outcome(include_listed: bool, file: Option<&str>) -> Outcome {
    if !include_listed {
        return Outcome {
            remediation: Some(SETUP.into()),
            ..Outcome::skip("Git delegation not set up")
        };
    }
    match file {
        None => Outcome::warn("Git include file is missing", SETUP),
        Some(c) if !c.contains(REWRITE) => {
            Outcome::warn("Git include file has no github.com rewrite", SETUP)
        }
        Some(_) => Outcome::ok("Git include is installed and rewrites github.com"),
    }
}

/// What the vault can tell us about key names.
enum Vault {
    Locked,
    /// The daemon is down or could not list key names.
    Unavailable,
    Names(Vec<String>),
}

fn upstream_outcome(
    in_repo: bool,
    binding: Option<&Binding>,
    remotes: &[String],
    vault: &Vault,
) -> Outcome {
    if !in_repo {
        return Outcome::skip("not a git repository");
    }
    let Some(b) = binding else {
        return Outcome::skip("no .locksmith.toml in this repository");
    };
    let mut keys: Vec<String> = remotes
        .iter()
        .filter_map(|r| r.split('/').next())
        .filter_map(|h| b.git.credential_key(h))
        .collect();
    keys.sort();
    keys.dedup();
    if keys.is_empty() {
        return Outcome::skip("no forwarded hosts among the remotes");
    }
    match vault {
        Vault::Locked => Outcome::skip("vault locked"),
        Vault::Unavailable => Outcome::skip("locksmithd is not running; not checked"),
        Vault::Names(have) => {
            let missing: Vec<&str> = keys
                .iter()
                .filter(|k| !have.contains(k))
                .map(String::as_str)
                .collect();
            if missing.is_empty() {
                return Outcome::ok(format!("upstream key(s) present: {}", keys.join(", ")));
            }
            let fix: Vec<String> = missing.iter().map(|k| format!("smith add {k}")).collect();
            Outcome::warn(
                format!("upstream key(s) not in the vault: {}", missing.join(", ")),
                fix.join("; "),
            )
        }
    }
}

/// Never starts the daemon.
fn forwarder() -> Outcome {
    let reply = Client::connect_default()
        .ok()
        .map(|mut c| c.call(&Request::GitInfo));
    forwarder_outcome(reply)
}

fn git_ok(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

fn insteadof() -> Outcome {
    let include = ls_core::config_dir()
        .join("git")
        .join("forwarder.gitconfig");
    let listed = |flag: &str| {
        git_ok(&["config", flag, "--get-all", "include.path"])
            .is_some_and(|s| s.lines().any(|l| Path::new(l) == include))
    };
    let listed = listed("--global") || listed("--local");
    insteadof_outcome(listed, std::fs::read_to_string(&include).ok().as_deref())
}

fn upstream_auth() -> Outcome {
    let in_repo = git_ok(&["rev-parse", "--git-dir"]).is_some();
    let b = std::env::current_dir()
        .ok()
        .and_then(|d| binding::find(&d))
        .and_then(|f| binding::load(&f).ok())
        .map(|(b, _)| b);
    let remotes: Vec<String> = git_ok(&["config", "--get-regexp", r"^remote\..*\.url$"])
        .map(|s| {
            s.lines()
                .filter_map(|l| l.split_once(' ').and_then(|(_, u)| git_cmd::remote_id(u)))
                .collect()
        })
        .unwrap_or_default();
    let req = Request::KeyNames {
        project: b
            .as_ref()
            .and_then(|b| b.project.clone())
            .unwrap_or("default".into()),
        env: b
            .as_ref()
            .and_then(|b| b.env.clone())
            .unwrap_or("development".into()),
    };
    let vault = match Client::connect_default().and_then(|mut c| c.call(&req)) {
        Ok(Response::Keys { keys }) => Vault::Names(keys),
        Ok(Response::Error {
            code: ls_ipc::ErrorCode::Locked,
            ..
        }) => Vault::Locked,
        _ => Vault::Unavailable,
    };
    upstream_outcome(in_repo, b.as_ref(), &remotes, &vault)
}

/// `listed`: the gateway include is in Git config. `file`: its contents. `logged_in`: an agent
/// token state file exists.
fn gateway_outcome(listed: bool, file: Option<&str>, logged_in: bool) -> Outcome {
    const FIX: &str = "smith git setup --gateway <url>";
    if !listed {
        return Outcome::skip("Git gateway not set up");
    }
    match file {
        None => Outcome::warn("Git gateway include file is missing", FIX),
        Some(c) if !c.contains("gateway-credential") => {
            Outcome::warn("Git gateway include has no credential helper", FIX)
        }
        Some(_) if !logged_in => Outcome::warn("no agent token", "smith login --agent"),
        Some(_) => Outcome::ok("Git gateway include installed and agent signed in"),
    }
}

fn gateway() -> Outcome {
    let include = git_cmd::gateway_include_path();
    let listed = |flag: &str| {
        git_ok(&["config", flag, "--get-all", "include.path"])
            .is_some_and(|s| s.lines().any(|l| Path::new(l) == include))
    };
    let listed = listed("--global") || listed("--local");
    gateway_outcome(
        listed,
        std::fs::read_to_string(&include).ok().as_deref(),
        ls_connector::State::path().exists(),
    )
}

inventory::submit! { Check { id: "git.gateway", run: gateway } }
inventory::submit! { Check { id: "git.forwarder", run: forwarder } }
inventory::submit! { Check { id: "git.insteadof", run: insteadof } }
inventory::submit! { Check { id: "git.upstream_auth", run: upstream_auth } }

#[cfg(test)]
mod tests {
    use super::*;
    use ls_diag::Status;
    use ls_ipc::ErrorCode;

    #[track_caller]
    fn expect(out: &Outcome, status: Status, summary: &str, remediation: Option<&str>) {
        assert_eq!(out.status, status, "status for {summary:?}");
        assert_eq!(out.summary, summary);
        assert_eq!(out.remediation.as_deref(), remediation);
    }

    #[test]
    fn git_gateway_branches() {
        expect(
            &gateway_outcome(false, None, false),
            Status::Skip,
            "Git gateway not set up",
            None,
        );
        expect(
            &gateway_outcome(true, None, true),
            Status::Warn,
            "Git gateway include file is missing",
            Some("smith git setup --gateway <url>"),
        );
        expect(
            &gateway_outcome(true, Some("helper = !smith git gateway-credential"), false),
            Status::Warn,
            "no agent token",
            Some("smith login --agent"),
        );
        expect(
            &gateway_outcome(true, Some("helper = !smith git gateway-credential"), true),
            Status::Ok,
            "Git gateway include installed and agent signed in",
            None,
        );
    }

    #[test]
    fn forwarder_branches() {
        expect(
            &forwarder_outcome(None),
            Status::Skip,
            "locksmithd is not running",
            None,
        );
        let info = Response::GitInfo {
            port: 4242,
            include: "/x".into(),
            hosts: vec![],
        };
        expect(
            &forwarder_outcome(Some(Ok(info))),
            Status::Ok,
            "listening on 127.0.0.1:4242",
            None,
        );
        let err = Response::Error {
            code: ErrorCode::Internal,
            message: "forwarder failed to bind".into(),
        };
        expect(
            &forwarder_outcome(Some(Ok(err))),
            Status::Fail,
            "forwarder failed to bind",
            Some("smith daemon status"),
        );
        expect(
            &forwarder_outcome(Some(Ok(Response::Ok))),
            Status::Fail,
            "unexpected daemon reply",
            Some("smith daemon status"),
        );
        expect(
            &forwarder_outcome(Some(Err(std::io::Error::other("boom")))),
            Status::Fail,
            "daemon did not answer: boom",
            Some("smith daemon status"),
        );
    }

    #[test]
    fn insteadof_branches() {
        expect(
            &insteadof_outcome(false, None),
            Status::Skip,
            "Git delegation not set up",
            Some(SETUP),
        );
        expect(
            &insteadof_outcome(true, None),
            Status::Warn,
            "Git include file is missing",
            Some(SETUP),
        );
        expect(
            &insteadof_outcome(true, Some("[url \"x\"]\n")),
            Status::Warn,
            "Git include file has no github.com rewrite",
            Some(SETUP),
        );
        let good =
            "[url \"http://127.0.0.1:1/git/github.com/\"]\n\tinsteadOf = https://github.com/\n";
        expect(
            &insteadof_outcome(true, Some(good)),
            Status::Ok,
            "Git include is installed and rewrites github.com",
            None,
        );
    }

    fn binding(toml: &str) -> Binding {
        ls_redact::binding::parse(toml.as_bytes()).unwrap()
    }

    #[test]
    fn upstream_auth_branches() {
        let b = binding("project = \"p\"\n[git.credentials]\n\"git.corp.io\" = \"CORP_GIT\"\n");
        let gh = vec!["github.com/a/b".to_string()];
        let names = |v: &[&str]| Vault::Names(v.iter().map(|s| s.to_string()).collect());

        expect(
            &upstream_outcome(false, Some(&b), &gh, &Vault::Locked),
            Status::Skip,
            "not a git repository",
            None,
        );
        expect(
            &upstream_outcome(true, None, &gh, &Vault::Locked),
            Status::Skip,
            "no .locksmith.toml in this repository",
            None,
        );
        expect(
            &upstream_outcome(true, Some(&b), &["example.com/a/b".into()], &Vault::Locked),
            Status::Skip,
            "no forwarded hosts among the remotes",
            None,
        );
        expect(
            &upstream_outcome(true, Some(&b), &gh, &Vault::Locked),
            Status::Skip,
            "vault locked",
            None,
        );
        expect(
            &upstream_outcome(true, Some(&b), &gh, &Vault::Unavailable),
            Status::Skip,
            "locksmithd is not running; not checked",
            None,
        );
        expect(
            &upstream_outcome(true, Some(&b), &gh, &names(&["GITHUB_TOKEN"])),
            Status::Ok,
            "upstream key(s) present: GITHUB_TOKEN",
            None,
        );
        expect(
            &upstream_outcome(true, Some(&b), &gh, &names(&["OTHER"])),
            Status::Warn,
            "upstream key(s) not in the vault: GITHUB_TOKEN",
            Some("smith add GITHUB_TOKEN"),
        );
        // A configured host uses its own key name; every missing key is named.
        let both = vec!["github.com/a/b".to_string(), "git.corp.io/x/y".to_string()];
        expect(
            &upstream_outcome(true, Some(&b), &both, &names(&[])),
            Status::Warn,
            "upstream key(s) not in the vault: CORP_GIT, GITHUB_TOKEN",
            Some("smith add CORP_GIT; smith add GITHUB_TOKEN"),
        );
    }
}
