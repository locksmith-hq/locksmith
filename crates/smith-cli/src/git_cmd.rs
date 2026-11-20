//! `smith git setup|status|teardown|credential` and `smith gh` (M5). Git reaches private hosts
//! through the daemon's loopback forwarder; this side only edits Git config and asks the daemon
//! for a session-scoped forwarder token. The upstream credential never passes through here.

use crate::session::{call, connect, exit_of};
use crate::{Fail, binding, session};
use clap::{Args, Subcommand};
use ls_core::ExitCode;
use ls_ipc::{Request, Response};
use serde_json::json;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Subcommand)]
pub enum GitCmd {
    /// Route Git for private hosts through Locksmith (adds an `include.path` to Git config).
    Setup(Scope),
    /// Show the forwarder port, include file and where it is installed.
    Status,
    /// Remove what `setup` added.
    Teardown(Scope),
    /// Git credential helper (called by Git, not by people).
    #[command(hide = true)]
    Credential { op: String },
    /// Git credential helper for the hosted gateway (called by Git, not by people).
    #[command(hide = true)]
    GatewayCredential { op: String },
}

#[derive(Args)]
pub struct Scope {
    /// Install in the user's global Git config (default outside a repository).
    #[arg(long, conflicts_with = "repo")]
    global: bool,
    /// Install in this repository's `.git/config` (default inside a repository).
    #[arg(long)]
    repo: bool,
    /// Also forward this host (e.g. a GitHub Enterprise server). Setup only.
    #[arg(long)]
    host: Vec<String>,
    /// Route Git through the hosted Locksmith gateway at this URL instead of the local
    /// forwarder (needs `smith login --agent`). Setup only.
    #[arg(long, value_name = "URL")]
    gateway: Option<String>,
}

fn fail(c: ExitCode, m: impl Into<String>) -> Fail {
    Fail(c, m.into())
}

fn git(args: &[&str]) -> Result<std::process::Output, Fail> {
    Command::new("git")
        .args(args)
        .output()
        .map_err(|e| fail(ExitCode::Failure, format!("cannot run git: {e}")))
}

fn in_repo() -> bool {
    git(&["rev-parse", "--git-dir"]).is_ok_and(|o| o.status.success())
}

fn scope_flag(s: &Scope) -> Result<&'static str, Fail> {
    if s.global {
        return Ok("--global");
    }
    if s.repo && !in_repo() {
        return Err(fail(ExitCode::Usage, "--repo needs a Git repository"));
    }
    Ok(if in_repo() { "--local" } else { "--global" })
}

/// Ask the daemon (starting it if needed) where the include file is; it rewrites it each time.
fn info() -> Result<(u16, PathBuf, Vec<String>), Fail> {
    let mut c = connect(true)?;
    match call(&mut c, &Request::GitInfo)? {
        Response::GitInfo {
            port,
            include,
            hosts,
        } => Ok((port, include, hosts)),
        Response::Error { code, message } => Err(fail(exit_of(code), message)),
        _ => Err(fail(ExitCode::Failure, "unexpected daemon reply")),
    }
}

fn installed(flag: &str, include: &Path) -> bool {
    git(&["config", flag, "--get-all", "include.path"]).is_ok_and(|o| {
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .any(|l| Path::new(l) == include)
    })
}

fn add_hosts(hosts: &[String]) -> Result<(), Fail> {
    if hosts.is_empty() {
        return Ok(());
    }
    let dir = ls_core::config_dir().join("git");
    ls_platform::fs::ensure_private_dir(&dir)
        .map_err(|e| fail(ExitCode::Failure, e.to_string()))?;
    let path = dir.join("hosts");
    let have = std::fs::read_to_string(&path).unwrap_or_default();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| fail(ExitCode::Failure, e.to_string()))?;
    for h in hosts {
        let h = h.trim().to_lowercase();
        let ok = !h.is_empty()
            && h.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b));
        if !ok {
            return Err(fail(ExitCode::Usage, format!("invalid host {h:?}")));
        }
        if !have.lines().any(|l| l.trim() == h) {
            writeln!(f, "{h}").map_err(|e| fail(ExitCode::Failure, e.to_string()))?;
        }
    }
    Ok(())
}

pub fn run(json: bool, cmd: GitCmd) -> Result<ExitCode, Fail> {
    match cmd {
        GitCmd::Setup(s) if s.gateway.is_some() => gateway_setup(json, &s),
        GitCmd::Setup(s) => {
            let flag = scope_flag(&s)?;
            add_hosts(&s.host)?;
            let (port, include, hosts) = info()?;
            let inc = include.display().to_string();
            if !installed(flag, &include) {
                let o = git(&["config", flag, "--add", "include.path", &inc])?;
                if !o.status.success() {
                    return Err(fail(
                        ExitCode::Failure,
                        String::from_utf8_lossy(&o.stderr).trim().to_string(),
                    ));
                }
            }
            if json {
                println!(
                    "{}",
                    json!({"scope": &flag[2..], "port": port, "include": inc, "hosts": hosts})
                );
            } else {
                println!(
                    "Git for {} now goes through Locksmith (port {port}, {} config).",
                    hosts.join(", "),
                    &flag[2..]
                );
                println!("Run Git inside `smith session start -- <agent>`.");
            }
            Ok(ExitCode::Ok)
        }
        GitCmd::Teardown(s) => {
            let flag = scope_flag(&s)?;
            remove_gateway_include(flag)?;
            let include = ls_core::config_dir()
                .join("git")
                .join("forwarder.gitconfig");
            let inc = include.display().to_string();
            if installed(flag, &include) {
                git(&[
                    "config",
                    flag,
                    "--fixed-value",
                    "--unset-all",
                    "include.path",
                    &inc,
                ])?;
            }
            // Git keeps an empty `[include]` header after the last key is unset.
            let left = git(&["config", flag, "--get-all", "include.path"])?;
            if left.stdout.is_empty() {
                let _ = git(&["config", flag, "--remove-section", "include"]);
            }
            if !json {
                println!(
                    "Removed the Locksmith Git include from {} config.",
                    &flag[2..]
                );
            }
            Ok(ExitCode::Ok)
        }
        GitCmd::Status => {
            let (port, include, hosts) = info()?;
            let global = installed("--global", &include);
            let local = in_repo() && installed("--local", &include);
            if json {
                println!(
                    "{}",
                    json!({"port": port, "include": include, "hosts": hosts,
                           "global": global, "repo": local})
                );
            } else {
                println!("forwarder: 127.0.0.1:{port}");
                println!("include:   {}", include.display());
                println!("hosts:     {}", hosts.join(", "));
                println!(
                    "installed: {}",
                    match (global, local) {
                        (true, true) => "global and this repository",
                        (true, false) => "global",
                        (false, true) => "this repository",
                        (false, false) => "no (run `smith git setup`)",
                    }
                );
            }
            Ok(if global || local {
                ExitCode::Ok
            } else {
                ExitCode::NotFound
            })
        }
        GitCmd::Credential { op } => credential(&op),
        GitCmd::GatewayCredential { op } => gateway_credential(&op),
    }
}

/// Include file for the hosted gateway, next to the forwarder's.
pub fn gateway_include_path() -> PathBuf {
    ls_core::config_dir().join("git").join("gateway.gitconfig")
}

/// Hosts Git is routed to the gateway for: github.com plus any `--host`.
fn gateway_hosts(extra: &[String]) -> Result<Vec<String>, Fail> {
    let mut hosts = vec!["github.com".to_string()];
    for h in extra {
        let h = h.trim().to_lowercase();
        let ok = !h.is_empty()
            && h.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b));
        if !ok {
            return Err(fail(ExitCode::Usage, format!("invalid host {h:?}")));
        }
        if !hosts.contains(&h) {
            hosts.push(h);
        }
    }
    Ok(hosts)
}

/// Contents of the gateway include file. Pure: the URL is already validated, no token inside.
pub fn gateway_gitconfig(gateway: &str, hosts: &[String]) -> String {
    let mut out = String::from(
        "# Written by `smith git setup --gateway`; `smith git teardown` removes it.\n",
    );
    for h in hosts {
        out.push_str(&format!(
            "[url \"{gateway}/git/{h}/\"]\n\tinsteadOf = https://{h}/\n"
        ));
    }
    out.push_str(&format!(
        "[credential \"{gateway}\"]\n\thelper =\n\thelper = !smith git gateway-credential\n"
    ));
    out
}

fn gateway_setup(json: bool, s: &Scope) -> Result<ExitCode, Fail> {
    let flag = scope_flag(s)?;
    let gateway = ls_connector::parse_endpoint(s.gateway.as_deref().unwrap_or_default())
        .map_err(|e| fail(ExitCode::Usage, e.to_string()))?;
    let hosts = gateway_hosts(&s.host)?;
    let include = gateway_include_path();
    let dir = include.parent().unwrap_or(Path::new("."));
    ls_platform::fs::ensure_private_dir(dir).map_err(|e| fail(ExitCode::Failure, e.to_string()))?;
    std::fs::write(&include, gateway_gitconfig(&gateway, &hosts))
        .map_err(|e| fail(ExitCode::Failure, e.to_string()))?;
    if !installed(flag, &include) {
        let inc = include.display().to_string();
        let o = git(&["config", flag, "--add", "include.path", &inc])?;
        if !o.status.success() {
            return Err(fail(
                ExitCode::Failure,
                String::from_utf8_lossy(&o.stderr).trim().to_string(),
            ));
        }
    }
    if json {
        println!(
            "{}",
            json!({"scope": &flag[2..], "gateway": gateway, "hosts": hosts, "include": include})
        );
    } else {
        println!(
            "Git for {} now goes through the gateway {gateway} ({} config).",
            hosts.join(", "),
            &flag[2..]
        );
        println!("Sign in with `smith login --agent` (the agent token is the Git password).");
    }
    Ok(ExitCode::Ok)
}

fn remove_gateway_include(flag: &str) -> Result<(), Fail> {
    let include = gateway_include_path();
    if installed(flag, &include) {
        let inc = include.display().to_string();
        git(&[
            "config",
            flag,
            "--fixed-value",
            "--unset-all",
            "include.path",
            &inc,
        ])?;
    }
    let _ = std::fs::remove_file(&include);
    Ok(())
}

fn gateway_credential(op: &str) -> Result<ExitCode, Fail> {
    if op != "get" {
        return Ok(ExitCode::Ok);
    }
    // Consume Git's request; the answer does not depend on it.
    for l in std::io::stdin().lock().lines() {
        if l.map_err(|e| fail(ExitCode::Failure, e.to_string()))?
            .is_empty()
        {
            break;
        }
    }
    let st =
        ls_connector::State::load_fresh().map_err(|e| fail(ExitCode::Failure, e.to_string()))?;
    let mut out = std::io::stdout().lock();
    out.write_all(st.git_credential_lines().as_bytes())
        .map_err(|e| fail(ExitCode::Failure, e.to_string()))?;
    Ok(ExitCode::Ok)
}

/// `host/owner/repo` for a remote URL in any of the forms the include file rewrites.
pub fn remote_id(url: &str) -> Option<String> {
    let u = url.trim();
    let rest = if let Some(r) = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"))
    {
        r.split_once('@')
            .filter(|(a, _)| !a.contains('/'))
            .map_or(r, |(_, h)| h)
            .to_string()
    } else if let Some(r) = u.strip_prefix("ssh://") {
        let r = r.split_once('@').map_or(r, |(_, h)| h);
        // ssh://host:22/owner/repo: drop the port
        let (h, p) = r.split_once('/')?;
        format!("{}/{p}", h.split(':').next()?)
    } else if let Some((user_host, path)) = u.split_once(':') {
        let h = user_host.rsplit_once('@').map_or(user_host, |(_, h)| h);
        if h.contains('/') {
            return None;
        }
        format!("{h}/{path}")
    } else {
        return None;
    };
    let rest = rest.trim_end_matches('/').trim_end_matches(".git");
    let (host, repo) = rest.split_once('/')?;
    // Forwarder URLs already carry /git/<host>/: keep the real host.
    if let Some(r) = repo.strip_prefix("git/") {
        return Some(r.to_lowercase());
    }
    repo.contains('/')
        .then(|| format!("{host}/{repo}").to_lowercase())
}

fn remotes() -> Vec<String> {
    git(&["config", "--get-regexp", r"^remote\..*\.url$"])
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|l| l.split_once(' ').and_then(|(_, u)| remote_id(u)))
                .collect()
        })
        .unwrap_or_default()
}

fn credential(op: &str) -> Result<ExitCode, Fail> {
    if op != "get" {
        return Ok(ExitCode::Ok); // store/erase: nothing is stored
    }
    let mut path = None;
    for l in std::io::stdin().lock().lines() {
        let l = l.map_err(|e| fail(ExitCode::Failure, e.to_string()))?;
        if l.is_empty() {
            break;
        }
        if let Some(p) = l.strip_prefix("path=") {
            path = Some(p.to_string());
        }
    }
    // path = git/<host>/<owner>/<repo>.git (useHttpPath in the include file)
    let Some((host, repo)) = path
        .as_deref()
        .and_then(|p| p.strip_prefix("git/"))
        .and_then(|p| p.split_once('/'))
        .map(|(h, r)| (h.to_string(), r.trim_end_matches(".git").to_string()))
    else {
        return Err(fail(
            ExitCode::Usage,
            "Locksmith credential helper: no forwarder path (is useHttpPath set?)",
        ));
    };
    let cwd = std::env::current_dir().map_err(|e| fail(ExitCode::Failure, e.to_string()))?;
    let binding = match binding::find(&cwd) {
        Some(p) => Some(binding::load(&p)?.1),
        None => None,
    };
    let mut c = connect(false)?;
    let req = Request::GitCredential {
        host,
        repo,
        binding,
        remotes: remotes(),
    };
    match call(&mut c, &req)? {
        Response::GitToken { username, token } => {
            println!("username={username}\npassword={token}");
            Ok(ExitCode::Ok)
        }
        Response::Error { code, message } => Err(fail(exit_of(code), message)),
        _ => Err(fail(ExitCode::Failure, "unexpected daemon reply")),
    }
}

#[derive(Args)]
pub struct GhArgs {
    /// Arguments for the GitHub CLI.
    #[arg(last = true, required = true)]
    args: Vec<String>,
}

/// `smith gh -- <args>`: `gh` with GH_TOKEN injected by the daemon and its output redacted.
/// Contained, not delegated: the token is visible to the `gh` process (design D5).
pub fn gh(a: GhArgs) -> Result<ExitCode, Fail> {
    let repo = remotes()
        .into_iter()
        .find_map(|r| r.strip_prefix("github.com/").map(String::from));
    let mut cmd = vec!["gh".to_string()];
    cmd.extend(a.args);
    session::run_gh(repo, cmd)
}

#[cfg(test)]
mod tests {
    use super::{gateway_gitconfig, gateway_hosts, remote_id};

    #[test]
    fn git_gateway_config_has_rewrite_and_helper_but_no_token() {
        let hosts = gateway_hosts(&["GHE.example.com".into()]).ok().unwrap();
        assert_eq!(hosts, ["github.com", "ghe.example.com"]);
        let c = gateway_gitconfig("https://gw.example.com", &hosts);
        assert!(c.contains("[url \"https://gw.example.com/git/github.com/\"]"));
        assert!(c.contains("insteadOf = https://github.com/"));
        assert!(c.contains("insteadOf = https://ghe.example.com/"));
        assert!(c.contains("helper = !smith git gateway-credential"));
        assert!(!c.to_lowercase().contains("password"));
    }

    #[test]
    fn git_gateway_rejects_bad_host() {
        assert!(gateway_hosts(&["bad host".into()]).is_err_and(|_| true));
    }

    #[test]
    fn remote_forms() {
        for (u, want) in [
            (
                "https://github.com/Acme/App.git",
                Some("github.com/acme/app"),
            ),
            (
                "https://user@github.com/acme/app",
                Some("github.com/acme/app"),
            ),
            ("git@github.com:acme/app.git", Some("github.com/acme/app")),
            (
                "ssh://git@github.com/acme/app.git",
                Some("github.com/acme/app"),
            ),
            (
                "ssh://git@gitlab.com:22/g/sub/r.git",
                Some("gitlab.com/g/sub/r"),
            ),
            (
                "http://127.0.0.1:5555/git/github.com/acme/app.git",
                Some("github.com/acme/app"),
            ),
            ("/local/path/repo", None),
            ("https://github.com/", None),
        ] {
            assert_eq!(remote_id(u).as_deref(), want, "{u}");
        }
    }
}
