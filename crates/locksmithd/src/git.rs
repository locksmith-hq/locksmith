//! M5 Git delegation glue: forwarder tokens bound to leases (design D2), the [`Authority`] the
//! `ls-proxy` forwarder consults, and the Git include file `smith git setup` points at (D1).
//! The upstream credential is read from the vault per request and only ever goes to the
//! forwarder's upstream leg.

use crate::{Actor, Daemon, deny_response, deny_rule, err, now, rec};
use ls_ipc::{ErrorCode, Response};
use ls_platform::proc::{Peer, ProcId};
use ls_proxy::{Authority, Deny, Grant, Route, github};
use ls_redact::binding::{Binding, parse};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::Zeroizing;

/// Hosts the forwarder serves without configuration; more go in `<config>/git/hosts`.
pub const DEFAULT_HOSTS: [&str; 3] = ["github.com", "gitlab.com", "bitbucket.org"];

/// What a forwarder token may do. Lives in memory only and dies with its lease.
struct Token {
    lease: String,
    project: String,
    env: String,
    host: String,
    /// Lowercase `host/owner/repo`.
    allowed: Vec<String>,
    protected: Vec<String>,
    key: String,
}

pub struct Git {
    tokens: Mutex<HashMap<String, Token>>,
    /// Actor of the last authorized request per lease (for the push-denied audit record).
    actors: Mutex<HashMap<String, Actor>>,
    cache: github::TokenCache,
    pub port: OnceLock<u16>,
}

impl Default for Git {
    fn default() -> Self {
        Git {
            tokens: Mutex::default(),
            actors: Mutex::default(),
            cache: github::TokenCache::new(github_api()),
            port: OnceLock::new(),
        }
    }
}

/// Test switch for a mocked GitHub API, debug builds only (like the weak KDF switch).
fn github_api() -> String {
    #[cfg(debug_assertions)]
    if let Ok(u) = std::env::var("LOCKSMITH_TEST_GITHUB_API") {
        return u;
    }
    "https://api.github.com".into()
}

/// Test switch for a plain-HTTP upstream (`host=127.0.0.1:port`), debug builds only.
pub fn upstream() -> ls_proxy::forward::Upstream {
    #[cfg(debug_assertions)]
    if let Ok(v) = std::env::var("LOCKSMITH_TEST_GIT_UPSTREAM")
        && let Some((h, a)) = v.split_once('=')
        && let Ok(a) = a.parse()
    {
        return ls_proxy::forward::Upstream {
            insecure_http: Some((h.into(), a)),
        };
    }
    ls_proxy::forward::Upstream {
        insecure_http: None,
    }
}

pub fn dir() -> PathBuf {
    ls_core::config_dir().join("git")
}

pub fn include_path() -> PathBuf {
    dir().join("forwarder.gitconfig")
}

pub fn hosts() -> Vec<String> {
    let mut h: Vec<String> = DEFAULT_HOSTS.iter().map(|s| s.to_string()).collect();
    if let Ok(s) = std::fs::read_to_string(dir().join("hosts")) {
        for l in s
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let l = l.to_lowercase();
            if !h.contains(&l) {
                h.push(l);
            }
        }
    }
    h
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The include file: rewrites for https, scp-style ssh and `ssh://` remotes, and a credential
/// helper scoped to the forwarder that resets any other helper (so no keychain stores or serves
/// a forwarder token).
pub fn render_include(port: u16, hosts: &[String], smith: &Path) -> String {
    let base = format!("http://127.0.0.1:{port}");
    let mut s =
        String::from("# Written by locksmithd and rewritten when its port changes. Do not edit.\n");
    for h in hosts {
        let _ = write!(
            s,
            "[url \"{base}/git/{h}/\"]\n\tinsteadOf = https://{h}/\n\tinsteadOf = git@{h}:\n\tinsteadOf = ssh://git@{h}/\n"
        );
    }
    let helper = format!(
        "!'{}' git credential",
        smith.display().to_string().replace('\'', "'\\''")
    );
    let _ = write!(
        s,
        "[credential \"{base}\"]\n\thelper =\n\thelper = {}\n\tuseHttpPath = true\n",
        quote(&helper)
    );
    s
}

/// Write the include file for `port` (0600 in a 0700 dir).
pub fn write_include(port: u16) -> std::io::Result<()> {
    let smith = std::env::current_exe()?
        .canonicalize()?
        .with_file_name("smith");
    ls_core::ensure_private_dir(&dir())?;
    let tmp = dir().join(".forwarder.gitconfig.tmp");
    {
        let mut f = ls_core::private_open_options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        std::io::Write::write_all(&mut f, render_include(port, &hosts(), &smith).as_bytes())?;
    }
    std::fs::rename(tmp, include_path())
}

fn norm(host: &str, repo: &str) -> String {
    format!(
        "{}/{}",
        host.to_lowercase(),
        repo.trim_end_matches(".git").to_lowercase()
    )
}

fn new_token() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS RNG");
    b.iter().fold(String::with_capacity(64), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// `Request::GitCredential`: mint a forwarder token under the caller's lease (scope `git`).
pub fn credential(
    d: &Daemon,
    peer: &Peer,
    actor: &Actor,
    host: &str,
    repo: &str,
    binding: Option<&[u8]>,
    remotes: &[String],
) -> Response {
    let host = host.to_lowercase();
    if !hosts().contains(&host) {
        return err(
            ErrorCode::BadRequest,
            format!("{host} is not a forwarder host; add it with `smith git setup --host {host}`"),
        );
    }
    let b: Binding = match binding.map(parse).transpose() {
        Ok(b) => b.unwrap_or_default(),
        Err(e) => return err(ErrorCode::BadRequest, format!("invalid binding: {e}")),
    };
    let project = b.project.clone().unwrap_or("default".into());
    let env = b.env.clone().unwrap_or("development".into());
    let target = norm(&host, repo);
    let mut st = d.state();
    let t = now();
    let lease = match st.leases.authorize(peer.id, "git", &project, &env, t) {
        Ok(l) => l.id.clone(),
        Err(den) => {
            let _ = st.audit(rec(
                actor,
                "BLOCKED",
                Some(target),
                &deny_rule(&den),
                "DENY",
                None,
            ));
            return deny_response(&den);
        }
    };
    let allowed: Vec<String> = if b.git.repos.is_empty() {
        remotes.iter().map(|r| r.to_lowercase()).collect()
    } else {
        b.git
            .repos
            .iter()
            .map(|r| r.trim_end_matches(".git").to_lowercase())
            .collect()
    };
    if !allowed.contains(&target) {
        let _ = st.audit(rec(
            actor,
            "BLOCKED",
            Some(target.clone()),
            "git_repo_not_allowed",
            "DENY",
            Some(lease),
        ));
        return err(
            ErrorCode::Denied,
            format!(
                "{target} is not in this project's Git allowlist ([git] repos in .locksmith.toml)"
            ),
        );
    }
    let Some(key) = b.git.credential_key(&host) else {
        return err(
            ErrorCode::BadRequest,
            format!("no upstream credential configured for {host}; add it under [git.credentials]"),
        );
    };
    let token = new_token();
    let live: Vec<String> = st.leases.active(t).into_iter().map(|l| l.id).collect();
    let mut toks = d.git.tokens.lock().unwrap_or_else(|e| e.into_inner());
    toks.retain(|_, v| live.contains(&v.lease));
    toks.insert(
        token.clone(),
        Token {
            lease,
            project,
            env,
            host,
            allowed,
            protected: b.git.protected(),
            key,
        },
    );
    Response::GitToken {
        username: "locksmith".into(),
        token,
    }
}

/// `smith gh`: the github.com upstream token for this session (raw, for GH_TOKEN). Audited as
/// ACCESS under the `git` scope.
pub fn gh_token(
    d: &Daemon,
    peer: &Peer,
    actor: &Actor,
    b: Option<&Binding>,
    project: &str,
    env: &str,
    repo: Option<&str>,
) -> Result<(String, Zeroizing<String>), Response> {
    let key = b
        .and_then(|b| b.git.credential_key("github.com"))
        .unwrap_or("GITHUB_TOKEN".into());
    let target = format!("{project}/{env}/{key}");
    let mut st = d.state();
    let t = now();
    let (lease, inject) = match st.leases.authorize(peer.id, "git", project, env, t) {
        Ok(l) => (l.id.clone(), l.inject.clone()),
        Err(den) => {
            let _ = st.audit(rec(
                actor,
                "BLOCKED",
                Some(target),
                &deny_rule(&den),
                "DENY",
                None,
            ));
            return Err(deny_response(&den));
        }
    };
    let secret = match &st.vault {
        None => return Err(err(ErrorCode::Locked, "vault is locked")),
        Some(v) => match v.get_secret(project, env, &key) {
            Ok(s) => Zeroizing::new(s.expose().to_vec()),
            Err(e) => return Err(err(ErrorCode::NotFound, e.to_string())),
        },
    };
    let cred = github::parse_credential(&secret).map_err(|e| err(ErrorCode::BadRequest, e))?;
    // M10e D1: a PAT would reach the child as GH_TOKEN verbatim, so an agent lease needs it in
    // `inject`. App mode hands over a short-lived installation token, never the stored key.
    if matches!(cred, github::Credential::Pat(_))
        && inject.as_ref().is_some_and(|i| !i.contains(&key))
    {
        return Err(crate::refuse_relay_only(
            &mut st,
            actor,
            &lease,
            project,
            env,
            &[&key],
        ));
    }
    st.audit(rec(
        actor,
        "ACCESS",
        Some(target),
        "gh",
        "ALLOW",
        Some(lease.clone()),
    ))
    .map_err(|e| err(ErrorCode::Internal, e))?;
    drop(st);
    if matches!(cred, github::Credential::App(_)) && repo.is_none() {
        return Err(err(
            ErrorCode::BadRequest,
            "GitHub App mode needs a repository: run `smith gh` inside a clone with a github.com remote",
        ));
    }
    let tok = github::upstream_token(&cred, &d.git.cache, repo.unwrap_or(""), now())
        .map_err(|e| err(ErrorCode::Internal, format!("github.com credential: {e}")))?;
    Ok((lease, tok))
}

pub fn info(d: &Daemon) -> Response {
    match d.git.port.get() {
        // Rewrite each time so hosts added by `smith git setup --host` take effect.
        Some(&port) if write_include(port).is_ok() => Response::GitInfo {
            port,
            include: include_path(),
            hosts: hosts(),
        },
        Some(_) => err(ErrorCode::Internal, "cannot write the Git include file"),
        None => err(ErrorCode::Internal, "Git forwarder is not running"),
    }
}

/// The forwarder's view of the daemon.
pub struct Gate(pub Arc<Daemon>);

fn deny(status: u16, m: impl Into<String>) -> Deny {
    Deny {
        status,
        message: m.into(),
    }
}

fn tcp_actor(p: ProcId) -> Actor {
    Actor {
        pid: p.pid,
        start: p.start,
        exe: "(git over loopback TCP)".into(),
        exe_hash: String::new(),
    }
}

impl Authority for Gate {
    fn authorize(
        &self,
        token: Option<&str>,
        client: SocketAddr,
        server: SocketAddr,
        route: &Route,
    ) -> Result<Grant, Deny> {
        let d = &self.0;
        let Some(token) = token else {
            return Err(deny(401, "Locksmith forwarder: authentication required"));
        };
        let target = norm(&route.host, &route.repo);
        let (lease, project, env, key, protected, allowed_here) = {
            let toks = d.git.tokens.lock().unwrap_or_else(|e| e.into_inner());
            let Some(k) = toks.get(token) else {
                return Err(deny(401, "unknown or expired Locksmith forwarder token"));
            };
            (
                k.lease.clone(),
                k.project.clone(),
                k.env.clone(),
                k.key.clone(),
                k.protected.clone(),
                k.host == route.host.to_lowercase() && k.allowed.contains(&target),
            )
        };
        let owners = ls_platform::net::tcp_peer_owners(client, server);
        let mut st = d.state();
        let t = now();
        let block = |st: &mut crate::State, a: &Actor, rule: &str| {
            let _ = st.audit(rec(
                a,
                "BLOCKED",
                Some(target.clone()),
                rule,
                "DENY",
                Some(lease.clone()),
            ));
        };
        let owners = match owners {
            Ok(o) if !o.is_empty() => o,
            _ => {
                block(&mut st, &d.me, "git_peer_unknown");
                return Err(deny(
                    403,
                    "Locksmith could not identify the process using the forwarder",
                ));
            }
        };
        let actor = tcp_actor(owners[0]);
        // Every process holding the client socket must be inside this token's live session.
        for o in &owners {
            match st.leases.authorize(*o, "git", &project, &env, t) {
                Ok(l) if l.id == lease => {}
                Ok(_) => {
                    block(&mut st, &tcp_actor(*o), "git_other_session");
                    return Err(deny(403, "forwarder token belongs to another session"));
                }
                Err(den) => {
                    block(&mut st, &tcp_actor(*o), &deny_rule(&den));
                    return Err(deny(
                        403,
                        format!("Locksmith refused the Git request: {den}"),
                    ));
                }
            }
        }
        if !allowed_here {
            block(&mut st, &actor, "git_repo_not_allowed");
            return Err(deny(
                403,
                format!("{target} is not in this session's Git allowlist"),
            ));
        }
        let secret = match &st.vault {
            None => {
                block(&mut st, &actor, "vault_locked");
                return Err(deny(403, "Locksmith vault is locked"));
            }
            Some(v) => match v.get_secret(&project, &env, &key) {
                Ok(s) => Zeroizing::new(s.expose().to_vec()),
                Err(_) => {
                    block(&mut st, &actor, "git_credential_missing");
                    return Err(deny(
                        403,
                        format!(
                            "vault key {key} for {} is missing in {project}/{env}",
                            route.host
                        ),
                    ));
                }
            },
        };
        if let Err(e) = st.audit(rec(
            &actor,
            "ACCESS",
            Some(format!("{project}/{env}/{key}")),
            &format!("git:{target}"),
            "ALLOW",
            Some(lease.clone()),
        )) {
            return Err(deny(500, e));
        }
        drop(st); // minting an App token is a network call
        let header = github::parse_credential(&secret)
            .and_then(|c| {
                if matches!(c, github::Credential::App(_))
                    && route.host.to_lowercase() != "github.com"
                {
                    return Err("GitHub App credentials only work for github.com".into());
                }
                github::upstream_header(&c, &d.git.cache, &route.repo, now())
            })
            .map_err(|e| deny(502, format!("upstream credential for {}: {e}", route.host)))?;
        d.git
            .actors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(lease.clone(), actor);
        Ok(Grant {
            upstream_auth: header,
            protected,
            lease,
        })
    }

    fn push_denied(&self, route: &Route, grant: &Grant, why: &str) {
        let d = &self.0;
        let actors = d.git.actors.lock().unwrap_or_else(|e| e.into_inner());
        let a = actors.get(&grant.lease).unwrap_or(&d.me);
        let _ = d.state().audit(rec(
            a,
            "BLOCKED",
            Some(norm(&route.host, &route.repo)),
            &format!("git_policy: {why}"),
            "DENY",
            Some(grant.lease.clone()),
        ));
    }

    fn forwarded(&self, _route: &Route, _grant: &Grant, _service: &str) {
        // Audited as ACCESS at authorization, once per request.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn include_rewrites_all_remote_forms_and_resets_helpers() {
        let s = render_include(4242, &["github.com".into()], Path::new("/opt/it's/smith"));
        for l in [
            "[url \"http://127.0.0.1:4242/git/github.com/\"]",
            "\tinsteadOf = https://github.com/",
            "\tinsteadOf = git@github.com:",
            "\tinsteadOf = ssh://git@github.com/",
            "[credential \"http://127.0.0.1:4242\"]",
            "\thelper =",
            "\tuseHttpPath = true",
        ] {
            assert!(s.lines().any(|x| x == l), "missing {l:?} in\n{s}");
        }
        assert!(
            s.contains(r#"helper = "!'/opt/it'\\''s/smith' git credential""#),
            "{s}"
        );
    }

    #[test]
    fn tokens_are_random_hex() {
        let (a, b) = (new_token(), new_token());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }
}
