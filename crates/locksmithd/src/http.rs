//! M6 HTTP delegation glue: opaque `lsk_` tokens bound to leases (design D1), the relay's
//! [`HttpAuthority`] (peer-to-PID check, host allowlist, placement, audit; D2) and the local
//! CA leaves for explicit-proxy mode (D4). Tokens live in memory only and die with their lease.
//! The credential is read from the vault per request and only goes to the relay's upstream leg.

use crate::policy::host_matches;
use crate::{Actor, Daemon, State, deny_response, deny_rule, err, now, rec};
use ls_ipc::{ErrorCode, HttpTokenInfo, IssuedToken, Response};
use ls_platform::proc::{Peer, ProcId};
use ls_proxy::catalog::{self, Resolved};
use ls_proxy::http::{self as relay, Attempt, HttpAuthority, HttpGrant, Placement};
use ls_proxy::rustls::ServerConfig;
use ls_proxy::{Deny, ca};
use ls_redact::binding::Binding;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::Zeroizing;

/// What an opaque token may do.
struct Token {
    lease: String,
    project: String,
    env: String,
    key: String,
    hosts: Vec<String>,
    placements: Vec<Placement>,
    created: i64,
}

#[derive(Default)]
pub struct Http {
    tokens: Mutex<HashMap<String, Token>>,
    /// Explicit-proxy leaves per host, with the CA certificate they were made from.
    leaves: Mutex<HashMap<String, (String, Arc<ServerConfig>)>>,
    pub port: OnceLock<u16>,
}

/// Test switch for plain-HTTP upstreams (`host=127.0.0.1:port[,…]`), debug builds only.
pub fn upstream() -> relay::Upstream {
    #[cfg(debug_assertions)]
    if let Ok(v) = std::env::var("LOCKSMITH_TEST_HTTP_UPSTREAM") {
        return relay::Upstream::parse(&v);
    }
    relay::Upstream::default()
}

fn live_leases(st: &State) -> Vec<String> {
    st.leases.active(now()).into_iter().map(|l| l.id).collect()
}

/// Drop tokens whose lease is no longer active (revoked, ended or expired).
pub fn prune(d: &Daemon, st: &State) {
    let live = live_leases(st);
    d.http
        .tokens
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|_, t| live.contains(&t.lease));
}

/// Mint a token for `key` under `lease` (the caller authorized it for `http`). Checks only
/// that the key name exists; the value is not read.
#[allow(clippy::too_many_arguments)]
fn mint(
    d: &Daemon,
    st: &mut State,
    actor: &Actor,
    lease: &str,
    project: &str,
    env: &str,
    key: &str,
    r: &Resolved,
) -> Result<String, Response> {
    let names = match &st.vault {
        None => return Err(err(ErrorCode::Locked, "vault is locked")),
        Some(v) => v
            .list_secrets(Some(project), Some(env))
            .map_err(|e| err(ErrorCode::Internal, e.to_string()))?,
    };
    if !names.iter().any(|m| m.name == key) {
        return Err(err(
            ErrorCode::NotFound,
            format!("vault key {key} is not in {project}/{env}"),
        ));
    }
    st.audit(rec(
        actor,
        "TOKEN_ISSUE",
        Some(format!("{project}/{env}/{key}")),
        &format!("http:{}", r.hosts.join(",")),
        "ALLOW",
        Some(lease.to_string()),
    ))
    .map_err(|e| err(ErrorCode::Internal, e))?;
    prune(d, st);
    let token = relay::new_token();
    d.http
        .tokens
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            token.clone(),
            Token {
                lease: lease.to_string(),
                project: project.to_string(),
                env: env.to_string(),
                key: key.to_string(),
                hosts: r.hosts.clone(),
                placements: r.placements.clone(),
                created: now(),
            },
        );
    Ok(token)
}

/// `Request::TokenIssue`.
#[allow(clippy::too_many_arguments)]
pub fn issue(
    d: &Daemon,
    peer: &Peer,
    actor: &Actor,
    key: &str,
    provider: Option<&str>,
    hosts: &[String],
    placement: Option<&str>,
    bytes: Option<&[u8]>,
) -> Response {
    let mut st = d.state();
    // Hosts come from the binding pinned at session start, never from a file the agent edited.
    let same = |c: &Binding, p: &Binding| {
        (&c.project, &c.env, c.http.keys.get(key)) == (&p.project, &p.env, p.http.keys.get(key))
    };
    let b =
        match crate::effective_binding(&mut st, peer, actor, &format!("http:{key}"), bytes, same) {
            Ok(b) => b,
            Err(r) => return r,
        };
    let project = b.project.clone().unwrap_or("default".into());
    let env = b.env.clone().unwrap_or("development".into());
    let (lease, agent) = match st.leases.authorize(peer.id, "http", &project, &env, now()) {
        Ok(l) => (l.id.clone(), l.agent),
        Err(den) => {
            let _ = st.audit(rec(
                actor,
                "BLOCKED",
                Some(format!("{project}/{env}/{key}")),
                &deny_rule(&den),
                "DENY",
                None,
            ));
            return deny_response(&den);
        }
    };
    // Agent leases: the hosts come from the agent policy, never the binding or the catalog.
    let policy_hosts = if agent {
        match agent_hosts(&mut st, actor, &lease, &project, &env, key, hosts) {
            Ok(h) => Some(h),
            Err(r) => return r,
        }
    } else {
        None
    };
    let r = match catalog::resolve(
        b.http.keys.get(key),
        provider,
        policy_hosts.as_deref().unwrap_or(hosts),
        placement,
    ) {
        Ok(r) => r,
        Err(e) => return err(ErrorCode::BadRequest, e),
    };
    // `--host` / `--provider` may narrow or pick among approved destinations, never add one: a
    // token for an agent-chosen host would carry the real key to it (gate A3b).
    if let Some(h) = r
        .hosts
        .iter()
        .find(|h| !agent && !host_approved(&b, key, h))
    {
        let _ = st.audit(rec(
            actor,
            "BLOCKED",
            Some(format!("{project}/{env}/{key}")),
            &format!("http_host_not_bound:{h}"),
            "DENY",
            Some(lease),
        ));
        return err(
            ErrorCode::Denied,
            format!(
                "{h} is not an approved host for {key}: list it under [http.keys] in \
                 .locksmith.toml and start a new session (catalog hosts are always allowed)"
            ),
        );
    }
    match mint(d, &mut st, actor, &lease, &project, &env, key, &r) {
        Ok(token) => Response::HttpToken(Box::new(IssuedToken {
            token,
            key: key.to_string(),
            hosts: r.hosts.clone(),
            placement: relay::placements_str(&r.placements),
            lease,
            base_url: d
                .http
                .port
                .get()
                .zip(r.base_url.as_deref())
                .and_then(|(p, u)| catalog::relay_url(*p, u)),
        })),
        Err(r) => r,
    }
}

/// M10e D2: the hosts an agent lease's token for `key` carries: those asked for if the agent
/// policy lists every one, else all the policy's hosts for the key. A key with no policy hosts,
/// or an asked host outside them, is refused and audited `BLOCKED relay_host`.
#[allow(clippy::too_many_arguments)]
fn agent_hosts(
    st: &mut State,
    actor: &Actor,
    lease: &str,
    project: &str,
    env: &str,
    key: &str,
    asked: &[String],
) -> Result<Vec<String>, Response> {
    let allowed = st.policy_hosts(project, key);
    let bad = match asked.iter().find(|h| !host_matches(&allowed, h)) {
        _ if allowed.is_empty() => None,
        Some(h) => Some(h.as_str()),
        None if asked.is_empty() => return Ok(allowed),
        None => return Ok(asked.to_vec()),
    };
    let _ = st.audit(rec(
        actor,
        "BLOCKED",
        Some(format!("{project}/{env}/{key}")),
        &format!("relay_host:{}", bad.unwrap_or("none")),
        "DENY",
        Some(lease.to_string()),
    ));
    Err(err(ErrorCode::Denied, relay_host_msg(project, key, bad)))
}

/// `host`: the refused host, or `None` when the policy lists no host for the key.
fn relay_host_msg(project: &str, key: &str, host: Option<&str>) -> String {
    let what = match host {
        Some(h) => format!("{h} is not a relay host for {key} in the agent policy"),
        None => format!("the agent policy lists no relay host for {key}"),
    };
    format!(
        "relay_host: {what}; nothing was sent. For agent sessions the human lists hosts under \
         [projects.{project}.http.{key}] hosts = [...] in {} and unlocks again \
         (.locksmith.toml hosts do not count)",
        crate::policy::default_path().display()
    )
}

/// May a token for `key` name `host`? Yes for the hosts the (pinned) binding gives the key, and
/// for any host the built-in provider catalog lists (well-known APIs, not agent-controlled).
/// A `*.suffix` entry must appear as such; an exact host may fall under a bound `*.suffix`.
pub fn host_approved(b: &Binding, key: &str, host: &str) -> bool {
    let bound = catalog::resolve(b.http.keys.get(key), None, &[], None)
        .map(|r| r.hosts)
        .unwrap_or_default();
    let in_catalog = catalog::all()
        .iter()
        .any(|p| p.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)));
    let in_binding = if host.starts_with("*.") {
        bound.iter().any(|h| h.eq_ignore_ascii_case(host))
    } else {
        relay::host_allowed(&bound, host)
    };
    in_catalog || in_binding
}

/// Variables for the child, and the key names they replace.
pub type RunVars = (Vec<(String, Vec<u8>)>, Vec<String>);

/// `smith run`: opaque tokens and relay base URLs for the binding's `[http.keys]` (all of them,
/// or those in `only`). Returns the variables and the key names they replace.
#[allow(clippy::too_many_arguments)]
pub fn for_run(
    d: &Daemon,
    st: &mut State,
    peer: &Peer,
    actor: &Actor,
    lease: &str,
    project: &str,
    env: &str,
    b: &Binding,
    only: &[String],
) -> Result<RunVars, Response> {
    let keys: Vec<&String> = b
        .http
        .keys
        .keys()
        .filter(|k| only.is_empty() || only.contains(k))
        .collect();
    if keys.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let agent = match st.leases.authorize(peer.id, "http", project, env, now()) {
        Ok(l) => l.agent,
        Err(den) => {
            let _ = st.audit(rec(
                actor,
                "BLOCKED",
                Some(format!("{project}/{env}")),
                &deny_rule(&den),
                "DENY",
                Some(lease.to_string()),
            ));
            return Err(err(
                ErrorCode::Denied,
                format!("keys under [http] need the session's `http` scope: {den}"),
            ));
        }
    };
    let Some(&port) = d.http.port.get() else {
        return Err(err(ErrorCode::Internal, "HTTP relay is not running"));
    };
    let (mut vars, mut names) = (Vec::new(), Vec::new());
    for k in keys {
        let hosts = if agent {
            agent_hosts(st, actor, lease, project, env, k, &[])?
        } else {
            Vec::new()
        };
        let r = catalog::resolve(b.http.keys.get(k), None, &hosts, None)
            .map_err(|e| err(ErrorCode::BadRequest, format!("[http.keys] {k}: {e}")))?;
        let token = mint(d, st, actor, lease, project, env, k, &r)?;
        vars.push((k.clone(), token.into_bytes()));
        names.push(k.clone());
        if let Some(url) = r
            .base_url
            .as_deref()
            .and_then(|u| catalog::relay_url(port, u))
        {
            for e in &r.base_url_env {
                vars.push((e.clone(), url.clone().into_bytes()));
            }
        }
    }
    Ok((vars, names))
}

pub fn list(d: &Daemon) -> Response {
    prune(d, &d.state());
    let toks = d.http.tokens.lock().unwrap_or_else(|e| e.into_inner());
    let mut tokens: Vec<HttpTokenInfo> = toks
        .iter()
        .map(|(t, v)| HttpTokenInfo {
            prefix: relay::shown(t),
            key: v.key.clone(),
            project: v.project.clone(),
            env: v.env.clone(),
            hosts: v.hosts.clone(),
            placement: relay::placements_str(&v.placements),
            lease: v.lease.clone(),
            created_at: v.created,
        })
        .collect();
    tokens.sort_by(|a, b| (a.created_at, &a.prefix).cmp(&(b.created_at, &b.prefix)));
    Response::HttpTokens { tokens }
}

/// `Request::TokenRevoke`: one token (or a unique prefix of at least 12 characters), or all.
pub fn revoke(d: &Daemon, actor: &Actor, which: Option<&str>) -> Response {
    let mut st = d.state();
    let mut toks = d.http.tokens.lock().unwrap_or_else(|e| e.into_inner());
    let gone: Vec<String> = match which {
        None => toks.keys().cloned().collect(),
        Some(w) if w.len() < relay::SHOWN => {
            return err(
                ErrorCode::BadRequest,
                format!(
                    "give the token or its first {} characters (smith token ls)",
                    relay::SHOWN
                ),
            );
        }
        Some(w) => {
            let m: Vec<String> = toks.keys().filter(|t| t.starts_with(w)).cloned().collect();
            match m.len() {
                0 => return err(ErrorCode::NotFound, "no such token"),
                1 => m,
                _ => return err(ErrorCode::BadRequest, "ambiguous token prefix"),
            }
        }
    };
    let mut records = Vec::new();
    for t in &gone {
        if let Some(v) = toks.remove(t) {
            records.push(rec(
                actor,
                "TOKEN_REVOKE",
                Some(format!("{}/{}/{}", v.project, v.env, v.key)),
                "user",
                "ALLOW",
                Some(v.lease),
            ));
        }
    }
    drop(toks);
    for r in records {
        let _ = st.audit(r);
    }
    Response::Revoked {
        count: gone.len() as u32,
    }
}

pub fn info(d: &Daemon) -> Response {
    match d.http.port.get() {
        Some(&port) => Response::HttpInfo {
            port,
            ca_hosts: ca::enabled_hosts(&ls_core::config_dir()),
        },
        None => err(ErrorCode::Internal, "HTTP relay is not running"),
    }
}

/// The relay's view of the daemon.
pub struct Relay(pub Arc<Daemon>);

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
        exe: "(http over loopback TCP)".into(),
        exe_hash: String::new(),
    }
}

impl HttpAuthority for Relay {
    fn authorize(&self, a: &Attempt<'_>) -> Result<HttpGrant, Deny> {
        let d = &self.0;
        let (lease, project, env, key, hosts, placements) = {
            let toks = d.http.tokens.lock().unwrap_or_else(|e| e.into_inner());
            let Some(t) = toks.get(a.token) else {
                return Err(deny(
                    401,
                    "unknown or expired Locksmith token (tokens end with their session)",
                ));
            };
            (
                t.lease.clone(),
                t.project.clone(),
                t.env.clone(),
                t.key.clone(),
                t.hosts.clone(),
                t.placements.clone(),
            )
        };
        let target = format!("{project}/{env}/{key}");
        let owners = ls_platform::net::tcp_peer_owners(a.client, a.server);
        let mut st = d.state();
        let t = now();
        let block = |st: &mut State, who: &Actor, rule: &str| {
            let _ = st.audit(rec(
                who,
                "BLOCKED",
                Some(target.clone()),
                &format!("{rule}:{}", a.host),
                "DENY",
                Some(lease.clone()),
            ));
        };
        let owners = match owners {
            Ok(o) if !o.is_empty() => o,
            _ => {
                block(&mut st, &d.me, "http_peer_unknown");
                return Err(deny(
                    403,
                    "Locksmith could not identify the process using the relay",
                ));
            }
        };
        let actor = tcp_actor(owners[0]);
        // Every process holding the client socket must be inside this token's live session.
        let mut agent = false;
        for o in &owners {
            match st.leases.authorize(*o, "http", &project, &env, t) {
                Ok(l) if l.id == lease => agent = l.agent,
                Ok(_) => {
                    block(&mut st, &tcp_actor(*o), "http_other_session");
                    return Err(deny(403, "Locksmith token belongs to another session"));
                }
                Err(den) => {
                    block(&mut st, &tcp_actor(*o), &deny_rule(&den));
                    return Err(deny(403, format!("Locksmith refused the request: {den}")));
                }
            }
        }
        // M10e D2: an agent lease's key goes only to hosts the agent policy lists, whatever the
        // token (minted from a binding the agent could edit) says.
        if agent && !host_matches(&st.policy_hosts(&project, &key), a.host) {
            block(&mut st, &actor, "relay_host");
            return Err(deny(403, relay_host_msg(&project, &key, Some(a.host))));
        }
        if let Err((rule, message)) = relay::check(&hosts, &placements, a.host, a.found) {
            block(&mut st, &actor, rule);
            return Err(deny(403, message));
        }
        let secret = match &st.vault {
            None => {
                block(&mut st, &actor, "vault_locked");
                return Err(deny(403, "Locksmith vault is locked"));
            }
            Some(v) => match v.get_secret(&project, &env, &key) {
                Ok(s) => Zeroizing::new(s.expose().to_vec()),
                Err(_) => {
                    block(&mut st, &actor, "http_credential_missing");
                    return Err(deny(
                        403,
                        format!("vault key {key} is missing in {project}/{env}"),
                    ));
                }
            },
        };
        st.audit(rec(
            &actor,
            "ACCESS",
            Some(target.clone()),
            &format!("http:{}", a.host),
            "ALLOW",
            Some(lease.clone()),
        ))
        .map_err(|e| deny(500, e))?;
        Ok(HttpGrant {
            secret,
            placements,
            label: key,
        })
    }

    fn intercept(
        &self,
        host: &str,
        client: SocketAddr,
        server: SocketAddr,
    ) -> Result<Arc<ServerConfig>, Deny> {
        let d = &self.0;
        let cfg_dir = ls_core::config_dir();
        let enabled = ca::enabled_hosts(&cfg_dir);
        let owners = ls_platform::net::tcp_peer_owners(client, server).unwrap_or_default();
        let actor = owners.first().map_or_else(
            || Actor {
                pid: d.me.pid,
                start: d.me.start,
                exe: d.me.exe.clone(),
                exe_hash: String::new(),
            },
            |o| tcp_actor(*o),
        );
        let mut st = d.state();
        let t = now();
        let block = |st: &mut State, rule: &str| {
            let _ = st.audit(rec(
                &actor,
                "BLOCKED",
                Some(host.to_string()),
                rule,
                "DENY",
                None,
            ));
        };
        if !relay::host_allowed(&enabled, host) {
            block(&mut st, "http_connect_not_enabled");
            return Err(deny(
                403,
                format!(
                    "Locksmith explicit proxy: {host} is not enabled (no blind tunnels; see `smith http ca status`)"
                ),
            ));
        }
        let in_session = !owners.is_empty()
            && owners.iter().all(|o| {
                st.leases.find(*o, t).is_some_and(|l| {
                    l.info(t).state == "active" && ls_broker::scope_allows(&l.scopes, "http")
                })
            });
        if !in_session {
            block(&mut st, "http_connect_no_session");
            return Err(deny(
                403,
                "Locksmith explicit proxy works only inside a session with the `http` scope",
            ));
        }
        let Ok(cert) = std::fs::read_to_string(ca::cert_path(&cfg_dir)) else {
            block(&mut st, "http_ca_missing");
            return Err(deny(403, "Locksmith local CA is not installed"));
        };
        if let Some((c, cfg)) = d
            .http
            .leaves
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(host)
            && *c == cert
        {
            return Ok(cfg.clone());
        }
        let key = match &st.vault {
            None => {
                block(&mut st, "vault_locked");
                return Err(deny(403, "Locksmith vault is locked"));
            }
            Some(v) => match v.get_secret(ca::KEY_PROJECT, ca::KEY_ENV, ca::KEY_NAME) {
                Ok(s) => Zeroizing::new(String::from_utf8_lossy(s.expose()).into_owned()),
                Err(_) => {
                    block(&mut st, "http_ca_key_missing");
                    return Err(deny(
                        403,
                        "the local CA key is not in the vault; run `smith http ca install` again",
                    ));
                }
            },
        };
        let _ = st.audit(rec(
            &actor,
            "ACCESS",
            Some(host.to_string()),
            "http_ca_leaf",
            "ALLOW",
            None,
        ));
        drop(st);
        let cfg = ca::leaf(&cert, &key, host)
            .and_then(|(chain, k)| ca::server_config(chain, k))
            .map_err(|e| deny(502, format!("cannot issue a certificate for {host}: {e}")))?;
        d.http
            .leaves
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(host.to_string(), (cert, cfg.clone()));
        Ok(cfg)
    }
}
