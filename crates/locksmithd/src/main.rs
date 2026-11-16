//! `locksmithd`: the per-user broker daemon. Holds the unlocked vault key in memory, keeps
//! session leases in memory only (a restart drops them: fail closed), and spawns `smith run`
//! children itself so secrets never travel back over the socket.

mod aws;
mod db;
mod git;
mod http;
mod policy;
mod run;
mod scan;

use ls_broker::{Denial, LeaseState, Leases, Manifest, Role};
use ls_ipc::{
    AuditEvent, ErrorCode, Frame, LOCK_FILE, Request, Response, SelfReport, read_frame, write_frame,
};
use ls_platform::proc::{Peer, ProcId, id_of};
use ls_redact::binding::{Binding, parse as parse_binding};
use ls_vault::audit::{AuditRecord, StoredEvent};
use ls_vault::{Error as VErr, Vault};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Lease operation scopes: `run` (M2), `git` (M5), `http` and `db` (M6).
pub const SCOPES: [&str; 5] = ["run", "git", "http", "db", "aws"];
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// sun_path is 104 bytes on macOS and 108 on Linux.
const MAX_SOCKET_PATH: usize = 100;
/// BLOCKED events recorded while locked wait here until the next unlock (lost on restart).
const MAX_PENDING: usize = 1000;

pub struct Actor {
    pub pid: u32,
    pub start: u64,
    pub exe: String,
    /// Pinned digest the caller matched; empty for unattested callers.
    pub exe_hash: String,
}

impl Actor {
    fn of(p: &Peer, m: &Manifest) -> Actor {
        Actor {
            pid: p.id.pid,
            start: p.id.start,
            exe: p.exe.display().to_string(),
            exe_hash: m.digest_of(p).map(|d| d.hex()).unwrap_or_default(),
        }
    }
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

pub fn rec(
    a: &Actor,
    action: &str,
    target: Option<String>,
    rule: &str,
    decision: &str,
    session: Option<String>,
) -> AuditRecord {
    AuditRecord {
        ts: now(),
        session_id: session,
        actor_pid: a.pid,
        actor_start: a.start,
        actor_exe: a.exe.clone(),
        actor_exe_hash: a.exe_hash.clone(),
        action: action.into(),
        target,
        policy_rule: rule.into(),
        decision: decision.into(),
    }
}

pub struct State {
    pub vault: Option<Vault>,
    pub leases: Leases,
    pub last: Instant,
    pending: Vec<AuditRecord>,
    /// Agent policy read at the last unlock (`None` while locked). Not re-read per request: an
    /// agent at the human's uid could edit the file; changes apply from the next unlock.
    agent_policy: Option<Result<policy::Policy, String>>,
}

impl State {
    /// Read the agent policy (at unlock) and hand its `[relay] allow_private` to the relays.
    fn load_policy(&mut self) {
        let p = load_agent_policy();
        ls_proxy::forward::set_allow_private(
            p.as_ref().map(|p| p.allow_private()).unwrap_or_default(),
        );
        self.agent_policy = Some(p);
    }

    /// M10e D2: the hosts the agent policy lets the relay send `key` to for `project`. Empty
    /// (nothing relayed) when the key is not listed or no policy is loaded.
    pub fn policy_hosts(&self, project: &str, key: &str) -> Vec<String> {
        match &self.agent_policy {
            Some(Ok(p)) => p.relay_hosts(project, key),
            _ => Vec::new(),
        }
    }

    /// Append now when unlocked; while locked, queue (flushed on the next unlock).
    pub fn audit(&mut self, r: AuditRecord) -> Result<(), String> {
        let Some(v) = &self.vault else {
            if self.pending.len() < MAX_PENDING {
                self.pending.push(r);
            }
            return Ok(());
        };
        for p in std::mem::take(&mut self.pending) {
            let _ = v.audit_append(&p);
        }
        v.audit_append(&r)
            .map(|_| ())
            .map_err(|e| format!("audit failed: {e}"))
    }
}

pub struct Daemon {
    st: Mutex<State>,
    manifest: Manifest,
    idle: Option<Duration>,
    me: Actor,
    git: git::Git,
    db: db::Db,
    http: http::Http,
    aws: aws::Aws,
}

impl Daemon {
    pub fn state(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drop the key material (auditing first). Also the entry point for a future screen-lock
    /// watcher: call `lock_now("screen_lock")`.
    pub fn lock_now(&self, reason: &str) {
        self.lock_as(&self.me, reason);
    }

    fn lock_as(&self, a: &Actor, reason: &str) {
        let mut st = self.state();
        if st.vault.is_some() {
            let _ = st.audit(rec(a, "LOCK", None, reason, "ALLOW", None));
            st.vault = None;
            st.agent_policy = None;
        }
    }
}

fn err(code: ErrorCode, m: impl Into<String>) -> Response {
    Response::Error {
        code,
        message: m.into(),
    }
}

fn vault_dir() -> std::path::PathBuf {
    ls_core::config_dir().join("vault")
}

fn vault_open(passphrase: &[u8]) -> Result<Vault, Response> {
    let dir = vault_dir();
    if let Err(e) = ls_vault::check_perms(&dir) {
        return Err(err(ErrorCode::Internal, e.to_string()));
    }
    if !ls_vault::exists(&dir) {
        return Err(err(ErrorCode::NotFound, VErr::NotInitialized.to_string()));
    }
    Vault::open_passphrase(&dir, passphrase, weak_kdf()).map_err(|e| match e {
        VErr::BadCredentials => err(ErrorCode::Denied, e.to_string()),
        e => err(ErrorCode::Internal, e.to_string()),
    })
}

/// Weak KDF parameters are accepted only in debug builds with the test switch.
#[cfg(debug_assertions)]
fn weak_kdf() -> bool {
    std::env::var("LOCKSMITH_INSECURE_TEST_KDF").as_deref() == Ok("1")
}
#[cfg(not(debug_assertions))]
fn weak_kdf() -> bool {
    false
}

pub fn deny_response(d: &Denial) -> Response {
    match d {
        Denial::NoLease | Denial::Inactive { .. } => err(ErrorCode::Locked, d.to_string()),
        Denial::OutOfScope { .. } => err(ErrorCode::Denied, d.to_string()),
    }
}

pub fn deny_rule(d: &Denial) -> String {
    match d {
        Denial::NoLease => "no_lease".into(),
        Denial::Inactive { state, .. } if *state == LeaseState::Revoked => "revoked".into(),
        Denial::Inactive { .. } => "expired".into(),
        Denial::OutOfScope { why, .. } => format!("out_of_scope: {why}"),
    }
}

/// The binding a credential-routing request must use (M6 gates A3/A3b): the copy pinned when the
/// caller's session started, because an agent inside the session can edit `.locksmith.toml`.
/// The client's copy is accepted only when `same(client, pinned)` holds for the part the request
/// uses; otherwise the request is refused and audited `BLOCKED binding_changed`. A client that
/// sends no binding gets the pinned one. Without any lease the client copy is returned as is:
/// the scope check that follows refuses the request.
pub fn effective_binding(
    st: &mut State,
    peer: &Peer,
    actor: &Actor,
    target: &str,
    client: Option<&[u8]>,
    same: impl Fn(&Binding, &Binding) -> bool,
) -> Result<Binding, Response> {
    let mine = match client.map(parse_binding).transpose() {
        Ok(b) => b.unwrap_or_default(),
        Err(e) => return Err(err(ErrorCode::BadRequest, format!("invalid binding: {e}"))),
    };
    let Some(l) = st.leases.find(peer.id, now()) else {
        return Ok(mine);
    };
    let lease = l.id.clone();
    let pinned = l
        .binding
        .as_ref()
        .and_then(|p| parse_binding(&p.0).ok())
        .unwrap_or_default();
    if client.is_none() || same(&mine, &pinned) {
        return Ok(pinned);
    }
    let _ = st.audit(rec(
        actor,
        "BLOCKED",
        Some(target.to_string()),
        "binding_changed",
        "DENY",
        Some(lease),
    ));
    Err(err(
        ErrorCode::Denied,
        format!(
            "{target}: .locksmith.toml differs from the copy this session started with; nothing \
             was sent. Start a new session to use the edited file"
        ),
    ))
}

fn event(e: StoredEvent) -> AuditEvent {
    let r = e.record;
    AuditEvent {
        seq: e.seq,
        ts: r.ts,
        session_id: r.session_id,
        actor_pid: r.actor_pid,
        actor_exe: r.actor_exe,
        action: r.action,
        target: r.target,
        policy_rule: r.policy_rule,
        decision: r.decision,
    }
}

/// What each caller role may ask. `smith` gets everything except `SecretPut` (an agent can
/// reach an attested `smith`; writing vault values without the passphrase is the desktop
/// app's job only) and `AgentSessionStart` (the passphrase-less grant is the MCP server's). The desktop app gets an explicit allowlist (M14); everything else, `Ping`.
fn allowed(role: Role, req: &Request) -> bool {
    match role {
        Role::Smith => !matches!(
            req,
            Request::SecretPut { .. } | Request::AgentSessionStart { .. }
        ),
        Role::Desktop => matches!(
            req,
            Request::Ping
                | Request::Unlock { .. }
                | Request::Lock
                | Request::Status
                | Request::Revoke { .. }
                | Request::AuditList { .. }
                | Request::AuditVerify
                | Request::KeyNames { .. }
                | Request::TokenList
                | Request::TokenRevoke { .. }
                | Request::GitInfo
                | Request::HttpInfo
                | Request::AwsInfo
                | Request::SecretPut { .. }
        ),
        // The agent-facing MCP server: discovery and opaque tokens under the caller's lease only.
        Role::Mcp => matches!(
            req,
            Request::Ping
                | Request::Status
                | Request::LeaseKeys
                | Request::TokenIssue { .. }
                | Request::AgentSessionStart { .. }
        ),
        Role::Unknown => matches!(req, Request::Ping),
    }
}

/// `SecretPut`: a new version of the key, audited `SECRET_PUT` with the target only.
fn secret_put(
    st: &mut State,
    actor: &Actor,
    project: &str,
    env: &str,
    name: &str,
    value: &[u8],
) -> Response {
    let Some(v) = st.vault.as_mut() else {
        return err(ErrorCode::Locked, "vault is locked");
    };
    // The vault validates the name (as for `smith add`); its errors never echo the value.
    let ver = match v.put_secret(project, env, name, value) {
        Ok(ver) => ver,
        Err(e @ VErr::Invalid(_)) => return err(ErrorCode::BadRequest, e.to_string()),
        Err(e @ VErr::NotFound(_)) => return err(ErrorCode::NotFound, e.to_string()),
        Err(e) => return err(ErrorCode::Internal, e.to_string()),
    };
    let target = format!("{project}/{env}/{name}");
    match st.audit(rec(
        actor,
        "SECRET_PUT",
        Some(target),
        &format!("desktop v{ver}"),
        "ALLOW",
        None,
    )) {
        Ok(()) => Response::Ok,
        Err(e) => err(ErrorCode::Internal, e),
    }
}

fn load_agent_policy() -> Result<policy::Policy, String> {
    policy::load(&policy::default_path(), ls_platform::current_uid())
}

/// M10e D1: refuse a run (or `smith gh`) that would inject keys an agent lease may not have.
/// Audits `BLOCKED relay_only` once per key, with the key name only.
pub fn refuse_relay_only(
    st: &mut State,
    actor: &Actor,
    lease: &str,
    project: &str,
    env: &str,
    keys: &[&String],
) -> Response {
    for k in keys {
        let _ = st.audit(rec(
            actor,
            "BLOCKED",
            Some(format!("{project}/{env}/{k}")),
            "relay_only",
            "DENY",
            Some(lease.to_string()),
        ));
    }
    let names = keys
        .iter()
        .map(|k| k.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    err(
        ErrorCode::Denied,
        format!(
            "relay_only: {names} {} relay-only for agent sessions; nothing was injected or run. \
             Use an http token instead (locksmith_issue_token or `smith token issue {}`). To let \
             agent sessions inject a key, the human adds it to `inject` under [projects.{project}] \
             in {} and unlocks again",
            if keys.len() == 1 { "is" } else { "are" },
            keys[0],
            policy::default_path().display()
        ),
    )
}

/// Self-reported `agent`/`model` (M10d): 1..=64 printable ASCII characters.
fn valid_report(v: &str) -> bool {
    (1..=64).contains(&v.len()) && v.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Wire name of a source kind (snake_case, as in `LeaseInfo`), for audit text.
fn kind_str(k: ls_ipc::SourceKind) -> String {
    serde_json::to_value(k)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

/// `AgentSessionStart` (M10b D1, D4): a lease without the passphrase, only on an unlocked vault
/// and only when the request fits the agent policy exactly, rooted at the agent process that
/// launched the MCP server (`caller`). Grants, replacements and refusals are audited.
#[allow(clippy::too_many_arguments)]
fn agent_session_start(
    st: &mut State,
    caller: ProcId,
    actor: &Actor,
    project: String,
    env: String,
    scopes: Vec<String>,
    ttl_secs: u64,
    command: String,
    binding: Option<Vec<u8>>,
    report: Option<SelfReport>,
) -> Response {
    let t = now();
    if ttl_secs == 0 || scopes.is_empty() || scopes.iter().any(|s| !SCOPES.contains(&s.as_str())) {
        return err(
            ErrorCode::BadRequest,
            "ttl must be > 0 and scopes a non-empty list of 'run', 'git', 'http', 'db', 'aws'",
        );
    }
    if let Some(r) = &report
        && [&r.agent, &r.model]
            .into_iter()
            .flatten()
            .any(|v| !valid_report(v))
    {
        return err(
            ErrorCode::BadRequest,
            "agent and model must be at most 64 printable ASCII characters",
        );
    }
    if st.vault.is_none() {
        return err(
            ErrorCode::Locked,
            "vault is locked; the human must unlock it before an agent can start a session",
        );
    }
    let target = format!("{project}/{env}");
    // D4: root at the agent that launched the MCP server, as the kernel reports it.
    let root = match ls_broker::agent_root(caller, ls_platform::current_uid()) {
        Ok(r) => r,
        Err(why) => {
            let _ = st.audit(rec(
                actor,
                "BLOCKED",
                Some(target),
                &format!("agent_root: {why}"),
                "DENY",
                None,
            ));
            return err(
                ErrorCode::Denied,
                format!("agent_root: {why}; ask the human to start this session"),
            );
        }
    };
    // No nesting. The one exception: this agent's own earlier agent-started lease is replaced.
    let mut replaced = None;
    for p in [root, caller] {
        if let Some(l) = st.leases.find(p, t).filter(|l| l.info(t).state == "active") {
            if !(l.root == root && l.agent) {
                return err(
                    ErrorCode::Denied,
                    format!("already inside session {}; sessions cannot be nested", l.id),
                );
            }
            replaced = Some(l.id.clone());
        }
    }
    let inject = match &st.agent_policy {
        Some(Ok(p)) => p.inject(&project),
        _ => Vec::new(),
    };
    let fit = match &st.agent_policy {
        Some(Ok(p)) => p.check(&project, &env, &scopes, ttl_secs),
        Some(Err(e)) => Err(e.clone()),
        None => Err("no agent policy loaded".into()),
    };
    if let Err(why) = fit {
        let _ = st.audit(rec(
            actor,
            "BLOCKED",
            Some(target),
            &format!("agent_policy: {why}"),
            "DENY",
            None,
        ));
        return err(
            ErrorCode::Denied,
            format!("agent_policy: {why}; ask the human to start this session"),
        );
    }
    let origin = ls_broker::source::detect(root.pid, None);
    let mut rule = format!(
        "agent_policy {}; root pid {} ({}); source {}",
        scopes.join(","),
        root.pid,
        ls_platform::proc::exe_name(root.pid).unwrap_or_else(|| "?".into()),
        kind_str(origin.0.kind)
    );
    if let Some(r) = &report {
        // As the agent reported them (validated printable ASCII); never trusted.
        rule.push_str(&format!(
            "; reported agent={:?} model={:?}",
            r.agent.as_deref().unwrap_or(""),
            r.model.as_deref().unwrap_or("")
        ));
    }
    // Revokes `replaced` (same root) before the new lease exists.
    let l = st
        .leases
        .start(root, ttl_secs, project, env, scopes, command, t);
    let (id, expires_at) = (l.id.clone(), l.expires_at);
    st.leases.pin(&id, binding);
    st.leases.mark_agent(&id, inject);
    st.leases.describe(&id, origin, report);
    if let Some(old) = replaced {
        let _ = st.audit(rec(
            actor,
            "REVOKE",
            Some(old.clone()),
            &format!("replaced by agent session {id}"),
            "ALLOW",
            Some(old),
        ));
    }
    if let Err(e) = st.audit(rec(
        actor,
        "SESSION_START",
        Some(target),
        &rule,
        "ALLOW",
        Some(id.clone()),
    )) {
        st.leases.revoke(Some(&id), t);
        return err(ErrorCode::Internal, e);
    }
    Response::Session { id, expires_at }
}

fn serve(d: Arc<Daemon>, mut s: UnixStream) {
    let Ok(peer) = Peer::of(&s) else { return };
    let role = d.manifest.classify(&peer);
    let actor = Actor::of(&peer, &d.manifest);
    loop {
        let req = match read_frame::<Request>(&mut s) {
            Ok(Some(Frame::Msg(r))) => r,
            Ok(Some(Frame::Version(v))) => {
                let _ = write_frame(
                    &mut s,
                    &err(
                        ErrorCode::Version,
                        format!(
                            "daemon speaks protocol v{}, got v{v}",
                            ls_ipc::PROTOCOL_VERSION
                        ),
                    ),
                );
                return;
            }
            _ => return,
        };
        if !peer.alive() {
            return;
        }
        if !allowed(role, &req) {
            let (rule, msg) = match role {
                Role::Unknown => (
                    "attestation".to_string(),
                    "caller is not an attested Locksmith binary".to_string(),
                ),
                r => (
                    format!("role: {}", r.as_str()),
                    format!("request not served to {}", r.as_str()),
                ),
            };
            let _ = d
                .state()
                .audit(rec(&actor, "BLOCKED", None, &rule, "DENY", None));
            if write_frame(&mut s, &err(ErrorCode::Denied, msg)).is_err() {
                return;
            }
            continue;
        }
        // The desktop tray polls Status every few seconds; that must not hold off idle lock.
        if !matches!(req, Request::Ping | Request::Status) {
            d.state().last = Instant::now();
        }
        if let Request::Run(spec) = req {
            run::run(&d, &peer, &actor, s, spec);
            return;
        }
        if write_frame(&mut s, &handle(&d, &peer, &actor, req)).is_err() {
            return;
        }
    }
}

fn handle(d: &Arc<Daemon>, peer: &Peer, actor: &Actor, req: Request) -> Response {
    let t = now();
    match req {
        Request::Ping => Response::Pong {
            version: VERSION.into(),
        },
        Request::Unlock { passphrase } => {
            if d.state().vault.is_some() {
                return Response::Ok;
            }
            match vault_open(passphrase.expose()) {
                Ok(v) => {
                    let mut st = d.state();
                    if st.vault.is_none() {
                        st.vault = Some(v);
                        st.load_policy();
                    }
                    let _ = st.audit(rec(actor, "UNLOCK", None, "passphrase", "ALLOW", None));
                    Response::Ok
                }
                Err(e) => e,
            }
        }
        Request::Lock => {
            d.lock_as(actor, "request");
            Response::Ok
        }
        Request::SessionStart {
            passphrase,
            ttl_secs,
            project,
            env,
            scopes,
            command,
            binding,
        } => {
            let scopes = if scopes.is_empty() {
                SCOPES.iter().map(|s| s.to_string()).collect()
            } else {
                scopes
            };
            if ttl_secs == 0 || scopes.iter().any(|s| !SCOPES.contains(&s.as_str())) {
                return err(
                    ErrorCode::BadRequest,
                    "ttl must be > 0 and scopes limited to 'run', 'git', 'http', 'db' and 'aws'",
                );
            }
            // Proof of the human: the passphrase opens the vault (and unlocks it if locked).
            // Run the KDF outside the state lock.
            let opened = vault_open(passphrase.expose());
            let mut st = d.state();
            match opened {
                Ok(v) => {
                    if st.vault.is_none() {
                        st.vault = Some(v);
                        st.load_policy();
                        let _ = st.audit(rec(actor, "UNLOCK", None, "passphrase", "ALLOW", None));
                    }
                }
                Err(e) => {
                    let _ = st.audit(rec(actor, "BLOCKED", None, "bad_passphrase", "DENY", None));
                    return e;
                }
            }
            // An agent must not mint itself a new (longer, wider) lease from inside a session.
            if let Some(l) = st
                .leases
                .find(peer.id, t)
                .filter(|l| l.info(t).state == "active")
            {
                return err(
                    ErrorCode::Denied,
                    format!("already inside session {}; sessions cannot be nested", l.id),
                );
            }
            let target = format!("{project}/{env}");
            let origin = ls_broker::source::detect(peer.id.pid, Some(&command));
            let rule = format!("{}; source {}", scopes.join(","), kind_str(origin.0.kind));
            let l = st
                .leases
                .start(peer.id, ttl_secs, project, env, scopes, command, t);
            let (id, expires_at) = (l.id.clone(), l.expires_at);
            st.leases.pin(&id, binding);
            st.leases.describe(&id, origin, None);
            if let Err(e) = st.audit(rec(
                actor,
                "SESSION_START",
                Some(target),
                &rule,
                "ALLOW",
                Some(id.clone()),
            )) {
                st.leases.revoke(Some(&id), t);
                return err(ErrorCode::Internal, e);
            }
            Response::Session { id, expires_at }
        }
        Request::AgentSessionStart {
            project,
            env,
            scopes,
            ttl_secs,
            command,
            binding,
            agent,
            model,
        } => {
            let mut st = d.state();
            let before = st.leases.active(t);
            let report = (agent.is_some() || model.is_some()).then_some(SelfReport {
                agent,
                model,
                reported: true,
            });
            let r = agent_session_start(
                &mut st, peer.id, actor, project, env, scopes, ttl_secs, command, binding, report,
            );
            // A replaced lease's relays and tokens die with it, as on Revoke.
            let live = st.leases.active(t);
            let gone: Vec<String> = before
                .into_iter()
                .map(|l| l.id)
                .filter(|i| !live.iter().any(|l| &l.id == i))
                .collect();
            if !gone.is_empty() {
                http::prune(d, &st);
                aws::prune(d, &st);
                drop(st);
                db::sweep(d);
                aws::revoke_older(d, &gone);
            }
            r
        }
        Request::SessionEnd => {
            d.state().leases.end(peer.id);
            aws::prune(d, &d.state());
            db::sweep(d);
            Response::Ok
        }
        Request::Status => {
            let st = d.state();
            Response::Status {
                locked: st.vault.is_none(),
                leases: st.leases.with_recent(t, 10),
            }
        }
        Request::Revoke { id } => {
            let mut st = d.state();
            let ids: Vec<String> = st
                .leases
                .active(t)
                .into_iter()
                .map(|l| l.id)
                .filter(|i| id.as_ref().is_none_or(|w| w == i))
                .collect();
            let revoked = ids.clone();
            let count = st.leases.revoke(id.as_deref(), t);
            http::prune(d, &st); // relay tokens die with their lease
            aws::prune(d, &st);
            for i in ids {
                let _ = st.audit(rec(
                    actor,
                    "REVOKE",
                    Some(i.clone()),
                    "user",
                    "ALLOW",
                    Some(i),
                ));
            }
            drop(st);
            // Relayed database connections close now, not at the next watcher tick.
            db::sweep(d);
            aws::revoke_older(d, &revoked);
            Response::Revoked { count }
        }
        Request::AuditList { limit } => match &d.state().vault {
            None => err(ErrorCode::Locked, "vault is locked"),
            Some(v) => match v.audit_list(limit) {
                Ok(e) => Response::Audit {
                    events: e.into_iter().map(event).collect(),
                },
                Err(e) => err(ErrorCode::Internal, e.to_string()),
            },
        },
        Request::AuditVerify => match &d.state().vault {
            None => err(ErrorCode::Locked, "vault is locked"),
            Some(v) => match v.audit_verify(None) {
                Ok(r) => Response::AuditVerify {
                    events: r.events,
                    broken_at: r.broken_at,
                    detail: r.detail,
                },
                Err(e) => err(ErrorCode::Internal, e.to_string()),
            },
        },
        Request::GitCredential {
            host,
            repo,
            binding,
            remotes,
        } => git::credential(d, peer, actor, &host, &repo, binding.as_deref(), &remotes),
        Request::GitInfo => git::info(d),
        Request::DbConnect { name, binding } => {
            db::connect(d, peer, actor, &name, binding.as_deref())
        }
        Request::TokenIssue {
            key,
            provider,
            hosts,
            placement,
            binding,
        } => http::issue(
            d,
            peer,
            actor,
            &key,
            provider.as_deref(),
            &hosts,
            placement.as_deref(),
            binding.as_deref(),
        ),
        Request::TokenList => http::list(d),
        Request::TokenRevoke { token } => http::revoke(d, actor, token.as_deref()),
        Request::HttpInfo => http::info(d),
        Request::AwsInfo => aws::info(d),
        Request::KeyNames { project, env } => match &d.state().vault {
            None => err(ErrorCode::Locked, "vault is locked"),
            Some(v) => match v.list_secrets(Some(&project), Some(&env)) {
                Ok(m) => Response::Keys {
                    keys: m.into_iter().map(|m| m.name).collect(),
                },
                Err(e) => err(ErrorCode::Internal, e.to_string()),
            },
        },
        Request::LeaseKeys => {
            let st = d.state();
            let Some((p, e)) = st
                .leases
                .find(peer.id, t)
                .map(|l| (l.project.clone(), l.env.clone()))
            else {
                return err(ErrorCode::Locked, "no active session for this process");
            };
            match &st.vault {
                None => err(ErrorCode::Locked, "vault is locked"),
                Some(v) => match v.list_secrets(Some(&p), Some(&e)) {
                    Ok(m) => Response::Keys {
                        keys: m.into_iter().map(|m| m.name).collect(),
                    },
                    Err(e) => err(ErrorCode::Internal, e.to_string()),
                },
            }
        }
        Request::SecretPut {
            project,
            env,
            name,
            value,
        } => secret_put(&mut d.state(), actor, &project, &env, &name, value.expose()),
        Request::ScanText { text } => scan::scan_text(d, &text),
        Request::ScanPath { path } => scan::scan_path(d, &path),
        Request::HookAudit {
            agent,
            event,
            decision,
            rule,
            target,
        } => scan::hook_audit(d, actor, &agent, &event, &decision, &rule, &target),
        Request::Run(_) | Request::Signal { .. } => {
            err(ErrorCode::BadRequest, "unexpected request")
        }
    }
}

/// Idle timeout and sleep detection. Wall-clock time advances across a sleep but the monotonic
/// clock does not, so a gap of more than 5 s between them means the machine slept.
fn watch(d: Arc<Daemon>) {
    let (mut wall, mut mono) = (SystemTime::now(), Instant::now());
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let (w, m) = (SystemTime::now(), Instant::now());
        let drift = w
            .duration_since(wall)
            .unwrap_or_default()
            .saturating_sub(m - mono);
        (wall, mono) = (w, m);
        db::sweep(&d); // leases that expired

        if drift > Duration::from_secs(5) {
            d.lock_now("sleep");
        } else if let Some(t) = d.idle {
            let st = d.state();
            if st.vault.is_some() && st.last.elapsed() >= t {
                drop(st);
                d.lock_now("idle");
            }
        }
    }
}

/// Git forwarder on a random loopback port (M5 D1). Failure is reported, not fatal: everything
/// else the daemon does still works, and Git through the forwarder fails closed.
fn start_git_forwarder(d: &Arc<Daemon>) {
    let l = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) => return eprintln!("locksmithd: Git forwarder unavailable ({e})"),
    };
    let Ok(port) = l.local_addr().map(|a| a.port()) else {
        return;
    };
    let _ = d.git.port.set(port);
    if let Err(e) = git::write_include(port) {
        eprintln!("locksmithd: cannot write the Git include file ({e})");
    }
    let gate = Arc::new(git::Gate(d.clone()));
    let up = Arc::new(git::upstream());
    std::thread::spawn(move || ls_proxy::forward::serve(l, gate, up));
}

/// HTTP relay on a random loopback port (M6). Like the Git forwarder, failure is reported,
/// not fatal; relayed requests then fail closed.
fn start_http_relay(d: &Arc<Daemon>) {
    let l = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) => return eprintln!("locksmithd: HTTP relay unavailable ({e})"),
    };
    let Ok(port) = l.local_addr().map(|a| a.port()) else {
        return;
    };
    let _ = d.http.port.set(port);
    let auth = Arc::new(http::Relay(d.clone()));
    let up = Arc::new(http::upstream());
    std::thread::spawn(move || ls_proxy::http::serve(l, auth, up));
}

/// SigV4 re-signing relay on its own random loopback port (M7).
fn start_aws_relay(d: &Arc<Daemon>) {
    let l = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) => return eprintln!("locksmithd: AWS relay unavailable ({e})"),
    };
    let Ok(port) = l.local_addr().map(|a| a.port()) else {
        return;
    };
    let _ = d.aws.port.set(port);
    let auth = Arc::new(aws::Relay(d.clone()));
    let up = Arc::new(aws::upstream());
    std::thread::spawn(move || ls_proxy::aws::relay::serve(l, auth, up));
}

fn die(msg: String) -> ! {
    eprintln!("locksmithd: {msg}");
    std::process::exit(1);
}

fn main() {
    let _ = ls_platform::disable_core_dumps();
    ls_platform::proc::deny_debugger_attach();

    let dir = ls_ipc::runtime_dir();
    if let Err(e) = ls_core::ensure_private_dir(&dir) {
        die(format!("cannot create {}: {e}", dir.display()));
    }
    if !ls_core::is_private_dir(&dir).unwrap_or(false) {
        die(format!("{} is not private (0700)", dir.display()));
    }
    let sock = ls_ipc::socket_path();
    if sock.as_os_str().len() > MAX_SOCKET_PATH {
        die(format!(
            "socket path is {} bytes (max {MAX_SOCKET_PATH}); set LOCKSMITH_RUNTIME_DIR to a shorter directory",
            sock.as_os_str().len()
        ));
    }

    let mut lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join(LOCK_FILE))
        .unwrap_or_else(|e| die(format!("cannot open lock file: {e}")));
    if lock.try_lock().is_err() {
        let mut pid = String::new();
        let _ = lock.read_to_string(&mut pid);
        die(format!(
            "already running (pid {}, socket {})",
            pid.trim(),
            sock.display()
        ));
    }
    let _ = lock.set_len(0);
    let _ = write!(lock, "{}", std::process::id());

    let _ = std::fs::remove_file(&sock); // stale: we hold the lock, so no live daemon owns it
    let listener = UnixListener::bind(&sock)
        .unwrap_or_else(|e| die(format!("cannot bind {}: {e}", sock.display())));
    if let Err(e) = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)) {
        die(format!("cannot chmod socket: {e}"));
    }

    let idle = std::env::var("LOCKSMITH_IDLE_LOCK_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1800);
    let me = Actor {
        pid: std::process::id(),
        start: id_of(std::process::id()).map_or(0, |i: ProcId| i.start),
        exe: std::env::current_exe()
            .map_or_else(|_| "locksmithd".into(), |p| p.display().to_string()),
        exe_hash: String::new(),
    };
    let d = Arc::new(Daemon {
        st: Mutex::new(State {
            vault: None,
            leases: Leases::default(),
            last: Instant::now(),
            pending: Vec::new(),
            agent_policy: None,
        }),
        manifest: Manifest::beside_current_exe(),
        idle: (idle > 0).then(|| Duration::from_secs(idle)),
        me,
        git: git::Git::default(),
        db: db::Db::default(),
        http: http::Http::default(),
        aws: aws::Aws::default(),
    });
    start_git_forwarder(&d);
    start_http_relay(&d);
    start_aws_relay(&d);
    let w = d.clone();
    std::thread::spawn(move || watch(w));
    let s = d.clone();
    if let Err(e) = ls_platform::screen::watch(move |r| s.lock_now(r)) {
        eprintln!(
            "locksmithd: screen-lock watcher unavailable ({e}); idle and sleep auto-lock still apply"
        );
    }
    for conn in listener.incoming().flatten() {
        let d = d.clone();
        std::thread::spawn(move || serve(d, conn));
    }
    drop(lock);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ls_ipc::Passphrase;

    fn every_request() -> Vec<Request> {
        let s = || String::from("x");
        let pw = || Passphrase::new(b"pw".to_vec());
        vec![
            Request::Ping,
            Request::Unlock { passphrase: pw() },
            Request::Lock,
            Request::SessionStart {
                passphrase: pw(),
                ttl_secs: 1,
                project: s(),
                env: s(),
                scopes: vec![],
                command: s(),
                binding: None,
            },
            Request::AgentSessionStart {
                project: s(),
                env: s(),
                scopes: vec![],
                ttl_secs: 1,
                command: s(),
                binding: None,
                agent: None,
                model: None,
            },
            Request::SessionEnd,
            Request::Status,
            Request::Revoke { id: None },
            Request::Run(ls_ipc::RunSpec {
                project: None,
                env: None,
                keys: vec![],
                all_keys: false,
                binding: None,
                cmd: vec![],
                cwd: "/".into(),
                environ: vec![],
                gh: None,
                aws: None,
                aws_contained: false,
            }),
            Request::Signal { sig: 2 },
            Request::AuditList { limit: 1 },
            Request::AuditVerify,
            Request::ScanText { text: s() },
            Request::ScanPath { path: "/x".into() },
            Request::GitCredential {
                host: s(),
                repo: s(),
                binding: None,
                remotes: vec![],
            },
            Request::GitInfo,
            Request::DbConnect {
                name: s(),
                binding: None,
            },
            Request::KeyNames {
                project: s(),
                env: s(),
            },
            Request::TokenIssue {
                key: s(),
                provider: None,
                hosts: vec![],
                placement: None,
                binding: None,
            },
            Request::LeaseKeys,
            Request::TokenList,
            Request::TokenRevoke { token: None },
            Request::HttpInfo,
            Request::AwsInfo,
            Request::HookAudit {
                agent: s(),
                event: s(),
                decision: s(),
                rule: s(),
                target: s(),
            },
            Request::SecretPut {
                project: s(),
                env: s(),
                name: s(),
                value: pw(),
            },
        ]
    }

    /// Exhaustive: a new request variant fails to compile here until it is classified.
    fn name(r: &Request) -> &'static str {
        match r {
            Request::Ping => "Ping",
            Request::Unlock { .. } => "Unlock",
            Request::Lock => "Lock",
            Request::SessionStart { .. } => "SessionStart",
            Request::AgentSessionStart { .. } => "AgentSessionStart",
            Request::SessionEnd => "SessionEnd",
            Request::Status => "Status",
            Request::Revoke { .. } => "Revoke",
            Request::Run(_) => "Run",
            Request::Signal { .. } => "Signal",
            Request::AuditList { .. } => "AuditList",
            Request::AuditVerify => "AuditVerify",
            Request::ScanText { .. } => "ScanText",
            Request::ScanPath { .. } => "ScanPath",
            Request::GitCredential { .. } => "GitCredential",
            Request::GitInfo => "GitInfo",
            Request::DbConnect { .. } => "DbConnect",
            Request::KeyNames { .. } => "KeyNames",
            Request::LeaseKeys => "LeaseKeys",
            Request::TokenIssue { .. } => "TokenIssue",
            Request::TokenList => "TokenList",
            Request::TokenRevoke { .. } => "TokenRevoke",
            Request::HttpInfo => "HttpInfo",
            Request::AwsInfo => "AwsInfo",
            Request::HookAudit { .. } => "HookAudit",
            Request::SecretPut { .. } => "SecretPut",
        }
    }

    #[test]
    fn role_allowlists() {
        const DESKTOP: &[&str] = &[
            "Ping",
            "Unlock",
            "Lock",
            "Status",
            "Revoke",
            "AuditList",
            "AuditVerify",
            "KeyNames",
            "TokenList",
            "TokenRevoke",
            "GitInfo",
            "HttpInfo",
            "AwsInfo",
            "SecretPut",
        ];
        for r in every_request() {
            let n = name(&r);
            assert_eq!(
                allowed(Role::Desktop, &r),
                DESKTOP.contains(&n),
                "desktop {n}"
            );
            assert_eq!(
                allowed(Role::Smith, &r),
                n != "SecretPut" && n != "AgentSessionStart",
                "smith {n}"
            );
            assert_eq!(
                allowed(Role::Mcp, &r),
                [
                    "Ping",
                    "Status",
                    "LeaseKeys",
                    "TokenIssue",
                    "AgentSessionStart"
                ]
                .contains(&n),
                "mcp {n}"
            );
            assert_eq!(allowed(Role::Unknown, &r), n == "Ping", "unknown {n}");
        }
    }

    struct Tmp(std::path::PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn secret_put_stores_value_and_audits_only_the_target() {
        let tmp = Tmp(std::env::temp_dir().join(format!("lsd-put-{}", std::process::id())));
        let _ = std::fs::remove_dir_all(&tmp.0);
        let weak = ls_crypto::kdf::KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
        };
        let phrase = ls_crypto::recovery::RecoveryPhrase::generate().unwrap();
        let mut v = Vault::create(&tmp.0.join("vault"), b"pw", weak, true, &phrase).unwrap();
        v.add_project("p").unwrap();
        v.add_env("p", "dev").unwrap();
        let mut st = State {
            vault: None,
            leases: Leases::default(),
            last: Instant::now(),
            pending: Vec::new(),
            agent_policy: None,
        };
        let a = Actor {
            pid: 1,
            start: 1,
            exe: "/Applications/Locksmith.app/locksmith-desktop".into(),
            exe_hash: String::new(),
        };
        const VALUE: &[u8] = b"sk_live_desktop_typed_9876";
        let locked = secret_put(&mut st, &a, "p", "dev", "K", VALUE);
        assert!(matches!(
            locked,
            Response::Error {
                code: ErrorCode::Locked,
                ..
            }
        ));

        st.vault = Some(v);
        assert_eq!(
            secret_put(&mut st, &a, "p", "dev", "K", VALUE),
            Response::Ok
        );
        assert_eq!(
            secret_put(&mut st, &a, "p", "dev", "K", b"v2"),
            Response::Ok
        );
        let bad = secret_put(&mut st, &a, "p", "dev", "bad name", VALUE);
        assert!(matches!(
            bad,
            Response::Error {
                code: ErrorCode::BadRequest,
                ..
            }
        ));
        let missing = secret_put(&mut st, &a, "p", "nope", "K", VALUE);
        assert!(matches!(
            missing,
            Response::Error {
                code: ErrorCode::NotFound,
                ..
            }
        ));

        let v = st.vault.as_ref().unwrap();
        assert_eq!(v.get_secret("p", "dev", "K").unwrap().expose(), b"v2");
        let events = v.audit_list(100).unwrap();
        let puts: Vec<_> = events
            .iter()
            .filter(|e| e.record.action == "SECRET_PUT")
            .collect();
        assert_eq!(puts.len(), 2);
        assert_eq!(puts[0].record.target.as_deref(), Some("p/dev/K"));
        assert_eq!(puts[1].record.policy_rule, "desktop v2");
        let text = format!("{:?}", events.iter().map(|e| &e.record).collect::<Vec<_>>());
        assert!(!text.contains("sk_live_desktop_typed"));
    }

    #[test]
    fn agent_session_start_grants_only_inside_policy() {
        let tmp = Tmp(std::env::temp_dir().join(format!("lsd-agent-{}", std::process::id())));
        let _ = std::fs::remove_dir_all(&tmp.0);
        let weak = ls_crypto::kdf::KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
        };
        let phrase = ls_crypto::recovery::RecoveryPhrase::generate().unwrap();
        let v = Vault::create(&tmp.0.join("vault"), b"pw", weak, true, &phrase).unwrap();
        let mut st = State {
            vault: None,
            leases: Leases::default(),
            last: Instant::now(),
            pending: Vec::new(),
            agent_policy: None,
        };
        let a = Actor {
            pid: 1,
            start: 1,
            exe: "locksmith-mcp".into(),
            exe_hash: String::new(),
        };
        // `sh` is the agent, with two children: the MCP server (the caller) and a shell command.
        use std::io::BufRead;
        let mut agent = std::process::Command::new("sh")
            .args(["-c", "sleep 30 & echo $!; sleep 30 & echo $!; wait"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = std::io::BufReader::new(agent.stdout.take().unwrap()).lines();
        let mut kid = || id_of(out.next().unwrap().unwrap().trim().parse().unwrap()).unwrap();
        let (mcp, shell) = (kid(), kid());
        let root = id_of(agent.id()).unwrap();
        let me = id_of(std::process::id()).unwrap();
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let report = |agent: &str, model: &str| SelfReport {
            agent: Some(agent.into()),
            model: Some(model.into()),
            reported: true,
        };
        let ask_with = |st: &mut State, caller, env: &str, scopes: &[&str], ttl, r| {
            agent_session_start(
                st,
                caller,
                &a,
                "app".into(),
                env.into(),
                s(scopes),
                ttl,
                "agent".into(),
                None,
                Some(r),
            )
        };
        let ask_as = |st: &mut State, caller, env: &str, scopes: &[&str], ttl| {
            ask_with(
                st,
                caller,
                env,
                scopes,
                ttl,
                report("claude-code", "claude-fable-5-2"),
            )
        };
        let ask =
            |st: &mut State, env: &str, scopes: &[&str], ttl| ask_as(st, mcp, env, scopes, ttl);
        let code = |r: &Response| match r {
            Response::Error { code, .. } => Some(*code),
            _ => None,
        };

        // M10d: self-reported fields are validated first (BadRequest even while locked).
        for (ag, mo) in [
            ("x".repeat(65), "m".to_string()),
            ("claude-code".into(), "model\n".into()),
            ("claude\u{1b}[2J".into(), "m".into()),
            ("café".into(), "m".into()),
            (String::new(), "m".into()),
        ] {
            assert_eq!(
                code(&ask_with(
                    &mut st,
                    mcp,
                    "dev",
                    &["http"],
                    60,
                    report(&ag, &mo)
                )),
                Some(ErrorCode::BadRequest),
                "{ag:?} {mo:?}"
            );
        }

        assert_eq!(
            code(&ask(&mut st, "dev", &["http"], 60)),
            Some(ErrorCode::Locked)
        );
        st.vault = Some(v);
        assert_eq!(
            code(&ask(&mut st, "dev", &[], 60)),
            Some(ErrorCode::BadRequest)
        );
        assert_eq!(
            code(&ask(&mut st, "dev", &["http"], 0)),
            Some(ErrorCode::BadRequest)
        );
        // Unlocked but no policy file: refused.
        st.agent_policy = Some(Err("no agent policy".into()));
        assert_eq!(
            code(&ask(&mut st, "dev", &["http"], 60)),
            Some(ErrorCode::Denied)
        );

        st.agent_policy = Some(Ok(policy::Policy {
            max_ttl_secs: 600,
            scopes: s(&["http"]),
            relay: Default::default(),
            projects: [(
                "app".to_string(),
                policy::Project {
                    envs: s(&["dev"]),
                    inject: s(&["OK"]),
                    ..Default::default()
                },
            )]
            .into(),
        }));
        for (env, scopes, ttl) in [
            ("prod", &["http"][..], 60),
            ("dev", &["run"], 60),
            ("dev", &["http"], 601),
        ] {
            assert_eq!(
                code(&ask(&mut st, env, scopes, ttl)),
                Some(ErrorCode::Denied),
                "{env} {scopes:?} {ttl}"
            );
        }
        assert!(st.leases.active(now()).is_empty(), "no lease on denial");

        // A caller whose parent cannot be identified (it has exited): refused and audited.
        let (mut c, gone) = {
            let c = std::process::Command::new("true").spawn().unwrap();
            let id = id_of(c.id()).unwrap();
            (c, id)
        };
        c.wait().unwrap();
        assert_eq!(
            code(&ask_as(&mut st, gone, "dev", &["http"], 60)),
            Some(ErrorCode::Denied)
        );
        assert!(st.leases.active(now()).is_empty(), "no lease on denial");

        let Response::Session { id, .. } = ask(&mut st, "dev", &["http"], 600) else {
            panic!("in-policy request not granted")
        };
        // Rooted at the agent: its shell commands and the MCP server are in, the terminal is not.
        for p in [shell, mcp, root] {
            let l = st.leases.find(p, now()).unwrap();
            assert_eq!(
                (l.id.as_str(), l.root, l.project.as_str(), l.env.as_str()),
                (id.as_str(), root, "app", "dev")
            );
        }
        assert!(st.leases.find(me, now()).is_none(), "the agent's parent");
        // M10e D1: the lease carries the policy's inject list (names only) for run and status.
        let l = st.leases.find(root, now()).unwrap();
        assert_eq!(l.inject, Some(s(&["OK"])));
        assert_eq!(l.info(now()).inject, Some(s(&["OK"])));

        // A second start from the same agent replaces the first; policy still applies to it.
        assert_eq!(
            code(&ask(&mut st, "prod", &["http"], 60)),
            Some(ErrorCode::Denied)
        );
        let Response::Session { id: id2, .. } = ask(&mut st, "dev", &["http"], 300) else {
            panic!("replacement not granted")
        };
        assert_ne!(id, id2);
        let active = st.leases.active(now());
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, id2);
        let i = &active[0];
        assert_eq!(i.started_by, ls_ipc::StartedBy::Agent);
        assert_eq!(i.source.kind, ls_ipc::SourceKind::Other);
        // `sh` may be dash or bash on Linux: the label is whatever the kernel names.
        assert_eq!(
            Some(i.source.label.as_str()),
            std::path::Path::new(&i.root_exe)
                .file_name()
                .and_then(|f| f.to_str())
        );
        assert_eq!(i.report, Some(report("claude-code", "claude-fable-5-2")));

        // Nesting: the agent inside a human-started lease, or a same-root human lease, refuses.
        st.leases.revoke(None, now());
        st.leases.start(
            me,
            60,
            "app".into(),
            "dev".into(),
            s(&["http"]),
            "human".into(),
            now(),
        );
        assert_eq!(
            code(&ask(&mut st, "dev", &["http"], 60)),
            Some(ErrorCode::Denied),
            "no nesting under a human lease"
        );
        st.leases.revoke(None, now());
        st.leases.start(
            root,
            60,
            "app".into(),
            "dev".into(),
            s(&["http"]),
            "human".into(),
            now(),
        );
        assert_eq!(
            code(&ask(&mut st, "dev", &["http"], 60)),
            Some(ErrorCode::Denied),
            "a human lease is never replaced by the agent"
        );

        let ev = st.vault.as_ref().unwrap().audit_list(100).unwrap();
        let rows: Vec<_> = ev
            .iter()
            .map(|e| (e.record.action.as_str(), e.record.decision.as_str()))
            .collect();
        let n = |r: (&str, &str)| rows.iter().filter(|x| **x == r).count();
        assert_eq!(n(("BLOCKED", "DENY")), 6, "4 policy, 1 agent_root, 1 prod");
        assert_eq!(n(("SESSION_START", "ALLOW")), 2);
        assert_eq!(n(("REVOKE", "ALLOW")), 1);
        let rule = |a: &str| {
            ev.iter()
                .filter(|e| e.record.action == a)
                .map(|e| e.record.policy_rule.clone())
                .collect::<Vec<_>>()
        };
        assert!(rule("SESSION_START")[0].contains(&format!("root pid {} (", root.pid)));
        assert!(
            !rule("SESSION_START")[0].contains("(?)"),
            "exe name resolved"
        );
        // `sh` is not in the agent table: honest `other`, and the report as the agent gave it.
        assert!(
            rule("SESSION_START")[0].ends_with(
                "; source other; reported agent=\"claude-code\" model=\"claude-fable-5-2\""
            ),
            "{}",
            rule("SESSION_START")[0]
        );
        assert_eq!(
            rule("REVOKE")[0],
            format!("replaced by agent session {id2}")
        );
        assert!(
            rule("BLOCKED")
                .iter()
                .any(|r| r.starts_with("agent_root: "))
        );

        for p in [mcp, shell] {
            let _ = std::process::Command::new("kill")
                .arg(p.pid.to_string())
                .status();
        }
        agent.wait().unwrap();
    }
}
