//! M6 database relay glue (design D5, D7): one loopback [`Relay`] per lease and `[db.<name>]`
//! target, the per-connection admission check (every process holding the client socket must be
//! inside that lease's session tree), and teardown when the lease stops being active. The
//! password is read from the vault per accepted connection and only goes to the upstream leg.

use crate::{Actor, Daemon, deny_response, deny_rule, err, now, rec};
use ls_ipc::{ErrorCode, Response};
use ls_platform::proc::{Peer, ProcId};
use ls_proxy::db::{Creds, Gate as DbGate, Kind, Relay, Settings, Target, TlsMode};
use ls_redact::binding::{Binding, DbTarget};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[derive(Default)]
pub struct Db {
    relays: Mutex<Vec<Arc<Relay>>>,
}

impl Db {
    fn relays(&self) -> std::sync::MutexGuard<'_, Vec<Arc<Relay>>> {
        self.relays.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Test switch for a test CA (PEM file) trusted for upstream TLS, debug builds only.
fn settings() -> Settings {
    #[cfg(debug_assertions)]
    if let Ok(p) = std::env::var("LOCKSMITH_TEST_DB_CA")
        && let Ok(pem) = std::fs::read(p)
    {
        return Settings::with_test_roots(&pem);
    }
    Settings::default()
}

/// `[db.<name>]` to a relay target (validated).
pub fn target(name: &str, t: &DbTarget) -> Result<Target, String> {
    t.check()?;
    let kind = Kind::parse(&t.kind).ok_or("bad kind")?;
    Ok(Target {
        name: name.into(),
        kind,
        host: t.host.trim().to_string(),
        port: t.port.unwrap_or(kind.default_port()),
        user: t.user.clone().unwrap_or_default(),
        database: t.database.clone().filter(|d| !d.is_empty()),
        tls: t
            .tls
            .as_deref()
            .and_then(TlsMode::parse)
            .unwrap_or(TlsMode::default_for(kind, t.host.trim())),
    })
}

fn endpoint(r: &Relay) -> Response {
    Response::DbEndpoint {
        kind: r.target.kind.as_str().into(),
        port: r.addr().port(),
        user: r.target.user.clone(),
        database: r.target.database.clone(),
    }
}

/// `Request::DbConnect`: open or reuse this lease's relay for `name`.
pub fn connect(
    d: &Arc<Daemon>,
    peer: &Peer,
    actor: &Actor,
    name: &str,
    binding: Option<&[u8]>,
) -> Response {
    // The target comes from the binding pinned at session start: an agent that edits
    // `.locksmith.toml` must not point the relay (and the password) at a server it runs (gate A3).
    let same = |c: &Binding, p: &Binding| {
        (&c.project, &c.env, c.db.get(name)) == (&p.project, &p.env, p.db.get(name))
    };
    let b = match crate::effective_binding(
        &mut d.state(),
        peer,
        actor,
        &format!("db:{name}"),
        binding,
        same,
    ) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(cfg) = b.db.get(name) else {
        return err(
            ErrorCode::NotFound,
            format!("no [db.{name}] in .locksmith.toml"),
        );
    };
    let t = match target(name, cfg) {
        Ok(t) => t,
        Err(e) => return err(ErrorCode::BadRequest, format!("[db.{name}]: {e}")),
    };
    let project = b.project.clone().unwrap_or("default".into());
    let env = b.env.clone().unwrap_or("development".into());
    let tgt = format!("db:{name}");
    let mut st = d.state();
    let lease = match st.leases.authorize(peer.id, "db", &project, &env, now()) {
        Ok(l) => l.id.clone(),
        Err(den) => {
            let _ = st.audit(rec(
                actor,
                "BLOCKED",
                Some(tgt),
                &deny_rule(&den),
                "DENY",
                None,
            ));
            return deny_response(&den);
        }
    };
    // Fail early on a missing key (names only; values are read per connection).
    if let Some(v) = &st.vault {
        let have: Vec<String> = v
            .list_secrets(Some(&project), Some(&env))
            .map(|m| m.into_iter().map(|m| m.name).collect())
            .unwrap_or_default();
        if let Some(k) = cfg.keys().into_iter().find(|k| !have.contains(k)) {
            return err(
                ErrorCode::NotFound,
                format!("vault key {k} for [db.{name}] is missing in {project}/{env}"),
            );
        }
    }
    drop(st);
    let mut relays = d.db.relays();
    relays.retain(|r| !r.is_closed());
    if let Some(r) = relays.iter().find(|r| r.lease == lease && r.target == t) {
        return endpoint(r);
    }
    let gate = Arc::new(Gate {
        d: d.clone(),
        name: name.into(),
        lease: lease.clone(),
        project,
        env,
        password_key: cfg.password_key.clone(),
        cert_key: cfg.client_cert_key.clone(),
        key_key: cfg.client_key_key.clone(),
    });
    match Relay::start(t, lease, gate, settings()) {
        Ok(r) => {
            let resp = endpoint(&r);
            relays.push(r);
            resp
        }
        Err(e) => err(
            ErrorCode::Internal,
            format!("cannot open a local listener: {e}"),
        ),
    }
}

/// Close every relay whose lease is no longer active (revoked, ended or expired). Called on
/// revoke and session end, and once a second by the watcher for expiry.
pub fn sweep(d: &Daemon) {
    let live: Vec<String> = d
        .state()
        .leases
        .active(now())
        .into_iter()
        .map(|l| l.id)
        .collect();
    let dead: Vec<Arc<Relay>> = {
        let mut r = d.db.relays();
        let (dead, keep) = r.drain(..).partition(|r| !live.contains(&r.lease));
        *r = keep;
        dead
    };
    for r in dead {
        r.close();
    }
}

/// The relay's view of the daemon, one per relay.
struct Gate {
    d: Arc<Daemon>,
    name: String,
    lease: String,
    project: String,
    env: String,
    password_key: Option<String>,
    cert_key: Option<String>,
    key_key: Option<String>,
}

fn tcp_actor(p: ProcId) -> Actor {
    Actor {
        pid: p.pid,
        start: p.start,
        exe: "(database client over loopback TCP)".into(),
        exe_hash: String::new(),
    }
}

impl DbGate for Gate {
    fn admit(&self, client: SocketAddr, server: SocketAddr) -> Result<Creds, String> {
        let d = &self.d;
        let target = format!("db:{}", self.name);
        let owners = ls_platform::net::tcp_peer_owners(client, server);
        let mut st = d.state();
        let t = now();
        let lease = Some(self.lease.clone());
        let block = |st: &mut crate::State, a: &Actor, rule: &str| {
            let _ = st.audit(rec(
                a,
                "BLOCKED",
                Some(target.clone()),
                rule,
                "DENY",
                lease.clone(),
            ));
        };
        let owners = match owners {
            Ok(o) if !o.is_empty() => o,
            _ => {
                block(&mut st, &d.me, "db_peer_unknown");
                return Err("could not identify the process using the relay".into());
            }
        };
        // Every process holding the client socket must be inside this relay's live session.
        for o in &owners {
            match st.leases.authorize(*o, "db", &self.project, &self.env, t) {
                Ok(l) if l.id == self.lease => {}
                Ok(_) => {
                    block(&mut st, &tcp_actor(*o), "db_other_session");
                    return Err("this relay belongs to another session".into());
                }
                Err(den) => {
                    block(&mut st, &tcp_actor(*o), &deny_rule(&den));
                    return Err(format!("refused: {den}"));
                }
            }
        }
        let actor = tcp_actor(owners[0]);
        let got = st.vault.as_ref().map(|v| {
            let read = |k: &Option<String>| -> Result<Option<Zeroizing<Vec<u8>>>, String> {
                match k {
                    None => Ok(None),
                    Some(k) => v
                        .get_secret(&self.project, &self.env, k)
                        .map(|s| Some(Zeroizing::new(s.expose().to_vec())))
                        .map_err(|_| k.clone()),
                }
            };
            Ok::<_, String>((
                read(&self.password_key)?,
                read(&self.cert_key)?,
                read(&self.key_key)?,
            ))
        });
        let (password, client_cert, client_key) = match got {
            None => {
                block(&mut st, &actor, "vault_locked");
                return Err("the vault is locked".into());
            }
            Some(Err(k)) => {
                block(&mut st, &actor, "db_credential_missing");
                return Err(format!(
                    "vault key {k} is missing in {}/{}",
                    self.project, self.env
                ));
            }
            Some(Ok(x)) => x,
        };
        let label = self.password_key.clone().unwrap_or("DB_PASSWORD".into());
        st.audit(rec(
            &actor,
            "ACCESS",
            Some(format!("{}/{}/{label}", self.project, self.env)),
            &target,
            "ALLOW",
            Some(self.lease.clone()),
        ))
        .map_err(|_| "audit failed".to_string())?;
        Ok(Creds {
            label,
            password: password.unwrap_or_default(),
            client_cert,
            client_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ls_redact::binding::parse;

    #[test]
    fn target_defaults() {
        let b = parse(
            b"[db.a]\nkind=\"postgres\"\nhost=\"db.example.com\"\nuser=\"u\"\npassword_key=\"K\"\n[db.b]\nkind=\"redis\"\nhost=\"localhost\"\ntls=\"require\"\nport=7000\n",
        )
        .unwrap();
        let a = target("a", &b.db["a"]).unwrap();
        assert_eq!((a.port, a.tls), (5432, TlsMode::Require));
        let r = target("b", &b.db["b"]).unwrap();
        assert_eq!(
            (r.port, r.tls, r.user.as_str()),
            (7000, TlsMode::Require, "")
        );
        let mut bad = b.db["a"].clone();
        bad.kind = "oracle".into();
        assert!(target("a", &bad).is_err());
    }
}
