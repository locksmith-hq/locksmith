//! M7 AWS delegation glue: per-run dummy credentials bound to a lease (design D2), the
//! [`AwsAuthority`] the SigV4 relay consults (peer-to-PID, lease, policy audit), and upstream
//! credentials: the stored keys, or STS credentials for the profile's role (cached until 5
//! minutes before expiry). Real credentials are read from the vault per request and only reach
//! the relay's re-signing step.

use crate::{Actor, Daemon, State, deny_rule, err, now, rec};
use ls_ipc::{ErrorCode, Response};
use ls_platform::proc::{Peer, ProcId};
use ls_proxy::Deny;
use ls_proxy::aws::{AwsAuthority, AwsSession, Call, Credentials, policy::Policy, sts};
use ls_redact::binding::{AwsProfile, Binding};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::Zeroizing;

/// Dummy key ids look like real ones (20 chars, `AKIA` prefix) so SDKs accept them.
const AKID_PREFIX: &str = "AKIALOCKSMITH";

/// What a dummy access key may do. Memory only; dies with its lease.
struct Dummy {
    lease: String,
    project: String,
    env: String,
    profile: AwsProfile,
    policy: Policy,
    secret: Zeroizing<String>,
}

/// Cached STS credentials for a role (owned parts; `Credentials` is not Clone on purpose).
struct RoleCreds {
    akid: String,
    secret: Zeroizing<String>,
    token: Option<Zeroizing<String>>,
    expiry: i64,
}

/// Child environment entries (name, value).
type EnvVars = Vec<(String, Vec<u8>)>;

/// A role that handed out contained credentials under a lease (for revoke-older-sessions).
struct Issued {
    lease: String,
    project: String,
    env: String,
    profile: AwsProfile,
}

#[derive(Default)]
pub struct Aws {
    dummies: Mutex<HashMap<String, Dummy>>,
    issued: Mutex<Vec<Issued>>,
    roles: Mutex<HashMap<(String, String), RoleCreds>>,
    actors: Mutex<HashMap<String, Actor>>,
    pub port: OnceLock<u16>,
}

/// Test switch, debug builds only: plain-HTTP upstreams (`host=addr[,…]`).
pub fn upstream() -> ls_proxy::http::Upstream {
    #[cfg(debug_assertions)]
    if let Ok(v) = std::env::var("LOCKSMITH_TEST_AWS_UPSTREAM") {
        return ls_proxy::http::Upstream::parse(&v);
    }
    ls_proxy::http::Upstream::default()
}

/// Test switch, debug builds only: the STS endpoint for AssumeRole.
fn sts_endpoint() -> Option<String> {
    #[cfg(debug_assertions)]
    if let Ok(v) = std::env::var("LOCKSMITH_TEST_STS_ENDPOINT") {
        return Some(v);
    }
    None
}

fn random(n: usize, alphabet: &[u8]) -> String {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("OS RNG");
    b.iter()
        .map(|x| alphabet[*x as usize % alphabet.len()] as char)
        .collect()
}

/// Drop dummy keys and role credentials whose lease is no longer active.
pub fn prune(d: &Daemon, st: &State) {
    let live: Vec<String> = st.leases.active(now()).into_iter().map(|l| l.id).collect();
    d.aws
        .dummies
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|_, t| live.contains(&t.lease));
    d.aws
        .roles
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(l, _), _| live.contains(l));
}

/// `[aws.policy]` as the relay's policy type (absent: the read-only default).
pub fn policy_of(b: &Binding) -> Result<Policy, String> {
    match &b.aws.policy {
        None => Ok(Policy::default()),
        Some(t) => toml::Value::Table(t.clone())
            .try_into::<Policy>()
            .map_err(|e| format!("[aws.policy]: {e}")),
    }
}

/// `smith run --aws <profile>`: mint dummy credentials under `lease` (scope `aws`) and return
/// the child's AWS environment. The caller redacts the dummy secret like any value.
#[allow(clippy::too_many_arguments)]
pub fn for_run(
    d: &Daemon,
    st: &mut State,
    peer: &Peer,
    actor: &Actor,
    lease: &str,
    project: &str,
    env: &str,
    b: Option<&Binding>,
    profile: &str,
) -> Result<Vec<(String, Vec<u8>)>, Response> {
    let target = format!("{project}/{env}/aws:{profile}");
    if let Err(den) = st.leases.authorize(peer.id, "aws", project, env, now()) {
        let _ = st.audit(rec(
            actor,
            "BLOCKED",
            Some(target),
            &deny_rule(&den),
            "DENY",
            Some(lease.to_string()),
        ));
        return Err(err(
            ErrorCode::Denied,
            format!("--aws needs the session's `aws` scope: {den}"),
        ));
    }
    let Some(b) = b else {
        return Err(err(
            ErrorCode::BadRequest,
            "--aws needs a .locksmith.toml with [aws.profiles.<name>]",
        ));
    };
    let Some(p) = b.aws.profiles.get(profile).cloned() else {
        return Err(err(
            ErrorCode::BadRequest,
            format!("no [aws.profiles.{profile}] in .locksmith.toml"),
        ));
    };
    let policy = policy_of(b).map_err(|e| err(ErrorCode::BadRequest, e))?;
    let Some(v) = &st.vault else {
        return Err(err(ErrorCode::Locked, "vault is locked"));
    };
    let names = v
        .list_secrets(Some(project), Some(env))
        .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
    if !names.iter().any(|m| m.name == p.key) {
        return Err(err(
            ErrorCode::NotFound,
            format!(
                "vault key {} for [aws.profiles.{profile}] is missing in {project}/{env}",
                p.key
            ),
        ));
    }
    let Some(&port) = d.aws.port.get() else {
        return Err(err(ErrorCode::Internal, "AWS relay is not running"));
    };
    let akid = format!(
        "{AKID_PREFIX}{}",
        random(20 - AKID_PREFIX.len(), b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    );
    let secret = Zeroizing::new(random(
        40,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    ));
    st.audit(rec(
        actor,
        "AWS_ISSUE",
        Some(target),
        &format!("dummy:{akid}"),
        "ALLOW",
        Some(lease.to_string()),
    ))
    .map_err(|e| err(ErrorCode::Internal, e))?;
    let vars = vec![
        ("AWS_ACCESS_KEY_ID".to_string(), akid.clone().into_bytes()),
        ("AWS_SECRET_ACCESS_KEY".into(), secret.as_bytes().to_vec()),
        ("AWS_REGION".into(), p.region.clone().into_bytes()),
        ("AWS_DEFAULT_REGION".into(), p.region.clone().into_bytes()),
        (
            "AWS_ENDPOINT_URL".into(),
            format!("http://127.0.0.1:{port}").into_bytes(),
        ),
        // Nothing else may supply credentials: no instance metadata, no session token.
        ("AWS_EC2_METADATA_DISABLED".into(), b"true".to_vec()),
        ("AWS_SESSION_TOKEN".into(), Vec::new()),
        // Newer SDKs/CLI (2.23+) otherwise add flexible checksums, which over a plain-HTTP
        // endpoint means signed trailers; the relay does not re-sign those yet.
        (
            "AWS_REQUEST_CHECKSUM_CALCULATION".into(),
            b"when_required".to_vec(),
        ),
        (
            "AWS_RESPONSE_CHECKSUM_VALIDATION".into(),
            b"when_required".to_vec(),
        ),
    ];
    d.aws
        .dummies
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            akid,
            Dummy {
                lease: lease.to_string(),
                project: project.to_string(),
                env: env.to_string(),
                profile: p,
                policy,
                secret,
            },
        );
    Ok(vars)
}

/// `smith aws creds --contained`: 15-minute STS credentials for the profile's role, limited by
/// the project policy as a session policy, injected into the child (contained, not delegated).
#[allow(clippy::too_many_arguments)]
pub fn contained(
    d: &Daemon,
    peer: &Peer,
    actor: &Actor,
    b: Option<&Binding>,
    project: &str,
    env: &str,
    profile: &str,
) -> Result<(String, EnvVars), Response> {
    let Some(b) = b else {
        return Err(err(
            ErrorCode::BadRequest,
            "--contained needs a .locksmith.toml with [aws.profiles.<name>]",
        ));
    };
    let Some(p) = b.aws.profiles.get(profile).cloned() else {
        return Err(err(
            ErrorCode::BadRequest,
            format!("no [aws.profiles.{profile}] in .locksmith.toml"),
        ));
    };
    let Some(role) = p.role_arn.clone() else {
        return Err(err(
            ErrorCode::BadRequest,
            format!(
                "--contained needs role_arn in [aws.profiles.{profile}] (credentials come from STS AssumeRole)"
            ),
        ));
    };
    let policy = policy_of(b)
        .map_err(|e| err(ErrorCode::BadRequest, e))?
        .session_policy_json();
    let target = format!("{project}/{env}/aws:{profile}");
    let mut st = d.state();
    let lease = match st.leases.authorize(peer.id, "aws", project, env, now()) {
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
            return Err(err(
                ErrorCode::Denied,
                format!("--contained needs the session's `aws` scope: {den}"),
            ));
        }
    };
    let base = match &st.vault {
        None => return Err(err(ErrorCode::Locked, "vault is locked")),
        Some(v) => match v.get_secret(project, env, &p.key) {
            Ok(s) => parse_keys(s.expose()).map_err(|e| err(ErrorCode::BadRequest, e))?,
            Err(e) => return Err(err(ErrorCode::NotFound, e.to_string())),
        },
    };
    st.audit(rec(
        actor,
        "ACCESS",
        Some(target),
        &format!("aws_contained:{role}"),
        "ALLOW",
        Some(lease.clone()),
    ))
    .map_err(|e| err(ErrorCode::Internal, e))?;
    drop(st); // STS is a network call
    let (c, _expiry) = sts::contained(
        &base,
        &p.region,
        &role,
        p.external_id.as_deref(),
        &format!("locksmith-{lease}"),
        Some(&policy),
        sts_endpoint().as_deref(),
    )
    .map_err(|e| err(ErrorCode::Internal, format!("AssumeRole {role}: {e}")))?;
    d.aws
        .issued
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(Issued {
            lease: lease.clone(),
            project: project.into(),
            env: env.into(),
            profile: p.clone(),
        });
    let mut vars = vec![
        (
            "AWS_ACCESS_KEY_ID".to_string(),
            c.access_key_id.into_bytes(),
        ),
        (
            "AWS_SECRET_ACCESS_KEY".into(),
            c.secret_access_key.as_bytes().to_vec(),
        ),
        ("AWS_REGION".into(), p.region.clone().into_bytes()),
        ("AWS_DEFAULT_REGION".into(), p.region.into_bytes()),
        ("AWS_EC2_METADATA_DISABLED".into(), b"true".to_vec()),
    ];
    if let Some(t) = &c.session_token {
        vars.push(("AWS_SESSION_TOKEN".into(), t.as_bytes().to_vec()));
    }
    Ok((lease, vars))
}

/// After `smith revoke`: for profiles with `revoke_older_sessions`, deny every STS session of
/// that role issued before now (IAM PutRolePolicy, in the background; audited).
pub fn revoke_older(d: &Arc<Daemon>, revoked: &[String]) {
    let todo: Vec<Issued> = {
        let mut issued = d.aws.issued.lock().unwrap_or_else(|e| e.into_inner());
        let (hit, keep): (Vec<Issued>, Vec<Issued>) = std::mem::take(&mut *issued)
            .into_iter()
            .partition(|i| revoked.contains(&i.lease));
        *issued = keep;
        hit.into_iter()
            .filter(|i| i.profile.revoke_older_sessions)
            .collect()
    };
    for i in todo {
        let Some(role) = i.profile.role_arn.clone() else {
            continue;
        };
        let base = match &d.state().vault {
            Some(v) => v
                .get_secret(&i.project, &i.env, &i.profile.key)
                .ok()
                .and_then(|s| parse_keys(s.expose()).ok()),
            None => None,
        };
        let d = d.clone();
        std::thread::spawn(move || {
            let r = match base {
                Some(b) => sts::revoke_older_sessions(&b, &role, now(), None),
                None => Err("vault locked or key missing".into()),
            };
            let _ = d.state().audit(rec(
                &d.me,
                "AWS_REVOKE_OLDER",
                Some(role),
                &match &r {
                    Ok(()) => "put_role_policy".to_string(),
                    Err(e) => format!("failed: {e}"),
                },
                if r.is_ok() { "ALLOW" } else { "DENY" },
                Some(i.lease),
            ));
        });
    }
}

pub fn info(d: &Daemon) -> Response {
    match d.aws.port.get() {
        Some(&port) => Response::AwsInfo { port },
        None => err(ErrorCode::Internal, "AWS relay is not running"),
    }
}

/// Parse the stored key JSON `{"access_key_id","secret_access_key","session_token"?}`. Errors
/// never include the input.
pub fn parse_keys(v: &[u8]) -> Result<Credentials, String> {
    #[derive(serde::Deserialize)]
    struct K {
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    }
    let k: K = serde_json::from_slice(v).map_err(|_| {
        "stored AWS key is not JSON {\"access_key_id\",\"secret_access_key\"[,\"session_token\"]}"
            .to_string()
    })?;
    Ok(Credentials {
        access_key_id: k.access_key_id,
        secret_access_key: Zeroizing::new(k.secret_access_key),
        session_token: k.session_token.map(Zeroizing::new),
    })
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
        exe: "(AWS client over loopback TCP)".into(),
        exe_hash: String::new(),
    }
}

impl Relay {
    /// Upstream credentials: the stored keys, or (with `role_arn`) cached STS ones.
    fn upstream(
        &self,
        lease: &str,
        profile: &AwsProfile,
        stored: Credentials,
    ) -> Result<Credentials, Deny> {
        let Some(role) = &profile.role_arn else {
            return Ok(stored);
        };
        let key = (lease.to_string(), role.clone());
        let mut roles = self.0.aws.roles.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = roles.get(&key).filter(|c| c.expiry - 300 > now()) {
            return Ok(Credentials {
                access_key_id: c.akid.clone(),
                secret_access_key: c.secret.clone(),
                session_token: c.token.clone(),
            });
        }
        let (c, expiry) = sts::assume_role(
            &stored,
            &profile.region,
            role,
            profile.external_id.as_deref(),
            &format!("locksmith-{lease}"),
            None,
            3600,
            sts_endpoint().as_deref(),
        )
        .map_err(|e| deny(502, format!("AssumeRole {role}: {e}")))?;
        roles.insert(
            key,
            RoleCreds {
                akid: c.access_key_id.clone(),
                secret: c.secret_access_key.clone(),
                token: c.session_token.clone(),
                expiry,
            },
        );
        Ok(c)
    }
}

impl AwsAuthority for Relay {
    fn session(
        &self,
        access_key_id: &str,
        client: SocketAddr,
        server: SocketAddr,
    ) -> Result<AwsSession, Deny> {
        let d = &self.0;
        let (lease, project, env, profile, policy, dummy_secret) = {
            let m = d.aws.dummies.lock().unwrap_or_else(|e| e.into_inner());
            let Some(t) = m.get(access_key_id) else {
                return Err(deny(
                    403,
                    "The security token included in the request is invalid (unknown or revoked Locksmith dummy key)",
                ));
            };
            (
                t.lease.clone(),
                t.project.clone(),
                t.env.clone(),
                t.profile.clone(),
                t.policy.clone(),
                t.secret.clone(),
            )
        };
        let owners = ls_platform::net::tcp_peer_owners(client, server);
        let mut st = d.state();
        let t = now();
        let target = format!("{project}/{env}/aws:{access_key_id}");
        let block = |st: &mut State, a: &Actor, rule: &str| {
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
                block(&mut st, &d.me, "aws_peer_unknown");
                return Err(deny(
                    403,
                    "Locksmith could not identify the process using the AWS relay",
                ));
            }
        };
        // Every process holding the client socket must be inside this key's live session.
        for o in &owners {
            match st.leases.authorize(*o, "aws", &project, &env, t) {
                Ok(l) if l.id == lease => {}
                Ok(_) => {
                    block(&mut st, &tcp_actor(*o), "aws_other_session");
                    return Err(deny(403, "dummy AWS key belongs to another session"));
                }
                Err(den) => {
                    block(&mut st, &tcp_actor(*o), &deny_rule(&den));
                    return Err(deny(
                        403,
                        format!("Locksmith refused the AWS request: {den}"),
                    ));
                }
            }
        }
        let actor = tcp_actor(owners[0]);
        let stored = match &st.vault {
            None => {
                block(&mut st, &actor, "vault_locked");
                return Err(deny(403, "Locksmith vault is locked"));
            }
            Some(v) => match v.get_secret(&project, &env, &profile.key) {
                Ok(s) => parse_keys(s.expose()).map_err(|e| deny(502, e))?,
                Err(_) => {
                    block(&mut st, &actor, "aws_credential_missing");
                    return Err(deny(403, format!("vault key {} is missing", profile.key)));
                }
            },
        };
        drop(st); // AssumeRole is a network call
        d.aws
            .actors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(lease.clone(), actor);
        let upstream = self.upstream(&lease, &profile, stored)?;
        Ok(AwsSession {
            lease,
            dummy_secret,
            upstream,
            policy,
        })
    }

    fn record(&self, s: &AwsSession, call: &Call, allowed: bool, rule: &str) {
        let d = &self.0;
        let actors = d.aws.actors.lock().unwrap_or_else(|e| e.into_inner());
        let a = actors.get(&s.lease).unwrap_or(&d.me);
        let action = call.action.as_deref().unwrap_or("unknown");
        let _ = d.state().audit(rec(
            a,
            if allowed { "ACCESS" } else { "BLOCKED" },
            Some(format!("{action} {}", call.resource)),
            &format!("aws:{}:{}:{rule}", call.service, call.region),
            if allowed { "ALLOW" } else { "DENY" },
            Some(s.lease.clone()),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_ids_look_like_access_keys() {
        let id = format!(
            "{AKID_PREFIX}{}",
            random(20 - AKID_PREFIX.len(), b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        );
        assert_eq!(id.len(), 20);
        assert!(
            id.bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn stored_keys_parse_and_errors_hide_input() {
        let c = parse_keys(br#"{"access_key_id":"AK","secret_access_key":"s3cr3t-x"}"#).unwrap();
        assert_eq!(c.access_key_id, "AK");
        assert!(c.session_token.is_none());
        let Err(e) = parse_keys(b"s3cr3t-not-json") else {
            panic!("not JSON must fail")
        };
        assert!(!e.contains("s3cr3t"));
    }
}
