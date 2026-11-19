//! `Request::Run`: authorize against the caller's lease, read the secrets, spawn the child with
//! them in its environment and relay its output (redacted) to the descriptors the client sent.
//! Children get pipes, not a pty.

use crate::{Actor, Daemon, deny_response, deny_rule, err, now, rec};
use ls_ipc::{ErrorCode, Frame, Request, Response, RunSpec, read_frame, write_frame};
use ls_platform::proc::Peer;
#[cfg(unix)]
use ls_platform::proc::{id_of, recv_fds};
use ls_redact::binding::{Binding, parse, secret_line};
use ls_redact::{Redactor, Secret, relay};
use ls_vault::Error as VErr;
#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::{ffi::OsStrExt, net::UnixStream, process::ExitStatusExt};
#[cfg(unix)]
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::time::Duration;
use std::time::Instant;

struct Prepared {
    lease: String,
    vars: Vec<(String, Vec<u8>)>,
    redactor: Redactor,
}

impl Drop for Prepared {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.vars.iter_mut().for_each(|(_, v)| v.zeroize());
    }
}

fn prepare(d: &Daemon, peer: &Peer, actor: &Actor, spec: &RunSpec) -> Result<Prepared, Response> {
    let binding = match spec.binding.as_deref().map(parse).transpose() {
        Ok(b) => b,
        Err(e) => return Err(err(ErrorCode::BadRequest, format!("invalid binding: {e}"))),
    };
    let project = spec
        .project
        .clone()
        .or_else(|| binding.as_ref()?.project.clone())
        .unwrap_or("default".into());
    let env = spec
        .env
        .clone()
        .or_else(|| binding.as_ref()?.env.clone())
        .unwrap_or("development".into());

    if let (Some(profile), true) = (&spec.aws, spec.aws_contained) {
        let (lease, vars) =
            crate::aws::contained(d, peer, actor, binding.as_ref(), &project, &env, profile)?;
        let secrets: Vec<Secret> = vars
            .iter()
            .filter(|(k, _)| k == "AWS_SECRET_ACCESS_KEY" || k == "AWS_SESSION_TOKEN")
            .map(|(k, v)| Secret::new(format!("{k}(contained)"), v))
            .collect();
        return Ok(Prepared {
            lease,
            vars,
            redactor: Redactor::new(&secrets),
        });
    }
    if let Some(gh) = &spec.gh {
        let (lease, tok) = crate::git::gh_token(
            d,
            peer,
            actor,
            binding.as_ref(),
            &project,
            &env,
            gh.repo.as_deref(),
        )?;
        let redactor = Redactor::new(&[Secret::new("GH_TOKEN", tok.as_bytes())]);
        return Ok(Prepared {
            lease,
            vars: vec![("GH_TOKEN".into(), tok.as_bytes().to_vec())],
            redactor,
        });
    }
    let mut st = d.state();
    st.last = Instant::now();
    let t = now();
    let (lease, inject) = match st.leases.authorize(peer.id, "run", &project, &env, t) {
        Ok(l) => (l.id.clone(), l.inject.clone()),
        Err(den) => {
            let r = rec(
                actor,
                "BLOCKED",
                Some(format!("{project}/{env}")),
                &deny_rule(&den),
                "DENY",
                None,
            );
            let _ = st.audit(r);
            return Err(deny_response(&den));
        }
    };
    let blocked = |st: &mut crate::State, rule: &str| {
        let r = rec(
            actor,
            "BLOCKED",
            Some(format!("{project}/{env}")),
            rule,
            "DENY",
            Some(lease.clone()),
        );
        let _ = st.audit(r);
    };
    let locked = |st: &mut crate::State| {
        blocked(st, "vault_locked");
        err(
            ErrorCode::Locked,
            "vault is locked; unlock with `smith session start`",
        )
    };
    // [http] keys get an opaque token and the relay base URL instead of the value (M6).
    let http_names: Vec<String> = binding
        .as_ref()
        .map(|b| {
            b.http
                .keys
                .keys()
                .filter(|k| spec.keys.is_empty() || spec.keys.contains(k))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let Some(out) = st
        .vault
        .as_ref()
        .map(|v| run_keys(v, spec, binding.as_ref(), &project, &env, &http_names))
    else {
        return Err(locked(&mut st));
    };
    let keys = match out {
        Ok(k) => k,
        Err((code, msg)) => {
            if code == ErrorCode::Denied {
                blocked(&mut st, "binding_holds_secret");
            }
            return Err(err(code, msg));
        }
    };
    // M10e D1: checked on the final key set (binding, --only, --all), before anything is read
    // or minted, so no flag combination skips it and a mixed request injects nothing.
    if let Some(inj) = &inject {
        let denied: Vec<&String> = keys.iter().filter(|k| !inj.contains(k)).collect();
        if !denied.is_empty() {
            return Err(crate::refuse_relay_only(
                &mut st, actor, &lease, &project, &env, &denied,
            ));
        }
    }
    let (http_vars, http_keys) = match &binding {
        Some(b) => crate::http::for_run(
            d, &mut st, peer, actor, &lease, &project, &env, b, &spec.keys,
        )?,
        None => (Vec::new(), Vec::new()),
    };
    let Some(read) = st
        .vault
        .as_ref()
        .map(|v| read_values(v, &project, &env, &keys))
    else {
        return Err(locked(&mut st));
    };
    let mut vars = read.map_err(|(code, msg)| err(code, msg))?;
    for k in &keys {
        let r = rec(
            actor,
            "ACCESS",
            Some(format!("{project}/{env}/{k}")),
            "run",
            "ALLOW",
            Some(lease.clone()),
        );
        if let Err(e) = st.audit(r) {
            return Err(err(ErrorCode::Internal, e));
        }
    }
    let mut secrets: Vec<Secret> = vars
        .iter()
        .map(|(k, v)| Secret::new(k.clone(), v))
        .collect();
    // Opaque tokens are placeholders, redacted under a low-sensitivity label (M6 D1).
    for (k, v) in &http_vars {
        if http_keys.contains(k) {
            secrets.push(Secret::new(format!("{k}(opaque)"), v));
        }
    }
    vars.extend(http_vars);
    // --aws: dummy keys and the relay endpoint; the dummy secret is redacted too (M7).
    if let Some(profile) = &spec.aws {
        let aws = crate::aws::for_run(
            d,
            &mut st,
            peer,
            actor,
            &lease,
            &project,
            &env,
            binding.as_ref(),
            profile,
        )?;
        for (k, v) in &aws {
            if k == "AWS_SECRET_ACCESS_KEY" {
                secrets.push(Secret::new("AWS_SECRET_ACCESS_KEY(dummy)", v));
            }
        }
        vars.extend(aws);
    }
    Ok(Prepared {
        lease,
        vars,
        redactor: Redactor::new(&secrets),
    })
}

fn internal(e: VErr) -> (ErrorCode, String) {
    match e {
        VErr::NotFound(_) => (ErrorCode::NotFound, e.to_string()),
        e => (ErrorCode::Internal, e.to_string()),
    }
}

/// The keys a run injects: `--only`, else the binding's keys, else (`--yes`) all of the env,
/// minus `skip` (keys relayed as opaque tokens). Reads no value except to refuse a binding that
/// holds one.
fn run_keys(
    v: &ls_vault::Vault,
    spec: &RunSpec,
    binding: Option<&Binding>,
    project: &str,
    env: &str,
    skip: &[String],
) -> Result<Vec<String>, (ErrorCode, String)> {
    if let Some(bytes) = spec.binding.as_deref() {
        // Bindings hold key names only; refuse one that contains a stored value.
        let mut all = Vec::new();
        for m in v.list_secrets(None, None).map_err(internal)? {
            let val = v
                .get_secret(&m.project, &m.environment, &m.name)
                .map_err(internal)?;
            all.push(Secret::new(m.name, val.expose()));
        }
        if secret_line(bytes, &Redactor::new(&all)).is_some() {
            return Err((
                ErrorCode::Denied,
                format!(
                    "{} contains a stored secret value; remove it",
                    ls_redact::binding::FILE
                ),
            ));
        }
    }
    let keys: Vec<String> = if !spec.keys.is_empty() {
        spec.keys.clone()
    } else if let Some(b) = binding {
        b.keys.clone()
    } else if spec.all_keys {
        v.list_secrets(Some(project), Some(env))
            .map_err(internal)?
            .into_iter()
            .map(|m| m.name)
            .collect()
    } else {
        return Err((ErrorCode::Denied, "no binding; use --only or --yes".into()));
    };
    Ok(keys.into_iter().filter(|k| !skip.contains(k)).collect())
}

type EnvVars = Vec<(String, Vec<u8>)>;

fn read_values(
    v: &ls_vault::Vault,
    project: &str,
    env: &str,
    keys: &[String],
) -> Result<EnvVars, (ErrorCode, String)> {
    let mut vars = Vec::new();
    for k in keys {
        let val = v.get_secret(project, env, k).map_err(internal)?;
        vars.push((k.clone(), val.expose().to_vec()));
    }
    // shortcut: on an error above, values already copied are not zeroized; they are dropped
    // with this Vec. Prepared (the success path) zeroizes on drop.
    Ok(vars)
}

/// Off Unix the client's stdio cannot be passed to the daemon yet (no SCM_RIGHTS), so `run` is
/// refused before any secret is read.
#[cfg(not(unix))]
pub fn run(
    _d: &Daemon,
    _peer: &Peer,
    _actor: &Actor,
    mut s: ls_ipc::DefaultTransport,
    _spec: RunSpec,
) {
    let _ = write_frame(
        &mut s,
        &err(
            ErrorCode::BadRequest,
            "smith run is not supported on this OS yet",
        ),
    );
}

#[cfg(unix)]
pub fn run(d: &Daemon, peer: &Peer, actor: &Actor, mut s: UnixStream, spec: RunSpec) {
    // The client sends its stdio right after the request; take it before replying. Bounded, so
    // a client that never sends them cannot pin this thread.
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    let fds = recv_fds(&s, 3).ok().filter(|f| f.len() == 3);
    let _ = s.set_read_timeout(None);
    let Some(mut fds) = fds.filter(|_| !spec.cmd.is_empty()) else {
        let _ = write_frame(
            &mut s,
            &err(
                ErrorCode::BadRequest,
                "run needs a command and 3 descriptors",
            ),
        );
        return;
    };
    let p = match prepare(d, peer, actor, &spec) {
        Ok(p) => p,
        Err(r) => {
            let _ = write_frame(&mut s, &r);
            return;
        }
    };
    let (stdin, stdout, stderr) = (
        fds.remove(0),
        File::from(fds.remove(0)),
        File::from(fds.remove(0)),
    );

    let mut c = Command::new(&spec.cmd[0]);
    c.args(&spec.cmd[1..])
        .env_clear()
        .envs(
            spec.environ
                .iter()
                .filter(|(k, _)| !k.starts_with("LOCKSMITH_"))
                .cloned(),
        )
        .env("LOCKSMITH_SESSION", &p.lease)
        .current_dir(&spec.cwd)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    p.vars.iter().for_each(|(k, v)| {
        c.env(k, OsStr::from_bytes(v));
    });
    let mut child = match c.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(&stderr, "smith: cannot run {}: {e}", spec.cmd[0]);
            let code = if e.kind() == std::io::ErrorKind::NotFound {
                127
            } else {
                126
            };
            let _ = write_frame(&mut s, &Response::RunExited { code });
            return;
        }
    };
    let pid = child.id();
    let child_id = id_of(pid).ok();
    if let Some(i) = child_id {
        d.state().leases.add_spawned(&p.lease, i);
    }
    let (so, se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());

    // Signals from the client are forwarded to the child; a vanished client terminates it.
    // `reaped` is held across kill and across the exit check so a recycled pid is never signalled.
    let reaped = Arc::new(Mutex::new(false));
    let (flag, mut rs) = (reaped.clone(), s.try_clone().expect("clone socket"));
    let _ = write_frame(&mut s, &Response::RunStarted { pid });
    std::thread::spawn(move || {
        let kill = |sig| {
            if !*flag.lock().unwrap_or_else(|e| e.into_inner()) {
                ls_platform::kill(pid, sig);
            }
        };
        while let Ok(Some(Frame::Msg(Request::Signal { sig }))) = read_frame(&mut rs) {
            if (1..32).contains(&sig) {
                kill(sig);
            }
        }
        kill(libc::SIGTERM);
    });

    let status = std::thread::scope(|sc| {
        sc.spawn(|| relay(so, stdout, &p.redactor));
        sc.spawn(|| relay(se, stderr, &p.redactor));
        loop {
            let mut g = reaped.lock().unwrap_or_else(|e| e.into_inner());
            match child.try_wait() {
                Ok(None) => {}
                r => {
                    *g = true;
                    break r.ok().flatten();
                }
            }
            drop(g);
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    let code = status.map_or(1, |st| {
        st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(0))
    });
    if let Some(i) = child_id {
        d.state().leases.remove_spawned(&p.lease, i);
    }
    d.state().last = Instant::now();
    let _ = write_frame(&mut s, &Response::RunExited { code });
    let _ = s.shutdown(std::net::Shutdown::Both);
}
