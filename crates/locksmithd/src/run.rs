//! `Request::Run`: authorize against the caller's lease, read the secrets, spawn the child with
//! them in its environment and relay its output (redacted) to the descriptors the client sent.
//! Children get pipes, not a pty.

use crate::{Actor, Daemon, deny_response, deny_rule, err, now, rec};
use ls_ipc::{ErrorCode, Frame, Request, Response, RunSpec, read_frame, write_frame};
use ls_platform::proc::{Peer, id_of, recv_fds};
use ls_redact::binding::{Binding, parse, secret_line};
use ls_redact::{Redactor, Secret, relay};
use ls_vault::Error as VErr;
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    let lease = match st.leases.authorize(peer.id, "run", &project, &env, t) {
        Ok(l) => l.id.clone(),
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
    let Some(out) = st
        .vault
        .as_ref()
        .map(|v| read_secrets(v, spec, binding.as_ref(), &project, &env))
    else {
        blocked(&mut st, "vault_locked");
        return Err(err(
            ErrorCode::Locked,
            "vault is locked; unlock with `smith session start`",
        ));
    };
    let (keys, vars) = match out {
        Ok(x) => x,
        Err((code, msg)) => {
            if code == ErrorCode::Denied {
                blocked(&mut st, "binding_holds_secret");
            }
            return Err(err(code, msg));
        }
    };
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
    let secrets: Vec<Secret> = vars
        .iter()
        .map(|(k, v)| Secret::new(k.clone(), v))
        .collect();
    Ok(Prepared {
        lease,
        vars,
        redactor: Redactor::new(&secrets),
    })
}

type Fetched = (Vec<String>, Vec<(String, Vec<u8>)>);

fn read_secrets(
    v: &ls_vault::Vault,
    spec: &RunSpec,
    binding: Option<&Binding>,
    project: &str,
    env: &str,
) -> Result<Fetched, (ErrorCode, String)> {
    let internal = |e: VErr| match e {
        VErr::NotFound(_) => (ErrorCode::NotFound, e.to_string()),
        e => (ErrorCode::Internal, e.to_string()),
    };
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
    let mut vars = Vec::new();
    for k in &keys {
        let val = v.get_secret(project, env, k).map_err(internal)?;
        vars.push((k.clone(), val.expose().to_vec()));
    }
    // shortcut: on an error above, values already copied are not zeroized; they are dropped
    // with this Vec. Prepared (the success path) zeroizes on drop.
    Ok((keys, vars))
}

pub fn run(d: &Daemon, peer: &Peer, actor: &Actor, mut s: UnixStream, spec: RunSpec) {
    // The client sends its stdio right after the request; take it before replying.
    let fds = recv_fds(&s, 3).ok().filter(|f| f.len() == 3);
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
