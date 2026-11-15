//! `smith run`, `smith env-template`, `smith init --binding-only`.
//! Secret values go only into the child's environment: never argv, never disk.

use crate::input::{self, Opts};
use crate::vault_cmds::{fail, unlock};
use crate::{Fail, binding};
use clap::Args;
use ls_core::ExitCode;
use ls_redact::{Redactor, Secret};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM, SIGWINCH};
use std::ffi::{OsStr, OsString};
use std::io::{IsTerminal, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

const EXPLAIN: &str = "\
smith run: what this protects, and what it does not

Injected secrets live in the child's environment. That means:
  - the child process can read every injected value;
  - any other process of the same OS user can read them too (for example via
    /proc/<pid>/environ or `ps eww`), unless OS containment is added;
  - anything the child writes to stdout/stderr is redacted (plain, base64, hex,
    URL- and JSON-escaped forms), but the child can still send the values over the
    network or write them to files, and redaction cannot stop that.

Do not inject secrets into an AI agent (claude, cursor-agent, codex, ...). The
agent's own tools (e.g. a Bash tool running `echo $KEY`) return output to the
model before smith sees it, so redaction cannot protect the model's context.
Run your app and tests with smith run; give agents delegated access instead.

Only keys listed in .locksmith.toml (or --only) are injected, and LOCKSMITH_*
variables are never passed on.

For stronger isolation, let Locksmith use the credential for the agent instead of
handing it over:
  smith git    delegated git operations
  smith http   delegated HTTP calls with the credential attached: keys under
               [http.keys] in .locksmith.toml reach the child as opaque lsk_
               tokens plus base-URL variables pointing at the local relay
  smith db     delegated database access
  smith run --aws <profile>
               delegated AWS access: the child gets dummy keys and AWS_ENDPOINT_URL
               pointing at a local relay that checks [aws.policy] and signs with the real
               keys. Contained fallback for tools that ignore the endpoint: `smith aws creds
               --contained` (15-minute STS credentials visible to that process).
";

#[derive(Args)]
pub struct RunArgs {
    #[arg(short, long)]
    project: Option<String>,
    #[arg(short, long)]
    env: Option<String>,
    /// Inject only these keys (comma-separated), instead of the binding's list.
    #[arg(long, value_delimiter = ',')]
    only: Vec<String>,
    /// Inject all keys of the environment without asking (when there is no binding).
    #[arg(long)]
    yes: bool,
    /// Explain the security model of `run` and exit.
    #[arg(long)]
    explain: bool,
    /// Give the command dummy AWS credentials for this `[aws.profiles.<name>]`; Locksmith
    /// signs its AWS calls with the real ones (M7).
    #[arg(long, value_name = "PROFILE")]
    aws: Option<String>,
    /// Command to run, after `--`.
    #[arg(last = true, required_unless_present = "explain")]
    cmd: Vec<String>,
}

#[derive(Args)]
pub struct TemplateArgs {
    #[arg(short, long)]
    project: Option<String>,
    #[arg(short, long)]
    env: Option<String>,
}

pub fn init(binding_only: bool) -> Result<ExitCode, Fail> {
    if !binding_only {
        return Err(Fail(
            ExitCode::Usage,
            "use `smith vault init` to create the vault, or `smith init --binding-only`".into(),
        ));
    }
    let cwd = cwd()?;
    let f = binding::init(&cwd)?;
    println!("wrote {}", f.display());
    Ok(ExitCode::Ok)
}

fn cwd() -> Result<std::path::PathBuf, Fail> {
    std::env::current_dir().map_err(|e| Fail(ExitCode::Failure, format!("no current dir: {e}")))
}

pub(crate) fn bound() -> Result<Option<(binding::Binding, Vec<u8>)>, Fail> {
    binding::find(&cwd()?)
        .map(|p| binding::load(&p))
        .transpose()
}

pub fn env_template(o: &Opts, a: TemplateArgs) -> Result<ExitCode, Fail> {
    let b = bound()?;
    let keys = match &b {
        Some((b, _)) => b.keys.clone(),
        None => {
            let (p, e) = (a.project.as_deref(), a.env.as_deref());
            let items = unlock(o)?
                .list_secrets(
                    Some(p.unwrap_or("default")),
                    Some(e.unwrap_or("development")),
                )
                .map_err(fail)?;
            items.into_iter().map(|m| m.name).collect()
        }
    };
    for k in keys {
        println!("{k}=");
    }
    Ok(ExitCode::Ok)
}

pub fn run(o: &Opts, a: RunArgs) -> Result<ExitCode, Fail> {
    if a.explain {
        print!("{EXPLAIN}");
        return Ok(ExitCode::Ok);
    }
    if std::env::var_os("LOCKSMITH_SESSION").is_some() {
        let keys = a.only;
        return crate::session::run_via_daemon(
            a.project,
            a.env,
            keys,
            a.yes,
            a.cmd,
            a.aws.map(|p| (p, false)),
        );
    }
    // Only the direct path holds secret values in this process. The daemon path must stay
    // dumpable: on Linux a non-dumpable process hides /proc/<pid>/exe, so the daemon could
    // not attest it.
    let b = bound()?;
    if a.aws.is_some() || b.as_ref().is_some_and(|(b, _)| !b.http.keys.is_empty()) {
        return crate::session::run_leased(
            o,
            a.project,
            a.env,
            a.only,
            a.yes,
            a.cmd,
            a.aws.map(|p| (p, false)),
        );
    }
    let _ = ls_platform::disable_core_dumps();
    let bind = b.as_ref().map(|(b, _)| b);
    let project = a
        .project
        .or_else(|| bind?.project.clone())
        .unwrap_or("default".into());
    let env = a
        .env
        .or_else(|| bind?.env.clone())
        .unwrap_or("development".into());

    let v = unlock(o)?;
    if let Some((_, bytes)) = &b {
        let mut all = Vec::new();
        for m in v.list_secrets(None, None).map_err(fail)? {
            let val = v
                .get_secret(&m.project, &m.environment, &m.name)
                .map_err(fail)?;
            all.push(Secret::new(m.name, val.expose()));
        }
        if let Some(line) = binding::secret_line(bytes, &Redactor::new(&all)) {
            let at = if line == 0 {
                "spanning several lines".into()
            } else {
                format!("on line {line}")
            };
            return Err(Fail(
                ExitCode::Blocked,
                format!(
                    "{} contains a stored secret value {at}; remove it (bindings hold key names only)",
                    binding::FILE
                ),
            ));
        }
    }

    let keys: Vec<String> = if !a.only.is_empty() {
        a.only
    } else if let Some(b) = bind {
        b.keys.clone()
    } else {
        let all: Vec<String> = v
            .list_secrets(Some(&project), Some(&env))
            .map_err(fail)?
            .into_iter()
            .map(|m| m.name)
            .collect();
        let ok = a.yes
            || input::tty_line(&format!(
                "No {} here: inject all {} key(s) of {project}/{env}? [y/N] ",
                binding::FILE,
                all.len()
            ))
            .is_some_and(|s| s.eq_ignore_ascii_case("y"));
        if !ok {
            return Err(Fail(
                ExitCode::Blocked,
                "not confirmed; add a binding (`smith init --binding-only`), use --only, or --yes"
                    .into(),
            ));
        }
        all
    };
    let mut vars: Vec<(OsString, Vec<u8>)> = Vec::new();
    let mut secrets = Vec::new();
    for k in &keys {
        let val = v.get_secret(&project, &env, k).map_err(fail)?;
        crate::audit_cmds::record(&v, "ACCESS", format!("{project}/{env}/{k}"), "run")?;
        secrets.push(Secret::new(k.clone(), val.expose()));
        vars.push((k.into(), val.expose().to_vec()));
    }
    drop(v);
    let code = exec(&a.cmd, &vars, &Redactor::new(&secrets));
    std::process::exit(code); // child's code; not an ExitCode variant
}

fn spawn_fail(prog: &str, e: &dyn std::fmt::Display, missing: bool) -> i32 {
    eprintln!("smith: cannot run {prog}: {e}");
    if missing { 127 } else { 126 }
}

fn exec(cmd: &[String], vars: &[(OsString, Vec<u8>)], r: &Redactor) -> i32 {
    let stale: Vec<OsString> = std::env::vars_os()
        .map(|(k, _)| k)
        .filter(|k| k.as_bytes().starts_with(b"LOCKSMITH_"))
        .collect();
    if std::io::stdout().is_terminal() {
        pty(cmd, vars, &stale, r)
    } else {
        pipe(cmd, vars, &stale, r)
    }
}

fn pipe(cmd: &[String], vars: &[(OsString, Vec<u8>)], stale: &[OsString], r: &Redactor) -> i32 {
    let mut c = Command::new(&cmd[0]);
    c.args(&cmd[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    stale.iter().for_each(|k| {
        c.env_remove(k);
    });
    vars.iter().for_each(|(k, v)| {
        c.env(k, OsStr::from_bytes(v));
    });
    let mut child = match c.spawn() {
        Ok(c) => c,
        Err(e) => return spawn_fail(&cmd[0], &e, e.kind() == std::io::ErrorKind::NotFound),
    };
    forward_signals(child.id(), false, None);
    let (so, se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    std::thread::scope(|s| {
        s.spawn(|| ls_redact::relay(so, std::io::stdout(), r));
        ls_redact::relay(se, std::io::stderr(), r);
    });
    match child.wait() {
        Ok(st) => st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(0)),
        Err(_) => 1,
    }
}

fn pty(cmd: &[String], vars: &[(OsString, Vec<u8>)], stale: &[OsString], r: &Redactor) -> i32 {
    let size = |(rows, cols)| PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    };
    let pair = match native_pty_system().openpty(size(ls_platform::term_size().unwrap_or((24, 80))))
    {
        Ok(p) => p,
        Err(e) => return spawn_fail(&cmd[0], &format!("no pty: {e}"), false),
    };
    let mut b = CommandBuilder::new(&cmd[0]);
    b.args(&cmd[1..]);
    stale.iter().for_each(|k| b.env_remove(k));
    vars.iter()
        .for_each(|(k, v)| b.env(k, OsStr::from_bytes(v)));
    if let Ok(d) = std::env::current_dir() {
        b.cwd(d);
    }
    let mut child = match pair.slave.spawn_command(b) {
        Ok(c) => c,
        Err(e) => return spawn_fail(&cmd[0], &e, e.to_string().contains("No such file")),
    };
    drop(pair.slave); // otherwise the reader never sees EOF
    let (Ok(reader), Ok(mut writer)) = (pair.master.try_clone_reader(), pair.master.take_writer())
    else {
        return spawn_fail(&cmd[0], &"pty io", false);
    };
    let master = Arc::new(Mutex::new(pair.master));
    // Raw mode is restored by Drop on every path out of this function.
    let tty_in = std::io::stdin().is_terminal();
    let raw = tty_in
        .then(ls_platform::RawMode::enable)
        .and_then(Result::ok);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n @ 1..) = std::io::stdin().read(&mut buf) {
            if writer
                .write_all(&buf[..n])
                .and_then(|_| writer.flush())
                .is_err()
            {
                return;
            }
        }
        if !tty_in {
            let _ = writer.write_all(&[4]); // EOF to the child's line discipline
        }
    });
    let m = master.clone();
    forward_signals(
        child.process_id().unwrap_or(0),
        true,
        Some(Box::new(move || {
            if let (Some(sz), Ok(m)) = (ls_platform::term_size(), m.lock()) {
                let _ = m.resize(size(sz));
            }
        })),
    );
    ls_redact::relay(reader, std::io::stdout(), r);
    let st = child.wait();
    drop(raw);
    match st {
        Ok(st) => match st.signal() {
            Some(n) => 128 + signal_number(n),
            None => st.exit_code() as i32,
        },
        Err(_) => 1,
    }
}

// shortcut: portable-pty reports a killed child only by strsignal() text; common signals mapped.
fn signal_number(name: &str) -> i32 {
    [
        ("Hangup", 1),
        ("Interrupt", 2),
        ("Quit", 3),
        ("Illegal", 4),
        ("Abort", 6),
        ("Killed", 9),
        ("Segmentation", 11),
        ("Broken", 13),
        ("Alarm", 14),
        ("Terminated", 15),
    ]
    .iter()
    .find(|(p, _)| name.starts_with(p))
    .map_or(1, |(_, n)| *n)
}

/// SIGWINCH resizes the pty; in PTY mode SIGINT is forwarded too (raw mode turns terminal ^C
/// into a byte). In pipe mode the child shares our terminal and gets ^C itself, so SIGINT is swallowed.
pub(crate) fn forward_signals(pid: u32, pty: bool, resize: Option<Box<dyn Fn() + Send>>) {
    let Ok(mut sigs) = signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP, SIGWINCH])
    else {
        return;
    };
    std::thread::spawn(move || {
        for s in sigs.forever() {
            match s {
                SIGWINCH => resize.iter().for_each(|f| f()),
                SIGINT if !pty => {}
                s if pid != 0 => ls_platform::kill(pid, s),
                _ => {}
            }
        }
    });
}
