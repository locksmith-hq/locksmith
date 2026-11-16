//! Daemon client: connection (with on-demand start), `smith session|status|revoke|lock|daemon`,
//! and the `smith run` path that goes through the daemon.

use crate::input::{self, Opts};
use crate::{Fail, run_cmd};
use clap::{Args, Subcommand};
use ls_core::ExitCode;
use ls_ipc::{Client, ErrorCode, Passphrase, Request, Response, RunSpec, write_frame};
use serde_json::json;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn fail(c: ExitCode, m: impl Into<String>) -> Fail {
    Fail(c, m.into())
}

pub fn exit_of(c: ErrorCode) -> ExitCode {
    match c {
        ErrorCode::Locked => ExitCode::Locked,
        ErrorCode::Denied => ExitCode::Blocked,
        ErrorCode::NotFound => ExitCode::NotFound,
        ErrorCode::BadRequest => ExitCode::Usage,
        _ => ExitCode::Failure,
    }
}

fn sibling(name: &str) -> Result<PathBuf, Fail> {
    std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .ok()
        .and_then(|p| Some(p.parent()?.join(name)))
        .filter(|p| p.is_file())
        .ok_or_else(|| {
            fail(
                ExitCode::Failure,
                format!("cannot find {name} next to smith"),
            )
        })
}

/// Connect to the daemon; with `start`, launch the sibling `locksmithd` first if it is down.
pub fn connect(start: bool) -> Result<Client, Fail> {
    let e = match Client::connect_default() {
        Ok(c) => return Ok(c),
        Err(e) if !start => {
            return Err(fail(
                ExitCode::Failure,
                format!("locksmithd is not running ({e})"),
            ));
        }
        Err(e) => e,
    };
    let exe = sibling("locksmithd").map_err(|_| {
        fail(
            ExitCode::Failure,
            format!("locksmithd is not running ({e})"),
        )
    })?;
    // shortcut: own process group instead of a new session (setsid needs unsafe); enough to
    // survive terminal hangups.
    Command::new(exe)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|e| fail(ExitCode::Failure, format!("cannot start locksmithd: {e}")))?;
    let t = Instant::now();
    loop {
        if let Ok(c) = Client::connect_default() {
            return Ok(c);
        }
        if t.elapsed() > Duration::from_secs(3) {
            return Err(fail(
                ExitCode::Failure,
                "locksmithd did not start within 3 s",
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// One request; daemon errors become `Fail` with the matching exit code.
pub fn call(c: &mut Client, req: &Request) -> Result<Response, Fail> {
    match c.call(req) {
        Ok(Response::Error { code, message }) => Err(fail(exit_of(code), message)),
        Ok(r) => Ok(r),
        Err(e) => Err(fail(ExitCode::Failure, format!("locksmithd: {e}"))),
    }
}

fn resolve(p: Option<String>, e: Option<String>) -> Result<(String, String), Fail> {
    let b = run_cmd::bound()?;
    let b = b.as_ref().map(|(b, _)| b);
    Ok((
        p.or_else(|| b?.project.clone()).unwrap_or("default".into()),
        e.or_else(|| b?.env.clone()).unwrap_or("development".into()),
    ))
}

/// `90s`, `30m`, `8h`, `2d`; a bare number is seconds.
pub fn parse_ttl(s: &str) -> Result<u64, String> {
    let (n, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        _ => (s, 1),
    };
    n.parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .filter(|n| *n > 0)
        .ok_or_else(|| format!("invalid duration '{s}' (examples: 90s, 30m, 8h)"))
}

#[derive(Subcommand)]
pub enum SessionCmd {
    /// Unlock once, run an agent command, and authorize it and its descendants for a while.
    Start(StartArgs),
}

#[derive(Args)]
pub struct StartArgs {
    #[arg(long, default_value = "8h", value_parser = parse_ttl)]
    ttl: u64,
    /// Operations the session allows: `run` (inject secrets), `git` (the Git forwarder), `http`
    /// (the HTTP relay and opaque tokens) and `db` (database relays).
    #[arg(long, default_values = ["run", "git", "http", "db", "aws"])]
    scope: Vec<String>,
    #[arg(short, long)]
    project: Option<String>,
    #[arg(short, long)]
    env: Option<String>,
    /// Agent command, after `--`.
    #[arg(last = true, required = true)]
    cmd: Vec<String>,
}

pub fn session(o: &Opts, cmd: SessionCmd) -> Result<ExitCode, Fail> {
    let SessionCmd::Start(a) = cmd;
    let (project, env) = resolve(a.project, a.env)?;
    let mut c = connect(true)?;
    // Asked for every session, even when the daemon is already unlocked (see Request docs).
    let pw = input::passphrase(o, "Passphrase: ")?;
    let req = Request::SessionStart {
        passphrase: Passphrase::new(pw.as_bytes().to_vec()),
        ttl_secs: a.ttl,
        project,
        env,
        scopes: a.scope,
        command: a.cmd.join(" "),
        binding: run_cmd::bound()?.map(|(_, bytes)| bytes),
    };
    let Response::Session { id, .. } = call(&mut c, &req)? else {
        return Err(fail(ExitCode::Failure, "unexpected daemon reply"));
    };
    let code = match Command::new(&a.cmd[0])
        .args(&a.cmd[1..])
        .env("LOCKSMITH_SESSION", &id)
        .spawn()
    {
        Ok(mut child) => {
            run_cmd::forward_signals(child.id(), false, None);
            child.wait().map_or(1, |st| {
                use std::os::unix::process::ExitStatusExt;
                st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(0))
            })
        }
        Err(e) => {
            eprintln!("smith: cannot run {}: {e}", a.cmd[0]);
            if e.kind() == std::io::ErrorKind::NotFound {
                127
            } else {
                126
            }
        }
    };
    let _ = c.call(&Request::SessionEnd);
    std::process::exit(code);
}

fn human(secs: i64) -> String {
    let s = secs.max(0);
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m", s / 60),
        _ => format!("{}h{}m", s / 3600, s % 3600 / 60),
    }
}

pub fn status(json: bool) -> Result<ExitCode, Fail> {
    let (running, locked, leases) = match connect(false)
        .ok()
        .map(|mut c| call(&mut c, &Request::Status))
    {
        Some(Ok(Response::Status { locked, leases })) => (
            true,
            locked,
            leases.into_iter().filter(|l| l.state == "active").collect(),
        ),
        Some(Err(e)) => return Err(e),
        _ => (false, true, vec![]),
    };
    if json {
        println!(
            "{}",
            json!({ "daemon": running, "locked": locked, "sessions": leases })
        );
        return Ok(ExitCode::Ok);
    }
    println!(
        "daemon: {}\nvault: {}",
        if running { "running" } else { "not running" },
        if locked { "locked" } else { "unlocked" }
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    for l in leases {
        // Source and host are hints from executable names; model is the agent's own claim.
        let mut from = l.source.label.clone();
        if let Some(h) = &l.host {
            from.push_str(&format!(" in {h}"));
        }
        if let Some(m) = l.report.as_ref().and_then(|r| r.model.as_deref()) {
            from.push_str(&format!(", model {m} (self-reported)"));
        }
        println!(
            "{}  pid {}  {}/{}  [{}]  created {} ago  expires in {}  {}  ({}, {})",
            l.id,
            l.root_pid,
            l.project,
            l.env,
            l.scopes.join(","),
            human(now - l.created_at),
            human(l.expires_at - now),
            l.command,
            match l.started_by {
                ls_ipc::StartedBy::Agent => "agent",
                ls_ipc::StartedBy::Human => "human",
            },
            from
        );
    }
    Ok(ExitCode::Ok)
}

pub fn revoke(id: Option<String>) -> Result<ExitCode, Fail> {
    let Ok(mut c) = connect(false) else {
        println!("locksmithd is not running; no sessions exist");
        return Ok(ExitCode::Ok);
    };
    let Response::Revoked { count } = call(&mut c, &Request::Revoke { id: id.clone() })? else {
        return Err(fail(ExitCode::Failure, "unexpected daemon reply"));
    };
    if id.is_some() && count == 0 {
        return Err(fail(ExitCode::NotFound, "no such active session"));
    }
    println!("revoked {count} session(s)");
    Ok(ExitCode::Ok)
}

pub fn lock() -> Result<ExitCode, Fail> {
    match connect(false) {
        Ok(mut c) => {
            call(&mut c, &Request::Lock)?;
            println!("locked");
        }
        Err(_) => println!("locksmithd is not running; nothing to lock"),
    }
    Ok(ExitCode::Ok)
}

/// Is this process inside a lease? The env var is set only in the child of `smith session start`;
/// an agent-started session (M10b) is rooted at the already-running agent, so ask the daemon,
/// which answers by kernel ancestry. Never starts the daemon; any error means "no". Cached.
pub fn in_session() -> bool {
    static IN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *IN.get_or_init(|| {
        if std::env::var_os("LOCKSMITH_SESSION").is_some() {
            return true;
        }
        let Ok(mut c) = connect(false) else {
            return false;
        };
        let _ = c.stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = c.stream.set_write_timeout(Some(Duration::from_secs(2)));
        matches!(c.call(&Request::LeaseKeys), Ok(Response::Keys { .. }))
    })
}

/// `smith run` inside a session: always through the daemon, never a prompt or direct vault open.
pub fn run_via_daemon(
    project: Option<String>,
    env: Option<String>,
    keys: Vec<String>,
    all_keys: bool,
    cmd: Vec<String>,
    aws: Option<(String, bool)>,
) -> Result<ExitCode, Fail> {
    run_spec(project, env, keys, all_keys, cmd, None, aws)
}

/// `smith gh`: the daemon injects only GH_TOKEN.
pub fn run_gh(repo: Option<String>, cmd: Vec<String>) -> Result<ExitCode, Fail> {
    run_spec(
        None,
        None,
        vec![],
        false,
        cmd,
        Some(ls_ipc::GhSpec { repo }),
        None,
    )
}

/// `smith run` outside a session when the binding has `[http]` keys: their opaque tokens must
/// belong to a lease, so start one rooted here (passphrase as for any session; scopes `run` and
/// `http`), run through the daemon and end it when the child exits.
pub fn run_leased(
    o: &Opts,
    project: Option<String>,
    env: Option<String>,
    keys: Vec<String>,
    all_keys: bool,
    cmd: Vec<String>,
    aws: Option<(String, bool)>,
) -> Result<ExitCode, Fail> {
    let (project, env) = resolve(project, env)?;
    let mut c = connect(true)?;
    let pw = input::passphrase(o, "Passphrase: ")?;
    let req = Request::SessionStart {
        passphrase: Passphrase::new(pw.as_bytes().to_vec()),
        ttl_secs: 24 * 3600,
        project: project.clone(),
        env: env.clone(),
        scopes: vec!["run".into(), "http".into(), "aws".into()],
        command: format!("smith run -- {}", cmd.join(" ")),
        binding: run_cmd::bound()?.map(|(_, bytes)| bytes),
    };
    drop(pw);
    let Response::Session { .. } = call(&mut c, &req)? else {
        return Err(fail(ExitCode::Failure, "unexpected daemon reply"));
    };
    let code = run_spec_code(Some(project), Some(env), keys, all_keys, cmd, None, aws);
    let _ = c.call(&Request::SessionEnd);
    std::process::exit(code?);
}

fn run_spec(
    project: Option<String>,
    env: Option<String>,
    keys: Vec<String>,
    all_keys: bool,
    cmd: Vec<String>,
    gh: Option<ls_ipc::GhSpec>,
    aws: Option<(String, bool)>,
) -> Result<ExitCode, Fail> {
    let code = run_spec_code(project, env, keys, all_keys, cmd, gh, aws)?;
    std::process::exit(code);
}

/// Runs the command through the daemon; returns the child's exit code.
fn run_spec_code(
    project: Option<String>,
    env: Option<String>,
    keys: Vec<String>,
    all_keys: bool,
    cmd: Vec<String>,
    gh: Option<ls_ipc::GhSpec>,
    aws: Option<(String, bool)>,
) -> Result<i32, Fail> {
    let cwd = std::env::current_dir()
        .map_err(|e| fail(ExitCode::Failure, format!("no current dir: {e}")))?;
    let spec = RunSpec {
        project,
        env,
        keys,
        all_keys,
        binding: run_cmd::bound()?.map(|(_, bytes)| bytes),
        cmd,
        cwd,
        environ: std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .filter(|(k, _)| !k.starts_with("LOCKSMITH_"))
            .collect(),
        gh,
        aws_contained: aws.as_ref().is_some_and(|a| a.1),
        aws: aws.map(|a| a.0),
    };
    let mut c = connect(false).map_err(|Fail(_, m)| {
        fail(
            ExitCode::Locked,
            format!("{m}; start a session with `smith session start`"),
        )
    })?;
    c.send(&Request::Run(spec))
        .map_err(|e| fail(ExitCode::Locked, format!("locksmithd: {e}")))?;
    // If the daemon already refused, the error reply is still readable below.
    if let Err(e) = ls_platform::proc::send_fds(&c.stream, &[0, 1, 2]) {
        // The daemon may already have refused the request: prefer its reply if one is there.
        let _ = c.stream.set_read_timeout(Some(Duration::from_secs(2)));
        if let Ok(Response::Error { code, message }) = c.recv() {
            return Err(fail(exit_of(code), message));
        }
        return Err(fail(
            ExitCode::Failure,
            format!("cannot pass stdio to locksmithd: {e}"),
        ));
    }
    let mut tx = c
        .stream
        .try_clone()
        .map_err(|e| fail(ExitCode::Failure, e.to_string()))?;
    if let Ok(mut sigs) = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ]) {
        std::thread::spawn(move || {
            for sig in sigs.forever() {
                let _ = write_frame(&mut tx, &Request::Signal { sig });
            }
        });
    }
    loop {
        match c.recv() {
            Ok(Response::RunStarted { .. }) => {}
            Ok(Response::RunExited { code }) => return Ok(code),
            Ok(Response::Error { code, message }) => return Err(fail(exit_of(code), message)),
            Ok(_) => return Err(fail(ExitCode::Failure, "unexpected daemon reply")),
            Err(e) => return Err(fail(ExitCode::Locked, format!("lost locksmithd: {e}"))),
        }
    }
}

// ---- smith daemon install|uninstall|status ----

#[derive(Subcommand)]
pub enum DaemonCmd {
    /// Start locksmithd at login (LaunchAgent on macOS, systemd user unit on Linux).
    Install,
    Uninstall,
    Status,
}

const PLIST: &str = include_str!("../../locksmithd/dist/dev.locksmith.locksmithd.plist");
const UNIT: &str = include_str!("../../locksmithd/dist/locksmithd.service");
const LABEL: &str = "dev.locksmith.locksmithd";

pub fn render_plist(bin: &Path) -> String {
    let p = bin.display().to_string();
    let esc = p
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    PLIST.replace("{{LOCKSMITHD}}", &esc)
}

pub fn render_unit(bin: &Path) -> String {
    UNIT.replace("{{LOCKSMITHD}}", &format!("\"{}\"", bin.display()))
}

fn sh(prog: &str, args: &[&str]) -> Result<(), Fail> {
    let ok = Command::new(prog)
        .args(args)
        .status()
        .is_ok_and(|s| s.success());
    ok.then_some(()).ok_or_else(|| {
        fail(
            ExitCode::Failure,
            format!("`{prog} {}` failed", args.join(" ")),
        )
    })
}

fn unit_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    if cfg!(target_os = "macos") {
        home.join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map_or(home.join(".config"), PathBuf::from)
            .join("systemd/user/locksmithd.service")
    }
}

pub fn daemon(cmd: DaemonCmd) -> Result<ExitCode, Fail> {
    let mac = cfg!(target_os = "macos");
    let path = unit_path();
    let domain = format!("gui/{}", ls_platform::current_uid());
    match cmd {
        DaemonCmd::Install => {
            let bin = sibling("locksmithd")?;
            let io =
                |e: std::io::Error| fail(ExitCode::Failure, format!("{}: {e}", path.display()));
            std::fs::create_dir_all(path.parent().expect("has parent")).map_err(io)?;
            std::fs::write(
                &path,
                if mac {
                    render_plist(&bin)
                } else {
                    render_unit(&bin)
                },
            )
            .map_err(io)?;
            let p = path.to_string_lossy();
            if mac {
                let _ = sh("launchctl", &["bootout", &format!("{domain}/{LABEL}")]);
                sh("launchctl", &["bootstrap", &domain, &p])?;
            } else {
                sh("systemctl", &["--user", "daemon-reload"])?;
                sh("systemctl", &["--user", "enable", "--now", "locksmithd"])?;
            }
            println!("installed {}", path.display());
        }
        DaemonCmd::Uninstall => {
            if mac {
                let _ = sh("launchctl", &["bootout", &format!("{domain}/{LABEL}")]);
            } else {
                let _ = sh("systemctl", &["--user", "disable", "--now", "locksmithd"]);
            }
            let _ = std::fs::remove_file(&path);
            if !mac {
                let _ = sh("systemctl", &["--user", "daemon-reload"]);
            }
            println!("uninstalled");
        }
        DaemonCmd::Status => match connect(false).map(|mut c| c.call(&Request::Ping)) {
            Ok(Ok(Response::Pong { version })) => {
                println!(
                    "running (version {version}, socket {})",
                    ls_ipc::socket_path().display()
                );
            }
            _ => return Err(fail(ExitCode::Failure, "not running")),
        },
    }
    Ok(ExitCode::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_parsing() {
        assert_eq!(parse_ttl("90s"), Ok(90));
        assert_eq!(parse_ttl("30m"), Ok(1800));
        assert_eq!(parse_ttl("8h"), Ok(28800));
        assert_eq!(parse_ttl("45"), Ok(45));
        assert!(parse_ttl("0s").is_err() && parse_ttl("h").is_err() && parse_ttl("").is_err());
    }

    #[test]
    fn renders_unit_files_with_the_real_path() {
        let bin = Path::new("/opt/a & b/locksmithd");
        let p = render_plist(bin);
        assert!(p.contains("<string>/opt/a &amp; b/locksmithd</string>") && !p.contains("{{"));
        assert!(p.contains("RunAtLoad") && p.contains("KeepAlive"));
        let u = render_unit(bin);
        assert!(u.contains("ExecStart=\"/opt/a & b/locksmithd\"") && !u.contains("{{"));
    }
}
