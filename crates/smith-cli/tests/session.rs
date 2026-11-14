//! e2e for the daemon and sessions: real `smith` and `locksmithd` binaries, one throwaway
//! LOCKSMITH_HOME (and runtime dir) per test, daemon killed on drop.

mod common;
use common::*;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Once;
use std::time::{Duration, Instant};

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn bin_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_smith"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn locksmithd() -> PathBuf {
    static BUILD: Once = Once::new();
    let p = bin_dir().join("locksmithd");
    BUILD.call_once(|| {
        if !p.exists() {
            let cargo = std::env::var("CARGO").unwrap_or("cargo".into());
            assert!(
                Command::new(cargo)
                    .args(["build", "-p", "locksmithd"])
                    .status()
                    .unwrap()
                    .success()
            );
        }
    });
    p
}

/// A home plus its own runtime dir; kills whatever daemon it started.
struct Env {
    h: Home,
    run: PathBuf,
    work: PathBuf,
}

impl Env {
    fn new() -> Env {
        // smith auto-starts the sibling locksmithd; `cargo test` does not build other packages'
        // binaries, so build it once up front (racing per-test builds made CI flaky).
        locksmithd();
        let h = Home::new();
        let run = std::env::temp_dir().join(format!(
            "lsr-{}",
            h.0.file_name()
                .unwrap()
                .to_string_lossy()
                .replace("smith-e2e-", "")
        ));
        let work = h.0.join("work");
        std::fs::create_dir_all(&work).unwrap();
        Env { h, run, work }
    }

    fn smith(&self, args: &[&str]) -> Command {
        let mut c = self.h.cmd(&[]);
        c.args(args)
            .current_dir(&self.work)
            .env("LOCKSMITH_RUNTIME_DIR", &self.run)
            .env(
                "PATH",
                format!("{}:{}", bin_dir().display(), std::env::var("PATH").unwrap()),
            );
        c
    }

    fn out(&self, args: &[&str]) -> Output {
        let mut c = self.smith(args);
        c.stdin(Stdio::null());
        c.output().unwrap()
    }

    /// `smith session start [extra] -- sh -c script`, passphrase on stdin; returns the child.
    fn session(&self, extra: &[&str], script: &str) -> std::process::Child {
        let mut args = vec!["--passphrase-stdin", "session", "start"];
        args.extend_from_slice(extra);
        args.extend(["--", "sh", "-c", script]);
        let mut c = self.smith(&args).spawn().unwrap();
        c.stdin
            .take()
            .unwrap()
            .write_all(format!("{PW}\n").as_bytes())
            .unwrap();
        c
    }

    fn daemon(&self) -> Command {
        let mut c = Command::new(locksmithd());
        c.env("LOCKSMITH_HOME", &self.h.0)
            .env("LOCKSMITH_RUNTIME_DIR", &self.run)
            .env("LOCKSMITH_INSECURE_TEST_KDF", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        c
    }

    fn daemon_pid(&self) -> Option<i32> {
        std::fs::read_to_string(self.run.join("locksmithd.lock"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn kill_daemon(&self, sig: &str) {
        if let Some(p) = self.daemon_pid() {
            let _ = Command::new("kill")
                .args([&format!("-{sig}"), &p.to_string()])
                .status();
        }
    }

    /// Vault with two keys, K and K2.
    fn setup(&self) -> String {
        let phrase = self.h.ready();
        assert!(self.h.add("K", "fake_key_value_one_4242").status.success());
        assert!(self.h.add("K2", "fake_key_value_two_4343").status.success());
        phrase
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        self.kill_daemon("KILL");
        let _ = std::fs::remove_dir_all(&self.run);
    }
}

fn wait_for(p: &Path) {
    let t = Instant::now();
    while !p.exists() {
        assert!(
            t.elapsed() < Duration::from_secs(30),
            "timed out waiting for {}",
            p.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

const INNER: &str = r#"smith run --only K -- sh -c 'test -n "$K" && echo injected'"#;

#[test]
fn second_instance_exits_with_message() {
    let e = Env::new();
    e.h.ready();
    let mut first = e.daemon().spawn().unwrap();
    wait_for(&e.run.join("locksmithd.sock"));
    let o = e.daemon().output().unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(
        s(&o.stderr).contains("already running (pid"),
        "{}",
        s(&o.stderr)
    );
    let _ = first.kill();
    let _ = first.wait();
}

#[test]
fn restart_fails_closed() {
    let e = Env::new();
    e.setup();
    let ready = e.work.join("ready");
    let go = e.work.join("go");
    let script = format!(
        "touch {}; while [ ! -e {} ]; do sleep 0.1; done; {INNER}; echo \"rc=$?\"",
        ready.display(),
        go.display()
    );
    let agent = e.session(&[], &script);
    wait_for(&ready);
    e.kill_daemon("KILL");
    let mut d = e.daemon().spawn().unwrap();
    wait_for(&e.run.join("locksmithd.sock"));
    std::fs::write(&go, "").unwrap();
    let o = agent.wait_with_output().unwrap();
    let out = s(&o.stdout);
    assert!(out.contains("rc=4"), "stdout={out} stderr={}", s(&o.stderr));
    let _ = d.kill();
    let _ = d.wait();
}

#[test]
fn descendant_allowed_without_prompt_and_value_never_printed() {
    let e = Env::new();
    e.setup();
    let o = e.session(&[], INNER).wait_with_output().unwrap();
    let (out, err) = (s(&o.stdout), s(&o.stderr));
    assert!(o.status.success(), "{err}");
    assert_eq!(out.trim(), "injected");
    assert!(!out.contains("fake_key_value") && !err.contains("fake_key_value"));
}

#[test]
fn outsider_with_forged_session_is_denied() {
    let e = Env::new();
    e.setup();
    let ready = e.work.join("ready");
    let go = e.work.join("go");
    let script = format!(
        "touch {}; while [ ! -e {} ]; do sleep 0.1; done",
        ready.display(),
        go.display()
    );
    let agent = e.session(&[], &script);
    wait_for(&ready);
    let st = e.out(&["status", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&st.stdout).unwrap();
    let id = v["sessions"][0]["id"].as_str().unwrap().to_string();
    let mut c = e.smith(&["run", "--only", "K", "--", "true"]);
    c.env("LOCKSMITH_SESSION", &id).stdin(Stdio::null());
    let o = c.output().unwrap();
    assert_eq!(o.status.code(), Some(4), "{}", s(&o.stderr));
    std::fs::write(&go, "").unwrap();
    agent.wait_with_output().unwrap();
}

/// An unlocked daemon must not hand a lease to any attested smith (e.g. one an agent
/// double-forked out of its tree): every session start proves the passphrase again.
#[test]
fn session_start_needs_passphrase_even_when_unlocked() {
    let e = Env::new();
    e.setup();
    let ready = e.work.join("ready");
    let go = e.work.join("go");
    let script = format!(
        "touch {}; while [ ! -e {} ]; do sleep 0.1; done",
        ready.display(),
        go.display()
    );
    let agent = e.session(&[], &script);
    wait_for(&ready);
    let mut p = e
        .smith(&["--passphrase-stdin", "session", "start", "--", "true"])
        .spawn()
        .unwrap();
    p.stdin
        .take()
        .unwrap()
        .write_all(b"not the passphrase\n")
        .unwrap();
    let o = p.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(3), "{}", s(&o.stderr));
    let st = e.out(&["status", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&st.stdout).unwrap();
    assert_eq!(
        v["sessions"].as_array().unwrap().len(),
        1,
        "no second lease"
    );
    std::fs::write(&go, "").unwrap();
    agent.wait_with_output().unwrap();
}

#[test]
fn ttl_expiry_exits_4() {
    let e = Env::new();
    e.setup();
    let script = format!("sleep 3; {INNER}; echo \"rc=$?\"");
    let o = e
        .session(&["--ttl", "2s"], &script)
        .wait_with_output()
        .unwrap();
    assert!(
        s(&o.stdout).contains("rc=4"),
        "{} {}",
        s(&o.stdout),
        s(&o.stderr)
    );
}

#[test]
fn revoke_blocks_next_run_and_is_audited() {
    let e = Env::new();
    e.setup();
    let ready = e.work.join("ready");
    let go = e.work.join("go");
    let script = format!(
        "smith run --only K,K2 -- true; touch {}; while [ ! -e {} ]; do sleep 0.1; done; {INNER}; echo \"rc=$?\"",
        ready.display(),
        go.display()
    );
    let agent = e.session(&[], &script);
    wait_for(&ready);
    let o = e.out(&["revoke", "--all"]);
    assert!(o.status.success(), "{}", s(&o.stderr));
    std::fs::write(&go, "").unwrap();
    let o = agent.wait_with_output().unwrap();
    assert!(s(&o.stdout).contains("rc=4"), "{}", s(&o.stdout));

    // Daemon is still unlocked, so the listing comes from it with no passphrase.
    let o = e.out(&["audit", "ls", "--json", "--limit", "100"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let ev = v["events"].as_array().unwrap();
    let n = |a: &str| ev.iter().filter(|e| e["action"] == a).count();
    assert_eq!(n("REVOKE"), 1);
    assert_eq!(n("ACCESS"), 2);
    assert!(n("BLOCKED") >= 1);
    assert!(!s(&o.stdout).contains("fake_key_value"));
}

#[test]
fn status_lists_two_sessions() {
    let e = Env::new();
    e.setup();
    let mut gos = vec![];
    let mut agents = vec![];
    for i in 0..2 {
        let go = e.work.join(format!("go{i}"));
        let ready = e.work.join(format!("ready{i}"));
        let script = format!(
            "touch {}; while [ ! -e {} ]; do sleep 0.1; done",
            ready.display(),
            go.display()
        );
        agents.push(e.session(&["--ttl", "1h"], &script));
        wait_for(&ready);
        gos.push(go);
    }
    let o = e.out(&["status", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["locked"], false);
    let ss = v["sessions"].as_array().unwrap();
    assert_eq!(ss.len(), 2, "{v}");
    for k in [
        "id",
        "root_pid",
        "command",
        "project",
        "env",
        "scopes",
        "created_at",
        "expires_at",
    ] {
        assert!(ss[0].get(k).is_some(), "missing {k}");
    }
    assert!(s(&e.out(&["status"]).stdout).contains("default/development"));
    gos.iter().for_each(|g| std::fs::write(g, "").unwrap());
    agents.into_iter().for_each(|a| {
        a.wait_with_output().unwrap();
    });
}

#[test]
fn lock_then_run_needs_new_session_and_audit_full_verify_passes() {
    let e = Env::new();
    let phrase = e.setup();
    assert!(
        e.session(&[], INNER)
            .wait_with_output()
            .unwrap()
            .status
            .success()
    );
    assert!(e.out(&["lock"]).status.success());
    assert!(s(&e.out(&["status"]).stdout).contains("vault: locked"));

    // Locked daemon: audit verify falls back to opening the vault directly.
    let o = e.h.run(&["audit", "verify"], "");
    assert!(o.status.success(), "{}", s(&o.stderr));
    let o = e.h.run_pw(&phrase, &["audit", "verify", "--full"], "");
    assert!(o.status.success(), "{}", s(&o.stderr));
    assert!(s(&o.stdout).contains("audit ledger ok"));
}

#[test]
fn idle_timeout_locks_the_vault() {
    let e = Env::new();
    e.setup();
    let mut d = e.daemon();
    d.env("LOCKSMITH_IDLE_LOCK_SECS", "1");
    let mut d = d.spawn().unwrap();
    wait_for(&e.run.join("locksmithd.sock"));
    let mut sess = e.session(&[], "true");
    assert!(sess.wait().unwrap().success());
    std::thread::sleep(Duration::from_secs(3));
    assert!(s(&e.out(&["status"]).stdout).contains("vault: locked"));
    let _ = d.kill();
    let _ = d.wait();
}

/// tasks.md 2.3: the daemon is non-dumpable, so the same user cannot open its memory, while an
/// ordinary child of this test can be opened (the control: Yama allows descendants).
#[cfg(target_os = "linux")]
#[test]
fn same_user_cannot_read_daemon_memory() {
    let e = Env::new();
    e.h.ready();
    let mut d = e.daemon().spawn().unwrap();
    wait_for(&e.run.join("locksmithd.sock"));
    let pid = e.daemon_pid().unwrap();
    let r = std::fs::File::open(format!("/proc/{pid}/mem"));
    assert_eq!(
        r.err().map(|e| e.kind()),
        Some(std::io::ErrorKind::PermissionDenied),
        "opened /proc/{pid}/mem of the daemon"
    );
    let mut control = Command::new("sleep").arg("5").spawn().unwrap();
    assert!(std::fs::File::open(format!("/proc/{}/mem", control.id())).is_ok());
    let _ = control.kill();
    let _ = control.wait();
    let _ = d.kill();
    let _ = d.wait();
}
