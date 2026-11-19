//! e2e for `smith run`, `env-template`, `init --binding-only`: real binary, throwaway home.

mod common;
use common::*;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const DB: &str = "postgres://app:DBPASS_canary_77881@db/app";

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Initialised vault holding DATABASE_URL and STRIPE_KEY, plus an empty work dir.
fn setup() -> (Home, PathBuf) {
    let h = Home::new();
    h.ready();
    assert!(h.add("DATABASE_URL", DB).status.success());
    assert!(h.add("STRIPE_KEY", VALUE).status.success());
    let work = h.0.join("work");
    std::fs::create_dir_all(&work).unwrap();
    (h, work)
}

/// `smith --passphrase-stdin <args>` in `work`, stdout/stderr piped (so pipe mode).
fn smith(h: &Home, work: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut c = h.cmd(&[]);
    c.args(["--passphrase-stdin"]).args(args).current_dir(work);
    c.envs(envs.iter().copied());
    let mut child = c.spawn().unwrap();
    let _ = child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PW}\n").as_bytes());
    child.wait_with_output().unwrap()
}

fn bind(work: &Path, body: &str) {
    std::fs::write(work.join(".locksmith.toml"), body).unwrap();
}

#[test]
fn exit_code_passes_through() {
    let (h, w) = setup();
    let o = smith(&h, &w, &["run", "--yes", "--", "sh", "-c", "exit 7"], &[]);
    assert_eq!(o.status.code(), Some(7), "{}", s(&o.stderr));
    let o = smith(
        &h,
        &w,
        &["run", "--yes", "--", "sh", "-c", "kill -TERM $$"],
        &[],
    );
    assert_eq!(o.status.code(), Some(128 + 15));
}

#[test]
fn locksmith_vars_are_stripped() {
    let (h, w) = setup();
    let o = smith(
        &h,
        &w,
        &["run", "--only", "DATABASE_URL", "--", "sh", "-c", "env"],
        &[("LOCKSMITH_OTHER", "x")],
    );
    let out = s(&o.stdout);
    assert!(o.status.success(), "{}", s(&o.stderr));
    assert!(!out.contains("LOCKSMITH_"), "leaked: {out}");
    assert!(out.contains("DATABASE_URL="), "bound key missing");
}

#[test]
fn only_bound_keys_are_injected() {
    let (h, w) = setup();
    bind(
        &w,
        "project = \"default\"\nenv = \"development\"\nkeys = [\"DATABASE_URL\"]\n",
    );
    let script = "echo db=${DATABASE_URL:+set} stripe=${STRIPE_KEY:+set}";
    let o = smith(&h, &w, &["run", "--", "sh", "-c", script], &[]);
    assert_eq!(s(&o.stdout).trim(), "db=set stripe=", "{}", s(&o.stderr));
    // --only overrides the binding's list
    let o = smith(
        &h,
        &w,
        &["run", "--only", "STRIPE_KEY", "--", "sh", "-c", script],
        &[],
    );
    assert_eq!(s(&o.stdout).trim(), "db= stripe=set");
}

#[test]
fn without_binding_needs_confirmation() {
    let (h, w) = setup();
    let o = smith(&h, &w, &["run", "--", "true"], &[]);
    assert_eq!(o.status.code(), Some(3), "no tty and no --yes must refuse");
}

#[test]
fn secret_in_binding_exits_3_naming_line() {
    let (h, w) = setup();
    bind(
        &w,
        &format!("project = \"default\"\ntoken = \"{VALUE}\"\nkeys = []\n"),
    );
    let o = smith(&h, &w, &["run", "--", "true"], &[]);
    assert_eq!(o.status.code(), Some(3));
    let err = s(&o.stderr);
    assert!(err.contains("line 2"), "{err}");
    assert!(!err.contains(VALUE) && !s(&o.stdout).contains(VALUE));
}

#[test]
fn child_output_is_redacted_in_every_form_and_stream() {
    let (h, w) = setup();
    bind(&w, "keys = [\"STRIPE_KEY\"]\n");
    let b64 = {
        let mut c = Command::new("base64")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(VALUE.as_bytes()).unwrap();
        s(&c.wait_with_output().unwrap().stdout).trim().to_string()
    };
    let script = r#"
import os, sys, time, base64
v = os.environ["STRIPE_KEY"]
print("plain:" + v); print("b64:" + base64.b64encode(v.encode()).decode())
print("err:" + v, file=sys.stderr, flush=True)
sys.stdout.write("slow:"); sys.stdout.flush()
for c in v:
    sys.stdout.write(c); sys.stdout.flush(); time.sleep(0.003)
print()
"#;
    let o = smith(&h, &w, &["run", "--", "python3", "-c", script], &[]);
    let (out, err) = (s(&o.stdout), s(&o.stderr));
    assert!(o.status.success(), "{err}");
    for hay in [&out, &err] {
        assert!(!hay.contains(VALUE) && !hay.contains(&b64), "leak: {hay}");
    }
    assert_eq!(out.matches("[REDACTED:STRIPE_KEY]").count(), 3, "{out}");
    assert!(err.contains("err:[REDACTED:STRIPE_KEY]"), "{err}");
}

#[test]
fn explain_and_env_template() {
    let (h, w) = setup();
    let o = smith(&h, &w, &["run", "--explain"], &[]);
    let t = s(&o.stdout);
    assert!(o.status.success());
    for k in [
        "same OS user",
        "child process can read",
        "smith git",
        "smith http",
        "smith db",
        "smith aws",
    ] {
        assert!(t.contains(k), "missing {k:?}");
    }
    // no binding: names come from the vault; with a binding: from the file
    let o = smith(&h, &w, &["env-template"], &[]);
    assert_eq!(
        s(&o.stdout),
        "DATABASE_URL=\nSTRIPE_KEY=\n",
        "{}",
        s(&o.stderr)
    );
    bind(&w, "keys = [\"STRIPE_KEY\"]\n");
    let o = smith(&h, &w, &["env-template"], &[]);
    assert_eq!(s(&o.stdout), "STRIPE_KEY=\n");
}

#[test]
fn init_binding_only_writes_once() {
    let (h, w) = setup();
    let o = smith(&h, &w, &["init", "--binding-only"], &[]);
    assert!(o.status.success(), "{}", s(&o.stderr));
    let f = std::fs::read_to_string(w.join(".locksmith.toml")).unwrap();
    assert!(f.contains("project = \"default\""));
    assert!(
        !smith(&h, &w, &["init", "--binding-only"], &[])
            .status
            .success()
    );
}

// ---- PTY mode, driven by `expect` (smith sees a real terminal on stdin and stdout) ----

const TCL: &str = r#"
set timeout 15
log_user 0
spawn {*}$argv
send "$env(TEST_PW)\r"
expect {
  "x> " { puts "SEEN=[clock milliseconds]" }
  timeout { puts "NOPROMPT"; exit 1 }
}
send "hello\r"
expect eof
puts "OUT=$expect_out(buffer)"
catch wait r
puts "EXIT=[lindex $r 3]"
"#;

const TCL_SIGNALS: &str = r#"
set timeout 15
log_user 0
spawn {*}$argv
send "$env(TEST_PW)\r"
expect "ready" 
stty rows 33 columns 77 < $spawn_out(slave,name)
expect "33 77"
send "\003"
expect eof
puts "OUT=$expect_out(buffer)"
catch wait r
puts "EXIT=[lindex $r 3]"
"#;

fn expect(h: &Home, w: &Path, tcl: &str, args: &[&str]) -> Option<String> {
    if Command::new("expect").arg("-v").output().is_err() {
        eprintln!("expect not installed; skipping PTY test");
        return None;
    }
    let f = h.0.join("t.exp");
    std::fs::write(&f, tcl).unwrap();
    let o = Command::new("expect")
        .arg("-f")
        .arg(&f)
        .arg(env!("CARGO_BIN_EXE_smith"))
        .arg("--passphrase-stdin")
        .args(args)
        .current_dir(w)
        .env("LOCKSMITH_HOME", &h.0)
        .env("LOCKSMITH_INSECURE_TEST_KDF", "1")
        .env("TEST_PW", PW)
        .env_remove("CLAUDECODE")
        .output()
        .unwrap();
    Some(s(&o.stdout))
}

fn field<'a>(out: &'a str, k: &str) -> &'a str {
    let i = out
        .find(&format!("{k}="))
        .unwrap_or_else(|| panic!("no {k} in {out}"))
        + k.len()
        + 1;
    out[i..].lines().next().unwrap().trim()
}

#[test]
fn pty_prompt_appears_promptly_and_output_is_redacted() {
    let (h, w) = setup();
    let py = r#"
import sys, os, time
t = int(time.time() * 1000)
sys.stdout.write("x> "); sys.stdout.flush()
l = input()
print("WROTE=%d" % t); print("GOT:" + l); print("KEY:" + os.environ["STRIPE_KEY"]); sys.exit(5)
"#;
    // Shared CI runners stall for tens of ms at random; the latency bound must hold on the best
    // of three runs (correctness is asserted on every run).
    let mut best = i64::MAX;
    for _ in 0..3 {
        let Some(out) = expect(
            &h,
            &w,
            TCL,
            &["run", "--only", "STRIPE_KEY", "--", "python3", "-c", py],
        ) else {
            return;
        };
        assert!(!out.contains(VALUE), "leak: {out}");
        assert!(
            out.contains("GOT:hello") && out.contains("KEY:[REDACTED:STRIPE_KEY]"),
            "{out}"
        );
        assert_eq!(field(&out, "EXIT"), "5", "{out}");
        let ms = field(&out, "SEEN").parse::<i64>().unwrap()
            - field(&out, "WROTE").parse::<i64>().unwrap();
        best = best.min(ms);
    }
    // macOS CI runners are slower and noisier than Linux ones (observed 64 ms best of 3).
    let bound = if cfg!(target_os = "macos") { 150 } else { 50 };
    assert!(best < bound, "prompt took {best} ms (best of 3)");
}

#[test]
fn pty_forwards_resize_and_sigint() {
    let (h, w) = setup();
    let sh = r#"trap 'stty size' WINCH; trap 'echo GOT_INT; exit 3' INT; echo ready; while :; do sleep 0.1; done"#;
    let Some(out) = expect(
        &h,
        &w,
        TCL_SIGNALS,
        &["run", "--only", "STRIPE_KEY", "--", "sh", "-c", sh],
    ) else {
        return;
    };
    assert!(out.contains("GOT_INT"), "{out}");
    assert_eq!(field(&out, "EXIT"), "3", "{out}");
}
