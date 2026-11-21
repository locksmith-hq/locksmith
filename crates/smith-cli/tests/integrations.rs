//! Smoke test for the generated agent integrations (`integrations/gemini-cli`, `integrations/copilot`):
//! the shipped hook command is run exactly as the agent would run it (`sh -c`, `smith` on PATH) and
//! must reproduce the recorded decisions from `crates/ls-hooks/tests/fixtures`.

use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn json(p: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{p:?}: {e}")))
        .unwrap()
}

/// A temp dir holding a `smith` symlink to the binary under test, plus a work dir with `.env`.
fn sandbox(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let base = std::env::temp_dir().join(format!("lsint-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let bin = base.join("bin");
    let work = base.join("work");
    let home = base.join("home");
    for d in [&bin, &work, &home] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_smith"), bin.join("smith")).unwrap();
    std::fs::write(work.join(".env"), "A=1\n").unwrap();
    (bin, work, home)
}

fn run_hook(
    command: &str,
    bin: &Path,
    work: &Path,
    home: &Path,
    stdin: &str,
    path: &str,
) -> (Option<i32>, String, String) {
    let mut c = Command::new("sh")
        .args(["-c", command])
        .current_dir(work)
        .env("PATH", path.replace("__BIN__", &bin.to_string_lossy()))
        .env("LOCKSMITH_HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = c.stdin.take().unwrap().write_all(stdin.as_bytes());
    let o = c.wait_with_output().unwrap();
    (
        o.status.code(),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// Replays every fixture of `agent` whose event is `event` through `command`.
fn replay(agent: &str, event: &str, command: &str) {
    let (bin, work, home) = sandbox(agent);
    let dir = root().join("crates/ls-hooks/tests/fixtures").join(agent);
    let path = format!(
        "{}:{}",
        "__BIN__",
        std::env::var("PATH").unwrap_or_default()
    );
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".in.json") else {
            continue;
        };
        let raw = std::fs::read_to_string(&p).unwrap();
        // Fixtures that need a vault key stay in the ls-hooks golden test.
        if raw.contains("__KEY__") {
            continue;
        }
        let input = raw.replace("__CWD__", &work.to_string_lossy());
        // Copilot payloads carry no event name; its hook file does.
        let ev = serde_json::from_str::<Value>(&input)
            .ok()
            .and_then(|v| v["hook_event_name"].as_str().map(String::from))
            .unwrap_or_else(|| {
                if agent == "copilot" {
                    "preToolUse"
                } else {
                    "BeforeTool"
                }
                .into()
            });
        if ev != event {
            continue;
        }
        let want = json(&dir.join(format!("{stem}.out.json")));
        let (code, out, err) = run_hook(command, &bin, &work, &home, &input, &path);
        assert_eq!(
            code.map(i64::from),
            want["code"].as_i64(),
            "{agent}/{stem} exit code"
        );
        match &want["stdout"] {
            Value::Null => assert!(out.trim().is_empty(), "{agent}/{stem} stdout: {out}"),
            v => assert_eq!(
                &serde_json::from_str::<Value>(&out).unwrap(),
                v,
                "{agent}/{stem}"
            ),
        }
        if let Some(s) = want["stderr"].as_str() {
            assert_eq!(err.trim(), s, "{agent}/{stem} stderr");
        }
        n += 1;
    }
    assert!(n > 0, "no fixtures replayed for {agent} {event}");
}

#[test]
fn gemini_cli_integration_replays_recorded_fixtures() {
    let v = json(&root().join("integrations/gemini-cli/settings.json"));
    for event in ["BeforeTool", "BeforeAgent"] {
        let cmd = v["hooks"][event][0]["hooks"][0]["command"]
            .as_str()
            .unwrap();
        replay("gemini-cli", event, cmd);
    }
}

#[test]
fn copilot_integration_replays_recorded_fixtures() {
    let v = json(&root().join("integrations/copilot/hooks/locksmith.json"));
    let cmd = v["hooks"]["preToolUse"][0]["bash"].as_str().unwrap();
    assert_eq!(v["hooks"]["preToolUse"][0]["timeoutSec"], 10);
    // every Copilot fixture is a preToolUse payload; malformed input fails closed too
    replay("copilot", "preToolUse", cmd);
}

/// With `smith` missing from PATH the shipped wrapper must block (exit 2) and say why.
#[test]
fn integrations_fail_closed_without_smith() {
    let (bin, work, home) = sandbox("nosmith");
    let v = json(&root().join("integrations/copilot/hooks/locksmith.json"));
    let cmd = v["hooks"]["preToolUse"][0]["bash"].as_str().unwrap();
    let (code, _, err) = run_hook(cmd, &bin, &work, &home, "{}", "/usr/bin:/bin");
    assert_eq!(code, Some(2));
    assert!(err.contains("smith doctor"), "{err}");
}
