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
                match agent {
                    "copilot" => "preToolUse",
                    "opencode" => "tool.execute.before",
                    "kiro" => "PreToolUse",
                    _ => "BeforeTool",
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

/// Cline: the shipped script is run as Cline would run it (executable, JSON on stdin) and must
/// reproduce the recorded decisions for the extension and the SDK payloads.
#[test]
fn cline_integration_replays_recorded_fixtures() {
    use std::os::unix::fs::PermissionsExt;
    let script = root().join("integrations/cline/PreToolUse");
    let mode = std::fs::metadata(&script).unwrap().permissions().mode();
    assert_ne!(mode & 0o111, 0, "the hook script must be executable");
    let text = std::fs::read_to_string(&script).unwrap();
    assert!(text.starts_with("#!/bin/sh\n"), "{text}");
    let (bin, work, home) = sandbox("cline");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let dir = root().join("crates/ls-hooks/tests/fixtures/cline");
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".in.json") else {
            continue;
        };
        let raw = std::fs::read_to_string(&p).unwrap();
        if raw.contains("__KEY__") {
            continue;
        }
        let input = raw.replace("__CWD__", &work.to_string_lossy());
        let want = json(&dir.join(format!("{stem}.out.json")));
        let (code, out, _) = run_hook(&script.to_string_lossy(), &bin, &work, &home, &input, &path);
        assert_eq!(
            code.map(i64::from),
            want["code"].as_i64(),
            "cline/{stem} exit code"
        );
        match &want["stdout"] {
            Value::Null => assert!(out.trim().is_empty(), "cline/{stem} stdout: {out}"),
            v => assert_eq!(
                &serde_json::from_str::<Value>(&out).unwrap(),
                v,
                "cline/{stem}"
            ),
        }
        n += 1;
    }
    assert!(n > 0, "no cline fixtures replayed");
    // without `smith` the script blocks in Cline's shape (and exits 0)
    let (code, out, _) = run_hook(
        &script.to_string_lossy(),
        &bin,
        &work,
        &home,
        "{}",
        "/usr/bin:/bin",
    );
    assert_eq!(code, Some(0));
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap()["cancel"],
        true,
        "{out}"
    );
}

/// Windsurf stays gated: no hook handler yet, so the README must say it is not protected and
/// every shipped command must name `smith hook windsurf`.
#[test]
fn windsurf_integration_is_labelled_not_protected() {
    assert!(!smith_agents_ready());
    let readme = std::fs::read_to_string(root().join("integrations/windsurf/README.md")).unwrap();
    assert!(readme.contains("unknown, not protected"), "{readme}");
    let v = json(&root().join("integrations/windsurf/hooks.json"));
    for ev in ["pre_read_code", "pre_run_command", "pre_user_prompt"] {
        let c = v["hooks"][ev][0]["command"].as_str().unwrap();
        assert!(c.contains(&format!("smith hook windsurf {ev}")), "{c}");
    }
}

fn smith_agents_ready() -> bool {
    // `smith doctor` reports Windsurf as unknown until a fixture confirms the format.
    let o = Command::new(env!("CARGO_BIN_EXE_smith"))
        .args(["hook", "windsurf", "pre_run_command"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    o.status.success()
}

/// Kiro: the shipped hook file is a versioned list; its `PreToolUse` command is run as Kiro would
/// (`sh -c`, JSON on stdin) and must reproduce the doc-derived decisions (non-zero exit blocks).
#[test]
fn kiro_integration_replays_fixtures() {
    let v = json(&root().join("integrations/kiro/hooks/locksmith.json"));
    assert_eq!(v["version"], "v1");
    let hook = &v["hooks"][0];
    assert_eq!(hook["trigger"], "PreToolUse");
    assert_eq!(hook["action"]["type"], "command");
    let cmd = hook["action"]["command"].as_str().unwrap();
    replay("kiro", "PreToolUse", cmd);
    // without `smith` the wrapper blocks (exit 2) with a visible reason
    let (bin, work, home) = sandbox("kiro-nosmith");
    let (code, _, err) = run_hook(cmd, &bin, &work, &home, "{}", "/usr/bin:/bin");
    assert_eq!(code, Some(2));
    assert!(err.contains("smith doctor"), "{err}");
}

const PLUGIN_RUNNER: &str = r#"import { pathToFileURL } from "node:url";
const [, , plugin, payload] = process.argv;
const { Locksmith } = await import(pathToFileURL(plugin).href);
const hooks = await Locksmith();
const { tool, args } = JSON.parse(payload);
try {
  await hooks["tool.execute.before"]({ tool }, { args });
  console.log("ALLOW");
} catch (e) {
  console.log("DENY:" + e.message);
}
"#;

/// OpenCode: the generated plugin is loaded with `node` and its `tool.execute.before` must throw
/// exactly where `smith hook opencode` denies, and throw when `smith` is not on PATH. Skipped with
/// a note when `node` is absent.
#[test]
fn opencode_plugin_runs_under_node_and_throws_on_deny() {
    let node = std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join("node"))
            .find(|n| n.is_file())
    });
    let Some(node) = node else {
        println!("skip: `node` is not on PATH, the OpenCode plugin was not executed");
        return;
    };
    let (bin, work, home) = sandbox("opencode");
    // `.mjs` so node loads the ES module whatever its version's default for `.js` is.
    let plugin = work.join("locksmith.mjs");
    std::fs::copy(
        root().join("integrations/opencode/plugins/locksmith.js"),
        &plugin,
    )
    .unwrap();
    let runner = work.join("runner.mjs");
    std::fs::write(&runner, PLUGIN_RUNNER).unwrap();
    let run = |payload: &str, path: &str| {
        let o = Command::new(&node)
            .arg(&runner)
            .arg(&plugin)
            .arg(payload)
            .current_dir(&work)
            .env("PATH", path)
            .env("LOCKSMITH_HOME", &home)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    };
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let dir = root().join("crates/ls-hooks/tests/fixtures/opencode");
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".in.json") else {
            continue;
        };
        let input = std::fs::read_to_string(&p)
            .unwrap()
            .replace("__CWD__", &work.to_string_lossy());
        // The plugin always sends `{tool, args}`; fixtures of another shape stay in the golden test.
        let Ok(v) = serde_json::from_str::<Value>(&input) else {
            continue;
        };
        let plugin_shape = v["tool"].is_string()
            && v["args"].is_object()
            && v.as_object().is_some_and(|o| o.len() == 2);
        if !plugin_shape {
            continue;
        }
        let want = json(&dir.join(format!("{stem}.out.json")));
        let got = run(&input, &path);
        if want["code"] == 0 {
            assert_eq!(got, "ALLOW", "opencode/{stem}");
        } else {
            let reason = want["stderr"].as_str().unwrap();
            assert_eq!(got, format!("DENY:{reason}"), "opencode/{stem}");
        }
        n += 1;
    }
    assert!(n >= 8, "only {n} OpenCode fixtures ran through the plugin");
    // without `smith` the plugin throws with the visible reason
    let got = run(
        r#"{"tool":"bash","args":{"command":"ls"}}"#,
        "/usr/bin:/bin",
    );
    assert!(
        got.starts_with("DENY:") && got.contains("smith doctor"),
        "{got}"
    );
    // the plugin carries no policy: it only forwards to `smith hook opencode`
    let text = std::fs::read_to_string(&plugin).unwrap();
    assert!(text.contains("smith hook opencode tool.execute.before"));
}
