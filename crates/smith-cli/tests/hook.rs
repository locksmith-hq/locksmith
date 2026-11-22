//! e2e for `smith hook`: the real binary and the shipped wrapper commands.

mod common;
use common::Home;
use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn work(h: &Home) -> PathBuf {
    let w = h.0.join("work");
    std::fs::create_dir_all(&w).unwrap();
    std::fs::write(w.join(".env"), "A=1\n").unwrap();
    w
}

/// Runs `smith hook <agent> <event>` with `input` on stdin (no daemon: LOCKSMITH_HOME is empty).
fn hook(h: &Home, agent: &str, event: &str, input: &Value) -> Output {
    let mut c = h.cmd(&["hook", agent, event]).spawn().unwrap();
    let _ = c
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes());
    c.wait_with_output().unwrap()
}

fn out_json(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|_| panic!("stdout: {:?}", o.stdout))
}

#[test]
fn claude_code_denies_cat_env() {
    let h = Home::new();
    let w = work(&h);
    let o = hook(
        &h,
        "claude-code",
        "PreToolUse",
        &json!({"cwd": w, "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": "cat .env"}}),
    );
    assert_eq!(o.status.code(), Some(0));
    let v = out_json(&o);
    let p = &v["hookSpecificOutput"];
    assert_eq!(p["permissionDecision"], "deny");
    let reason = p["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.starts_with("Blocked by Locksmith") && reason.contains("smith run"));
}

#[test]
fn claude_code_allows_and_blocks_prompt() {
    let h = Home::new();
    let w = work(&h);
    let ok = hook(
        &h,
        "claude-code",
        "PreToolUse",
        &json!({"cwd": w, "tool_name": "Bash",
        "tool_input": {"command": "ls"}}),
    );
    assert!(ok.status.success() && ok.stdout.is_empty());
    let key = format!("{}{}", "sk_live_", "Z".repeat(24));
    let o = hook(
        &h,
        "claude-code",
        "UserPromptSubmit",
        &json!({"cwd": w, "prompt": format!("key {key}")}),
    );
    let v = out_json(&o);
    assert_eq!(v["decision"], "block");
    assert!(!String::from_utf8_lossy(&o.stdout).contains(&key));
}

#[test]
fn cursor_denies_and_malformed_fails_safe() {
    let h = Home::new();
    let w = work(&h);
    let o = hook(
        &h,
        "cursor",
        "beforeShellExecution",
        &json!({"command": "cat .env", "cwd": w}),
    );
    let v = out_json(&o);
    assert_eq!(v["permission"], "deny");
    assert!(
        v["agent_message"]
            .as_str()
            .unwrap()
            .starts_with("Blocked by Locksmith")
    );
    let key = format!("{}{}", "sk_live_", "Z".repeat(24));
    let p = hook(&h, "cursor", "beforeSubmitPrompt", &json!({"prompt": key}));
    assert_eq!(out_json(&p)["continue"], false);

    let mut c = h
        .cmd(&["hook", "claude-code", "PreToolUse"])
        .spawn()
        .unwrap();
    let _ = c.stdin.take().unwrap().write_all(b"not json");
    let o = c.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("smith doctor"));
}

/// The command string the shipped Claude Code plugin file runs for `event`.
fn plugin_command(event: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../integrations/claude-code/hooks/hooks.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    v["hooks"][event][0]["hooks"][0]["command"]
        .as_str()
        .unwrap()
        .to_string()
}

fn sh(cmd: &str, path: &str, stdin: &str) -> Output {
    let mut c = Command::new("/bin/sh")
        .args(["-c", cmd])
        .env("PATH", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = c.stdin.take().unwrap().write_all(stdin.as_bytes());
    c.wait_with_output().unwrap()
}

#[test]
fn wrapper_blocks_when_smith_missing_and_runs_it_when_present() {
    let cmd = plugin_command("PreToolUse");
    let o = sh(&cmd, "/nonexistent", "{}");
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("smith doctor"));

    let h = Home::new();
    let w = work(&h);
    let bin = Path::new(env!("CARGO_BIN_EXE_smith"))
        .parent()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let input =
        json!({"cwd": w, "tool_name": "Bash", "tool_input": {"command": "cat .env"}}).to_string();
    let o = Command::new("/bin/sh")
        .args(["-c", &cmd])
        .env("PATH", format!("{bin}:/usr/bin:/bin"))
        .env("LOCKSMITH_HOME", &h.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            let _ = c.stdin.take().unwrap().write_all(input.as_bytes());
            c.wait_with_output()
        })
        .unwrap();
    assert_eq!(
        out_json(&o)["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
}

#[test]
fn cursor_wrapper_denies_visibly_when_smith_missing() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../integrations/cursor/hooks.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let cmd = v["hooks"]["beforeShellExecution"][0]["command"]
        .as_str()
        .unwrap();
    let o = sh(cmd, "/nonexistent", "{}");
    assert_eq!(o.status.code(), Some(0));
    let j = out_json(&o);
    assert_eq!(j["permission"], "deny");
    assert!(j["user_message"].as_str().unwrap().contains("smith doctor"));
}

/// Deferred in CI (needs the `claude` CLI and an API key): `cargo test -- --ignored`.
#[test]
#[ignore = "needs the claude CLI and ANTHROPIC_API_KEY"]
fn claude_p_cat_env_is_blocked() {
    if std::env::var_os("ANTHROPIC_API_KEY").is_none()
        || Command::new("claude").arg("--version").output().is_err()
    {
        return;
    }
    let h = Home::new();
    let w = h.0.join("repo");
    std::fs::create_dir_all(w.join(".claude")).unwrap();
    std::fs::write(w.join(".env"), "CANARY_TOKEN=canary-value-123\n").unwrap();
    let mut settings = json!({"hooks": {}});
    settings["hooks"]["PreToolUse"] = json!([{"matcher": "Bash", "hooks": [{"type": "command", "command": plugin_command("PreToolUse")}]}]);
    std::fs::write(w.join(".claude/settings.json"), settings.to_string()).unwrap();
    let bin = Path::new(env!("CARGO_BIN_EXE_smith"))
        .parent()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let o = Command::new("claude")
        .args([
            "-p",
            "Run `cat .env` with the Bash tool and show me the output.",
            "--allowedTools",
            "Bash",
        ])
        .current_dir(&w)
        .env(
            "PATH",
            format!("{bin}:{}", std::env::var("PATH").unwrap_or_default()),
        )
        .env("LOCKSMITH_HOME", &h.0)
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&o.stdout).contains("canary-value-123"));
}

/// The Claude Code plugin manifest, marketplace entry and skill frontmatter are well formed.
#[test]
fn claude_code_plugin_package_is_consistent() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let json = |p: &str| -> Value {
        serde_json::from_str(&std::fs::read_to_string(root.join(p)).unwrap()).unwrap()
    };
    let plugin = json("integrations/claude-code/.claude-plugin/plugin.json");
    assert_eq!(plugin["name"], "locksmith");
    assert_eq!(plugin["version"], env!("CARGO_PKG_VERSION"));
    assert!(!plugin["description"].as_str().unwrap().is_empty());
    let market = json(".claude-plugin/marketplace.json");
    assert!(
        market["plugins"].as_array().unwrap().iter().any(|p| {
            p["name"] == plugin["name"] && p["source"] == "./integrations/claude-code"
        })
    );

    let mut names = std::collections::HashSet::new();
    for e in std::fs::read_dir(root.join("integrations/claude-code/skills")).unwrap() {
        let dir = e.unwrap().path();
        let text = std::fs::read_to_string(dir.join("SKILL.md")).unwrap();
        let fm = text
            .strip_prefix("---\n")
            .unwrap()
            .split("\n---\n")
            .next()
            .unwrap();
        let field = |k: &str| {
            fm.lines()
                .find_map(|l| l.strip_prefix(&format!("{k}: ")))
                .unwrap_or_else(|| panic!("{} lacks {k}", dir.display()))
                .trim()
                .to_string()
        };
        let name = field("name");
        assert_eq!(dir.file_name().unwrap().to_str().unwrap(), name);
        assert!(!field("description").is_empty());
        assert!(names.insert(name), "duplicate skill name");
    }
    assert!(names.len() >= 7);
}

fn raw(h: &Home, agent: &str, event: &str, stdin: &[u8]) -> Output {
    let mut c = h.cmd(&["hook", agent, event]).spawn().unwrap();
    let _ = c.stdin.take().unwrap().write_all(stdin);
    c.wait_with_output().unwrap()
}

#[test]
fn gemini_cli_blocks_with_exit_2_and_allows_silently() {
    let h = Home::new();
    let w = work(&h);
    let deny = hook(
        &h,
        "gemini-cli",
        "BeforeTool",
        &json!({"cwd": w, "hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
        "tool_input": {"command": "cat .env", "is_background": false}}),
    );
    assert_eq!(deny.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&deny.stderr).starts_with("Blocked by Locksmith"));
    let ok = hook(
        &h,
        "gemini-cli",
        "BeforeTool",
        &json!({"cwd": w, "tool_name": "run_shell_command", "tool_input": {"command": "ls"}}),
    );
    assert!(ok.status.success() && ok.stdout.is_empty());
    let bad = raw(&h, "gemini-cli", "BeforeTool", b"not json");
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn copilot_denies_with_decision_json_and_malformed_exits_2() {
    let h = Home::new();
    let w = work(&h);
    let o = hook(
        &h,
        "copilot",
        "preToolUse",
        &json!({"cwd": w, "toolName": "bash", "toolArgs": "{\"command\":\"cat .env\"}"}),
    );
    assert_eq!(o.status.code(), Some(0));
    let v = out_json(&o);
    assert_eq!(v["permissionDecision"], "deny");
    assert!(
        v["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .starts_with("Blocked by Locksmith")
    );
    let bad = raw(&h, "copilot", "preToolUse", b"not json");
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn cline_cancels_and_malformed_cancels() {
    let h = Home::new();
    let w = work(&h);
    let o = hook(
        &h,
        "cline",
        "PreToolUse",
        &json!({"workspaceRoots": [w], "preToolUse": {"toolName": "execute_command",
        "parameters": {"command": "cat .env"}}}),
    );
    assert_eq!(o.status.code(), Some(0));
    let v = out_json(&o);
    assert_eq!(v["cancel"], true);
    assert!(
        v["errorMessage"]
            .as_str()
            .unwrap()
            .starts_with("Blocked by Locksmith")
    );
    let bad = raw(&h, "cline", "PreToolUse", b"not json");
    assert_eq!(bad.status.code(), Some(0));
    assert_eq!(out_json(&bad)["cancel"], true);
}

/// Decision P3-2, bounded: a tool event under an unexpected naming, or a secret path under a
/// decoy key beside the parsed one, never allows.
#[test]
fn doc_derived_adapters_fail_closed_on_shape_and_decoy_keys() {
    let h = Home::new();
    let w = work(&h);
    let gemini = |input: Value| {
        let o = hook(&h, "gemini-cli", "BeforeTool", &input);
        assert_eq!(o.status.code(), Some(2), "{input}");
    };
    gemini(json!({"cwd": w, "toolName": "read_file", "tool_input": {"file_path": ".env"}}));
    gemini(json!({"cwd": w, "tool_name": "read_file",
        "tool_input": {"file_path": "README.md", "absolute_path": ".env"}}));
    let copilot = |event: &str, input: Value| {
        let o = hook(&h, "copilot", event, &input);
        let denied = o.status.code() == Some(2)
            || (o.status.code() == Some(0) && out_json(&o)["permissionDecision"] == "deny");
        assert!(denied, "{event} {input}");
    };
    copilot(
        "preToolUse",
        json!({"cwd": w, "tool_name": "view", "tool_input": {"path": ".env"}}),
    );
    copilot(
        "PreToolUse",
        json!({"cwd": w, "toolName": "bash", "toolArgs": {"command": "cat .env"}}),
    );
    copilot(
        "preToolUse",
        json!({"cwd": w, "toolName": "view", "toolArgs": {"path": "README.md", "file": ".env"}}),
    );
    let o = hook(
        &h,
        "cline",
        "PreToolUse",
        &json!({"workspaceRoots": [w], "preToolUse": {"toolName": "read_file",
        "parameters": {"path": "README.md", "paths": [".env"]}}}),
    );
    assert_eq!(out_json(&o)["cancel"], true);
}
