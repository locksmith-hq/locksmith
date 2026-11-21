//! Single source of truth for wiring Locksmith hooks into agents. Used by `smith init`, doctor
//! and the `integrations/` files (a test keeps those in sync).
#![allow(dead_code)] // consumed by init/doctor

use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Agent {
    ClaudeCode,
    Cursor,
    Codex,
    GeminiCli,
    Copilot,
    Windsurf,
    Cline,
}

pub const ALL: [Agent; 7] = [
    Agent::ClaudeCode,
    Agent::Cursor,
    Agent::Codex,
    Agent::GeminiCli,
    Agent::Copilot,
    Agent::Windsurf,
    Agent::Cline,
];

/// What the integration really does about a secret read (never claim more than this).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    /// A blocking pre-tool or pre-prompt hook can stop the action.
    Prevention,
    /// Actions are only observed after the fact.
    Detection,
    /// No hook: MCP configuration and instructions only.
    None,
}

impl Protection {
    pub fn label(self) -> &'static str {
        match self {
            Protection::Prevention => "prevention (blocking hook)",
            Protection::Detection => "detection only (no preventing hook)",
            Protection::None => "none (no preventing hook; MCP and instructions only)",
        }
    }
}

const CLAUDE_MATCHER: &str = "Bash|Read|Edit|MultiEdit|Grep|Glob";
const MISSING: &str = "Locksmith hook unavailable: run smith doctor";

impl Agent {
    /// The `<agent>` argument of `smith hook`.
    pub fn id(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "claude-code",
            Agent::Cursor => "cursor",
            Agent::Codex => "codex",
            Agent::GeminiCli => "gemini-cli",
            Agent::Copilot => "copilot",
            Agent::Windsurf => "windsurf",
            Agent::Cline => "cline",
        }
    }

    pub fn events(self) -> &'static [&'static str] {
        match self {
            Agent::ClaudeCode | Agent::Codex => &["PreToolUse", "UserPromptSubmit"],
            Agent::Cursor => &[
                "beforeShellExecution",
                "beforeReadFile",
                "beforeSubmitPrompt",
            ],
            Agent::GeminiCli => &["BeforeTool", "BeforeAgent"],
            Agent::Copilot => &["preToolUse"],
            Agent::Windsurf => &["pre_run_command", "pre_read_code", "pre_user_prompt"],
            Agent::Cline => &["PreToolUse"],
        }
    }

    /// Prevention only where the agent has a blocking hook (empty events means none).
    pub fn protection(self) -> Protection {
        if self.events().is_empty() {
            Protection::None
        } else {
            Protection::Prevention
        }
    }

    fn binaries(self) -> &'static [&'static str] {
        match self {
            Agent::ClaudeCode => &["claude"],
            Agent::Cursor => &["cursor-agent", "cursor"],
            Agent::Codex => &["codex"],
            Agent::GeminiCli => &["gemini"],
            Agent::Copilot => &["copilot"],
            Agent::Windsurf => &["windsurf"],
            Agent::Cline => &["cline"],
        }
    }
}

fn marker(a: Agent, event: &str) -> String {
    format!("smith hook {} {event}", a.id())
}

/// The command the agent runs. It blocks visibly when `smith` is missing (design D5).
pub fn wrapper(a: Agent, event: &str) -> String {
    let run = marker(a, event);
    let test = "command -v smith >/dev/null 2>&1 ||";
    match a {
        Agent::Cline => {
            let deny = json!({"cancel": true, "errorMessage": MISSING});
            format!("{test} {{ echo '{deny}'; exit 0; }}; {run}")
        }
        Agent::Cursor => {
            let deny = match event {
                "beforeSubmitPrompt" => json!({"continue": false, "user_message": MISSING}),
                "beforeReadFile" => json!({"permission": "deny", "user_message": MISSING}),
                _ => json!({"permission": "deny", "user_message": MISSING,
                            "agent_message": MISSING}),
            };
            format!("{test} {{ echo '{deny}'; exit 0; }}; {run}")
        }
        _ => format!("{test} {{ echo '{MISSING}' >&2; exit 2; }}; {run}"),
    }
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
}

pub fn binary_on_path(a: Agent) -> bool {
    a.binaries().iter().any(|b| on_path(b))
}

/// True once `smith hook <agent>` can parse the agent's payload. Windsurf waits for a fixture of
/// the Devin Desktop hook format (docs/research/agent-plugin-formats.md).
pub fn hook_handler_ready(a: Agent) -> bool {
    a != Agent::Windsurf
}

/// Agents the repo shows signs of using.
pub fn detect(repo: &Path) -> Vec<Agent> {
    ALL.into_iter()
        .filter(|a| match a {
            Agent::ClaudeCode => repo.join(".claude").is_dir(),
            Agent::Cursor => repo.join(".cursor").is_dir(),
            Agent::Codex => repo.join(".codex").is_dir() || repo.join("AGENTS.md").is_file(),
            Agent::GeminiCli => repo.join(".gemini").is_dir() || repo.join("GEMINI.md").is_file(),
            Agent::Copilot => {
                repo.join(".github/copilot-instructions.md").is_file()
                    || repo.join(".github/hooks").is_dir()
            }
            Agent::Windsurf => {
                repo.join(".windsurf").is_dir()
                    || repo.join(".windsurfrules").is_file()
                    || repo.join(".devin").is_dir()
            }
            Agent::Cline => repo.join(".clinerules").is_dir() || repo.join(".cline").is_dir(),
        })
        .collect()
}

pub fn config_path(a: Agent, repo: &Path) -> PathBuf {
    repo.join(match a {
        Agent::ClaudeCode => ".claude/settings.json",
        Agent::Cursor => ".cursor/hooks.json",
        Agent::Codex => ".codex/config.toml",
        Agent::GeminiCli => ".gemini/settings.json",
        Agent::Copilot => ".github/hooks/locksmith.json",
        Agent::Windsurf => ".windsurf/hooks.json",
        // Cline hooks are executable scripts named after the event, not a config file.
        Agent::Cline => ".clinerules/hooks/PreToolUse",
    })
}

pub fn installed(a: Agent, repo: &Path) -> bool {
    std::fs::read_to_string(config_path(a, repo))
        .is_ok_and(|t| a.events().iter().all(|e| t.contains(&marker(a, e))))
}

/// Our handler for one event, in the agent's JSON shape (not Codex or Cline).
fn json_entry(a: Agent, event: &str) -> Value {
    let command = wrapper(a, event);
    match a {
        Agent::Cursor => json!({"command": command, "failClosed": true, "timeout": 10}),
        // Gemini CLI timeouts are milliseconds. No matcher: the hook sees every tool call.
        Agent::GeminiCli => json!({"hooks": [{"name": "locksmith", "type": "command",
            "command": command, "timeout": 10000}]}),
        Agent::Copilot => json!({"type": "command", "bash": command, "timeoutSec": 10}),
        Agent::Windsurf => json!({"command": command, "show_output": false}),
        // Cline has no JSON config; `cline_script` builds its hook file.
        Agent::Cline => json!({"command": command}),
        _ => {
            let hooks = json!([{"type": "command", "command": command, "timeout": 10}]);
            if event == "PreToolUse" {
                json!({"matcher": CLAUDE_MATCHER, "hooks": hooks})
            } else {
                json!({"hooks": hooks})
            }
        }
    }
}

/// The Cline hook file: an executable script named after the event.
pub fn cline_script() -> String {
    format!("#!/bin/sh\n{}\n", wrapper(Agent::Cline, "PreToolUse"))
}

/// Whether the agent's hooks file carries a top-level `version` key.
fn versioned(a: Agent) -> bool {
    matches!(a, Agent::Cursor | Agent::Copilot)
}

/// Hooks object for the JSON agents (Claude Code, Cursor, Gemini CLI, Copilot, Windsurf). Cline
/// uses `cline_script` and Codex TOML, so they get an empty object.
pub fn hooks_json(a: Agent) -> Value {
    if matches!(a, Agent::Cline | Agent::Codex) {
        return json!({});
    }
    let hooks: serde_json::Map<String, Value> = a
        .events()
        .iter()
        .map(|e| (e.to_string(), json!([json_entry(a, e)])))
        .collect();
    if versioned(a) {
        json!({"version": 1, "hooks": hooks})
    } else {
        json!({"hooks": hooks})
    }
}

/// Idempotent merge of our hooks into an agent config. Other settings and hooks are kept;
/// text is returned unchanged when everything is already present. Errors on unparsable input
/// rather than overwriting it. (JSON key order may change; TOML is appended to, so comments stay.)
pub fn merge_hooks(a: Agent, existing: Option<&str>) -> Result<String, String> {
    if a == Agent::Codex {
        return merge_toml(existing.unwrap_or(""));
    }
    if a == Agent::Cline {
        return merge_cline(existing);
    }
    let mut root: Value = match existing.filter(|t| !t.trim().is_empty()) {
        None => json!({}),
        Some(t) => serde_json::from_str(t)
            .map_err(|e| format!("existing config is not valid JSON: {e}"))?,
    };
    let obj = root
        .as_object_mut()
        .ok_or("existing config is not a JSON object")?;
    if versioned(a) {
        obj.entry("version").or_insert(json!(1));
    }
    let hooks = obj
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or("`hooks` is not an object")?;
    let mut changed = false;
    for e in a.events() {
        let list = hooks
            .entry(e.to_string())
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| format!("`hooks.{e}` is not an array"))?;
        if !list.iter().any(|x| x.to_string().contains(&marker(a, e))) {
            list.push(json_entry(a, e));
            changed = true;
        }
    }
    match existing {
        Some(t) if !changed => Ok(t.to_string()),
        _ => Ok(serde_json::to_string_pretty(&root).map_err(|e| e.to_string())? + "\n"),
    }
}

const MCP_COMMAND: &str = "locksmith-mcp";

/// Repo-level file the agent reads MCP servers from (Codex and Gemini CLI share their hooks
/// file). `None` when the agent only reads a user-level file (Windsurf, Cline): `smith init`
/// never edits the home directory, so it prints `mcp_user_hint` instead.
pub fn mcp_path(a: Agent, repo: &Path) -> Option<PathBuf> {
    Some(match a {
        Agent::ClaudeCode => repo.join(".mcp.json"),
        Agent::Cursor => repo.join(".cursor/mcp.json"),
        Agent::Codex | Agent::GeminiCli => config_path(a, repo),
        Agent::Copilot => repo.join(".vscode/mcp.json"),
        Agent::Windsurf | Agent::Cline => return None,
    })
}

/// The user-level MCP file to edit by hand when `mcp_path` is `None` (unverified, see
/// `docs/research/agent-plugin-formats.md`).
pub fn mcp_user_hint(a: Agent) -> Option<&'static str> {
    match a {
        Agent::Windsurf => Some("~/.codeium/windsurf/mcp_config.json"),
        Agent::Cline => Some("cline_mcp_settings.json (Cline MCP Servers panel)"),
        _ => None,
    }
}

/// The JSON key that holds MCP servers (VS Code Copilot uses `servers`).
fn servers_key(a: Agent) -> &'static str {
    if a == Agent::Copilot {
        "servers"
    } else {
        "mcpServers"
    }
}

/// Idempotent merge of the `locksmith` MCP server (runs the installed `locksmith-mcp`). Keeps
/// other servers and settings; an existing `locksmith` entry is left as the user wrote it.
pub fn merge_mcp(a: Agent, existing: Option<&str>) -> Result<String, String> {
    if a == Agent::Codex {
        let t = existing.unwrap_or("");
        let table: toml::Table =
            toml::from_str(t).map_err(|e| format!("existing config is not valid TOML: {e}"))?;
        let have = table
            .get("mcp_servers")
            .and_then(|v| v.get("locksmith"))
            .is_some();
        if have {
            return Ok(t.to_string());
        }
        let sep = if t.is_empty() || t.ends_with("\n\n") {
            ""
        } else if t.ends_with('\n') {
            "\n"
        } else {
            "\n\n"
        };
        let out = format!("{t}{sep}[mcp_servers.locksmith]\ncommand = \"{MCP_COMMAND}\"\n");
        return toml::from_str::<toml::Table>(&out)
            .map(|_| out)
            .map_err(|e| format!("cannot add the MCP server to this config: {e}"));
    }
    let mut root: Value = match existing.filter(|t| !t.trim().is_empty()) {
        None => json!({}),
        Some(t) => serde_json::from_str(t)
            .map_err(|e| format!("existing config is not valid JSON: {e}"))?,
    };
    let servers = root
        .as_object_mut()
        .ok_or("existing config is not a JSON object")?
        .entry(servers_key(a))
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| format!("`{}` is not an object", servers_key(a)))?;
    if servers.contains_key("locksmith") {
        return Ok(existing.map_or_else(String::new, str::to_string));
    }
    let entry = if a == Agent::Copilot {
        json!({"type": "stdio", "command": MCP_COMMAND, "args": []})
    } else {
        json!({"command": MCP_COMMAND, "args": []})
    };
    servers.insert("locksmith".into(), entry);
    Ok(serde_json::to_string_pretty(&root).map_err(|e| e.to_string())? + "\n")
}

/// Cline hook file. Ours is replaced by nothing (already current); a script someone else wrote
/// is never overwritten, so it errors and the user adds the Locksmith call by hand.
fn merge_cline(existing: Option<&str>) -> Result<String, String> {
    let want = cline_script();
    match existing.filter(|t| !t.trim().is_empty()) {
        None => Ok(want),
        Some(t) if t.contains(&marker(Agent::Cline, "PreToolUse")) => Ok(t.to_string()),
        Some(_) => Err(format!(
            "a PreToolUse hook already exists; add `{}` to it by hand",
            marker(Agent::Cline, "PreToolUse")
        )),
    }
}

fn merge_toml(existing: &str) -> Result<String, String> {
    toml::from_str::<toml::Table>(existing)
        .map_err(|e| format!("existing config is not valid TOML: {e}"))?;
    let mut out = existing.to_string();
    for e in Agent::Codex.events() {
        if out.contains(&marker(Agent::Codex, e)) {
            continue;
        }
        let command = toml::Value::String(wrapper(Agent::Codex, e));
        if !out.is_empty() {
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push('\n');
        }
        out.push_str(&format!("[[hooks.{e}]]\n"));
        if *e == "PreToolUse" {
            out.push_str("matcher = \"^Bash$\"\n\n[[hooks.PreToolUse.hooks]]\n");
        } else {
            out.push_str("\n[[hooks.UserPromptSubmit.hooks]]\n");
        }
        out.push_str(&format!(
            "type = \"command\"\ncommand = {command}\ntimeout = 10\n"
        ));
    }
    toml::from_str::<toml::Table>(&out)
        .map_err(|e| format!("cannot add hooks to this config: {e}"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("agents-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn merge_is_idempotent_and_preserves() {
        let user_json = r#"{"model":"x","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"mine"}]}],"Stop":[]}}"#;
        let user_toml = "# keep me\nmodel = \"o3\"\n\n[[hooks.PreToolUse]]\nmatcher = \"x\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"mine\"\n";
        for a in ALL {
            if a == Agent::Cline {
                continue; // a script, not a config: see `cline_hook_script`
            }
            let seed = if a == Agent::Codex {
                user_toml
            } else {
                user_json
            };
            for start in [None, Some(seed)] {
                let once = merge_hooks(a, start).unwrap();
                assert_eq!(
                    merge_hooks(a, Some(&once)).unwrap(),
                    once,
                    "{a:?} idempotent"
                );
                for e in a.events() {
                    assert_eq!(once.matches(&marker(a, e)).count(), 1, "{a:?} {e} once");
                }
                if start.is_some() {
                    assert!(once.contains("mine"), "{a:?} keeps the user's hook");
                }
            }
        }
        let c = merge_hooks(Agent::ClaudeCode, Some(user_json)).unwrap();
        assert!(c.contains("\"model\"") && c.contains("\"Stop\""));
        assert!(
            merge_hooks(Agent::Codex, Some(user_toml))
                .unwrap()
                .starts_with("# keep me")
        );
        assert!(merge_hooks(Agent::ClaudeCode, Some("{oops")).is_err());
        assert!(merge_hooks(Agent::Codex, Some("= =")).is_err());
    }

    #[test]
    fn new_agents_hook_shapes() {
        let g = hooks_json(Agent::GeminiCli);
        let cmd = &g["hooks"]["BeforeTool"][0]["hooks"][0];
        assert_eq!(cmd["type"], "command");
        assert_eq!(
            cmd["timeout"], 10000,
            "Gemini CLI timeouts are milliseconds"
        );
        assert!(g["hooks"]["BeforeAgent"].is_array());
        let c = hooks_json(Agent::Copilot);
        assert_eq!(c["version"], 1);
        assert!(
            c["hooks"]["preToolUse"][0]["bash"]
                .as_str()
                .unwrap()
                .contains("smith hook copilot preToolUse")
        );
        let w = hooks_json(Agent::Windsurf);
        for e in ["pre_run_command", "pre_read_code", "pre_user_prompt"] {
            assert!(w["hooks"][e][0]["command"].as_str().unwrap().contains(e));
        }
        assert_eq!(hooks_json(Agent::Cline), json!({}));
    }

    #[test]
    fn fail_closed_wrappers_deny_in_the_agents_shape() {
        for a in [Agent::GeminiCli, Agent::Copilot, Agent::Windsurf] {
            for e in a.events() {
                let w = wrapper(a, e);
                assert!(w.contains("exit 2") && w.contains(MISSING), "{a:?} {e}");
                assert!(w.ends_with(&marker(a, e)));
            }
        }
        let w = wrapper(Agent::Cline, "PreToolUse");
        assert!(w.contains("\"cancel\":true") && w.contains(MISSING));
        assert!(
            w.contains("exit 0"),
            "Cline reads the JSON reply, not the exit code"
        );
        // Run for real with no `smith` on PATH: the command must deny, not allow.
        for a in [Agent::GeminiCli, Agent::Windsurf, Agent::Cline] {
            let e = a.events()[0];
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(wrapper(a, e))
                .env("PATH", "/nonexistent")
                .output()
                .unwrap();
            let shown = String::from_utf8_lossy(&out.stdout).to_string()
                + &String::from_utf8_lossy(&out.stderr);
            assert!(shown.contains(MISSING), "{a:?}: {shown}");
            if a == Agent::Cline {
                assert!(out.status.success());
            } else {
                assert_eq!(out.status.code(), Some(2), "{a:?}");
            }
        }
    }

    #[test]
    fn cline_hook_script() {
        let once = merge_hooks(Agent::Cline, None).unwrap();
        assert!(once.starts_with("#!/bin/sh\n"));
        assert_eq!(once.matches("smith hook cline PreToolUse").count(), 1);
        assert_eq!(merge_hooks(Agent::Cline, Some(&once)).unwrap(), once);
        assert_eq!(merge_hooks(Agent::Cline, Some("  \n")).unwrap(), once);
        // Someone else's hook is never overwritten.
        assert!(merge_hooks(Agent::Cline, Some("#!/bin/sh\necho mine\n")).is_err());
    }

    #[test]
    fn gemini_and_copilot_keep_other_settings() {
        let g = r#"{"theme":"dark","mcpServers":{"other":{"command":"x"}},"hooks":{"BeforeTool":[{"matcher":"x","hooks":[{"type":"command","command":"mine"}]}]}}"#;
        let h = merge_hooks(Agent::GeminiCli, Some(g)).unwrap();
        let both = merge_mcp(Agent::GeminiCli, Some(&h)).unwrap();
        let v: Value = serde_json::from_str(&both).unwrap();
        assert_eq!(v["theme"], "dark");
        assert!(v["mcpServers"]["other"].is_object() && v["mcpServers"]["locksmith"].is_object());
        assert_eq!(v["hooks"]["BeforeTool"].as_array().unwrap().len(), 2);
        assert_eq!(merge_mcp(Agent::GeminiCli, Some(&both)).unwrap(), both);

        let m = merge_mcp(
            Agent::Copilot,
            Some(r#"{"servers":{"other":{"command":"x"}},"inputs":[]}"#),
        )
        .unwrap();
        let v: Value = serde_json::from_str(&m).unwrap();
        assert_eq!(v["servers"]["locksmith"]["type"], "stdio");
        assert!(v["servers"]["other"].is_object() && v["inputs"].is_array());
        assert!(v.get("mcpServers").is_none(), "VS Code uses `servers`");
    }

    #[test]
    fn invalid_input_is_an_error_for_new_agents() {
        for a in [Agent::GeminiCli, Agent::Copilot, Agent::Windsurf] {
            assert!(merge_hooks(a, Some("{oops")).is_err(), "{a:?}");
            assert!(merge_mcp(a, Some("{oops")).is_err(), "{a:?}");
            assert!(merge_hooks(a, Some("[]")).is_err(), "{a:?} not an object");
            assert!(merge_hooks(a, Some(r#"{"hooks":[]}"#)).is_err(), "{a:?}");
        }
        assert!(merge_mcp(Agent::Copilot, Some(r#"{"servers":[]}"#)).is_err());
        assert!(merge_mcp(Agent::GeminiCli, Some(r#"{"mcpServers":1}"#)).is_err());
    }

    #[test]
    fn protection_labels_and_paths() {
        for a in ALL {
            assert_eq!(a.protection(), Protection::Prevention, "{a:?} has a hook");
        }
        assert!(Protection::None.label().contains("no preventing hook"));
        assert!(Protection::Detection.label().contains("no preventing hook"));
        let repo = Path::new("/r");
        assert_eq!(mcp_path(Agent::Windsurf, repo), None);
        assert_eq!(mcp_path(Agent::Cline, repo), None);
        assert!(mcp_user_hint(Agent::Windsurf).is_some() && mcp_user_hint(Agent::Cline).is_some());
        assert_eq!(
            mcp_path(Agent::GeminiCli, repo),
            Some(config_path(Agent::GeminiCli, repo))
        );
        let ids: std::collections::HashSet<_> = ALL.iter().map(|a| a.id()).collect();
        assert_eq!(ids.len(), ALL.len());
    }

    #[test]
    fn detect_new_agents() {
        let repo = tmp("detect-new");
        for (marker, agent) in [
            (".gemini", Agent::GeminiCli),
            (".github/hooks", Agent::Copilot),
            (".windsurf", Agent::Windsurf),
            (".clinerules", Agent::Cline),
        ] {
            let r = repo.join(agent.id());
            std::fs::create_dir_all(r.join(marker)).unwrap();
            assert_eq!(detect(&r), vec![agent]);
        }
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn detect_and_installed() {
        let repo = tmp("detect");
        assert!(detect(&repo).is_empty());
        std::fs::create_dir_all(repo.join(".claude")).unwrap();
        std::fs::write(repo.join("AGENTS.md"), "x").unwrap();
        assert_eq!(detect(&repo), vec![Agent::ClaudeCode, Agent::Codex]);
        assert!(!installed(Agent::ClaudeCode, &repo));
        let p = config_path(Agent::ClaudeCode, &repo);
        std::fs::write(&p, merge_hooks(Agent::ClaudeCode, None).unwrap()).unwrap();
        assert!(installed(Agent::ClaudeCode, &repo));
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn mcp_merge_is_idempotent_and_preserves() {
        let user_json = r#"{"mcpServers":{"other":{"command":"x"}},"keep":1}"#;
        for a in ALL {
            let seed = if a == Agent::Codex {
                "# keep me\n[mcp_servers.other]\ncommand = \"x\"\n"
            } else {
                user_json
            };
            for start in [None, Some(seed)] {
                let once = merge_mcp(a, start).unwrap();
                assert_eq!(merge_mcp(a, Some(&once)).unwrap(), once, "{a:?} idempotent");
                assert_eq!(once.matches("locksmith-mcp").count(), 1, "{a:?} once");
                if start.is_some() {
                    assert!(once.contains("other") && !once.contains("\"other\":{}"));
                }
            }
        }
        assert!(merge_mcp(Agent::ClaudeCode, Some("{oops")).is_err());
        assert!(merge_mcp(Agent::Codex, Some("= =")).is_err());
    }

    fn check(path: &str, want: String) {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../integrations")
            .join(path);
        if std::env::var_os("UPDATE_INTEGRATIONS").is_some() {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, &want).unwrap();
        }
        let got = std::fs::read_to_string(&p).unwrap_or_default();
        assert_eq!(got, want, "{path} drifted; run with UPDATE_INTEGRATIONS=1");
    }

    /// `integrations/` files are generated from this module.
    #[test]
    fn integrations_match_generated() {
        let mut plugin = hooks_json(Agent::ClaudeCode);
        plugin["description"] = "Locksmith guardrails: block secret reads and env dumps".into();
        let pretty = |v: &Value| serde_json::to_string_pretty(v).unwrap() + "\n";
        check("claude-code/hooks/hooks.json", pretty(&plugin));
        check("cursor/hooks.json", pretty(&hooks_json(Agent::Cursor)));
        check(
            "codex/config.toml",
            merge_mcp(
                Agent::Codex,
                Some(&merge_hooks(Agent::Codex, None).unwrap()),
            )
            .unwrap(),
        );
        check(
            "claude-code/.mcp.json",
            merge_mcp(Agent::ClaudeCode, None).unwrap(),
        );
        check("cursor/mcp.json", merge_mcp(Agent::Cursor, None).unwrap());
    }
}
