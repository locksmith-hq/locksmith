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
    OpenCode,
    Kiro,
}

pub const ALL: [Agent; 9] = [
    Agent::ClaudeCode,
    Agent::Cursor,
    Agent::Codex,
    Agent::GeminiCli,
    Agent::Copilot,
    Agent::Windsurf,
    Agent::Cline,
    Agent::OpenCode,
    Agent::Kiro,
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
            Agent::OpenCode => "opencode",
            Agent::Kiro => "kiro",
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
            Agent::OpenCode => &["tool.execute.before"],
            Agent::Kiro => &["PreToolUse"],
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
            Agent::OpenCode => &["opencode"],
            Agent::Kiro => &["kiro", "kiro-cli"],
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
/// the Devin Desktop hook format (docs/research/agent-plugin-formats.md); OpenCode and Kiro wait
/// for their adapters (p7 task 2.1), so `smith init` does not wire a hook that always denies.
pub fn hook_handler_ready(a: Agent) -> bool {
    !matches!(a, Agent::Windsurf | Agent::OpenCode | Agent::Kiro)
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
            Agent::OpenCode => {
                repo.join("opencode.json").is_file()
                    || repo.join("opencode.jsonc").is_file()
                    || repo.join(".opencode").is_dir()
            }
            Agent::Kiro => repo.join(".kiro").is_dir(),
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
        // OpenCode loads every file in `.opencode/plugins/` (both plugin APIs, task 1.1 notes).
        Agent::OpenCode => ".opencode/plugins/locksmith.js",
        Agent::Kiro => ".kiro/hooks/locksmith.json",
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
        // Kiro: no timeout key, its unit is not documented (task 1.1 notes).
        Agent::Kiro => json!({"name": "locksmith", "trigger": "PreToolUse", "matcher": "",
            "action": {"type": "command", "command": command}, "enabled": true}),
        // OpenCode has no JSON config; `opencode_plugin` builds its plugin file.
        Agent::OpenCode => json!({"command": command}),
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

/// The OpenCode plugin: pipes `{tool, args}` to `smith hook opencode` and throws (which blocks the
/// tool call) on a non-zero exit, a spawn failure or a timeout. No security logic lives here; the
/// wrapper also fails closed when `smith` is missing. Targets the V1 `tool.execute.before` API; the
/// V2 deny mechanism is unverified (task 1.1), so protection stays "unknown" until the adapter lands.
pub fn opencode_plugin() -> String {
    let wrapper = serde_json::to_string(&wrapper(Agent::OpenCode, "tool.execute.before"))
        .expect("string serializes");
    const TEMPLATE: &str = r#"// Generated by Locksmith (smith init). Blocks the tool call when the hook denies or is unavailable.
import { spawnSync } from "node:child_process";

const COMMAND = @COMMAND@;

export const Locksmith = async () => ({
  "tool.execute.before": async (input, output) => {
    const r = spawnSync("sh", ["-c", COMMAND], {
      input: JSON.stringify({ tool: input.tool, args: output.args }),
      encoding: "utf8",
      timeout: 10000,
    });
    if (r.error || r.status !== 0) {
      throw new Error((r.stderr || "").trim() || "@MISSING@");
    }
  },
});
"#;
    TEMPLATE
        .replace("@COMMAND@", &wrapper)
        .replace("@MISSING@", MISSING)
}

/// The Kiro hooks file (`{"version": "v1", "hooks": [...]}`, a list, unlike the other agents).
fn kiro_file(hooks: Vec<Value>) -> Value {
    json!({"version": "v1", "hooks": hooks})
}

/// Whether the agent's hooks file carries a top-level `version` key.
fn versioned(a: Agent) -> bool {
    matches!(a, Agent::Cursor | Agent::Copilot)
}

/// Hooks object for the JSON agents (Claude Code, Cursor, Gemini CLI, Copilot, Windsurf). Cline
/// uses `cline_script` and Codex TOML, so they get an empty object.
pub fn hooks_json(a: Agent) -> Value {
    if a == Agent::Kiro {
        return kiro_file(vec![json_entry(a, "PreToolUse")]);
    }
    if matches!(a, Agent::Cline | Agent::Codex | Agent::OpenCode) {
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
    if a == Agent::OpenCode {
        return merge_opencode(existing);
    }
    if a == Agent::Kiro {
        return merge_kiro(existing);
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
        // An existing `opencode.jsonc` is the project config; never create a second file next to it.
        Agent::OpenCode => {
            let jsonc = repo.join("opencode.jsonc");
            if jsonc.is_file() && !repo.join("opencode.json").is_file() {
                jsonc
            } else {
                repo.join("opencode.json")
            }
        }
        Agent::Kiro => repo.join(".kiro/settings/mcp.json"),
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
    let top = root
        .as_object_mut()
        .ok_or("existing config is not a JSON object")?;
    // OpenCode V2 keeps servers one level down, at `mcp.servers` (task 1.1 notes).
    let servers = if a == Agent::OpenCode {
        top.entry("mcp")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or("`mcp` is not an object")?
            .entry("servers")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or("`mcp.servers` is not an object")?
    } else {
        top.entry(servers_key(a))
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| format!("`{}` is not an object", servers_key(a)))?
    };
    if servers.contains_key("locksmith") {
        return Ok(existing.map_or_else(String::new, str::to_string));
    }
    let entry = if a == Agent::Copilot {
        json!({"type": "stdio", "command": MCP_COMMAND, "args": []})
    } else if a == Agent::OpenCode {
        json!({"type": "local", "command": [MCP_COMMAND]})
    } else {
        json!({"command": MCP_COMMAND, "args": []})
    };
    servers.insert("locksmith".into(), entry);
    Ok(serde_json::to_string_pretty(&root).map_err(|e| e.to_string())? + "\n")
}

/// What `smith init --mcp-gateway` changed in one MCP file.
pub struct GatewayRewrite {
    /// The new file text.
    pub after: String,
    /// The old text with every value in a rewritten entry replaced by `***`, for the preview only
    /// (the entry may hold a token; it is not saved anywhere).
    pub masked_before: String,
    /// The upstream names whose entry was replaced.
    pub rewritten: Vec<String>,
}

/// The stdio entry that runs `smith mcp bridge <name>`.
fn bridge_args(name: &str) -> [&str; 3] {
    ["mcp", "bridge", name]
}

const MASK: &str = "***";

fn mask_json(v: &mut Value) {
    match v {
        Value::String(s) => *s = MASK.into(),
        Value::Array(a) => a.iter_mut().for_each(mask_json),
        Value::Object(o) => o.values_mut().for_each(mask_json),
        _ => {}
    }
}

fn mask_toml(item: &mut toml_edit::Item) {
    use toml_edit::{Item, Value as V};
    match item {
        Item::Value(V::String(s)) => *s = toml_edit::Formatted::new(MASK.into()),
        Item::Value(V::Array(a)) => {
            for v in a.iter_mut() {
                *v = V::from(MASK);
            }
        }
        Item::Value(V::InlineTable(t)) => {
            for (_, v) in t.iter_mut() {
                *v = V::from(MASK);
            }
        }
        Item::Table(t) => {
            for (_, v) in t.iter_mut() {
                mask_toml(v);
            }
        }
        _ => {}
    }
}

/// Replace every MCP entry named like an upstream the gateway serves to this agent with the
/// stdio bridge (`smith mcp bridge <name>`), dropping its `url`, `headers`, `env` and anything
/// else. Other entries are untouched; an entry that already is the bridge is left alone, so the
/// rewrite is idempotent. `None` when nothing changed.
pub fn rewrite_gateway_mcp(
    a: Agent,
    existing: &str,
    upstreams: &[String],
) -> Result<Option<GatewayRewrite>, String> {
    let mut rewritten = Vec::new();
    if a == Agent::Codex {
        let mut doc: toml_edit::DocumentMut = existing
            .parse()
            .map_err(|e| format!("existing config is not valid TOML: {e}"))?;
        let mut masked = doc.clone();
        for name in upstreams {
            let Some(item) = doc
                .get_mut("mcp_servers")
                .and_then(|s| s.as_table_like_mut())
                .and_then(|t| t.get_mut(name))
            else {
                continue;
            };
            let is_bridge = item.as_table_like().is_some_and(|t| {
                t.len() == 2
                    && t.get("command").and_then(|c| c.as_str()) == Some("smith")
                    && t.get("args").and_then(|a| a.as_array()).is_some_and(|a| {
                        a.iter()
                            .map(|v| v.as_str().unwrap_or(""))
                            .eq(bridge_args(name))
                    })
            });
            if is_bridge {
                continue;
            }
            let mut t = toml_edit::Table::new();
            t["command"] = toml_edit::value("smith");
            let mut args = toml_edit::Array::new();
            bridge_args(name).iter().for_each(|x| args.push(*x));
            t["args"] = toml_edit::value(args);
            *item = toml_edit::Item::Table(t);
            if let Some(m) = masked
                .get_mut("mcp_servers")
                .and_then(|s| s.as_table_like_mut())
                .and_then(|t| t.get_mut(name))
            {
                mask_toml(m);
            }
            rewritten.push(name.clone());
        }
        if rewritten.is_empty() {
            return Ok(None);
        }
        return Ok(Some(GatewayRewrite {
            after: doc.to_string(),
            masked_before: masked.to_string(),
            rewritten,
        }));
    }
    let mut root: Value = serde_json::from_str(existing)
        .map_err(|e| format!("existing config is not valid JSON: {e}"))?;
    let mut masked = root.clone();
    let key = servers_key(a);
    let Some(servers) = root.get_mut(key).and_then(Value::as_object_mut) else {
        return Ok(None);
    };
    for name in upstreams {
        let Some(entry) = servers.get(name) else {
            continue;
        };
        let is_bridge = entry["command"] == "smith"
            && entry["args"] == json!(bridge_args(name))
            && entry.as_object().is_some_and(|o| {
                o.keys()
                    .all(|k| matches!(k.as_str(), "command" | "args" | "type"))
            });
        if is_bridge {
            continue;
        }
        let new = if a == Agent::Copilot {
            json!({"type": "stdio", "command": "smith", "args": bridge_args(name)})
        } else {
            json!({"command": "smith", "args": bridge_args(name)})
        };
        servers.insert(name.clone(), new);
        if let Some(m) = masked.get_mut(key).and_then(|s| s.get_mut(name.as_str())) {
            mask_json(m);
        }
        rewritten.push(name.clone());
    }
    if rewritten.is_empty() {
        return Ok(None);
    }
    let pretty = |v: &Value| serde_json::to_string_pretty(v).map(|s| s + "\n");
    Ok(Some(GatewayRewrite {
        after: pretty(&root).map_err(|e| e.to_string())?,
        masked_before: pretty(&masked).map_err(|e| e.to_string())?,
        rewritten,
    }))
}

/// Names of servers, in an MCP file's text, that carry a credential-like header or env value
/// (`Authorization`, `*-key`, `*-token`, `*_KEY`, `*_TOKEN`, ...) with a non-empty value.
/// Names only, never a value. Invalid text yields no findings.
pub fn mcp_credentials(a: Agent, text: &str) -> Vec<(String, String)> {
    fn credential_like(field: &str) -> bool {
        let f = field.to_ascii_lowercase().replace('_', "-");
        f == "authorization"
            || f == "proxy-authorization"
            || f == "cookie"
            || ["key", "token", "secret", "password", "apikey"]
                .iter()
                .any(|s| f == *s || f.ends_with(&format!("-{s}")))
    }
    let mut out = Vec::new();
    let mut scan = |server: &str, field: &str, v: bool| {
        if v && credential_like(field) {
            out.push((server.to_owned(), field.to_owned()));
        }
    };
    if a == Agent::Codex {
        let Ok(t) = text.parse::<toml_edit::DocumentMut>() else {
            return out;
        };
        let Some(servers) = t.get("mcp_servers").and_then(|s| s.as_table_like()) else {
            return out;
        };
        for (name, entry) in servers.iter() {
            for group in ["env", "http_headers", "headers"] {
                if let Some(g) = entry.get(group).and_then(|g| g.as_table_like()) {
                    for (k, v) in g.iter() {
                        scan(name, k, v.as_str().is_some_and(|s| !s.is_empty()));
                    }
                }
            }
            // A token-valued option is a credential by name, whatever it is called.
            if entry
                .get("bearer_token")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty())
            {
                scan(name, "bearer_token", true);
            }
        }
        return out;
    }
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return out;
    };
    let Some(servers) = v.get(servers_key(a)).and_then(Value::as_object) else {
        return out;
    };
    for (name, entry) in servers {
        for group in ["headers", "env"] {
            if let Some(g) = entry.get(group).and_then(Value::as_object) {
                for (k, v) in g {
                    scan(name, k, v.as_str().is_some_and(|s| !s.is_empty()));
                }
            }
        }
    }
    out
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

/// OpenCode plugin file. Ours is kept as is; another plugin file is never overwritten.
fn merge_opencode(existing: Option<&str>) -> Result<String, String> {
    match existing.filter(|t| !t.trim().is_empty()) {
        None => Ok(opencode_plugin()),
        Some(t) if t.contains(&marker(Agent::OpenCode, "tool.execute.before")) => Ok(t.to_string()),
        Some(_) => Err(format!(
            "a locksmith.js plugin already exists; call `{}` from its tool.execute.before by hand",
            marker(Agent::OpenCode, "tool.execute.before")
        )),
    }
}

/// Kiro hooks file: add our `PreToolUse` command hook to `hooks`, keeping every other hook.
fn merge_kiro(existing: Option<&str>) -> Result<String, String> {
    let mut root: Value = match existing.filter(|t| !t.trim().is_empty()) {
        None => kiro_file(vec![]),
        Some(t) => serde_json::from_str(t)
            .map_err(|e| format!("existing config is not valid JSON: {e}"))?,
    };
    let obj = root
        .as_object_mut()
        .ok_or("existing config is not a JSON object")?;
    obj.entry("version").or_insert(json!("v1"));
    let list = obj
        .entry("hooks")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or("`hooks` is not an array")?;
    if list
        .iter()
        .any(|x| x.to_string().contains(&marker(Agent::Kiro, "PreToolUse")))
    {
        return Ok(existing.map_or_else(
            || serde_json::to_string_pretty(&root).unwrap_or_default() + "\n",
            str::to_string,
        ));
    }
    list.push(json_entry(Agent::Kiro, "PreToolUse"));
    Ok(serde_json::to_string_pretty(&root).map_err(|e| e.to_string())? + "\n")
}

/// Server name of the remote Hub MCP entry (the stdio entry is `locksmith`).
pub const HUB_SERVER: &str = "locksmith-hub";
/// The Hub's documented pre-registered public OAuth client (PKCE, no secret).
pub const HUB_CLIENT_ID: &str = "locksmith-mcp";

impl Agent {
    /// Whether the agent supports a remote Streamable HTTP MCP server with OAuth and a
    /// pre-registered client id (`docs/research/remote-mcp-auth.md` section 6). Cursor is not
    /// verified, so it gets no entry.
    pub fn remote_mcp(self) -> bool {
        matches!(self, Agent::ClaudeCode | Agent::Codex)
    }
}

/// `<hub>/mcp` for a Hub base URL: https, or http only on a loopback host (local stack).
pub fn hub_mcp_url(hub: &str) -> Result<String, String> {
    let base = hub.trim().trim_end_matches('/');
    let rest = base
        .strip_prefix("https://")
        .or_else(|| {
            base.strip_prefix("http://").filter(|r| {
                let host = match r.strip_prefix('[') {
                    Some(v6) => r.get(..v6.find(']').map_or(0, |i| i + 2)).unwrap_or(""),
                    None => r.split(['/', ':']).next().unwrap_or(""),
                };
                matches!(host, "localhost" | "127.0.0.1" | "[::1]")
            })
        })
        .ok_or("--hub must be an https:// URL (http:// only for localhost)")?;
    let authority = rest.split('/').next().unwrap_or("");
    if rest.is_empty()
        || authority.contains('@')
        || rest.contains(['?', '#'])
        || rest.chars().any(char::is_whitespace)
    {
        return Err("--hub must be a plain base URL like https://hub.example".into());
    }
    Ok(format!("{base}/mcp"))
}

/// Whether the config text already has a `locksmith-hub` server.
pub fn has_hub_entry(a: Agent, text: &str) -> bool {
    if a == Agent::Codex {
        return toml::from_str::<toml::Table>(text)
            .ok()
            .and_then(|t| t.get("mcp_servers")?.get(HUB_SERVER).cloned())
            .is_some();
    }
    serde_json::from_str::<Value>(text)
        .ok()
        .is_some_and(|v| v["mcpServers"].get(HUB_SERVER).is_some())
}

/// Idempotent merge of the remote Hub MCP entry: the URL and the public client id only, never a
/// token or secret. Agents without remote-MCP support get the text back unchanged. An existing
/// `locksmith-hub` entry is left as the user wrote it.
pub fn merge_hub_mcp(a: Agent, existing: Option<&str>, mcp_url: &str) -> Result<String, String> {
    let keep = existing.unwrap_or("").to_string();
    if !a.remote_mcp() {
        return Ok(keep);
    }
    if a == Agent::Codex {
        let table: toml::Table =
            toml::from_str(&keep).map_err(|e| format!("existing config is not valid TOML: {e}"))?;
        if table
            .get("mcp_servers")
            .and_then(|v| v.get(HUB_SERVER))
            .is_some()
        {
            return Ok(keep);
        }
        let sep = if keep.is_empty() || keep.ends_with("\n\n") {
            ""
        } else if keep.ends_with('\n') {
            "\n"
        } else {
            "\n\n"
        };
        let url = toml::Value::String(mcp_url.into());
        let out = format!(
            "{keep}{sep}[mcp_servers.{HUB_SERVER}]\nurl = {url}\noauth_resource = {url}\n\n[mcp_servers.{HUB_SERVER}.oauth]\nclient_id = \"{HUB_CLIENT_ID}\"\n"
        );
        return toml::from_str::<toml::Table>(&out)
            .map(|_| out)
            .map_err(|e| format!("cannot add the Hub MCP server to this config: {e}"));
    }
    let mut root: Value = match existing.filter(|t| !t.trim().is_empty()) {
        None => json!({}),
        Some(t) => serde_json::from_str(t)
            .map_err(|e| format!("existing config is not valid JSON: {e}"))?,
    };
    let servers = root
        .as_object_mut()
        .ok_or("existing config is not a JSON object")?
        .entry("mcpServers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or("`mcpServers` is not an object")?;
    if servers.contains_key(HUB_SERVER) {
        return Ok(keep);
    }
    servers.insert(
        HUB_SERVER.into(),
        json!({"type": "http", "url": mcp_url, "oauth": {"clientId": HUB_CLIENT_ID}}),
    );
    Ok(serde_json::to_string_pretty(&root).map_err(|e| e.to_string())? + "\n")
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
    fn hub_url_rules() {
        assert_eq!(
            hub_mcp_url("https://hub.example/").unwrap(),
            "https://hub.example/mcp"
        );
        assert_eq!(
            hub_mcp_url("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080/mcp"
        );
        assert_eq!(
            hub_mcp_url("http://[::1]:8080").unwrap(),
            "http://[::1]:8080/mcp"
        );
        for bad in [
            "http://hub.example",
            "hub.example",
            "https://",
            "https://h/x?t=1",
            "https://user:token@hub.example",
            "https://user@hub.example/x",
            "ftp://h",
        ] {
            assert!(hub_mcp_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hub_entry_is_idempotent_secret_free_and_agent_gated() {
        let url = "https://hub.example/mcp";
        for a in [Agent::ClaudeCode, Agent::Codex] {
            let base = merge_mcp(a, None).unwrap();
            let once = merge_hub_mcp(a, Some(&base), url).unwrap();
            assert!(has_hub_entry(a, &once));
            assert!(once.contains(url) && once.contains(HUB_CLIENT_ID));
            assert!(once.contains("locksmith-mcp") && !once.to_lowercase().contains("secret"));
            assert_eq!(
                merge_hub_mcp(a, Some(&once), url).unwrap(),
                once,
                "second run"
            );
            // the stdio entry survives
            assert!(once.contains(MCP_COMMAND));
        }
        assert_eq!(merge_hub_mcp(Agent::Cursor, None, url).unwrap(), "");
        assert!(merge_hub_mcp(Agent::ClaudeCode, Some("{oops"), url).is_err());
        // a hand-written entry is kept
        let mine = r#"{"mcpServers":{"locksmith-hub":{"url":"x"}}}"#;
        assert_eq!(
            merge_hub_mcp(Agent::ClaudeCode, Some(mine), url).unwrap(),
            mine
        );
    }

    #[test]
    fn merge_is_idempotent_and_preserves() {
        let user_json = r#"{"model":"x","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"mine"}]}],"Stop":[]}}"#;
        let user_toml = "# keep me\nmodel = \"o3\"\n\n[[hooks.PreToolUse]]\nmatcher = \"x\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"mine\"\n";
        for a in ALL {
            if matches!(a, Agent::Cline | Agent::OpenCode | Agent::Kiro) {
                continue; // a script or a list: see `cline_hook_script`, `opencode_and_kiro_hooks`
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
    fn opencode_and_kiro_hooks() {
        // OpenCode: a plugin file, ours kept, someone else's never overwritten.
        let once = merge_hooks(Agent::OpenCode, None).unwrap();
        assert_eq!(merge_hooks(Agent::OpenCode, Some(&once)).unwrap(), once);
        assert_eq!(
            once.matches("smith hook opencode tool.execute.before")
                .count(),
            1
        );
        assert!(once.contains("tool.execute.before") && once.contains("throw new Error"));
        assert!(
            once.contains("Locksmith hook unavailable"),
            "fails closed without smith"
        );
        assert!(merge_hooks(Agent::OpenCode, Some("export const X = 1;")).is_err());
        // Kiro: a versioned list; the user's hooks stay, ours is added once.
        let user = r#"{"version":"v1","hooks":[{"name":"mine","trigger":"PostToolUse","action":{"type":"command","command":"echo"}}],"extra":1}"#;
        for start in [None, Some(user)] {
            let once = merge_hooks(Agent::Kiro, start).unwrap();
            assert_eq!(merge_hooks(Agent::Kiro, Some(&once)).unwrap(), once);
            assert_eq!(once.matches("smith hook kiro PreToolUse").count(), 1);
            let v: Value = serde_json::from_str(&once).unwrap();
            assert_eq!(v["version"], "v1");
            assert_eq!(
                v["hooks"].as_array().unwrap().len(),
                if start.is_some() { 2 } else { 1 }
            );
            if start.is_some() {
                assert!(once.contains("mine") && v["extra"] == 1);
            }
        }
        assert!(merge_hooks(Agent::Kiro, Some("{oops")).is_err());
        assert!(merge_hooks(Agent::Kiro, Some(r#"{"hooks":{}}"#)).is_err());
        assert_eq!(hooks_json(Agent::OpenCode), json!({}));
        // MCP: OpenCode under mcp.servers, Kiro under mcpServers; settings kept; idempotent.
        for (a, seed) in [
            (
                Agent::OpenCode,
                r#"{"theme":"x","mcp":{"servers":{"other":{"type":"local","command":["a"]}}}}"#,
            ),
            (
                Agent::Kiro,
                r#"{"theme":"x","mcpServers":{"other":{"command":"a"}}}"#,
            ),
        ] {
            for start in [None, Some(seed)] {
                let once = merge_mcp(a, start).unwrap();
                assert_eq!(merge_mcp(a, Some(&once)).unwrap(), once, "{a:?}");
                let v: Value = serde_json::from_str(&once).unwrap();
                let servers = if a == Agent::OpenCode {
                    &v["mcp"]["servers"]
                } else {
                    &v["mcpServers"]
                };
                assert!(servers.get("locksmith").is_some());
                if start.is_some() {
                    assert!(servers.get("other").is_some() && v["theme"] == "x");
                }
            }
            assert!(merge_mcp(a, Some("{oops")).is_err());
        }
        assert_eq!(
            merge_mcp(Agent::OpenCode, None)
                .unwrap()
                .contains("\"command\": [\n"),
            true
        );
        assert!(merge_mcp(Agent::OpenCode, Some(r#"{"mcp":[]}"#)).is_err());
    }

    #[test]
    fn opencode_and_kiro_paths_detection_and_gating() {
        let d = tmp("p7");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(mcp_path(Agent::OpenCode, &d), Some(d.join("opencode.json")));
        std::fs::write(d.join("opencode.jsonc"), "{}").unwrap();
        assert_eq!(
            mcp_path(Agent::OpenCode, &d),
            Some(d.join("opencode.jsonc"))
        );
        assert_eq!(
            mcp_path(Agent::Kiro, &d),
            Some(d.join(".kiro/settings/mcp.json"))
        );
        assert!(detect(&d).contains(&Agent::OpenCode) && !detect(&d).contains(&Agent::Kiro));
        std::fs::create_dir_all(d.join(".kiro")).unwrap();
        assert!(detect(&d).contains(&Agent::Kiro));
        assert!(!hook_handler_ready(Agent::OpenCode) && !hook_handler_ready(Agent::Kiro));
        assert!(!Agent::OpenCode.remote_mcp() && !Agent::Kiro.remote_mcp());
        assert_eq!(
            config_path(Agent::OpenCode, &d),
            d.join(".opencode/plugins/locksmith.js")
        );
        assert_eq!(
            config_path(Agent::Kiro, &d),
            d.join(".kiro/hooks/locksmith.json")
        );
        let _ = std::fs::remove_dir_all(&d);
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
        // Any MCP client: the plain `mcpServers` stdio snippet, no hook and no secrets.
        check(
            "generic-mcp/mcp.json",
            merge_mcp(Agent::ClaudeCode, None).unwrap(),
        );
        check(
            "gemini-cli/settings.json",
            merge_mcp(
                Agent::GeminiCli,
                Some(&merge_hooks(Agent::GeminiCli, None).unwrap()),
            )
            .unwrap(),
        );
        check(
            "copilot/hooks/locksmith.json",
            merge_hooks(Agent::Copilot, None).unwrap(),
        );
        check("copilot/mcp.json", merge_mcp(Agent::Copilot, None).unwrap());
        check(
            "windsurf/hooks.json",
            merge_hooks(Agent::Windsurf, None).unwrap(),
        );
        check("cline/PreToolUse", cline_script());
        check("opencode/plugins/locksmith.js", opencode_plugin());
        check(
            "opencode/opencode.json",
            merge_mcp(Agent::OpenCode, None).unwrap(),
        );
        check(
            "kiro/hooks/locksmith.json",
            merge_hooks(Agent::Kiro, None).unwrap(),
        );
        check(
            "kiro/settings/mcp.json",
            merge_mcp(Agent::Kiro, None).unwrap(),
        );
        let hub = "https://hub.example/mcp";
        check(
            "claude-code/.mcp.hub.json",
            merge_hub_mcp(Agent::ClaudeCode, None, hub).unwrap(),
        );
        check(
            "codex/config.hub.toml",
            merge_hub_mcp(Agent::Codex, None, hub).unwrap(),
        );
    }

    const TOKEN: &str = "ghp_TOKEN_CANARY_0123456789";

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn gateway_rewrite_json_replaces_only_named_entries_and_is_idempotent() {
        let text = format!(
            r#"{{"keep":1,"mcpServers":{{"github":{{"url":"https://x.test/mcp","headers":{{"Authorization":"Bearer {TOKEN}"}}}},"other":{{"command":"npx","env":{{"K":"v"}}}},"local":{{"command":"x"}}}}}}"#
        );
        for a in [Agent::ClaudeCode, Agent::Cursor, Agent::GeminiCli] {
            let r = rewrite_gateway_mcp(a, &text, &names(&["github", "absent"]))
                .unwrap()
                .expect("rewritten");
            assert_eq!(r.rewritten, ["github"]);
            assert!(
                !r.after.contains(TOKEN) && !r.after.contains("x.test"),
                "{a:?}"
            );
            // The preview text hides every value of the replaced entry.
            assert!(!r.masked_before.contains(TOKEN) && !r.masked_before.contains("x.test"));
            assert!(r.masked_before.contains("***"));
            let v: Value = serde_json::from_str(&r.after).unwrap();
            assert_eq!(v["keep"], 1);
            assert_eq!(
                v["mcpServers"]["github"],
                json!({"command":"smith","args":["mcp","bridge","github"]})
            );
            // Other entries are untouched, secrets in them included (doctor reports those).
            assert_eq!(
                v["mcpServers"]["other"],
                json!({"command":"npx","env":{"K":"v"}})
            );
            assert_eq!(v["mcpServers"]["local"], json!({"command":"x"}));
            assert!(
                rewrite_gateway_mcp(a, &r.after, &names(&["github"]))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn gateway_rewrite_copilot_uses_servers_and_a_stdio_type() {
        let text = format!(
            r#"{{"servers":{{"github":{{"type":"http","url":"https://x.test","headers":{{"x-api-key":"{TOKEN}"}}}}}}}}"#
        );
        let r = rewrite_gateway_mcp(Agent::Copilot, &text, &names(&["github"]))
            .unwrap()
            .unwrap();
        let v: Value = serde_json::from_str(&r.after).unwrap();
        assert_eq!(
            v["servers"]["github"],
            json!({"type":"stdio","command":"smith","args":["mcp","bridge","github"]})
        );
        assert!(!r.after.contains(TOKEN) && !r.masked_before.contains(TOKEN));
        assert!(
            rewrite_gateway_mcp(Agent::Copilot, &r.after, &names(&["github"]))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn gateway_rewrite_codex_keeps_comments_and_other_tables() {
        let text = format!(
            "# mine\nmodel = \"x\"\n\n[mcp_servers.github]\nurl = \"https://x.test/mcp\"\nbearer_token = \"{TOKEN}\"\n\n[mcp_servers.github.env]\nGITHUB_TOKEN = \"{TOKEN}\"\n\n[mcp_servers.other]\ncommand = \"npx\"\n"
        );
        let r = rewrite_gateway_mcp(Agent::Codex, &text, &names(&["github"]))
            .unwrap()
            .unwrap();
        assert!(r.after.contains("# mine") && r.after.contains("[mcp_servers.other]"));
        assert!(
            !r.after.contains(TOKEN) && !r.after.contains("x.test"),
            "{}",
            r.after
        );
        assert!(!r.masked_before.contains(TOKEN), "{}", r.masked_before);
        let t: toml::Table = toml::from_str(&r.after).unwrap();
        assert_eq!(
            t["mcp_servers"]["github"]["command"].as_str(),
            Some("smith")
        );
        assert_eq!(
            t["mcp_servers"]["github"]["args"].as_array().unwrap().len(),
            3
        );
        assert!(t["mcp_servers"]["github"].get("env").is_none());
        assert!(
            rewrite_gateway_mcp(Agent::Codex, &r.after, &names(&["github"]))
                .unwrap()
                .is_none()
        );
        assert!(rewrite_gateway_mcp(Agent::Codex, "= =", &names(&["github"])).is_err());
        assert!(rewrite_gateway_mcp(Agent::ClaudeCode, "{oops", &names(&["github"])).is_err());
    }

    #[test]
    fn credential_like_values_are_reported_by_name_only() {
        let json = format!(
            r#"{{"mcpServers":{{"a":{{"headers":{{"Authorization":"Bearer {TOKEN}","Accept":"x"}}}},"b":{{"env":{{"GITHUB_TOKEN":"{TOKEN}","LOG":"1","API_KEY":""}}}},"c":{{"headers":{{"X-Api-Key":"{TOKEN}"}}}},"d":{{"command":"x"}}}}}}"#
        );
        let f = mcp_credentials(Agent::ClaudeCode, &json);
        assert_eq!(
            f,
            vec![
                ("a".to_owned(), "Authorization".to_owned()),
                ("b".to_owned(), "GITHUB_TOKEN".to_owned()),
                ("c".to_owned(), "X-Api-Key".to_owned()),
            ]
        );
        assert!(!format!("{f:?}").contains(TOKEN));
        let toml = format!(
            "[mcp_servers.a]\n[mcp_servers.a.env]\nOPENAI_API_KEY = \"{TOKEN}\"\nMODE = \"x\"\n"
        );
        assert_eq!(
            mcp_credentials(Agent::Codex, &toml),
            vec![("a".to_owned(), "OPENAI_API_KEY".to_owned())]
        );
        assert!(mcp_credentials(Agent::ClaudeCode, "{oops").is_empty());
    }
}
