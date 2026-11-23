//! Single source of truth for wiring Locksmith hooks into agents. Used by `smith init`, doctor
//! and the `integrations/` files (a test keeps those in sync).

use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Agent {
    ClaudeCode,
    Cursor,
    Codex,
}

pub const ALL: [Agent; 3] = [Agent::ClaudeCode, Agent::Cursor, Agent::Codex];

const CLAUDE_MATCHER: &str = "Bash|Read|Edit|MultiEdit|Grep|Glob";
const MISSING: &str = "Locksmith hook unavailable: run smith doctor";

impl Agent {
    /// The `<agent>` argument of `smith hook`.
    pub fn id(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "claude-code",
            Agent::Cursor => "cursor",
            Agent::Codex => "codex",
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

/// Agents the repo shows signs of using.
pub fn detect(repo: &Path) -> Vec<Agent> {
    ALL.into_iter()
        .filter(|a| match a {
            Agent::ClaudeCode => repo.join(".claude").is_dir(),
            Agent::Cursor => repo.join(".cursor").is_dir(),
            Agent::Codex => repo.join(".codex").is_dir() || repo.join("AGENTS.md").is_file(),
        })
        .collect()
}

pub fn config_path(a: Agent, repo: &Path) -> PathBuf {
    repo.join(match a {
        Agent::ClaudeCode => ".claude/settings.json",
        Agent::Cursor => ".cursor/hooks.json",
        Agent::Codex => ".codex/config.toml",
    })
}

pub fn installed(a: Agent, repo: &Path) -> bool {
    std::fs::read_to_string(config_path(a, repo))
        .is_ok_and(|t| a.events().iter().all(|e| t.contains(&marker(a, e))))
}

/// Our handler for one event, in the agent's JSON shape (Claude Code, Cursor).
fn json_entry(a: Agent, event: &str) -> Value {
    let command = wrapper(a, event);
    match a {
        Agent::Cursor => json!({"command": command, "failClosed": true, "timeout": 10}),
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

/// Hooks object for Claude Code (plugin and settings) and Cursor.
#[cfg(test)]
pub fn hooks_json(a: Agent) -> Value {
    let hooks: serde_json::Map<String, Value> = a
        .events()
        .iter()
        .map(|e| (e.to_string(), json!([json_entry(a, e)])))
        .collect();
    if a == Agent::Cursor {
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
    let mut root: Value = match existing.filter(|t| !t.trim().is_empty()) {
        None => json!({}),
        Some(t) => serde_json::from_str(t)
            .map_err(|e| format!("existing config is not valid JSON: {e}"))?,
    };
    let obj = root
        .as_object_mut()
        .ok_or("existing config is not a JSON object")?;
    if a == Agent::Cursor {
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

/// Where the agent reads MCP servers from. Codex shares its hooks file.
pub fn mcp_path(a: Agent, repo: &Path) -> PathBuf {
    match a {
        Agent::ClaudeCode => repo.join(".mcp.json"),
        Agent::Cursor => repo.join(".cursor/mcp.json"),
        Agent::Codex => config_path(a, repo),
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
        .entry("mcpServers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or("`mcpServers` is not an object")?;
    if servers.contains_key("locksmith") {
        return Ok(existing.map_or_else(String::new, str::to_string));
    }
    servers.insert(
        "locksmith".into(),
        json!({"command": MCP_COMMAND, "args": []}),
    );
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
}
