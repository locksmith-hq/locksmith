//! GitHub Copilot (CLI, cloud agent, VS Code agent mode): `preToolUse` hooks in
//! `.github/hooks/*.json`. The event name's casing selects the payload: `preToolUse` gives
//! `{toolName, toolArgs}` (`toolArgs` may be a JSON string or an object), `PreToolUse` gives the
//! Claude-style `{tool_name, tool_input}`. See docs/research/agent-plugin-formats.md.
use super::{MALFORMED, Out, claude_code, cwd_of, field};
use crate::{Decision, Event};
use serde_json::{Value, json};
use std::path::PathBuf;

/// Tools the `preToolUse` parser recognises (doc-derived schema: a known tool whose arguments
/// do not parse must deny, not pass).
const KNOWN_TOOLS: &[&str] = &["bash", "powershell", "view", "edit", "create", "grep"];

/// `preToolUse` with `toolName` but no readable `toolArgs`, or a known tool that does not parse,
/// must deny, not pass as an unknown tool.
pub fn unreadable(event: &str, v: &Value) -> bool {
    event == "preToolUse"
        && v.get("toolName").is_some()
        && (match v.get("toolArgs") {
            None | Some(Value::Null) => true,
            Some(Value::String(s)) => serde_json::from_str::<Value>(s).is_err(),
            Some(_) => false,
        } || field(v, "toolName").is_some_and(|n| KNOWN_TOOLS.contains(&n))
            && parse(event, v).is_none())
}

pub fn parse(event: &str, v: &Value) -> Option<Event> {
    match event {
        "PreToolUse" => claude_code::parse("PreToolUse", v),
        "preToolUse" => {
            let cwd = cwd_of(v);
            let args = match v.get("toolArgs")? {
                Value::String(s) => serde_json::from_str::<Value>(s).ok()?,
                o => o.clone(),
            };
            let path = || {
                ["path", "filePath", "file_path"]
                    .iter()
                    .find_map(|k| field(&args, k))
                    .map(PathBuf::from)
            };
            match field(v, "toolName")? {
                "bash" | "powershell" => Some(Event::Shell {
                    command: field(&args, "command")?.to_string(),
                    cwd,
                }),
                "view" => Some(Event::Read { path: path()?, cwd }),
                "edit" | "create" => Some(Event::Edit { path: path()?, cwd }),
                "grep" => Some(Event::Search {
                    path: field(&args, "path").map(PathBuf::from),
                    glob: field(&args, "glob").map(String::from),
                    cwd,
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Allow is empty output (default behaviour). A denial is JSON on exit 0; the cloud agent treats
/// `ask` as deny.
pub fn render(_event: &str, d: &Decision) -> Out {
    match d {
        Decision::Allow => Out::silent(),
        d => Out::json(json!({
            "permissionDecision": if matches!(d, Decision::Ask { .. }) { "ask" } else { "deny" },
            "permissionDecisionReason": d.message(),
        })),
    }
}

/// Exit 2 denies on Copilot, even without valid output.
pub fn malformed(_event: &str) -> Out {
    Out::block_stderr(MALFORMED)
}
