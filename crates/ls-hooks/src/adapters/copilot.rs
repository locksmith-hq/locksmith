//! GitHub Copilot (CLI, cloud agent, VS Code agent mode): `preToolUse` hooks in
//! `.github/hooks/*.json`. The event name's casing selects the payload: `preToolUse` gives
//! `{toolName, toolArgs}` (`toolArgs` may be a JSON string or an object), `PreToolUse` gives the
//! Claude-style `{tool_name, tool_input}`. See docs/research/agent-plugin-formats.md.
use super::{MALFORMED, Out, claude_code, cwd_of, field, search_args};
use crate::{Decision, Event};
use serde_json::{Value, json};
use std::path::PathBuf;

/// Tools the `preToolUse` parser recognises (doc-derived schema: a known tool whose arguments
/// do not parse must deny, not pass).
const KNOWN_TOOLS: &[&str] = &["bash", "powershell", "view", "edit", "create", "grep"];

/// Claude-style tool names `claude_code::parse` recognises, for the `PreToolUse` casing.
const CLAUDE_TOOLS: &[&str] = &["Bash", "Read", "Edit", "MultiEdit", "Grep"];

/// Grep option keys besides `path` and `glob` (ripgrep-style, as in Claude Code's `Grep`) that
/// cannot widen the files searched. `type` is left out: a file type selects files.
const GREP_KEYS: &[&str] = &[
    "pattern",
    "output_mode",
    "-i",
    "-n",
    "-A",
    "-B",
    "-C",
    "context",
    "head_limit",
    "offset",
    "multiline",
];

/// A tool call whose arguments cannot be read, or a known tool that does not parse, must deny,
/// not pass as an unknown tool. Both casings fail closed the same way.
pub fn unreadable(event: &str, v: &Value) -> bool {
    let known = |n: &str| KNOWN_TOOLS.contains(&n) || CLAUDE_TOOLS.contains(&n);
    match event {
        "preToolUse" => {
            v.get("toolName").is_some()
                && (match v.get("toolArgs") {
                    None | Some(Value::Null) => true,
                    Some(Value::String(s)) => serde_json::from_str::<Value>(s).is_err(),
                    Some(_) => false,
                } || field(v, "toolName").is_some_and(known) && parse(event, v).is_none())
        }
        "PreToolUse" => {
            v.get("tool_name").is_some()
                && (matches!(v.get("tool_input"), None | Some(Value::Null))
                    || field(v, "tool_name").is_some_and(known) && parse(event, v).is_none())
        }
        _ => false,
    }
}

pub fn parse(event: &str, v: &Value) -> Option<Event> {
    match event {
        // Claude-style payload. Copilot may still send its own lowercase tool names here, so
        // those are read with the `preToolUse` rules; `Grep` gets the search key check.
        "PreToolUse" => match field(v, "tool_name")? {
            "Grep" => grep(v.get("tool_input")?, cwd_of(v)),
            n if CLAUDE_TOOLS.contains(&n) => claude_code::parse("PreToolUse", v),
            n => tool(n, v.get("tool_input")?, cwd_of(v)),
        },
        "preToolUse" => {
            let args = match v.get("toolArgs")? {
                Value::String(s) => serde_json::from_str::<Value>(s).ok()?,
                o => o.clone(),
            };
            tool(field(v, "toolName")?, &args, cwd_of(v))
        }
        _ => None,
    }
}

/// One of Copilot's own tools (`KNOWN_TOOLS`) with its arguments.
fn tool(name: &str, args: &Value, cwd: PathBuf) -> Option<Event> {
    let path = || {
        ["path", "filePath", "file_path"]
            .iter()
            .find_map(|k| field(args, k))
            .map(PathBuf::from)
    };
    match name {
        "bash" | "powershell" => Some(Event::Shell {
            command: field(args, "command")?.to_string(),
            cwd,
        }),
        "view" => Some(Event::Read { path: path()?, cwd }),
        "edit" | "create" => Some(Event::Edit { path: path()?, cwd }),
        "grep" => grep(args, cwd),
        _ => None,
    }
}

/// A guessed key name (one right, one wrong, or neither set) denies via `unreadable` rather than
/// search with the wrong key dropped.
fn grep(args: &Value, cwd: PathBuf) -> Option<Event> {
    let (path, glob) = search_args(args, "path", "glob", GREP_KEYS)?;
    Some(Event::Search { path, glob, cwd })
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
