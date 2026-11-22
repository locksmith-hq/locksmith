//! Cline: the `PreToolUse` hook script. Payload `{preToolUse:{toolName, parameters}}` with string
//! values; the SDK/CLI runner sends `{tool_call:{name, input}}` instead, so both are parsed. The
//! reply is JSON on exit 0 (`cancel` true blocks); exit codes are undocumented, so none is used.
use super::{MALFORMED, Out, cwd_of, field, search_args};
use crate::{Decision, Event};
use serde_json::{Value, json};
use std::path::PathBuf;

fn cwd(v: &Value) -> PathBuf {
    let c = cwd_of(v);
    if c.as_os_str() != "." {
        return c;
    }
    v.get("workspaceRoots")
        .and_then(|r| r.get(0))
        .and_then(Value::as_str)
        .map_or(c, Into::into)
}

/// Tools `parse` recognises. The payload schema is doc-derived, so a known tool whose input does
/// not parse (a path key under another name) must cancel, not pass.
const KNOWN_TOOLS: &[&str] = &[
    "execute_command",
    "run_commands",
    "read_file",
    "write_to_file",
    "replace_in_file",
    "apply_patch",
    "search_files",
];

/// PreToolUse without a readable tool call, or a known tool that does not parse, must cancel.
pub fn unreadable(event: &str, v: &Value) -> bool {
    if event != "PreToolUse" {
        return false;
    }
    let (name, args) = match (v.get("preToolUse"), v.get("tool_call")) {
        (Some(p), _) => (field(p, "toolName"), p.get("parameters")),
        (None, Some(c)) => (field(c, "name"), c.get("input")),
        (None, None) => return true,
    };
    let (Some(name), Some(_)) = (name, args) else {
        return true;
    };
    KNOWN_TOOLS.contains(&name) && parse(event, v).is_none()
}

pub fn parse(event: &str, v: &Value) -> Option<Event> {
    if event != "PreToolUse" {
        return None;
    }
    let (name, args) = if let Some(p) = v.get("preToolUse") {
        (field(p, "toolName")?, p.get("parameters")?)
    } else {
        let c = v.get("tool_call")?;
        (field(c, "name")?, c.get("input")?)
    };
    let cwd = cwd(v);
    let path = || field(args, "path").map(PathBuf::from);
    match name {
        "execute_command" => Some(Event::Shell {
            command: field(args, "command")?.to_string(),
            cwd,
        }),
        // SDK runner: `commands` is a list of shell commands (or one `command`).
        "run_commands" => {
            let command = match args.get("commands") {
                Some(Value::Array(a)) => a
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n"),
                Some(Value::String(s)) => s.clone(),
                _ => field(args, "command")?.to_string(),
            };
            Some(Event::Shell { command, cwd })
        }
        "read_file" => Some(Event::Read { path: path()?, cwd }),
        "write_to_file" | "replace_in_file" | "apply_patch" => {
            Some(Event::Edit { path: path()?, cwd })
        }
        // `path`, `regex` and `file_pattern` are the only keys: a guessed key name (one right,
        // one wrong, or neither set) cancels via `unreadable` rather than search with the wrong
        // key dropped.
        "search_files" => {
            let (path, glob) = search_args(args, "path", "file_pattern", &["regex"])?;
            Some(Event::Search { path, glob, cwd })
        }
        _ => None,
    }
}

pub fn render(_event: &str, d: &Decision) -> Out {
    match d {
        Decision::Allow => Out::json(json!({"cancel": false})),
        d => Out::json(json!({"cancel": true, "errorMessage": d.message()})),
    }
}

/// Unreadable input blocks: a missing `cancel` would let the tool run.
pub fn malformed(_event: &str) -> Out {
    Out::json(json!({"cancel": true, "errorMessage": MALFORMED}))
}
