//! Cline: the `PreToolUse` hook script. Payload `{preToolUse:{toolName, parameters}}` with string
//! values; the SDK/CLI runner sends `{tool_call:{name, input}}` instead, so both are parsed. The
//! reply is JSON on exit 0 (`cancel` true blocks); exit codes are undocumented, so none is used.
use super::{MALFORMED, Out, cwd_of, field};
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

/// PreToolUse without a readable tool call, or a shell tool without its command, must cancel.
pub fn unreadable(event: &str, v: &Value) -> bool {
    if event != "PreToolUse" {
        return false;
    }
    let (name, args) = match (v.get("preToolUse"), v.get("tool_call")) {
        (Some(p), _) => (field(p, "toolName"), p.get("parameters")),
        (None, Some(c)) => (field(c, "name"), c.get("input")),
        (None, None) => return true,
    };
    let (Some(name), Some(args)) = (name, args) else {
        return true;
    };
    matches!(name, "execute_command") && field(args, "command").is_none()
        || name == "run_commands"
            && args.get("commands").is_none()
            && field(args, "command").is_none()
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
        "search_files" => Some(Event::Search {
            path: path(),
            glob: field(args, "file_pattern").map(String::from),
            cwd,
        }),
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
