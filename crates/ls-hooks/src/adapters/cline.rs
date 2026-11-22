//! Cline: the `PreToolUse` hook script. Payload `{preToolUse:{toolName, parameters}}` with string
//! values; the SDK/CLI runner sends `{tool_call:{name, input}}` instead, so both are parsed. The
//! reply is JSON on exit 0 (`cancel` true blocks); exit codes are undocumented, so none is used.
use super::{Call, MALFORMED, Out, cwd_of, field, input_object, search_args};
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

/// Tools whose input is checked. The payload schema is doc-derived, so a known tool whose input
/// does not parse (a path key under another name) must cancel, not pass.
pub(crate) const KNOWN_TOOLS: &[&str] = &[
    "execute_command",
    "run_commands",
    "read_file",
    "write_to_file",
    "replace_in_file",
    "apply_patch",
    "search_files",
];

/// The tool call under exactly one of the two shapes; neither, both, or a missing name or
/// parameters object is unrecognised and cancels.
pub(crate) fn call(event: &str, v: &Value) -> Call {
    if event != "PreToolUse" {
        return Call::NotTool;
    }
    let (name, args) = match (v.get("preToolUse"), v.get("tool_call")) {
        (Some(p), None) => (field(p, "toolName"), p.get("parameters")),
        (None, Some(c)) => (field(c, "name"), c.get("input")),
        _ => return Call::Unrecognised,
    };
    match (name, input_object(args)) {
        (Some(name), Some(input)) => Call::Tool {
            name: name.to_string(),
            input,
            cwd: cwd(v),
        },
        _ => Call::Unrecognised,
    }
}

/// Keys that hold a command, file content or a search pattern rather than a file name.
pub(crate) fn content_keys(name: &str) -> &'static [&'static str] {
    match name {
        "execute_command" | "run_commands" => &["command", "commands"],
        "write_to_file" => &["content"],
        "replace_in_file" => &["diff"],
        "search_files" => &["regex"],
        _ => &[],
    }
}

/// The primary arguments of a known tool, or `None` (cancel) when they do not parse.
pub(crate) fn primary(name: &str, args: &Value, cwd: PathBuf) -> Option<Vec<Event>> {
    let path = || field(args, "path").map(PathBuf::from);
    let ev = match name {
        "execute_command" => Event::Shell {
            command: field(args, "command")?.to_string(),
            cwd,
        },
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
            Event::Shell { command, cwd }
        }
        "read_file" => Event::Read { path: path()?, cwd },
        "write_to_file" | "replace_in_file" | "apply_patch" => Event::Edit { path: path()?, cwd },
        // `path`, `regex` and `file_pattern` are the only keys: a guessed key name (one right,
        // one wrong, or neither set) cancels rather than search with the wrong key dropped.
        "search_files" => {
            let (path, glob) = search_args(args, "path", "file_pattern", &["regex"])?;
            Event::Search { path, glob, cwd }
        }
        _ => return None,
    };
    Some(vec![ev])
}

/// Cline has no prompt event here; tool events go through `call` and `primary`.
pub fn parse(_event: &str, _v: &Value) -> Option<Event> {
    None
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
