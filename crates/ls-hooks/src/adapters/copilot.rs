//! GitHub Copilot (CLI, cloud agent, VS Code agent mode): `preToolUse` hooks in
//! `.github/hooks/*.json`. The docs give `preToolUse` a `{toolName, toolArgs}` payload (`toolArgs`
//! may be a JSON string or an object) and `PreToolUse` the Claude-style `{tool_name, tool_input}`.
//! That pairing is doc-derived, so either naming is read under either event name; a payload with
//! neither naming, or with both, denies (decision P3-2). See docs/research/agent-plugin-formats.md.
use super::{Call, MALFORMED, Out, cwd_of, field, input_object, search_args};
use crate::{Decision, Event};
use serde_json::{Value, json};
use std::path::PathBuf;

/// Tools whose input is checked: Copilot's own names and the Claude-style ones. A known tool
/// whose arguments do not parse must deny, not pass.
pub(crate) const KNOWN_TOOLS: &[&str] = &[
    "bash",
    "powershell",
    "view",
    "edit",
    "create",
    "grep",
    "Bash",
    "Read",
    "Edit",
    "MultiEdit",
    "Grep",
];

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

/// The tool name and input under exactly one of the two namings; anything else is unrecognised.
pub(crate) fn call(event: &str, v: &Value) -> Call {
    if !matches!(event, "preToolUse" | "PreToolUse") {
        return Call::NotTool;
    }
    let has = |ks: [&str; 2]| ks.iter().any(|k| v.get(k).is_some());
    let (name, args) = match (
        has(["toolName", "toolArgs"]),
        has(["tool_name", "tool_input"]),
    ) {
        (true, false) => ("toolName", "toolArgs"),
        (false, true) => ("tool_name", "tool_input"),
        _ => return Call::Unrecognised,
    };
    match (field(v, name), input_object(v.get(args))) {
        (Some(name), Some(input)) => Call::Tool {
            name: name.to_string(),
            input,
            cwd: cwd_of(v),
        },
        _ => Call::Unrecognised,
    }
}

/// Keys that hold a command, file content or a search pattern rather than a file name.
pub(crate) fn content_keys(name: &str) -> &'static [&'static str] {
    match name {
        "bash" | "powershell" | "Bash" => &["command", "description"],
        "edit" => &["old_str", "new_str"],
        "create" => &["file_text"],
        "Edit" | "MultiEdit" => &["old_string", "new_string"],
        "grep" | "Grep" => &["pattern"],
        _ => &[],
    }
}

/// The primary arguments of a known tool, or `None` (deny) when they do not parse.
pub(crate) fn primary(name: &str, args: &Value, cwd: PathBuf) -> Option<Vec<Event>> {
    let path = || {
        ["path", "filePath", "file_path"]
            .iter()
            .find_map(|k| field(args, k))
            .map(PathBuf::from)
    };
    let file = || field(args, "file_path").map(PathBuf::from);
    let ev = match name {
        "bash" | "powershell" | "Bash" => Event::Shell {
            command: field(args, "command")?.to_string(),
            cwd,
        },
        "view" => Event::Read { path: path()?, cwd },
        "edit" | "create" => Event::Edit { path: path()?, cwd },
        "Read" => Event::Read { path: file()?, cwd },
        "Edit" | "MultiEdit" => Event::Edit { path: file()?, cwd },
        // A guessed key name (one right, one wrong, or neither set) denies rather than search
        // with the wrong key dropped.
        "grep" | "Grep" => {
            let (path, glob) = search_args(args, "path", "glob", GREP_KEYS)?;
            Event::Search { path, glob, cwd }
        }
        _ => return None,
    };
    Some(vec![ev])
}

/// Copilot has no prompt event here; tool events go through `call` and `primary`.
pub fn parse(_event: &str, _v: &Value) -> Option<Event> {
    None
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
