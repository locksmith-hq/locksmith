//! OpenCode: the generated plugin's `tool.execute.before` hook pipes `{"tool", "args"}` (V1 API,
//! https://opencode.ai/v1/docs/plugins/) to `smith hook opencode tool.execute.before` and throws
//! on a non-zero exit. Only `read` (`filePath`) and `bash` (`command`) are read from the vendor
//! docs (tests/fixtures/opencode/SOURCE.md); any other tool name passes as unknown. Exit 2 with
//! the reason on stderr denies; malformed input exits 2 too.
use super::{Call, MALFORMED, Out, field, input_object};
use crate::{Decision, Event};
use serde_json::Value;
use std::path::PathBuf;

pub(crate) const KNOWN_TOOLS: &[&str] = &["bash", "read"];

/// The plugin sends `tool` and an `args` object. A Claude-style or camelCase naming, a missing
/// tool name or missing args is unrecognised and denies. The plugin runs in the project, so the
/// cwd is the hook process's own.
pub(crate) fn call(event: &str, v: &Value) -> Call {
    if event != "tool.execute.before" {
        return Call::NotTool;
    }
    let other_naming = ["tool_name", "tool_input", "toolName", "toolInput", "input"]
        .iter()
        .any(|k| v.get(k).is_some());
    match (field(v, "tool"), input_object(v.get("args"))) {
        (Some(name), Some(input)) if !other_naming => Call::Tool {
            name: name.to_string(),
            input,
            cwd: PathBuf::from("."),
        },
        _ => Call::Unrecognised,
    }
}

pub(crate) fn shell_keys(name: &str) -> &'static [&'static str] {
    match name {
        "bash" => &["command"],
        _ => &[],
    }
}

pub(crate) fn content_keys(name: &str) -> &'static [&'static str] {
    match name {
        "bash" => &["description"],
        _ => &[],
    }
}

pub(crate) fn primary(name: &str, t: &Value, cwd: PathBuf) -> Option<Vec<Event>> {
    let ev = match name {
        "bash" => Event::Shell {
            command: field(t, "command")?.to_string(),
            cwd,
        },
        "read" => Event::Read {
            path: field(t, "filePath").map(PathBuf::from)?,
            cwd,
        },
        _ => return None,
    };
    Some(vec![ev])
}

/// OpenCode has no prompt hook: nothing but tool events reach the adapter.
pub fn parse(_event: &str, _v: &Value) -> Option<Event> {
    None
}

/// Allow is silent; any other decision blocks (the plugin throws the stderr text).
pub fn render(_event: &str, d: &Decision) -> Out {
    match d {
        Decision::Allow => Out::silent(),
        d => Out::block_stderr(&d.message()),
    }
}

pub fn malformed(_event: &str) -> Out {
    Out::block_stderr(MALFORMED)
}
