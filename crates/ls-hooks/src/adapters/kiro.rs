//! Kiro: a project `PreToolUse` command hook (`.kiro/hooks/*.json`, https://kiro.dev/docs/hooks/)
//! gets `{"hook_event_name", "cwd", "tool_name", "tool_input"}` on stdin; a non-zero exit blocks
//! the tool call and stderr goes to the agent. The payload is documented for MCP tools and for
//! `read_file` (`path`) only (tests/fixtures/kiro/SOURCE.md), so only `read_file` is checked and
//! any other tool name passes as unknown; a payload that does not fit the shape denies.
use super::{Call, MALFORMED, Out, cwd_of, field, input_object};
use crate::{Decision, Event};
use serde_json::Value;
use std::path::PathBuf;

pub(crate) const KNOWN_TOOLS: &[&str] = &["read_file"];

pub(crate) fn call(event: &str, v: &Value) -> Call {
    if event != "PreToolUse" {
        return Call::NotTool;
    }
    let other_naming = ["toolName", "toolInput", "tool", "args", "toolArgs"]
        .iter()
        .any(|k| v.get(k).is_some());
    match (field(v, "tool_name"), input_object(v.get("tool_input"))) {
        (Some(name), Some(input)) if !other_naming => Call::Tool {
            name: name.to_string(),
            input,
            cwd: cwd_of(v),
        },
        _ => Call::Unrecognised,
    }
}

pub(crate) fn shell_keys(_name: &str) -> &'static [&'static str] {
    &[]
}

pub(crate) fn content_keys(_name: &str) -> &'static [&'static str] {
    &[]
}

pub(crate) fn primary(name: &str, t: &Value, cwd: PathBuf) -> Option<Vec<Event>> {
    match name {
        "read_file" => Some(vec![Event::Read {
            path: field(t, "path").map(PathBuf::from)?,
            cwd,
        }]),
        _ => None,
    }
}

/// Kiro's prompt hooks are not used: nothing but tool events reach the adapter.
pub fn parse(_event: &str, _v: &Value) -> Option<Event> {
    None
}

/// Allow is silent (exit 0); any other decision exits 2 with the reason on stderr.
pub fn render(_event: &str, d: &Decision) -> Out {
    match d {
        Decision::Allow => Out::silent(),
        d => Out::block_stderr(&d.message()),
    }
}

pub fn malformed(_event: &str) -> Out {
    Out::block_stderr(MALFORMED)
}
