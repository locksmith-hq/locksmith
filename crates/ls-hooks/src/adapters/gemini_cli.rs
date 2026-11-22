//! Gemini CLI: `BeforeTool` and `BeforeAgent` hooks (docs/hooks/reference.md in
//! google-gemini/gemini-cli; see docs/research/agent-plugin-formats.md). Exit 2 blocks with
//! stderr as the reason; any other exit code lets the action run, so malformed input exits 2 too.
use super::{Call, MALFORMED, Out, cwd_of, field, input_object, search_args};
use crate::{Decision, Event};
use serde_json::Value;
use std::path::PathBuf;

/// Tools whose input is checked. A payload schema is only doc-derived, so a known tool whose
/// input cannot be turned into an `Event` (a path key under another name) must deny, not pass.
pub(crate) const KNOWN_TOOLS: &[&str] = &[
    "run_shell_command",
    "read_file",
    "read_many_files",
    "write_file",
    "replace",
    "grep_search",
];

/// `grep_search` keys besides `dir_path` and `include_pattern` that cannot widen the files read.
const GREP_KEYS: &[&str] = &["pattern", "exclude_pattern"];

/// `read_many_files` keys besides `include` that only narrow or filter the files read.
const READ_MANY_KEYS: &[&str] = &[
    "exclude",
    "recursive",
    "useDefaultExcludes",
    "file_filtering_options",
];

/// `BeforeTool` carries `tool_name` and a `tool_input` object. Anything else (a camelCase
/// `toolName`/`toolInput`, a missing name or input) is unrecognised and denies.
pub(crate) fn call(event: &str, v: &Value) -> Call {
    if event != "BeforeTool" {
        return Call::NotTool;
    }
    let other_naming = ["toolName", "toolInput", "toolArgs"]
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

/// Keys that hold a command, file content or a search pattern rather than a file name.
pub(crate) fn content_keys(name: &str) -> &'static [&'static str] {
    match name {
        "run_shell_command" => &["command", "description"],
        "write_file" => &["content"],
        "replace" => &["old_string", "new_string", "instruction"],
        "grep_search" => &["pattern", "exclude_pattern"],
        "read_many_files" => &["exclude"],
        _ => &[],
    }
}

/// The primary arguments of a known tool, or `None` (deny) when they do not parse.
pub(crate) fn primary(name: &str, t: &Value, cwd: PathBuf) -> Option<Vec<Event>> {
    let file = || field(t, "file_path").map(PathBuf::from);
    let ev = match name {
        "run_shell_command" => Event::Shell {
            command: field(t, "command")?.to_string(),
            cwd,
        },
        "read_file" => Event::Read { path: file()?, cwd },
        "write_file" | "replace" => Event::Edit { path: file()?, cwd },
        // A guessed key name (one right, one wrong, or neither set) denies rather than search
        // with the wrong key dropped.
        "grep_search" => {
            let (path, glob) = search_args(t, "dir_path", "include_pattern", GREP_KEYS)?;
            Event::Search { path, glob, cwd }
        }
        "read_many_files" => return read_many(t, cwd),
        _ => return None,
    };
    Some(vec![ev])
}

/// `read_many_files` returns file content for every `include` entry (a path or a glob): one
/// `Search` event per entry, so a secret file or a secret-naming glob denies. Any other shape
/// (no entries, a non-string entry, an unknown key) is `None`, which denies.
fn read_many(t: &Value, cwd: PathBuf) -> Option<Vec<Event>> {
    let t = t.as_object()?;
    if !t
        .keys()
        .all(|k| k == "include" || READ_MANY_KEYS.contains(&k.as_str()))
    {
        return None;
    }
    let entries = t.get("include")?.as_array()?;
    let events = entries
        .iter()
        .map(|e| {
            let s = e.as_str().filter(|s| !s.is_empty())?;
            Some(Event::Search {
                path: Some(PathBuf::from(s)),
                glob: Some(s.to_string()),
                cwd: cwd.clone(),
            })
        })
        .collect::<Option<Vec<_>>>()?;
    (!events.is_empty()).then_some(events)
}

/// Prompt events; tool events go through `call` and `primary`.
pub fn parse(event: &str, v: &Value) -> Option<Event> {
    match event {
        "BeforeAgent" => Some(Event::Prompt {
            text: field(v, "prompt")?.to_string(),
        }),
        _ => None,
    }
}

/// Allow is silent (Gemini's own flow applies). Gemini has no "ask": Ask becomes a block.
pub fn render(_event: &str, d: &Decision) -> Out {
    match d {
        Decision::Allow => Out::silent(),
        d => Out::block_stderr(&d.message()),
    }
}

pub fn malformed(_event: &str) -> Out {
    Out::block_stderr(MALFORMED)
}
