//! Gemini CLI: `BeforeTool` and `BeforeAgent` hooks (docs/hooks/reference.md in
//! google-gemini/gemini-cli; see docs/research/agent-plugin-formats.md). Exit 2 blocks with
//! stderr as the reason; any other exit code lets the action run, so malformed input exits 2 too.
use super::{MALFORMED, Out, cwd_of, field, search_args};
use crate::{Decision, Event};
use serde_json::Value;
use std::path::PathBuf;

/// Tools `parse` recognises. A payload schema is only doc-derived, so a known tool whose input
/// cannot be turned into an `Event` (a path key under another name) must deny, not pass.
const KNOWN_TOOLS: &[&str] = &[
    "run_shell_command",
    "read_file",
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

/// A tool event whose input cannot be read, or a known tool that does not parse, must deny.
pub fn unreadable(event: &str, v: &Value) -> bool {
    event == "BeforeTool"
        && (v.get("tool_input").is_none()
            || match field(v, "tool_name") {
                Some("read_many_files") => parse_many(event, v).is_none(),
                Some(n) => KNOWN_TOOLS.contains(&n) && parse(event, v).is_none(),
                None => false,
            })
}

/// `read_many_files` returns file content for every `include` entry (a path or a glob): one
/// `Search` event per entry, so a secret file or a secret-naming glob denies. Any other shape
/// (no entries, a non-string entry, an unknown key) is `None`, which denies via `unreadable`.
pub fn parse_many(event: &str, v: &Value) -> Option<Vec<Event>> {
    if event != "BeforeTool" || field(v, "tool_name")? != "read_many_files" {
        return None;
    }
    let t = v.get("tool_input")?.as_object()?;
    if !t
        .keys()
        .all(|k| k == "include" || READ_MANY_KEYS.contains(&k.as_str()))
    {
        return None;
    }
    let cwd = cwd_of(v);
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

pub fn parse(event: &str, v: &Value) -> Option<Event> {
    let cwd = cwd_of(v);
    match event {
        "BeforeAgent" => Some(Event::Prompt {
            text: field(v, "prompt")?.to_string(),
        }),
        "BeforeTool" => {
            let t = v.get("tool_input")?;
            let file = || field(t, "file_path").map(PathBuf::from);
            match field(v, "tool_name")? {
                "run_shell_command" => Some(Event::Shell {
                    command: field(t, "command")?.to_string(),
                    cwd,
                }),
                "read_file" => Some(Event::Read { path: file()?, cwd }),
                "write_file" | "replace" => Some(Event::Edit { path: file()?, cwd }),
                // A guessed key name (one right, one wrong, or neither set) denies via
                // `unreadable` rather than search with the wrong key dropped.
                "grep_search" => {
                    let (path, glob) = search_args(t, "dir_path", "include_pattern", GREP_KEYS)?;
                    Some(Event::Search { path, glob, cwd })
                }
                // `read_many_files` is checked per entry by `parse_many`. The rest return names
                // only or no file content (list_directory, glob, web tools).
                _ => None,
            }
        }
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
