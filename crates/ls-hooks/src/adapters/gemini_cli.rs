//! Gemini CLI: `BeforeTool` and `BeforeAgent` hooks (docs/hooks/reference.md in
//! google-gemini/gemini-cli; see docs/research/agent-plugin-formats.md). Exit 2 blocks with
//! stderr as the reason; any other exit code lets the action run, so malformed input exits 2 too.
use super::{MALFORMED, Out, cwd_of, field};
use crate::{Decision, Event};
use serde_json::Value;
use std::path::PathBuf;

/// A tool event whose shell command or tool input cannot be read must deny, not pass as unknown.
pub fn unreadable(event: &str, v: &Value) -> bool {
    event == "BeforeTool"
        && (v.get("tool_input").is_none()
            || (field(v, "tool_name") == Some("run_shell_command")
                && v.get("tool_input")
                    .and_then(|t| field(t, "command"))
                    .is_none()))
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
                "grep_search" => Some(Event::Search {
                    path: field(t, "dir_path").map(PathBuf::from),
                    glob: field(t, "include_pattern").map(String::from),
                    cwd,
                }),
                // Names only or no file content (list_directory, glob, web tools).
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
