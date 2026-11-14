//! Claude Code: `PreToolUse` and `UserPromptSubmit` (https://code.claude.com/docs/en/hooks).
use super::{MALFORMED, Out, cwd_of, field};
use crate::{Decision, Event};
use serde_json::{Value, json};
use std::path::PathBuf;

pub fn parse(event: &str, v: &Value) -> Option<Event> {
    let cwd = cwd_of(v);
    match event {
        "UserPromptSubmit" => Some(Event::Prompt {
            text: field(v, "prompt")?.to_string(),
        }),
        "PreToolUse" => {
            let t = v.get("tool_input")?;
            let file = || field(t, "file_path").map(PathBuf::from);
            match field(v, "tool_name")? {
                "Bash" => Some(Event::Shell {
                    command: field(t, "command")?.to_string(),
                    cwd,
                }),
                "Read" => Some(Event::Read { path: file()?, cwd }),
                "Edit" | "MultiEdit" => Some(Event::Edit { path: file()?, cwd }),
                "Grep" => Some(Event::Search {
                    path: field(t, "path").map(PathBuf::from),
                    glob: field(t, "glob").map(String::from),
                    cwd,
                }),
                // Glob lists names only; it never returns file content.
                _ => None,
            }
        }
        _ => None,
    }
}

pub fn render(event: &str, d: &Decision) -> Out {
    let msg = d.message();
    match (event, d) {
        // Allow is silent so Claude's own permission flow still applies; "allow" would skip it.
        (_, Decision::Allow) => Out::silent(),
        ("UserPromptSubmit", _) => Out::json(json!({
            "decision": "block",
            "reason": msg,
            // The prompt holds a secret: keep it out of the transcript echo too.
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": true}
        })),
        (_, d) => Out::json(json!({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": if matches!(d, Decision::Ask { .. }) { "ask" } else { "deny" },
            "permissionDecisionReason": msg,
        }})),
    }
}

/// Exit 2 blocks on both events; anything else would let the action run.
pub fn malformed(_event: &str) -> Out {
    Out::block_stderr(MALFORMED)
}
