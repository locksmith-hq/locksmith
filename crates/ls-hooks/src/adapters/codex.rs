//! Codex hooks (https://learn.chatgpt.com/docs/hooks): same events and output as Claude Code.
//! Differences: shell is `Bash` (commands only; Codex has no Read tool, file edits are
//! `apply_patch`), and `permissionDecision: "ask"` is unsupported and fails open, so an Ask
//! becomes a deny that tells the user to run the command themselves.
use super::{MALFORMED, Out, cwd_of, field};
use crate::{Decision, Event};
use serde_json::{Value, json};

pub fn parse(event: &str, v: &Value) -> Option<Event> {
    match event {
        "UserPromptSubmit" => Some(Event::Prompt {
            text: field(v, "prompt")?.to_string(),
        }),
        "PreToolUse" if field(v, "tool_name")? == "Bash" => Some(Event::Shell {
            command: field(v.get("tool_input")?, "command")?.to_string(),
            cwd: cwd_of(v),
        }),
        _ => None,
    }
}

pub fn render(event: &str, d: &Decision) -> Out {
    let msg = match d {
        Decision::Allow => return Out::silent(),
        Decision::Ask { reason, .. } => format!(
            "Blocked by Locksmith: cannot verify this command ({reason}). Codex cannot ask for \
             approval here; run it yourself in a terminal if you trust it"
        ),
        _ => d.message(),
    };
    if event == "UserPromptSubmit" {
        return Out::json(json!({"decision": "block", "reason": msg}));
    }
    Out::json(json!({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": msg,
    }}))
}

pub fn malformed(_event: &str) -> Out {
    Out::block_stderr(MALFORMED)
}
