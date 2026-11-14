//! Cursor hooks (https://cursor.com/docs/agent/hooks): `beforeShellExecution`,
//! `beforeReadFile`, `beforeSubmitPrompt`. Output keys are snake_case per the current docs.
use super::{MALFORMED, Out, cwd_of, field};
use crate::{Decision, Event};
use serde_json::{Value, json};

pub fn parse(event: &str, v: &Value) -> Option<Event> {
    let cwd = || {
        let c = cwd_of(v);
        if c.as_os_str() != "." {
            return c;
        }
        v.get("workspace_roots")
            .and_then(|r| r.get(0))
            .and_then(Value::as_str)
            .map_or(c, Into::into)
    };
    match event {
        "beforeShellExecution" => Some(Event::Shell {
            command: field(v, "command")?.to_string(),
            cwd: cwd(),
        }),
        "beforeReadFile" => Some(Event::Read {
            path: field(v, "file_path")?.into(),
            cwd: cwd(),
        }),
        "beforeSubmitPrompt" => Some(Event::Prompt {
            text: field(v, "prompt")?.to_string(),
        }),
        _ => None,
    }
}

fn deny_json(event: &str, msg: &str, ask: bool) -> Out {
    match event {
        "beforeSubmitPrompt" => Out::json(json!({"continue": false, "user_message": msg})),
        // beforeReadFile has no "ask": the ask reason goes out as a deny.
        "beforeReadFile" => Out::json(json!({"permission": "deny", "user_message": msg})),
        _ => Out::json(json!({
            "permission": if ask { "ask" } else { "deny" },
            "user_message": msg,
            "agent_message": msg,
        })),
    }
}

pub fn render(event: &str, d: &Decision) -> Out {
    match d {
        Decision::Allow => match event {
            "beforeSubmitPrompt" => Out::json(json!({"continue": true})),
            _ => Out::json(json!({"permission": "allow"})),
        },
        d => deny_json(event, &d.message(), matches!(d, Decision::Ask { .. })),
    }
}

/// Exit 0 with an explicit deny: for permission hooks invalid output blocks anyway.
pub fn malformed(event: &str) -> Out {
    deny_json(event, MALFORMED, false)
}
