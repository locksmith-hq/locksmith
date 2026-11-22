//! Agent adapters: translate one agent's hook JSON into an `Event` and a `Decision` back into
//! that agent's answer (design D1). Schemas verified against the agents' docs, see
//! `tests/fixtures/README.md`. The engine (`decide`) never sees JSON.

pub mod claude_code;
pub mod cline;
pub mod codex;
pub mod copilot;
pub mod cursor;
pub mod gemini_cli;

use crate::{Decision, Event, Vault, decide};
use serde_json::Value;
use std::path::PathBuf;

/// What the hook process prints and its exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Out {
    pub stdout: String,
    pub stderr: String,
    pub code: u8,
}

impl Out {
    pub fn json(v: Value) -> Self {
        Out {
            stdout: v.to_string(),
            stderr: String::new(),
            code: 0,
        }
    }
    /// Exit 0 with no output: the agent's normal flow continues.
    pub fn silent() -> Self {
        Out {
            stdout: String::new(),
            stderr: String::new(),
            code: 0,
        }
    }
    /// Exit 2 with the reason on stderr (blocking error for Claude Code and Codex).
    pub fn block_stderr(msg: &str) -> Self {
        Out {
            stdout: String::new(),
            stderr: format!("{msg}\n"),
            code: 2,
        }
    }
}

pub const MALFORMED: &str = "Locksmith hook could not read the event; run `smith doctor`";

pub struct Handled {
    pub out: Out,
    pub decision: Decision,
    /// What to put in the audit record: the command or path; the literal "prompt" for prompts.
    pub target: String,
}

pub(crate) fn field<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// The path and glob of a doc-derived search tool's arguments, or `None` (the caller denies) when
/// the arguments cannot be trusted: not an object, the path or glob key holds a non-string, neither
/// is set, or a key outside `path_key`, `glob_key` and `other` holds a string, array or object.
/// Such a key may be a misnamed path or glob (decision P3-2: a wrong guess must deny); a bool,
/// number or null cannot name a file, so option flags and counts pass.
pub(crate) fn search_args(
    args: &Value,
    path_key: &str,
    glob_key: &str,
    other: &[&str],
) -> Option<(Option<PathBuf>, Option<String>)> {
    let known = args.as_object()?.iter().all(|(k, v)| {
        if k == path_key || k == glob_key {
            v.is_string()
        } else {
            other.contains(&k.as_str()) || v.is_boolean() || v.is_number() || v.is_null()
        }
    });
    let path = field(args, path_key).map(PathBuf::from);
    let glob = field(args, glob_key).map(String::from);
    (known && (path.is_some() || glob.is_some())).then_some((path, glob))
}

pub(crate) fn cwd_of(v: &Value) -> PathBuf {
    PathBuf::from(field(v, "cwd").unwrap_or("."))
}

pub fn target_of(ev: &Event) -> String {
    match ev {
        Event::Shell { command, .. } => command.clone(),
        Event::Read { path, .. } | Event::Edit { path, .. } => path.display().to_string(),
        Event::Search { path, glob, .. } => path
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| glob.clone())
            .unwrap_or_default(),
        Event::Prompt { .. } => "prompt".into(),
    }
}

/// Parse, decide, render. `None` means an unknown agent.
pub fn handle(agent: &str, event: &str, input: &str, v: &dyn Vault) -> Option<Handled> {
    type Parse = fn(&str, &Value) -> Option<Event>;
    type Render = fn(&str, &Decision) -> Out;
    type Bad = fn(&str) -> Out;
    let (parse, render, bad): (Parse, Render, Bad) = match agent {
        "claude-code" => (
            claude_code::parse,
            claude_code::render,
            claude_code::malformed,
        ),
        "cursor" => (cursor::parse, cursor::render, cursor::malformed),
        "codex" => (codex::parse, codex::render, codex::malformed),
        "gemini-cli" => (gemini_cli::parse, gemini_cli::render, gemini_cli::malformed),
        "copilot" => (copilot::parse, copilot::render, copilot::malformed),
        "cline" => (cline::parse, cline::render, cline::malformed),
        _ => return None,
    };
    let bad_in = || Handled {
        out: bad(event),
        decision: Decision::Deny {
            rule: "bad-hook-input",
            reason: MALFORMED.into(),
            alternative: "run `smith doctor`".into(),
        },
        target: String::new(),
    };
    let Ok(json) = serde_json::from_str::<Value>(input) else {
        return Some(bad_in());
    };
    if !json.is_object() || unreadable(agent, event, &json) {
        return Some(bad_in());
    }
    // A tool that reads several files at once yields one event per file; the first one that is
    // not allowed decides.
    let events = match agent {
        "gemini-cli" => gemini_cli::parse_many(event, &json),
        _ => None,
    }
    .or_else(|| parse(event, &json).map(|e| vec![e]))
    .unwrap_or_default();
    let mut first = None;
    for ev in &events {
        let decision = decide(ev, v);
        if decision != Decision::Allow {
            return Some(Handled {
                out: render(event, &decision),
                target: target_of(ev),
                decision,
            });
        }
        first.get_or_insert(ev);
    }
    Some(Handled {
        out: render(event, &Decision::Allow),
        decision: Decision::Allow,
        target: first.map(target_of).unwrap_or_default(),
    })
}

/// Payloads of the newer adapters that look like a tool call but cannot be read: deny them.
fn unreadable(agent: &str, event: &str, v: &Value) -> bool {
    match agent {
        "gemini-cli" => gemini_cli::unreadable(event, v),
        "copilot" => copilot::unreadable(event, v),
        "cline" => cline::unreadable(event, v),
        _ => false,
    }
}
