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
        Event::Arg { arg, .. } => arg.clone(),
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
    if !json.is_object() {
        return Some(bad_in());
    }
    // A tool call may yield several events (several files, or every string in its input); the
    // first one that is not allowed decides.
    let events = match guard(agent).map(|g| ((g.call)(event, &json), g)) {
        Some((Call::Unrecognised, _)) => return Some(bad_in()),
        Some((Call::Tool { name, input, cwd }, g)) => {
            match guarded_events(&g, &name, &input, cwd) {
                Some(events) => events,
                None => return Some(bad_in()),
            }
        }
        Some((Call::NotTool, _)) | None => parse(event, &json).into_iter().collect(),
    };
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

/// A pre-tool payload of a doc-derived adapter (Gemini CLI, Copilot, Cline; decision P3-2),
/// reduced to the tool name and its input.
pub(crate) enum Call {
    /// Not a tool event (a prompt event): the adapter's `parse` handles it.
    NotTool,
    /// A tool event whose tool name or input object is not under the expected keys, or that
    /// carries two namings at once. Always denies: a tool that cannot be identified never
    /// passes as an unknown one.
    Unrecognised,
    /// `input` is always a JSON object.
    Tool {
        name: String,
        input: Value,
        cwd: PathBuf,
    },
}

/// A tool input as a JSON object: an object, or a string holding one; anything else is `None`.
pub(crate) fn input_object(v: Option<&Value>) -> Option<Value> {
    let v = match v? {
        Value::String(s) => serde_json::from_str::<Value>(s).ok()?,
        o => o.clone(),
    };
    v.is_object().then_some(v)
}

/// The fail-closed checks of a doc-derived adapter.
struct Guard {
    call: fn(&str, &Value) -> Call,
    /// Tools whose input is checked; any other tool name passes as unknown.
    known: &'static [&'static str],
    /// The events of a known tool's primary arguments, or `None` (deny) when they do not parse.
    primary: fn(&str, &Value, PathBuf) -> Option<Vec<Event>>,
    /// Keys of a known tool that hold content, a command or a search pattern, not a file name
    /// (shell commands go through the shell analysis in `primary`).
    content: fn(&str) -> &'static [&'static str],
}

fn guard(agent: &str) -> Option<Guard> {
    Some(match agent {
        "gemini-cli" => Guard {
            call: gemini_cli::call,
            known: gemini_cli::KNOWN_TOOLS,
            primary: gemini_cli::primary,
            content: gemini_cli::content_keys,
        },
        "copilot" => Guard {
            call: copilot::call,
            known: copilot::KNOWN_TOOLS,
            primary: copilot::primary,
            content: copilot::content_keys,
        },
        "cline" => Guard {
            call: cline::call,
            known: cline::KNOWN_TOOLS,
            primary: cline::primary,
            content: cline::content_keys,
        },
        _ => return None,
    })
}

/// Every non-empty string in a tool input at any depth (arrays included), except those held
/// directly by a `content` key (an array's items count as held by the array's key).
fn input_strings<'a>(v: &'a Value, key: Option<&str>, content: &[&str], out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) if !s.is_empty() && !key.is_some_and(|k| content.contains(&k)) => {
            out.push(s);
        }
        Value::Array(a) => a.iter().for_each(|e| input_strings(e, key, content, out)),
        Value::Object(o) => o
            .iter()
            .for_each(|(k, e)| input_strings(e, Some(k), content, out)),
        _ => {}
    }
}

/// The events of a doc-derived tool call: its primary arguments, plus every other string in the
/// input judged as a path or glob, so a path under a misnamed key beside a decoy one still meets
/// the protected-path policy (decision P3-2). `None` denies.
fn guarded_events(g: &Guard, name: &str, input: &Value, cwd: PathBuf) -> Option<Vec<Event>> {
    if !g.known.contains(&name) {
        return Some(Vec::new());
    }
    let mut events = (g.primary)(name, input, cwd.clone())?;
    let mut strings = Vec::new();
    input_strings(input, None, (g.content)(name), &mut strings);
    events.extend(strings.into_iter().map(|s| Event::Arg {
        arg: s.to_string(),
        cwd: cwd.clone(),
    }));
    Some(events)
}
