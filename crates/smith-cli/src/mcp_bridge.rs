//! `smith mcp bridge <name>` (m2-mcp-gateway task 6.2): a stdio MCP server for an upstream MCP
//! server behind the gateway. The agent runs it as a stdio entry in its MCP file; it holds no
//! credential. Each request reads the short-lived agent token from the 0600 state file
//! (`State::load_fresh`), forwards `initialize`, `ping`, `tools/list` and `tools/call` to
//! `<gateway>/mcp/upstream/<name>` and prints the answer. The token never appears in output or
//! logs; an expired one is a JSON-RPC error saying to run `smith login --agent`.
//!
//! The wire is newline-delimited JSON-RPC, as MCP stdio defines it.

use std::io::{BufRead, Write};

use ls_connector::State;
use ls_connector::mcp::{Bridge, rpc_error};
use ls_core::ExitCode;
use serde_json::Value;

use crate::Fail;

/// Largest request line accepted from the agent.
const MAX_LINE: usize = 4 * 1024 * 1024;

pub fn run(name: &str) -> Result<ExitCode, Fail> {
    let mut bridge = Bridge::new(name)?;
    let stdin = std::io::stdin().lock();
    let stdout = std::io::stdout().lock();
    serve(&mut bridge, stdin, stdout, State::load_fresh)?;
    Ok(ExitCode::Ok)
}

/// The request loop, with the state source injected for tests.
pub fn serve<R: BufRead, W: Write>(
    bridge: &mut Bridge,
    input: R,
    mut output: W,
    load: impl Fn() -> ls_connector::Result<State>,
) -> Result<(), Fail> {
    for line in input.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let answer = if line.len() > MAX_LINE {
            Some(rpc_error(None, "request too large"))
        } else {
            handle(bridge, &line, &load)
        };
        if let Some(a) = answer {
            let mut text = a.to_string();
            text.push('\n');
            if output
                .write_all(text.as_bytes())
                .and_then(|()| output.flush())
                .is_err()
            {
                break;
            }
        }
    }
    Ok(())
}

fn handle(
    bridge: &mut Bridge,
    line: &str,
    load: &impl Fn() -> ls_connector::Result<State>,
) -> Option<Value> {
    let Ok(message) = serde_json::from_str::<Value>(line) else {
        return Some(rpc_error(None, "invalid JSON"));
    };
    if message.is_array() {
        return Some(rpc_error(None, "batch requests are not supported"));
    }
    let id = message.get("id").cloned();
    // The state is read per request: a token renewed by `smith login --agent` is picked up, and
    // an expired one is refused here, before anything is sent.
    let st = match load() {
        Ok(st) => st,
        Err(e) => return id.as_ref().map(|id| rpc_error(Some(id), &e.message)),
    };
    match bridge.forward(&st, &message) {
        Ok(answer) => answer,
        Err(e) => id.as_ref().map(|id| rpc_error(Some(id), &e.message)),
    }
}
