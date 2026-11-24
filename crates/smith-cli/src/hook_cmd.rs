//! `smith hook <agent> <event>`: read the agent's hook JSON on stdin, decide with `ls_hooks`,
//! answer in the agent's format. Never starts the daemon (must stay fast); denials are audited.

use crate::Fail;
use crate::daemon_vault::DaemonVault;
use ls_core::ExitCode;
use ls_hooks::adapters::handle;
use std::io::{Read, Write};

const MAX_INPUT: u64 = 1 << 20;

pub fn run(agent: &str, event: &str) -> Result<ExitCode, Fail> {
    let mut buf = Vec::new();
    // Oversized or unreadable input is handled like malformed input: fail safe.
    let ok = std::io::stdin()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut buf)
        .is_ok()
        && buf.len() as u64 <= MAX_INPUT;
    let input = if ok {
        String::from_utf8(buf).unwrap_or_default()
    } else {
        String::new()
    };
    let vault = DaemonVault::default();
    let Some(h) = handle(agent, event, &input, &vault) else {
        return Err(Fail(
            ExitCode::Usage,
            format!(
                "unknown agent `{agent}` (claude-code, cursor, codex, gemini-cli, copilot, cline)"
            ),
        ));
    };
    vault.audit(agent, event, &h.decision, &h.target);
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    let _ = out.write_all(h.out.stdout.as_bytes());
    let _ = err.write_all(h.out.stderr.as_bytes());
    let _ = out.flush();
    // Exit 2 is the blocking code for Claude Code and Codex; it equals ExitCode::Usage.
    Ok(if h.out.code == 2 {
        ExitCode::Usage
    } else {
        ExitCode::Ok
    })
}
