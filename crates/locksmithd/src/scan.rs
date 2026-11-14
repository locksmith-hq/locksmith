//! `scan_text` / `scan_path` (M4 design D3, D4) and hook audit records. Only key names leave
//! the daemon; values are used in memory to build a redactor and dropped.

use crate::{Actor, Daemon, err, rec};
use ls_ipc::{ErrorCode, Response};
use ls_redact::{Redactor, Secret};
use ls_vault::Vault;
use std::path::Path;

/// Files larger than this are not scanned (the hook then relies on name rules only).
const MAX_SCAN: u64 = 2 << 20;
/// Values this short match ordinary text too often and would make scans a guessing oracle.
const MIN_LEN: usize = 8;

fn redactor(v: &Vault) -> Result<Redactor, String> {
    let mut secrets = Vec::new();
    for m in v.list_secrets(None, None).map_err(|e| e.to_string())? {
        let val = v
            .get_secret(&m.project, &m.environment, &m.name)
            .map_err(|e| e.to_string())?;
        if val.expose().len() >= MIN_LEN {
            secrets.push(Secret::new(m.name, val.expose()));
        }
    }
    Ok(Redactor::new(&secrets))
}

fn keys(r: &Redactor, data: &[u8]) -> Vec<String> {
    let mut k: Vec<String> = r
        .find(data)
        .into_iter()
        .map(|(n, _)| n.to_string())
        .collect();
    k.sort();
    k.dedup();
    k
}

fn with_vault(d: &Daemon, f: impl FnOnce(&Vault) -> Response) -> Response {
    match &d.state().vault {
        None => err(ErrorCode::Locked, "vault is locked"),
        Some(v) => f(v),
    }
}

pub fn scan_text(d: &Daemon, text: &str) -> Response {
    with_vault(d, |v| match redactor(v) {
        Ok(r) => Response::Keys {
            keys: keys(&r, text.as_bytes()),
        },
        Err(e) => err(ErrorCode::Internal, e),
    })
}

pub fn scan_path(d: &Daemon, path: &Path) -> Response {
    if !path.is_absolute() {
        return err(ErrorCode::BadRequest, "scan_path needs an absolute path");
    }
    // Regular files only (never /dev/zero or a FIFO), bounded in size.
    let data = match std::fs::metadata(path) {
        Ok(m) if m.is_file() && m.len() <= MAX_SCAN => match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => return err(ErrorCode::NotFound, e.to_string()),
        },
        Ok(_) => return Response::Keys { keys: vec![] },
        Err(e) => return err(ErrorCode::NotFound, e.to_string()),
    };
    with_vault(d, |v| match redactor(v) {
        Ok(r) => Response::Keys {
            keys: keys(&r, &data),
        },
        Err(e) => err(ErrorCode::Internal, e),
    })
}

/// Audit a hook deny/ask. The target (a command line or path) is redacted with the vault's
/// values and truncated before it is stored, so a command that embeds a secret cannot leak it
/// into the ledger.
pub fn hook_audit(
    d: &Daemon,
    a: &Actor,
    agent: &str,
    event: &str,
    decision: &str,
    rule: &str,
    target: &str,
) -> Response {
    let decision = decision.to_ascii_uppercase();
    if !matches!(decision.as_str(), "DENY" | "ASK") {
        return err(ErrorCode::BadRequest, "decision must be deny or ask");
    }
    let mut st = d.state();
    let target = match &st.vault {
        Some(v) => match redactor(v) {
            Ok(r) => String::from_utf8_lossy(&r.redact_all(target.as_bytes())).into_owned(),
            Err(e) => return err(ErrorCode::Internal, e),
        },
        // Locked: no way to redact, so keep only the rule (the queue is flushed on unlock).
        None => String::from("(not recorded: vault locked)"),
    };
    let target: String = target.chars().take(200).collect();
    let r = rec(
        a,
        &format!("HOOK_{decision}"),
        Some(target),
        &format!("{agent}/{event}: {rule}"),
        &decision,
        None,
    );
    match st.audit(r) {
        Ok(()) => Response::Ok,
        Err(e) => err(ErrorCode::Internal, e),
    }
}
