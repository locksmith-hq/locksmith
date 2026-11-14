//! `smith audit ls|verify` and the audit records smith itself writes (direct `run`, secret writes).

use crate::Fail;
use crate::input::{self, Opts};
use crate::session::{call, connect};
use crate::vault_cmds::{dir, fail, precheck, unlock};
use clap::Subcommand;
use ls_core::ExitCode;
use ls_crypto::recovery::RecoveryPhrase;
use ls_ipc::{AuditEvent, Request, Response};
use ls_vault::Vault;
use ls_vault::audit::AuditRecord;
use serde_json::json;

#[derive(Subcommand)]
pub enum AuditCmd {
    /// List recent audit events (identifiers only, never values).
    Ls {
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Check the audit chain; `--full` also re-derives every MAC from the recovery phrase.
    Verify {
        #[arg(long)]
        full: bool,
    },
}

/// Append an event attributed to this `smith` process.
pub fn record(v: &Vault, action: &str, target: String, rule: &str) -> Result<(), Fail> {
    let me = ls_platform::proc::id_of(std::process::id()).ok();
    v.audit_append(&AuditRecord {
        ts: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64),
        session_id: None,
        actor_pid: std::process::id(),
        actor_start: me.map_or(0, |i| i.start),
        actor_exe: std::env::current_exe()
            .map_or_else(|_| "smith".into(), |p| p.display().to_string()),
        actor_exe_hash: String::new(),
        action: action.into(),
        target: Some(target),
        policy_rule: rule.into(),
        decision: "ALLOW".into(),
    })
    .map(|_| ())
    .map_err(fail)
}

/// A reply from the daemon, when it is up and unlocked (otherwise the caller opens the vault).
fn from_daemon(req: &Request) -> Option<Response> {
    let mut c = connect(false).ok()?;
    match call(&mut c, &Request::Status) {
        Ok(Response::Status { locked: false, .. }) => call(&mut c, req).ok(),
        _ => None,
    }
}

pub fn run(o: &Opts, cmd: AuditCmd) -> Result<ExitCode, Fail> {
    match cmd {
        AuditCmd::Ls { limit } => {
            let events = match from_daemon(&Request::AuditList { limit }) {
                Some(Response::Audit { events }) => events,
                _ => unlock(o)?
                    .audit_list(limit)
                    .map_err(fail)?
                    .into_iter()
                    .map(|e| AuditEvent {
                        seq: e.seq,
                        ts: e.record.ts,
                        session_id: e.record.session_id,
                        actor_pid: e.record.actor_pid,
                        actor_exe: e.record.actor_exe,
                        action: e.record.action,
                        target: e.record.target,
                        policy_rule: e.record.policy_rule,
                        decision: e.record.decision,
                    })
                    .collect(),
            };
            if o.json {
                println!("{}", json!({ "events": events }));
            }
            for e in events.iter().filter(|_| !o.json) {
                println!(
                    "{:>5}  {}  {:<13} {:<5} {}  {}  pid {}",
                    e.seq,
                    e.ts,
                    e.action,
                    e.decision,
                    e.target.as_deref().unwrap_or("-"),
                    e.policy_rule,
                    e.actor_pid
                );
            }
        }
        AuditCmd::Verify { full } => {
            let (events, broken_at, detail) =
                match from_daemon(&Request::AuditVerify).filter(|_| !full) {
                    Some(Response::AuditVerify {
                        events,
                        broken_at,
                        detail,
                    }) => (events, broken_at, detail),
                    _ => {
                        let r = if full {
                            let d = dir();
                            precheck(&d)?;
                            let typed = input::passphrase(o, "Recovery phrase (24 words): ")?;
                            let phrase = RecoveryPhrase::parse(&typed)
                                .map_err(|e| Fail(ExitCode::Usage, e.to_string()))?;
                            Vault::open_recovery(&d, &phrase)
                                .and_then(|v| v.audit_verify(Some(&phrase)))
                        } else {
                            unlock(o)?.audit_verify(None)
                        }
                        .map_err(fail)?;
                        (r.events, r.broken_at, r.detail)
                    }
                };
            if let Some(seq) = broken_at {
                return Err(Fail(
                    ExitCode::Failure,
                    format!("audit ledger broken at event {seq}: {detail}"),
                ));
            }
            if o.json {
                println!(
                    "{}",
                    json!({ "events": events, "broken_at": null, "detail": detail })
                );
            } else {
                println!("audit ledger ok: {events} event(s); {detail}");
            }
        }
    }
    Ok(ExitCode::Ok)
}
