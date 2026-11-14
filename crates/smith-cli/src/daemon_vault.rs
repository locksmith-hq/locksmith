//! `ls_hooks::Vault` answered by locksmithd (key names only). Never auto-starts the daemon:
//! a hook must stay fast, and without an unlocked daemon the engine falls back to name and
//! generic-pattern rules.

use ls_ipc::{Client, Request, Response};
use std::cell::RefCell;
use std::path::Path;

#[derive(Default)]
pub struct DaemonVault {
    client: RefCell<Option<Client>>,
}

impl DaemonVault {
    fn ask(&self, req: &Request) -> Option<Response> {
        let mut c = self.client.borrow_mut();
        if c.is_none() {
            *c = Client::connect_default().ok();
        }
        let r = c.as_mut()?.call(req).ok();
        if r.is_none() {
            *c = None;
        }
        r
    }

    fn keys(&self, req: &Request) -> Option<Vec<String>> {
        match self.ask(req)? {
            Response::Keys { keys } => Some(keys),
            _ => None,
        }
    }

    /// Best effort: record a deny/ask decision in the audit ledger.
    pub fn audit(&self, agent: &str, event: &str, decision: &ls_hooks::Decision, target: &str) {
        let (d, rule) = match decision {
            ls_hooks::Decision::Allow => return,
            ls_hooks::Decision::Deny { rule, .. } => ("deny", *rule),
            ls_hooks::Decision::Ask { rule, .. } => ("ask", *rule),
        };
        let _ = self.ask(&Request::HookAudit {
            agent: agent.into(),
            event: event.into(),
            decision: d.into(),
            rule: rule.into(),
            target: target.into(),
        });
    }
}

impl ls_hooks::Vault for DaemonVault {
    fn keys_in_text(&self, text: &str) -> Option<Vec<String>> {
        self.keys(&Request::ScanText { text: text.into() })
    }

    fn keys_in_file(&self, path: &Path) -> Option<Vec<String>> {
        let abs = std::path::absolute(path).ok()?;
        self.keys(&Request::ScanPath { path: abs })
    }
}
