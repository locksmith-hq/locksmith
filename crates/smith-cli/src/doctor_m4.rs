//! Doctor checks for the M4 guardrails: agent hooks (Claude Code, Cursor, Codex) and the
//! pre-commit step. Each branch is a pure function over a repo directory, so the tests run on
//! temp dirs. The `run` wrappers only find the repo root.

use crate::agents::{self, Agent};
use crate::precommit;
use ls_diag::{Check, Outcome};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The git top level when inside a repository, else the current directory (as `smith init` uses).
fn repo_dir() -> PathBuf {
    let top = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()));
    top.or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn is_git_repo(repo: &Path) -> bool {
    Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(repo)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn agent_outcome(a: Agent, repo: &Path) -> Outcome {
    if !agents::detect(repo).contains(&a) {
        return Outcome::skip("not used in this project");
    }
    if agents::installed(a, repo) {
        Outcome::ok("Locksmith hooks installed")
    } else {
        Outcome::warn(
            "agent detected but Locksmith hooks are missing",
            "smith init",
        )
    }
}

/// `hub.mcp`: the remote Hub MCP entry per detected agent: ok, missing or unsupported. Nothing
/// is flagged until some agent has an entry (the Hub is optional), then a supported agent
/// without one is a warning.
fn hub_mcp_outcome(repo: &Path) -> Outcome {
    let found = agents::detect(repo);
    if found.is_empty() {
        return Outcome::skip("no agent detected in this project");
    }
    let has = |a: Agent| {
        std::fs::read_to_string(agents::mcp_path(a, repo))
            .is_ok_and(|t| agents::has_hub_entry(a, &t))
    };
    let mut parts = Vec::new();
    let (mut any, mut missing) = (false, false);
    for a in found {
        let state = if !a.remote_mcp() {
            "unsupported"
        } else if has(a) {
            any = true;
            "ok"
        } else {
            missing = true;
            "missing"
        };
        parts.push(format!("{}: {state}", a.id()));
    }
    let summary = format!("hub.mcp {}", parts.join(", "));
    if !any && missing {
        Outcome::skip(format!("{summary} (no Hub MCP entry yet)"))
    } else if missing {
        Outcome::warn(summary, "smith init --hub <url>")
    } else {
        Outcome::ok(summary)
    }
}

fn precommit_outcome(repo: &Path) -> Outcome {
    if !is_git_repo(repo) {
        return Outcome::skip("not a git repository");
    }
    if precommit::installed(repo) {
        Outcome::ok("Locksmith pre-commit step is installed")
    } else {
        Outcome::warn("Locksmith pre-commit step is missing", "smith init")
    }
}

fn claude_code() -> Outcome {
    agent_outcome(Agent::ClaudeCode, &repo_dir())
}

fn cursor() -> Outcome {
    agent_outcome(Agent::Cursor, &repo_dir())
}

fn codex() -> Outcome {
    agent_outcome(Agent::Codex, &repo_dir())
}

fn hub_mcp() -> Outcome {
    hub_mcp_outcome(&repo_dir())
}

fn repo_precommit() -> Outcome {
    precommit_outcome(&repo_dir())
}

inventory::submit! { Check { id: "hooks.claude_code", run: claude_code } }
inventory::submit! { Check { id: "hooks.cursor", run: cursor } }
inventory::submit! { Check { id: "hooks.codex", run: codex } }
inventory::submit! { Check { id: "hub.mcp", run: hub_mcp } }
inventory::submit! { Check { id: "repo.precommit", run: repo_precommit } }

#[cfg(test)]
mod tests {
    use super::*;
    use ls_diag::Status;

    /// Asserts the exact status, summary and remediation a branch must produce.
    #[track_caller]
    fn expect(out: &Outcome, status: Status, summary: &str, remediation: Option<&str>) {
        assert_eq!(out.status, status, "status for {summary:?}");
        assert_eq!(out.summary, summary);
        assert_eq!(out.remediation.as_deref(), remediation);
    }

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("smith-doctor-m4-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn hub_mcp_branches() {
        let t = Tmp::new("hub");
        let repo = t.0.as_path();
        assert_eq!(hub_mcp_outcome(repo).status, Status::Skip);
        std::fs::create_dir_all(repo.join(".claude")).unwrap();
        std::fs::create_dir_all(repo.join(".cursor")).unwrap();
        let o = hub_mcp_outcome(repo);
        assert_eq!(o.status, Status::Skip);
        assert!(o.summary.contains("cursor: unsupported"), "{}", o.summary);
        let url = "https://hub.example/mcp";
        let f = agents::mcp_path(Agent::ClaudeCode, repo);
        std::fs::write(
            &f,
            agents::merge_hub_mcp(Agent::ClaudeCode, None, url).unwrap(),
        )
        .unwrap();
        let o = hub_mcp_outcome(repo);
        assert_eq!(o.status, Status::Ok);
        assert!(o.summary.contains("claude-code: ok"));
        std::fs::create_dir_all(repo.join(".codex")).unwrap();
        let o = hub_mcp_outcome(repo);
        assert_eq!(o.status, Status::Warn);
        assert!(o.summary.contains("codex: missing"));
        assert_eq!(o.remediation.as_deref(), Some("smith init --hub <url>"));
    }

    const NOT_USED: &str = "not used in this project";
    const MISSING: &str = "agent detected but Locksmith hooks are missing";
    const INSTALLED: &str = "Locksmith hooks installed";

    #[test]
    fn agent_hooks_branches() {
        let t = Tmp::new("agents");
        let repo = t.0.as_path();

        // Claude Code: not detected, then detected without hooks, then with hooks.
        expect(
            &agent_outcome(Agent::ClaudeCode, repo),
            Status::Skip,
            NOT_USED,
            None,
        );
        std::fs::create_dir_all(repo.join(".claude")).unwrap();
        expect(
            &agent_outcome(Agent::ClaudeCode, repo),
            Status::Warn,
            MISSING,
            Some("smith init"),
        );
        let cfg = agents::config_path(Agent::ClaudeCode, repo);
        std::fs::write(&cfg, agents::merge_hooks(Agent::ClaudeCode, None).unwrap()).unwrap();
        expect(
            &agent_outcome(Agent::ClaudeCode, repo),
            Status::Ok,
            INSTALLED,
            None,
        );

        // Cursor: its directory marks it as used.
        expect(
            &agent_outcome(Agent::Cursor, repo),
            Status::Skip,
            NOT_USED,
            None,
        );
        std::fs::create_dir_all(repo.join(".cursor")).unwrap();
        expect(
            &agent_outcome(Agent::Cursor, repo),
            Status::Warn,
            MISSING,
            Some("smith init"),
        );
        let cfg = agents::config_path(Agent::Cursor, repo);
        std::fs::write(&cfg, agents::merge_hooks(Agent::Cursor, None).unwrap()).unwrap();
        expect(
            &agent_outcome(Agent::Cursor, repo),
            Status::Ok,
            INSTALLED,
            None,
        );

        // Codex: AGENTS.md marks it as used; the TOML config carries the hooks.
        expect(
            &agent_outcome(Agent::Codex, repo),
            Status::Skip,
            NOT_USED,
            None,
        );
        std::fs::write(repo.join("AGENTS.md"), "# agents\n").unwrap();
        expect(
            &agent_outcome(Agent::Codex, repo),
            Status::Warn,
            MISSING,
            Some("smith init"),
        );
        let cfg = agents::config_path(Agent::Codex, repo);
        std::fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        std::fs::write(&cfg, agents::merge_hooks(Agent::Codex, None).unwrap()).unwrap();
        expect(
            &agent_outcome(Agent::Codex, repo),
            Status::Ok,
            INSTALLED,
            None,
        );
    }

    #[test]
    fn precommit_branches() {
        let t = Tmp::new("precommit");
        let repo = t.0.as_path();

        // Not a git repository: nothing to check.
        expect(
            &precommit_outcome(repo),
            Status::Skip,
            "not a git repository",
            None,
        );

        let init = Command::new("git")
            .args(["init", "-q"])
            .current_dir(repo)
            .status()
            .unwrap();
        assert!(init.success());
        expect(
            &precommit_outcome(repo),
            Status::Warn,
            "Locksmith pre-commit step is missing",
            Some("smith init"),
        );

        // Install the step the way `smith init` does.
        for c in precommit::plan(repo).unwrap().unwrap().1 {
            precommit::apply(repo, &c).unwrap();
        }
        expect(
            &precommit_outcome(repo),
            Status::Ok,
            "Locksmith pre-commit step is installed",
            None,
        );
    }
}
