//! Doctor checks for the M4 guardrails: agent hooks (Claude Code, Cursor, Codex) and the
//! pre-commit step. Each branch is a pure function over a repo directory, so the tests run on
//! temp dirs. The `run` wrappers only find the repo root.

use crate::agents::{self, Agent, Protection};
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

/// Per-agent hook check. The summary carries the protection label so the report never claims
/// more than the integration does.
fn agent_outcome(a: Agent, repo: &Path) -> Outcome {
    agent_outcome_with(a, a.protection(), repo)
}

fn agent_outcome_with(a: Agent, protection: Protection, repo: &Path) -> Outcome {
    if !agents::detect(repo).contains(&a) {
        return Outcome::skip("not used in this project");
    }
    let label = protection.label();
    if protection == Protection::None {
        // No blocking hook exists for this agent: nothing to install, say what is left.
        return Outcome::ok(format!(
            "no hook available for this agent; protection: {label}"
        ));
    }
    if !agents::hook_handler_ready(a) {
        return Outcome::warn(
            format!(
                "agent detected but its hook format is unknown to `smith hook {}`: not protected",
                a.id()
            ),
            "use the MCP server only and keep secrets out of the repo; support is tracked in OpenSpec change p3-agent-plugins",
        );
    }
    if agents::installed(a, repo) {
        Outcome::ok(format!("Locksmith hooks installed; protection: {label}"))
    } else {
        Outcome::warn(
            "agent detected but Locksmith hooks are missing",
            "smith init",
        )
    }
}

/// Gemini CLI loads project hooks and stdio MCP servers only in a trusted folder. Reads the
/// user's trust list (best effort: absent or unreadable means nothing to say).
fn gemini_trust_outcome(repo: &Path, home: Option<&Path>) -> Outcome {
    if !agents::detect(repo).contains(&Agent::GeminiCli) {
        return Outcome::skip("not used in this project");
    }
    let Some(list) = home
        .map(|h| h.join(".gemini/trustedFolders.json"))
        .and_then(|f| std::fs::read_to_string(f).ok())
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
    else {
        return Outcome::ok("no Gemini trust list found (folder trust is off unless enabled)");
    };
    let trusted = list.as_object().is_some_and(|m| {
        m.iter().any(|(path, v)| {
            (v == "TRUST_FOLDER" && repo.starts_with(path))
                || (v == "TRUST_PARENT" && repo.parent().is_some_and(|p| p.starts_with(path)))
        })
    });
    if trusted {
        Outcome::ok("repository is a trusted Gemini folder")
    } else {
        Outcome::warn(
            "repository is not a trusted Gemini folder: Gemini ignores project hooks and shows the locksmith MCP server as Disconnected",
            "start gemini here and trust the folder (/permissions), then re-run smith doctor",
        )
    }
}

/// Copilot lets the tool call proceed when a hook times out (fail-open), so the timeout must stay
/// the one `smith init` wrote.
fn copilot_timeout_outcome(repo: &Path) -> Outcome {
    if !agents::detect(repo).contains(&Agent::Copilot) {
        return Outcome::skip("not used in this project");
    }
    let timeout = std::fs::read_to_string(agents::config_path(Agent::Copilot, repo))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v["hooks"]["preToolUse"].as_array().cloned())
        .and_then(|l| {
            l.iter()
                .find(|e| e.to_string().contains("smith hook copilot"))
                .and_then(|e| e["timeoutSec"].as_u64())
        });
    match timeout {
        Some(t) if t <= 10 => Outcome::ok(format!(
            "Copilot hook timeout is {t}s; a hook that times out lets the tool call proceed (fail-open)"
        )),
        _ => Outcome::warn(
            "Copilot hook timeout is missing or above 10s; a hook that times out lets the tool call proceed (fail-open)",
            "smith init",
        ),
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
        agents::mcp_path(a, repo)
            .and_then(|p| std::fs::read_to_string(p).ok())
            .is_some_and(|t| agents::has_hub_entry(a, &t))
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

fn gemini_cli() -> Outcome {
    agent_outcome(Agent::GeminiCli, &repo_dir())
}

fn gemini_trust() -> Outcome {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    gemini_trust_outcome(&repo_dir(), home.as_deref())
}

fn copilot() -> Outcome {
    agent_outcome(Agent::Copilot, &repo_dir())
}

fn copilot_timeout() -> Outcome {
    copilot_timeout_outcome(&repo_dir())
}

fn cline() -> Outcome {
    agent_outcome(Agent::Cline, &repo_dir())
}

fn windsurf() -> Outcome {
    agent_outcome(Agent::Windsurf, &repo_dir())
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
inventory::submit! { Check { id: "hooks.gemini_cli", run: gemini_cli } }
inventory::submit! { Check { id: "hooks.gemini_cli.trust", run: gemini_trust } }
inventory::submit! { Check { id: "hooks.copilot", run: copilot } }
inventory::submit! { Check { id: "hooks.copilot.timeout", run: copilot_timeout } }
inventory::submit! { Check { id: "hooks.cline", run: cline } }
inventory::submit! { Check { id: "hooks.windsurf", run: windsurf } }
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
        let f = agents::mcp_path(Agent::ClaudeCode, repo).unwrap();
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
    const INSTALLED: &str = "Locksmith hooks installed; protection: prevention (blocking hook)";

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
    fn new_agents_hook_branches() {
        let t = Tmp::new("new-agents");
        let repo = t.0.as_path();
        for (a, marker_dir) in [
            (Agent::GeminiCli, ".gemini"),
            (Agent::Cline, ".clinerules"),
            (Agent::Copilot, ".github/hooks"),
        ] {
            expect(&agent_outcome(a, repo), Status::Skip, NOT_USED, None);
            std::fs::create_dir_all(repo.join(marker_dir)).unwrap();
            expect(
                &agent_outcome(a, repo),
                Status::Warn,
                MISSING,
                Some("smith init"),
            );
            let cfg = agents::config_path(a, repo);
            std::fs::create_dir_all(cfg.parent().unwrap()).unwrap();
            std::fs::write(&cfg, agents::merge_hooks(a, None).unwrap()).unwrap();
            expect(&agent_outcome(a, repo), Status::Ok, INSTALLED, None);
        }
    }

    #[test]
    fn windsurf_is_reported_as_not_protected() {
        let t = Tmp::new("windsurf");
        let repo = t.0.as_path();
        expect(
            &agent_outcome(Agent::Windsurf, repo),
            Status::Skip,
            NOT_USED,
            None,
        );
        std::fs::create_dir_all(repo.join(".devin")).unwrap();
        let o = agent_outcome(Agent::Windsurf, repo);
        assert_eq!(o.status, Status::Warn);
        assert!(o.summary.contains("unknown") && o.summary.contains("not protected"));
    }

    #[test]
    fn gemini_trust_branches() {
        let t = Tmp::new("gemini-trust");
        let repo = t.0.join("repo");
        let home = t.0.join("home");
        std::fs::create_dir_all(repo.join(".gemini")).unwrap();
        std::fs::create_dir_all(home.join(".gemini")).unwrap();
        // No trust list: nothing to warn about.
        assert_eq!(gemini_trust_outcome(&repo, Some(&home)).status, Status::Ok);
        let list = home.join(".gemini/trustedFolders.json");
        std::fs::write(&list, "{\"/somewhere/else\": \"TRUST_FOLDER\"}").unwrap();
        let o = gemini_trust_outcome(&repo, Some(&home));
        assert_eq!(o.status, Status::Warn);
        assert!(o.summary.contains("not a trusted Gemini folder"));
        std::fs::write(
            &list,
            format!("{{\"{}\": \"TRUST_FOLDER\"}}", repo.display()),
        )
        .unwrap();
        assert_eq!(gemini_trust_outcome(&repo, Some(&home)).status, Status::Ok);
        let bare = t.0.join("bare");
        std::fs::create_dir_all(&bare).unwrap();
        assert_eq!(
            gemini_trust_outcome(&bare, Some(&home)).status,
            Status::Skip
        );
    }

    #[test]
    fn copilot_timeout_branches() {
        let t = Tmp::new("copilot-timeout");
        let repo = t.0.as_path();
        expect(&copilot_timeout_outcome(repo), Status::Skip, NOT_USED, None);
        std::fs::create_dir_all(repo.join(".github/hooks")).unwrap();
        // Detected, no hook file: timeout missing.
        assert_eq!(copilot_timeout_outcome(repo).status, Status::Warn);
        let cfg = agents::config_path(Agent::Copilot, repo);
        let ours = agents::merge_hooks(Agent::Copilot, None).unwrap();
        std::fs::write(&cfg, &ours).unwrap();
        let o = copilot_timeout_outcome(repo);
        assert_eq!(o.status, Status::Ok);
        assert!(o.summary.contains("fail-open"));
        std::fs::write(
            &cfg,
            ours.replace("\"timeoutSec\": 10", "\"timeoutSec\": 120"),
        )
        .unwrap();
        assert_eq!(copilot_timeout_outcome(repo).status, Status::Warn);
    }

    #[test]
    fn hookless_agent_gets_a_clear_line() {
        // No agent is hookless today; the branch is shared, so drive it with the label.
        let t = Tmp::new("hookless");
        std::fs::create_dir_all(t.0.join(".clinerules")).unwrap();
        let o = agent_outcome_with(Agent::Cline, Protection::None, &t.0);
        assert_eq!(o.status, Status::Ok);
        assert_eq!(
            o.summary,
            "no hook available for this agent; protection: none (no preventing hook; MCP and instructions only)"
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
