//! Doctor check `mcp.credentials` (m2-mcp-gateway task 6.4): warns, by server and field name
//! only, when an agent's repo-level MCP file still holds a credential-like header or env value.
//! The remedy is the gateway: `smith init --mcp-gateway` swaps an upstream's entry for the
//! bridge, which holds no credential.

use crate::agents;
use ls_diag::{Check, Outcome};
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn outcome(repo: &Path) -> Outcome {
    let mut found: Vec<String> = Vec::new();
    let mut files = 0;
    for a in agents::ALL {
        let Some(path) = agents::mcp_path(a, repo) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        files += 1;
        let rel = path
            .strip_prefix(repo)
            .unwrap_or(&path)
            .display()
            .to_string();
        for (server, field) in agents::mcp_credentials(a, &text) {
            let line = format!("{rel}: {server} {field}");
            if !found.contains(&line) {
                found.push(line);
            }
        }
    }
    if files == 0 {
        return Outcome::skip("no agent MCP file in this repository");
    }
    if found.is_empty() {
        return Outcome::ok("no credential-like header or env value in the agents' MCP files");
    }
    Outcome::warn(
        format!(
            "an MCP file holds a credential the agent can read ({})",
            found.join("; ")
        ),
        "smith login --agent, then smith init --mcp-gateway (the gateway holds the credential)",
    )
}

fn run() -> Outcome {
    outcome(&repo_dir())
}

inventory::submit! { Check { id: "mcp.credentials", run } }

#[cfg(test)]
mod tests {
    use super::*;
    use ls_diag::Status;

    fn repo(files: &[(&str, &str)]) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "smith-doctor-mcp-{}-{}",
            std::process::id(),
            files.len()
        ));
        let _ = std::fs::remove_dir_all(&d);
        for (p, text) in files {
            let f = d.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, text).unwrap();
        }
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn no_mcp_file_is_a_skip() {
        assert_eq!(outcome(&repo(&[])).status, Status::Skip);
    }

    #[test]
    fn a_clean_file_is_ok() {
        let r = repo(&[(
            ".mcp.json",
            r#"{"mcpServers":{"locksmith":{"command":"locksmith-mcp"}}}"#,
        )]);
        assert_eq!(outcome(&r).status, Status::Ok);
    }

    #[test]
    fn credentials_are_named_and_never_shown() {
        const CANARY: &str = "ghp_DOCTOR_CANARY_0123456789";
        let r = repo(&[
            (
                ".mcp.json",
                &format!(
                    r#"{{"mcpServers":{{"github":{{"url":"https://x.test","headers":{{"Authorization":"Bearer {CANARY}"}}}}}}}}"#
                ),
            ),
            (
                ".codex/config.toml",
                &format!("[mcp_servers.db.env]\nDB_TOKEN = \"{CANARY}\"\n"),
            ),
        ]);
        let o = outcome(&r);
        assert_eq!(o.status, Status::Warn);
        assert!(
            o.summary.contains(".mcp.json: github Authorization"),
            "{}",
            o.summary
        );
        assert!(o.summary.contains("db DB_TOKEN"), "{}", o.summary);
        assert!(!o.summary.contains(CANARY));
        assert!(!o.remediation.unwrap_or_default().contains(CANARY));
    }
}
