//! `.locksmith.toml` parsing shared by `smith` and `locksmithd`: names only, never values.

use crate::Redactor;
use serde::Deserialize;

pub const FILE: &str = ".locksmith.toml";

#[derive(Deserialize, Default, Debug, PartialEq)]
pub struct Binding {
    pub project: Option<String>,
    pub env: Option<String>,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub git: Git,
}

/// `[git]`: which repositories the session may reach through the Git forwarder, which refs are
/// protected, and which vault key holds each host's upstream credential (names only).
#[derive(Deserialize, Default, Debug, PartialEq)]
pub struct Git {
    /// `host/owner/repo` entries. Empty: the repository's own remotes.
    #[serde(default)]
    pub repos: Vec<String>,
    /// Ref patterns (`main`, `release/*`, `refs/tags/*`). Absent: `main` and `master`.
    pub protected: Option<Vec<String>>,
    /// Host -> vault key name (a PAT, or GitHub App JSON). Defaults in [`Git::credential_key`].
    #[serde(default)]
    pub credentials: std::collections::BTreeMap<String, String>,
}

impl Git {
    pub fn protected(&self) -> Vec<String> {
        self.protected
            .clone()
            .unwrap_or_else(|| vec!["main".into(), "master".into()])
    }

    /// Vault key holding `host`'s credential: configured, else `GITHUB_TOKEN`, `GITLAB_TOKEN`
    /// or `BITBUCKET_TOKEN` for the public hosts.
    pub fn credential_key(&self, host: &str) -> Option<String> {
        self.credentials.get(host).cloned().or_else(|| {
            match host {
                "github.com" => Some("GITHUB_TOKEN"),
                "gitlab.com" => Some("GITLAB_TOKEN"),
                "bitbucket.org" => Some("BITBUCKET_TOKEN"),
                _ => None,
            }
            .map(String::from)
        })
    }
}

pub fn parse(bytes: &[u8]) -> Result<Binding, String> {
    toml::from_str(std::str::from_utf8(bytes).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

/// 1-based line of the first line a stored secret appears on (0: only across lines).
pub fn secret_line(bytes: &[u8], r: &Redactor) -> Option<usize> {
    if r.is_empty() || r.redact_all(bytes) == bytes {
        return None;
    }
    Some(
        bytes
            .split_inclusive(|b| *b == b'\n')
            .position(|l| r.redact_all(l) != l)
            .map_or(0, |i| i + 1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Secret;

    #[test]
    fn parses_fields() {
        let b =
            parse(b"project=\"p\"\nenv=\"e\"\nkeys=[\"A\",\"B\"]\n[commands]\nx=\"y\"\n").unwrap();
        assert_eq!(b.project.as_deref(), Some("p"));
        assert_eq!(b.keys, ["A", "B"]);
        assert!(parse(b"keys = 3").is_err());
    }

    #[test]
    fn git_section_defaults_and_overrides() {
        let b = parse(b"project=\"p\"\n").unwrap();
        assert_eq!(b.git.protected(), ["main", "master"]);
        assert_eq!(
            b.git.credential_key("github.com").as_deref(),
            Some("GITHUB_TOKEN")
        );
        assert_eq!(b.git.credential_key("git.example.com"), None);
        let b = parse(
            b"[git]\nrepos=[\"github.com/a/b\"]\nprotected=[]\n[git.credentials]\n\"git.example.com\"=\"CORP_GIT\"\n",
        )
        .unwrap();
        assert_eq!(b.git.repos, ["github.com/a/b"]);
        assert!(b.git.protected().is_empty());
        assert_eq!(
            b.git.credential_key("git.example.com").as_deref(),
            Some("CORP_GIT")
        );
    }

    #[test]
    fn detects_value_and_line_without_leaking() {
        let r = Redactor::new(&[Secret::new("K", b"fake_live_abcdef123456")]);
        assert_eq!(
            secret_line(b"a=1\nb=\"fake_live_abcdef123456\"\n", &r),
            Some(2)
        );
        assert_eq!(secret_line(b"project=\"x\"\nkeys=[\"K\"]\n", &r), None);
    }
}
