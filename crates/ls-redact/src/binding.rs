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
    #[serde(default)]
    pub http: Http,
    /// `[db.<name>]` database relay targets (M6).
    #[serde(default)]
    pub db: std::collections::BTreeMap<String, DbTarget>,
}

/// `[db.<name>]`: one upstream database for `smith db connect <name>`. Names only: the password
/// and mTLS material are vault key names. Unknown fields are rejected, so a literal
/// `password = "..."` is an error rather than silently ignored.
#[derive(Deserialize, Default, Debug, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct DbTarget {
    /// `postgres`, `mysql` (also MariaDB) or `redis`.
    pub kind: String,
    pub host: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub database: Option<String>,
    /// Vault key holding the password.
    pub password_key: Option<String>,
    /// `require` (default for non-loopback hosts), `prefer` or `disable`.
    pub tls: Option<String>,
    /// Vault keys holding a PEM client certificate chain and private key (mTLS).
    pub client_cert_key: Option<String>,
    pub client_key_key: Option<String>,
}

pub const DB_KINDS: [&str; 3] = ["postgres", "mysql", "redis"];

impl DbTarget {
    /// Configuration errors, for the daemon and doctor (no network, no vault).
    pub fn check(&self) -> Result<(), String> {
        let kind = self.kind.to_ascii_lowercase();
        if !DB_KINDS.contains(&kind.as_str()) {
            return Err(format!(
                "kind {:?} is not one of postgres, mysql, redis",
                self.kind
            ));
        }
        if self.host.trim().is_empty() {
            return Err("host is empty".into());
        }
        if let Some(t) = &self.tls
            && !["require", "prefer", "disable"].contains(&t.to_ascii_lowercase().as_str())
        {
            return Err(format!("tls {t:?} is not one of require, prefer, disable"));
        }
        if kind != "redis" {
            if self.user.as_deref().unwrap_or("").is_empty() {
                return Err("user is required".into());
            }
            if self.password_key.is_none() && self.client_cert_key.is_none() {
                return Err("password_key (or client_cert_key) is required".into());
            }
        }
        if self.client_cert_key.is_some() != self.client_key_key.is_some() {
            return Err("client_cert_key and client_key_key go together".into());
        }
        Ok(())
    }

    /// Vault key names this target reads.
    pub fn keys(&self) -> Vec<String> {
        [
            &self.password_key,
            &self.client_cert_key,
            &self.client_key_key,
        ]
        .into_iter()
        .flatten()
        .cloned()
        .collect()
    }
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

/// `[http]`: keys reached through the HTTP relay (M6). The child of `smith run` gets an opaque
/// `lsk_` token and the provider's base-URL variables instead of the value.
#[derive(Deserialize, Default, Debug, PartialEq)]
pub struct Http {
    /// Key name -> provider id from the catalog (`STRIPE_KEY = "stripe"`) or a table.
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, HttpKey>,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum HttpKey {
    Provider(String),
    Custom(HttpKeySpec),
}

/// `KEY = { provider = "…", hosts = […], placement = "header:X-Api-Key", base_url_env = […] }`.
/// Fields given here override the provider's.
#[derive(Deserialize, Default, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpKeySpec {
    pub provider: Option<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    /// `bearer`, `basic`, `header:<Name>` or `query:<param>`; comma-separated for several.
    pub placement: Option<String>,
    #[serde(default)]
    pub base_url_env: Vec<String>,
}

impl HttpKey {
    pub fn provider(&self) -> Option<&str> {
        match self {
            HttpKey::Provider(p) => Some(p),
            HttpKey::Custom(s) => s.provider.as_deref(),
        }
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
    fn db_section() {
        let b = parse(
            b"[db.main]\nkind=\"postgres\"\nhost=\"db.example.com\"\nuser=\"app\"\ndatabase=\"appdb\"\npassword_key=\"PG_PASSWORD\"\n[db.cache]\nkind=\"redis\"\nhost=\"127.0.0.1\"\n",
        )
        .unwrap();
        let m = &b.db["main"];
        assert_eq!(m.port, None);
        assert_eq!(m.keys(), ["PG_PASSWORD"]);
        assert!(m.check().is_ok());
        assert!(
            b.db["cache"].check().is_ok(),
            "redis without auth is allowed"
        );
        // A literal password is refused, not ignored.
        assert!(parse(b"[db.x]\nkind=\"mysql\"\nhost=\"h\"\npassword=\"p\"\n").is_err());
        let bad = |t: &str| parse(t.as_bytes()).unwrap().db["x"].check().unwrap_err();
        assert!(bad("[db.x]\nkind=\"mongo\"\nhost=\"h\"\n").contains("kind"));
        assert!(bad("[db.x]\nkind=\"mysql\"\nhost=\"h\"\npassword_key=\"K\"\n").contains("user"));
        assert!(bad("[db.x]\nkind=\"redis\"\nhost=\"h\"\ntls=\"verify\"\n").contains("tls"));
        assert!(
            bad("[db.x]\nkind=\"redis\"\nhost=\"h\"\nclient_cert_key=\"C\"\n").contains("together")
        );
    }

    #[test]
    fn http_section() {
        let b = parse(
            b"[http.keys]\nSTRIPE_KEY = \"stripe\"\nX = { hosts = [\"api.x.test\"], placement = \"header:X-Key\" }\n",
        )
        .unwrap();
        assert_eq!(
            b.http.keys["STRIPE_KEY"],
            HttpKey::Provider("stripe".into())
        );
        let HttpKey::Custom(x) = &b.http.keys["X"] else {
            panic!("table form")
        };
        assert_eq!(x.hosts, ["api.x.test"]);
        assert_eq!(x.placement.as_deref(), Some("header:X-Key"));
        assert!(parse(b"[http.keys]\nX = { nope = 1 }\n").is_err());
        assert!(parse(b"project=\"p\"\n").unwrap().http.keys.is_empty());
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
