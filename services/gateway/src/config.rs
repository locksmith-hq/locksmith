//! Configuration: environment variables for service settings, a TOML file for bindings
//! (S3 design decision 4). Errors name the variable or the field, never a value.
//!
//! No type here derives `Debug` or `Clone` where it holds a token or a URL with credentials.

use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;

use secrecy::SecretString;
use serde::Deserialize;
use url::Url;
use uuid::Uuid;

pub const ENV_BIND: &str = "LOCKSMITH_GATEWAY_BIND";
pub const ENV_DATABASE_URL: &str = "DATABASE_URL";
pub const ENV_OTLP_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
pub const ENV_CONTROL_PLANE_URL: &str = "LOCKSMITH_CONTROL_PLANE_URL";
pub const ENV_SERVICE_TOKEN: &str = "LOCKSMITH_GATEWAY_SERVICE_TOKEN";
pub const ENV_OPENBAO_ADDR: &str = "OPENBAO_ADDR";
pub const ENV_OPENBAO_TOKEN: &str = "OPENBAO_GATEWAY_TOKEN";
pub const ENV_OPENBAO_KEY: &str = "OPENBAO_TRANSIT_KEY";
pub const ENV_BINDINGS: &str = "LOCKSMITH_GATEWAY_BINDINGS";

/// Shortest accepted bearer token, in bytes. Shorter values are rejected, not accepted as a
/// guessable credential.
pub const MIN_TOKEN_BYTES: usize = 32;

const DEFAULT_BIND: &str = "127.0.0.1:8090";
const DEFAULT_TRANSIT_KEY: &str = "gateway";

/// Why configuration was rejected. Holds only names, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid(&'static str),
    /// The bindings file could not be read or parsed.
    BindingsUnreadable,
    /// A binding is invalid; names the binding's index and the field.
    Binding {
        index: usize,
        field: &'static str,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(var) => write!(f, "required environment variable {var} is not set"),
            Self::Invalid(var) => write!(f, "environment variable {var} has an invalid value"),
            Self::BindingsUnreadable => {
                write!(
                    f,
                    "the bindings file ({ENV_BINDINGS}) cannot be read or parsed"
                )
            }
            Self::Binding { index, field } => {
                write!(f, "binding #{index} has an invalid `{field}`")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Gateway settings. No `Debug`/`Clone`: it holds tokens and a database URL with a password.
pub struct Config {
    pub bind: SocketAddr,
    pub database_url: SecretString,
    pub otlp_endpoint: Option<String>,
    /// The control plane: internal endpoints (material, grants) and the agent-token JWKS
    /// (`/.well-known/jwks.json`) that authenticates callers (S4 task 2.1).
    pub control_plane_url: Url,
    /// Presented to the control plane's internal material endpoint (S3 task 1).
    pub service_token: SecretString,
    pub openbao: OpenBaoConfig,
    pub bindings: Bindings,
}

/// OpenBao transit settings for unwrapping DEKs: the gateway's decrypt-capable token.
pub struct OpenBaoConfig {
    pub addr: String,
    pub token: SecretString,
    pub key: String,
}

/// One allowed use of a secret: which upstream origin it may be sent to and how it is injected.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub secret_id: Uuid,
    /// Exact `scheme://host[:port]` the secret may be sent to; no path, no wildcard.
    pub origin: String,
    /// Header the secret is injected into.
    pub header: String,
    /// Header value with a `{secret}` placeholder, e.g. `Bearer {secret}`.
    pub template: String,
    /// Permit this origin to resolve to a private or loopback address (the local mock upstream).
    #[serde(default)]
    pub allow_private_hosts: bool,
}

/// The bindings file: the org the gateway acts for, and its bindings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bindings {
    pub org_id: Uuid,
    #[serde(default, rename = "binding")]
    pub bindings: Vec<Binding>,
    /// Git repositories a secret may be used for through `/git/...` (D1).
    #[serde(default, rename = "git_binding")]
    pub git_bindings: Vec<crate::git::GitBinding>,
}

impl Bindings {
    /// Parse and validate a bindings TOML document.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let parsed: Bindings = toml::from_str(text).map_err(|_| ConfigError::BindingsUnreadable)?;
        parsed.validate()?;
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let mut seen = HashSet::new();
        let mut git_seen = HashSet::new();
        for (index, g) in self.git_bindings.iter().enumerate() {
            g.validate()
                .map_err(|field| ConfigError::Binding { index, field })?;
            if !git_seen.insert(g.secret_id) {
                return Err(ConfigError::Binding {
                    index,
                    field: "git_binding.secret_id",
                });
            }
        }
        for (index, b) in self.bindings.iter().enumerate() {
            let bad = |field| ConfigError::Binding { index, field };
            if !seen.insert(b.secret_id) {
                return Err(bad("secret_id"));
            }
            let url = Url::parse(&b.origin).map_err(|_| bad("origin"))?;
            let origin_only = matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none();
            if !origin_only {
                return Err(bad("origin"));
            }
            if !valid_header_name(&b.header) {
                return Err(bad("header"));
            }
            if b.template.matches("{secret}").count() != 1
                || b.template.chars().any(|c| c.is_control())
            {
                return Err(bad("template"));
            }
        }
        Ok(())
    }

    /// The Git binding for `secret_id`, if any.
    pub fn git_for_secret(&self, secret_id: Uuid) -> Option<&crate::git::GitBinding> {
        self.git_bindings.iter().find(|b| b.secret_id == secret_id)
    }

    /// The binding for `secret_id`, if any.
    pub fn for_secret(&self, secret_id: Uuid) -> Option<&Binding> {
        self.bindings.iter().find(|b| b.secret_id == secret_id)
    }
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

impl Config {
    /// Load from the process environment, reading the bindings file named by [`ENV_BINDINGS`].
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(
            |k| std::env::var(k).ok(),
            |path| std::fs::read_to_string(path).ok(),
        )
    }

    /// Load through lookups (used by tests to avoid the environment and the file system).
    pub fn from_lookup(
        get: impl Fn(&str) -> Option<String>,
        read_file: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let required = |var: &'static str| -> Result<String, ConfigError> {
            match get(var) {
                Some(v) if !v.trim().is_empty() => Ok(v),
                _ => Err(ConfigError::Missing(var)),
            }
        };
        let token = |var: &'static str| -> Result<SecretString, ConfigError> {
            let v = required(var)?;
            if v.trim() != v || v.len() < MIN_TOKEN_BYTES {
                return Err(ConfigError::Invalid(var));
            }
            Ok(SecretString::from(v))
        };

        let bind = get(ENV_BIND).unwrap_or_else(|| DEFAULT_BIND.to_owned());
        let bind: SocketAddr = bind.parse().map_err(|_| ConfigError::Invalid(ENV_BIND))?;

        let database_url = SecretString::from(required(ENV_DATABASE_URL)?);
        let otlp_endpoint = get(ENV_OTLP_ENDPOINT).filter(|v| !v.trim().is_empty());
        let service_token = token(ENV_SERVICE_TOKEN)?;

        let control_plane_url = Url::parse(&required(ENV_CONTROL_PLANE_URL)?)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
            .ok_or(ConfigError::Invalid(ENV_CONTROL_PLANE_URL))?;

        let openbao = OpenBaoConfig {
            addr: required(ENV_OPENBAO_ADDR)?,
            token: token(ENV_OPENBAO_TOKEN).or_else(|e| match e {
                // OpenBao tokens are not required to be 32 bytes; only reject emptiness.
                ConfigError::Invalid(var) => get(var)
                    .filter(|v| !v.trim().is_empty() && v.trim() == v)
                    .map(SecretString::from)
                    .ok_or(ConfigError::Invalid(var)),
                other => Err(other),
            })?,
            key: get(ENV_OPENBAO_KEY)
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_TRANSIT_KEY.to_owned()),
        };

        let path = required(ENV_BINDINGS)?;
        let text = read_file(&path).ok_or(ConfigError::BindingsUnreadable)?;
        let bindings = Bindings::parse(&text)?;

        Ok(Self {
            bind,
            database_url,
            otlp_endpoint,
            control_plane_url,
            service_token,
            openbao,
            bindings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const ORG: &str = "0197c1f0-0000-7000-8000-000000000001";
    const SECRET: &str = "0197c1f0-0000-7000-8000-000000000002";

    fn bindings_toml(extra: &str) -> String {
        format!(
            "org_id = \"{ORG}\"\n[[binding]]\nsecret_id = \"{SECRET}\"\norigin = \"https://api.example.com\"\nheader = \"Authorization\"\ntemplate = \"Bearer {{secret}}\"\n{extra}"
        )
    }

    fn env() -> HashMap<&'static str, String> {
        HashMap::from([
            (ENV_DATABASE_URL, "postgres://u:p@localhost/db".to_owned()),
            (ENV_SERVICE_TOKEN, "s".repeat(32)),
            (ENV_CONTROL_PLANE_URL, "http://localhost:8080".to_owned()),
            (ENV_OPENBAO_ADDR, "http://localhost:8200".to_owned()),
            (ENV_OPENBAO_TOKEN, "bao-token".to_owned()),
            (ENV_BINDINGS, "/etc/bindings.toml".to_owned()),
        ])
    }

    fn load(env: &HashMap<&'static str, String>, toml: &str) -> Result<Config, ConfigError> {
        Config::from_lookup(|k| env.get(k).cloned(), |_| Some(toml.to_owned()))
    }

    #[test]
    fn config_loads_with_defaults() {
        let c = load(&env(), &bindings_toml("")).expect("valid config");
        assert_eq!(c.bind, DEFAULT_BIND.parse().unwrap());
        assert_eq!(c.openbao.key, "gateway");
        assert_eq!(c.bindings.bindings.len(), 1);
        assert!(!c.bindings.bindings[0].allow_private_hosts);
        assert!(c.bindings.for_secret(SECRET.parse().unwrap()).is_some());
    }

    #[test]
    fn config_requires_each_variable() {
        for var in [
            ENV_DATABASE_URL,
            ENV_SERVICE_TOKEN,
            ENV_CONTROL_PLANE_URL,
            ENV_OPENBAO_ADDR,
            ENV_OPENBAO_TOKEN,
            ENV_BINDINGS,
        ] {
            let mut e = env();
            e.remove(var);
            assert_eq!(
                load(&e, &bindings_toml("")).err(),
                Some(ConfigError::Missing(var))
            );
        }
    }

    #[test]
    fn config_rejects_short_or_padded_tokens() {
        for var in [ENV_SERVICE_TOKEN] {
            for bad in ["short".to_owned(), format!(" {}", "x".repeat(32))] {
                let mut e = env();
                e.insert(var, bad);
                assert_eq!(
                    load(&e, &bindings_toml("")).err(),
                    Some(ConfigError::Invalid(var))
                );
            }
        }
    }

    #[test]
    fn config_errors_never_contain_values() {
        let mut e = env();
        e.insert(ENV_SERVICE_TOKEN, "hunter2".to_owned());
        let msg = load(&e, &bindings_toml("")).err().unwrap().to_string();
        assert!(!msg.contains("hunter2"), "{msg}");
    }

    #[test]
    fn config_rejects_bad_bindings() {
        let bad_origins = [
            "api.example.com",
            "ftp://api.example.com",
            "https://api.example.com/v1",
            "https://user:pw@api.example.com",
            "https://api.example.com?x=1",
        ];
        for origin in bad_origins {
            let t = bindings_toml("").replace("https://api.example.com", origin);
            assert_eq!(
                load(&env(), &t).err(),
                Some(ConfigError::Binding {
                    index: 0,
                    field: "origin"
                }),
                "{origin}"
            );
        }
        let t = bindings_toml("").replace("{secret}", "no placeholder");
        assert_eq!(
            load(&env(), &t).err(),
            Some(ConfigError::Binding {
                index: 0,
                field: "template"
            })
        );
        let t = bindings_toml("").replace("Authorization", "Bad Header");
        assert_eq!(
            load(&env(), &t).err(),
            Some(ConfigError::Binding {
                index: 0,
                field: "header"
            })
        );
        let t = format!(
            "{}\n[[binding]]\nsecret_id = \"{SECRET}\"\norigin = \"https://b.example.com\"\nheader = \"X-Key\"\ntemplate = \"{{secret}}\"\n",
            bindings_toml("")
        );
        assert_eq!(
            load(&env(), &t).err(),
            Some(ConfigError::Binding {
                index: 1,
                field: "secret_id"
            })
        );
        assert_eq!(
            load(&env(), "not toml [").err(),
            Some(ConfigError::BindingsUnreadable)
        );
        assert_eq!(
            load(&env(), &bindings_toml("unknown = 1")).err(),
            Some(ConfigError::BindingsUnreadable)
        );
    }
}
