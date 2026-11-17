//! Configuration from environment variables only (design decision 14).
//!
//! Errors name the variable, never its value. `Config` deliberately has no `Debug`
//! because it carries database URLs that contain passwords.

use std::fmt;
use std::net::SocketAddr;

use secrecy::SecretString;

pub const ENV_DATABASE_URL: &str = "DATABASE_URL";
pub const ENV_DATABASE_OWNER_URL: &str = "DATABASE_OWNER_URL";
pub const ENV_BIND: &str = "LOCKSMITH_BIND";
pub const ENV_OTLP_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
pub const ENV_DEV_AUTH: &str = "LOCKSMITH_DEV_AUTH";
pub const ENV_OPENBAO_ADDR: &str = "OPENBAO_ADDR";
pub const ENV_OPENBAO_TOKEN: &str = "OPENBAO_CONTROL_PLANE_TOKEN";
pub const ENV_OPENBAO_KEY: &str = "OPENBAO_TRANSIT_KEY";
pub const ENV_OPENBAO_KEY_VERSION: &str = "OPENBAO_TRANSIT_KEY_VERSION";
pub const ENV_GATEWAY_SERVICE_TOKEN: &str = "LOCKSMITH_GATEWAY_SERVICE_TOKEN";

/// Shortest accepted gateway service token, in bytes (a 256-bit random token in hex or base64
/// is longer). Shorter values are rejected rather than accepted as a guessable credential.
pub const MIN_SERVICE_TOKEN_BYTES: usize = 32;

const DEFAULT_TRANSIT_KEY: &str = "gateway";

const DEFAULT_BIND: &str = "127.0.0.1:8080";

/// Why configuration was rejected. Holds only variable names, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid(&'static str),
    /// Dev auth is on but the bind address is not loopback.
    DevAuthNonLoopback(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(var) => write!(f, "required environment variable {var} is not set"),
            Self::Invalid(var) => write!(f, "environment variable {var} has an invalid value"),
            Self::DevAuthNonLoopback(var) => write!(
                f,
                "{ENV_DEV_AUTH}=1 is only allowed with a loopback bind address; fix {var} or unset {ENV_DEV_AUTH}"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Service configuration. No `Debug`/`Clone`: it holds secret-bearing URLs.
pub struct Config {
    pub database_url: SecretString,
    pub database_owner_url: SecretString,
    pub bind: SocketAddr,
    pub otlp_endpoint: Option<String>,
    pub dev_auth: bool,
    /// The KMS that wraps secret-version DEKs (S2). `None` when `OPENBAO_ADDR` is unset; secret
    /// version writes then answer `503`.
    pub kms: Option<KmsConfig>,
    /// The bearer token the gateway presents on `/internal/v1` (S3 design decision 2). `None`
    /// when unset: every internal request is then refused (`401`, fail closed).
    pub gateway_service_token: Option<SecretString>,
}

/// OpenBao transit settings for wrapping DEKs. No `Debug`/`Clone`: it holds the control
/// plane's token (encrypt-only by policy, S2 design decision 4).
pub struct KmsConfig {
    pub addr: String,
    pub token: SecretString,
    pub key: String,
    pub key_version: u32,
}

impl Config {
    /// Load from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Load through an arbitrary lookup (used by tests to avoid touching the environment).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let required = |var: &'static str| -> Result<SecretString, ConfigError> {
            match get(var) {
                Some(v) if !v.trim().is_empty() => Ok(SecretString::from(v)),
                _ => Err(ConfigError::Missing(var)),
            }
        };
        let database_url = required(ENV_DATABASE_URL)?;
        let database_owner_url = required(ENV_DATABASE_OWNER_URL)?;

        let bind = get(ENV_BIND).unwrap_or_else(|| DEFAULT_BIND.to_owned());
        let bind: SocketAddr = bind.parse().map_err(|_| ConfigError::Invalid(ENV_BIND))?;

        let otlp_endpoint = get(ENV_OTLP_ENDPOINT).filter(|v| !v.trim().is_empty());

        let dev_auth = match get(ENV_DEV_AUTH).as_deref() {
            None | Some("") | Some("0") => false,
            Some("1") => true,
            Some(_) => return Err(ConfigError::Invalid(ENV_DEV_AUTH)),
        };

        if dev_auth && !bind.ip().is_loopback() {
            return Err(ConfigError::DevAuthNonLoopback(ENV_BIND));
        }

        let kms = match get(ENV_OPENBAO_ADDR).filter(|v| !v.trim().is_empty()) {
            None => None,
            Some(addr) => {
                let token = required(ENV_OPENBAO_TOKEN)?;
                let key = get(ENV_OPENBAO_KEY)
                    .filter(|v| !v.trim().is_empty())
                    .unwrap_or_else(|| DEFAULT_TRANSIT_KEY.to_owned());
                let key_version = match get(ENV_OPENBAO_KEY_VERSION) {
                    None => 1,
                    Some(v) => v
                        .parse::<u32>()
                        .ok()
                        .filter(|&v| v >= 1)
                        .ok_or(ConfigError::Invalid(ENV_OPENBAO_KEY_VERSION))?,
                };
                Some(KmsConfig {
                    addr,
                    token,
                    key,
                    key_version,
                })
            }
        };

        let gateway_service_token = match get(ENV_GATEWAY_SERVICE_TOKEN) {
            None => None,
            Some(v) if v.is_empty() => None,
            Some(v) if v.trim() != v || v.len() < MIN_SERVICE_TOKEN_BYTES => {
                return Err(ConfigError::Invalid(ENV_GATEWAY_SERVICE_TOKEN));
            }
            Some(v) => Some(SecretString::from(v)),
        };

        Ok(Self {
            database_url,
            database_owner_url,
            bind,
            otlp_endpoint,
            dev_auth,
            kms,
            gateway_service_token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| m.get(k).cloned()
    }

    const DB: [(&str, &str); 2] = [
        (ENV_DATABASE_URL, "postgres://u:hunter2@h/db"),
        (ENV_DATABASE_OWNER_URL, "postgres://o:hunter3@h/db"),
    ];

    fn with(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
        let mut v = DB.to_vec();
        v.extend_from_slice(extra);
        v
    }

    #[test]
    fn defaults_to_loopback_without_dev_auth() {
        let c = Config::from_lookup(lookup(&DB)).ok().unwrap();
        assert!(c.bind.ip().is_loopback());
        assert!(!c.dev_auth);
    }

    #[test]
    fn missing_variable_is_named_without_values() {
        let err = Config::from_lookup(lookup(&[(ENV_DATABASE_URL, "postgres://u:hunter2@h/db")]))
            .err()
            .unwrap();
        assert_eq!(err, ConfigError::Missing(ENV_DATABASE_OWNER_URL));
        assert!(err.to_string().contains(ENV_DATABASE_OWNER_URL));
        assert!(!err.to_string().contains("hunter"));
    }

    #[test]
    fn dev_auth_on_non_loopback_bind_is_refused() {
        let err = Config::from_lookup(lookup(&with(&[
            (ENV_DEV_AUTH, "1"),
            (ENV_BIND, "0.0.0.0:8080"),
        ])))
        .err()
        .unwrap();
        assert_eq!(err, ConfigError::DevAuthNonLoopback(ENV_BIND));
        assert!(err.to_string().contains(ENV_BIND));
    }

    #[test]
    fn dev_auth_on_loopback_is_allowed() {
        for bind in ["127.0.0.1:9000", "[::1]:9000"] {
            let c = Config::from_lookup(lookup(&with(&[(ENV_DEV_AUTH, "1"), (ENV_BIND, bind)])))
                .ok()
                .unwrap();
            assert!(c.dev_auth);
        }
    }

    #[test]
    fn non_loopback_without_dev_auth_is_allowed() {
        let c = Config::from_lookup(lookup(&with(&[(ENV_BIND, "0.0.0.0:8080")])))
            .ok()
            .unwrap();
        assert!(!c.dev_auth);
    }

    #[test]
    fn kms_is_optional_and_needs_a_token_when_set() {
        let c = Config::from_lookup(lookup(&DB)).ok().unwrap();
        assert!(c.kms.is_none());
        let err = Config::from_lookup(lookup(&with(&[(
            ENV_OPENBAO_ADDR,
            "http://127.0.0.1:8200",
        )])))
        .err()
        .unwrap();
        assert_eq!(err, ConfigError::Missing(ENV_OPENBAO_TOKEN));
        let c = Config::from_lookup(lookup(&with(&[
            (ENV_OPENBAO_ADDR, "http://127.0.0.1:8200"),
            (ENV_OPENBAO_TOKEN, "tok-hunter4"),
        ])))
        .ok()
        .unwrap();
        let kms = c.kms.unwrap();
        assert_eq!((kms.key.as_str(), kms.key_version), ("gateway", 1));
        let err = Config::from_lookup(lookup(&with(&[
            (ENV_OPENBAO_ADDR, "http://127.0.0.1:8200"),
            (ENV_OPENBAO_TOKEN, "tok-hunter4"),
            (ENV_OPENBAO_KEY_VERSION, "0"),
        ])))
        .err()
        .unwrap();
        assert_eq!(err, ConfigError::Invalid(ENV_OPENBAO_KEY_VERSION));
        assert!(!err.to_string().contains("hunter"));
    }

    #[test]
    fn gateway_service_token_is_optional_and_must_be_long() {
        let c = Config::from_lookup(lookup(&DB)).ok().unwrap();
        assert!(c.gateway_service_token.is_none());
        let c = Config::from_lookup(lookup(&with(&[(ENV_GATEWAY_SERVICE_TOKEN, "")])))
            .ok()
            .unwrap();
        assert!(c.gateway_service_token.is_none());
        for bad in ["short-hunter5", " hunter5-padded-to-be-long-enough-xx "] {
            let err = Config::from_lookup(lookup(&with(&[(ENV_GATEWAY_SERVICE_TOKEN, bad)])))
                .err()
                .unwrap();
            assert_eq!(err, ConfigError::Invalid(ENV_GATEWAY_SERVICE_TOKEN));
            assert!(!err.to_string().contains("hunter"));
        }
        let c = Config::from_lookup(lookup(&with(&[(
            ENV_GATEWAY_SERVICE_TOKEN,
            "hunter5-0123456789abcdef0123456789abcdef",
        )])))
        .ok()
        .unwrap();
        assert!(c.gateway_service_token.is_some());
    }

    #[test]
    fn invalid_values_name_the_variable_only() {
        let err = Config::from_lookup(lookup(&with(&[(ENV_BIND, "not-an-addr")])))
            .err()
            .unwrap();
        assert_eq!(err, ConfigError::Invalid(ENV_BIND));
        assert!(!err.to_string().contains("not-an-addr"));
        let err = Config::from_lookup(lookup(&with(&[(ENV_DEV_AUTH, "yes")])))
            .err()
            .unwrap();
        assert_eq!(err, ConfigError::Invalid(ENV_DEV_AUTH));
    }
}
