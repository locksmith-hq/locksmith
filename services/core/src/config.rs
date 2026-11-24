//! Configuration from the environment. Fails closed: the service token is required.

use std::net::SocketAddr;

use secrecy::SecretString;

pub const ENV_BIND: &str = "LOCKSMITH_CORE_BIND";
pub const ENV_SERVICE_TOKEN: &str = "LOCKSMITH_CORE_SERVICE_TOKEN";
pub const ENV_DATABASE_URL: &str = "LOCKSMITH_CORE_DATABASE_URL";
pub const ENV_OPENBAO_ADDR: &str = "LOCKSMITH_CORE_OPENBAO_ADDR";
pub const ENV_OPENBAO_TOKEN: &str = "LOCKSMITH_CORE_OPENBAO_TOKEN";
pub const ENV_CHECKPOINT_KEY: &str = "LOCKSMITH_CORE_CHECKPOINT_KEY";
pub const DEFAULT_CHECKPOINT_KEY: &str = "audit-checkpoint";
pub const ENV_OTLP_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
const DEFAULT_BIND: &str = "127.0.0.1:8090";

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid(&'static str),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(v) => write!(f, "environment variable {v} is required"),
            Self::Invalid(v) => write!(f, "environment variable {v} has an invalid value"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// No `Debug`, `Display` or `Clone`: it holds the service token.
pub struct Config {
    pub bind: SocketAddr,
    pub service_token: SecretString,
    /// Postgres URL of the `locksmith_app` role (RLS applies). Holds a password: secret.
    pub database_url: Option<SecretString>,
    pub otlp_endpoint: Option<String>,
    /// OpenBao transit signing for audit checkpoints. `None` when the address or token is unset.
    pub checkpoint_kms: Option<CheckpointKms>,
}

/// No `Debug`, `Display` or `Clone`: it holds the OpenBao token (sign-only policy).
pub struct CheckpointKms {
    pub addr: String,
    pub token: SecretString,
    pub key: String,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let service_token = match get(ENV_SERVICE_TOKEN) {
            Some(v) if !v.trim().is_empty() => SecretString::from(v),
            _ => return Err(ConfigError::Missing(ENV_SERVICE_TOKEN)),
        };
        let bind = get(ENV_BIND)
            .unwrap_or_else(|| DEFAULT_BIND.to_owned())
            .parse()
            .map_err(|_| ConfigError::Invalid(ENV_BIND))?;
        let otlp_endpoint = get(ENV_OTLP_ENDPOINT).filter(|v| !v.trim().is_empty());
        let database_url = get(ENV_DATABASE_URL)
            .filter(|v| !v.trim().is_empty())
            .map(SecretString::from);
        let checkpoint_kms = match (
            get(ENV_OPENBAO_ADDR).filter(|v| !v.trim().is_empty()),
            get(ENV_OPENBAO_TOKEN).filter(|v| !v.trim().is_empty()),
        ) {
            (Some(addr), Some(token)) => Some(CheckpointKms {
                addr,
                token: SecretString::from(token),
                key: get(ENV_CHECKPOINT_KEY)
                    .filter(|v| !v.trim().is_empty())
                    .unwrap_or_else(|| DEFAULT_CHECKPOINT_KEY.to_owned()),
            }),
            (None, None) => None,
            (Some(_), None) => return Err(ConfigError::Missing(ENV_OPENBAO_TOKEN)),
            (None, Some(_)) => return Err(ConfigError::Missing(ENV_OPENBAO_ADDR)),
        };
        Ok(Self {
            bind,
            service_token,
            database_url,
            otlp_endpoint,
            checkpoint_kms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_required() {
        assert_eq!(
            Config::from_lookup(|_| None).err(),
            Some(ConfigError::Missing(ENV_SERVICE_TOKEN))
        );
        assert!(Config::from_lookup(|k| (k == ENV_SERVICE_TOKEN).then(|| "  ".into())).is_err());
    }

    #[test]
    fn defaults_to_loopback() {
        let c = Config::from_lookup(|k| (k == ENV_SERVICE_TOKEN).then(|| "t".into())).unwrap();
        assert!(c.bind.ip().is_loopback());
    }

    #[test]
    fn kms_needs_both_address_and_token() {
        let with = |extra: &'static [(&'static str, &'static str)]| {
            Config::from_lookup(|k| {
                if k == ENV_SERVICE_TOKEN {
                    return Some("t".into());
                }
                extra
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| (*v).into())
            })
        };
        assert!(with(&[]).unwrap().checkpoint_kms.is_none());
        assert_eq!(
            with(&[(ENV_OPENBAO_ADDR, "http://bao:8200")]).err(),
            Some(ConfigError::Missing(ENV_OPENBAO_TOKEN))
        );
        assert_eq!(
            with(&[(ENV_OPENBAO_TOKEN, "x")]).err(),
            Some(ConfigError::Missing(ENV_OPENBAO_ADDR))
        );
        let c = with(&[
            (ENV_OPENBAO_ADDR, "http://bao:8200"),
            (ENV_OPENBAO_TOKEN, "x"),
        ])
        .unwrap();
        assert_eq!(c.checkpoint_kms.unwrap().key, DEFAULT_CHECKPOINT_KEY);
    }

    #[test]
    fn bad_bind_is_rejected() {
        let r = Config::from_lookup(|k| match k {
            ENV_SERVICE_TOKEN => Some("t".into()),
            ENV_BIND => Some("nope".into()),
            _ => None,
        });
        assert_eq!(r.err(), Some(ConfigError::Invalid(ENV_BIND)));
    }
}
