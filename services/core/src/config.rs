//! Configuration from the environment. Fails closed: the service token is required.

use std::net::SocketAddr;

use secrecy::SecretString;

pub const ENV_BIND: &str = "LOCKSMITH_CORE_BIND";
pub const ENV_SERVICE_TOKEN: &str = "LOCKSMITH_CORE_SERVICE_TOKEN";
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
    pub otlp_endpoint: Option<String>,
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
        Ok(Self {
            bind,
            service_token,
            otlp_endpoint,
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
    fn bad_bind_is_rejected() {
        let r = Config::from_lookup(|k| match k {
            ENV_SERVICE_TOKEN => Some("t".into()),
            ENV_BIND => Some("nope".into()),
            _ => None,
        });
        assert_eq!(r.err(), Some(ConfigError::Invalid(ENV_BIND)));
    }
}
