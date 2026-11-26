//! Configuration from the environment. Fails closed: the service token is required.

use std::net::SocketAddr;

use secrecy::SecretString;

pub const ENV_BIND: &str = "LOCKSMITH_CORE_BIND";
pub const ENV_SERVICE_TOKEN: &str = "LOCKSMITH_CORE_SERVICE_TOKEN";
pub const ENV_DATABASE_URL: &str = "LOCKSMITH_CORE_DATABASE_URL";
pub const ENV_OPENBAO_ADDR: &str = "LOCKSMITH_CORE_OPENBAO_ADDR";
pub const ENV_OPENBAO_TOKEN: &str = "LOCKSMITH_CORE_OPENBAO_TOKEN";
pub const ENV_AGENT_SIGNING_KEY: &str = "LOCKSMITH_CORE_AGENT_SIGNING_KEY";
/// Local development only: `1` lets workload issuers live on loopback or private addresses.
pub const ENV_WORKLOAD_ALLOW_PRIVATE_ISSUERS: &str =
    "LOCKSMITH_CORE_WORKLOAD_ALLOW_PRIVATE_ISSUERS";
/// Token for DEK wrap and unwrap (a policy allowing `transit/encrypt` and `transit/decrypt` on the DEK key only).
pub const ENV_DEK_TOKEN: &str = "LOCKSMITH_CORE_OPENBAO_DEK_TOKEN";
pub const ENV_DEK_KEY: &str = "LOCKSMITH_CORE_DEK_KEY";
pub const ENV_DEK_KEY_VERSION: &str = "LOCKSMITH_CORE_DEK_KEY_VERSION";
pub const DEFAULT_DEK_KEY: &str = "gateway";
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
    /// OpenBao transit wrapping for data keys. `None` when the address or DEK token is unset.
    pub dek_kms: Option<DekKms>,
    /// Base64 32-byte Ed25519 seed for agent tokens. Secret.
    pub agent_signing_key: Option<SecretString>,
    /// Whether workload issuers may be on private addresses (local development only).
    pub workload_allow_private_issuers: bool,
}

/// No `Debug`, `Display` or `Clone`: it holds the OpenBao token (sign-only policy).
pub struct CheckpointKms {
    pub addr: String,
    pub token: SecretString,
    pub key: String,
}

/// No `Debug`, `Display` or `Clone`: it holds the OpenBao token (wrap and unwrap policy).
pub struct DekKms {
    pub addr: String,
    pub token: SecretString,
    pub key: String,
    pub key_version: u32,
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
        let addr = get(ENV_OPENBAO_ADDR).filter(|v| !v.trim().is_empty());
        let cp_token = get(ENV_OPENBAO_TOKEN).filter(|v| !v.trim().is_empty());
        let dek_token = get(ENV_DEK_TOKEN).filter(|v| !v.trim().is_empty());
        match (&addr, cp_token.is_some() || dek_token.is_some()) {
            (Some(_), false) => return Err(ConfigError::Missing(ENV_OPENBAO_TOKEN)),
            (None, true) => return Err(ConfigError::Missing(ENV_OPENBAO_ADDR)),
            _ => {}
        }
        let checkpoint_kms = match (&addr, cp_token) {
            (Some(addr), Some(token)) => Some(CheckpointKms {
                addr: addr.clone(),
                token: SecretString::from(token),
                key: get(ENV_CHECKPOINT_KEY)
                    .filter(|v| !v.trim().is_empty())
                    .unwrap_or_else(|| DEFAULT_CHECKPOINT_KEY.to_owned()),
            }),
            _ => None,
        };
        let dek_kms = match (&addr, dek_token) {
            (Some(addr), Some(token)) => Some(DekKms {
                addr: addr.clone(),
                token: SecretString::from(token),
                key: get(ENV_DEK_KEY)
                    .filter(|v| !v.trim().is_empty())
                    .unwrap_or_else(|| DEFAULT_DEK_KEY.to_owned()),
                key_version: match get(ENV_DEK_KEY_VERSION).filter(|v| !v.trim().is_empty()) {
                    None => 1,
                    Some(v) => v
                        .parse::<u32>()
                        .ok()
                        .filter(|v| *v >= 1)
                        .ok_or(ConfigError::Invalid(ENV_DEK_KEY_VERSION))?,
                },
            }),
            _ => None,
        };
        let workload_allow_private_issuers =
            match get(ENV_WORKLOAD_ALLOW_PRIVATE_ISSUERS).as_deref() {
                None | Some("" | "0") => false,
                Some("1") => true,
                Some(_) => return Err(ConfigError::Invalid(ENV_WORKLOAD_ALLOW_PRIVATE_ISSUERS)),
            };
        Ok(Self {
            workload_allow_private_issuers,
            bind,
            service_token,
            database_url,
            otlp_endpoint,
            checkpoint_kms,
            dek_kms,
            agent_signing_key: get(ENV_AGENT_SIGNING_KEY)
                .filter(|v| !v.trim().is_empty())
                .map(SecretString::from),
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
    fn dek_kms_is_configured_by_its_own_token() {
        let c = Config::from_lookup(|k| match k {
            ENV_SERVICE_TOKEN => Some("t".into()),
            ENV_OPENBAO_ADDR => Some("http://bao:8200".into()),
            ENV_DEK_TOKEN => Some("x".into()),
            _ => None,
        })
        .unwrap();
        assert!(c.checkpoint_kms.is_none());
        let k = c.dek_kms.unwrap();
        assert_eq!((k.key.as_str(), k.key_version), (DEFAULT_DEK_KEY, 1));
        let bad = Config::from_lookup(|k| match k {
            ENV_SERVICE_TOKEN => Some("t".into()),
            ENV_OPENBAO_ADDR => Some("http://bao:8200".into()),
            ENV_DEK_TOKEN => Some("x".into()),
            ENV_DEK_KEY_VERSION => Some("0".into()),
            _ => None,
        });
        assert_eq!(bad.err(), Some(ConfigError::Invalid(ENV_DEK_KEY_VERSION)));
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
