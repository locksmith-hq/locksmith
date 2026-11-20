//! Configuration from environment variables only (design decision 14).
//!
//! Errors name the variable, never its value. `Config` deliberately has no `Debug`
//! because it carries database URLs that contain passwords.

use std::fmt;
use std::net::SocketAddr;

use secrecy::{ExposeSecret, SecretString};

use crate::auth::human::HumanAuthConfig;

pub const ENV_DATABASE_URL: &str = "DATABASE_URL";
pub const ENV_DATABASE_OWNER_URL: &str = "DATABASE_OWNER_URL";
pub const ENV_BIND: &str = "LOCKSMITH_BIND";
pub const ENV_OTLP_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
pub const ENV_DEV_AUTH: &str = "LOCKSMITH_DEV_AUTH";
/// Explicit override that lets a release build start with `LOCKSMITH_DEV_AUTH=1`.
pub const ENV_ALLOW_DEV_AUTH: &str = "LOCKSMITH_ALLOW_DEV_AUTH";
pub const ENV_OPENBAO_ADDR: &str = "OPENBAO_ADDR";
pub const ENV_OPENBAO_TOKEN: &str = "OPENBAO_CONTROL_PLANE_TOKEN";
pub const ENV_OPENBAO_KEY: &str = "OPENBAO_TRANSIT_KEY";
pub const ENV_OPENBAO_KEY_VERSION: &str = "OPENBAO_TRANSIT_KEY_VERSION";
/// S5: the OpenBao token that may only sign with the audit checkpoint key.
pub const ENV_AUDIT_CHECKPOINT_TOKEN: &str = "OPENBAO_AUDIT_CHECKPOINT_TOKEN";
/// S5: the transit key audit checkpoints are signed with (default `audit-checkpoint`).
pub const ENV_AUDIT_CHECKPOINT_KEY: &str = "OPENBAO_AUDIT_CHECKPOINT_KEY";
pub const ENV_GATEWAY_SERVICE_TOKEN: &str = "LOCKSMITH_GATEWAY_SERVICE_TOKEN";
/// S4: the Ed25519 seed (32 bytes, base64) that signs agent tokens.
pub const ENV_AGENT_SIGNING_KEY: &str = "LOCKSMITH_AGENT_SIGNING_KEY";

/// T1: the OIDC issuer (`iss`) human access tokens must carry.
pub const ENV_OIDC_ISSUER: &str = "LOCKSMITH_OIDC_ISSUER";
/// T1: the audience (`aud`) human access tokens must include.
pub const ENV_OIDC_AUDIENCE: &str = "LOCKSMITH_OIDC_AUDIENCE";
/// T1: where the issuer publishes its JWKS (an `http` or `https` URL).
pub const ENV_OIDC_JWKS_URL: &str = "LOCKSMITH_OIDC_JWKS_URL";

/// M1 2.1: the canonical public URL of the hub `/mcp` route (RFC 8707 resource). MCP tokens must
/// carry it as `aud`. Needs the `LOCKSMITH_OIDC_*` issuer settings; unset leaves `/mcp` answering `401`.
pub const ENV_MCP_RESOURCE_URL: &str = "LOCKSMITH_MCP_RESOURCE_URL";

/// Shortest accepted gateway service token, in bytes (a 256-bit random token in hex or base64
/// is longer). Shorter values are rejected rather than accepted as a guessable credential.
pub const MIN_SERVICE_TOKEN_BYTES: usize = 32;

const DEFAULT_TRANSIT_KEY: &str = "gateway";
const DEFAULT_CHECKPOINT_KEY: &str = "audit-checkpoint";

const DEFAULT_BIND: &str = "127.0.0.1:8080";

/// Why configuration was rejected. Holds only variable names, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid(&'static str),
    /// Dev auth is on but the bind address is not loopback.
    DevAuthNonLoopback(&'static str),
    /// Dev auth is on in a release build without the explicit override.
    DevAuthInRelease,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(var) => write!(f, "required environment variable {var} is not set"),
            Self::Invalid(var) => write!(f, "environment variable {var} has an invalid value"),
            Self::DevAuthInRelease => write!(
                f,
                "{ENV_DEV_AUTH}=1 is refused in release builds unless {ENV_ALLOW_DEV_AUTH}=1 is also set"
            ),
            Self::DevAuthNonLoopback(var) => write!(
                f,
                "{ENV_DEV_AUTH}=1 is only allowed with a loopback bind address; fix {var} or unset {ENV_DEV_AUTH}"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// A release build refuses dev header auth unless the override flag is set (t1 design decision 7).
fn check_release_dev_auth(dev_auth: bool, release: bool, allowed: bool) -> Result<(), ConfigError> {
    if dev_auth && release && !allowed {
        return Err(ConfigError::DevAuthInRelease);
    }
    Ok(())
}

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
    /// The OpenBao transit key that signs audit checkpoints (S5 design decision 4). `None` when
    /// `OPENBAO_AUDIT_CHECKPOINT_TOKEN` is unset: the checkpoint job then does not run.
    pub audit_checkpoint: Option<CheckpointKmsConfig>,
    /// The bearer token the gateway presents on `/internal/v1` (S3 design decision 2). `None`
    /// when unset: every internal request is then refused (`401`, fail closed).
    pub gateway_service_token: Option<SecretString>,
    /// The agent-token signing seed (S4 design decision 1), validated. `None` when unset: with
    /// dev auth an ephemeral key is generated at startup, otherwise token requests answer `503`.
    pub agent_signing_key: Option<SecretString>,
    /// The OIDC issuer human tokens are verified against (T1). `None` when
    /// `LOCKSMITH_OIDC_ISSUER` is unset: every bearer token is then refused. Public values only.
    pub human_auth: Option<HumanAuthConfig>,
    /// The canonical hub MCP resource URL (M1 2.1). `None` when unset. Public value only.
    pub mcp_resource_url: Option<String>,
}

/// OpenBao transit settings for wrapping DEKs. No `Debug`/`Clone`: it holds the control
/// plane's token (encrypt-only by policy, S2 design decision 4).
pub struct KmsConfig {
    pub addr: String,
    pub token: SecretString,
    pub key: String,
    pub key_version: u32,
}

/// OpenBao transit settings for signing audit checkpoints. No `Debug`/`Clone`: it holds the
/// control plane's sign-only token (a policy allowing `transit/sign/audit-checkpoint` only).
pub struct CheckpointKmsConfig {
    pub addr: String,
    pub token: SecretString,
    pub key: String,
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
        check_release_dev_auth(
            dev_auth,
            !cfg!(debug_assertions),
            get(ENV_ALLOW_DEV_AUTH).as_deref() == Some("1"),
        )?;

        let openbao_addr = get(ENV_OPENBAO_ADDR).filter(|v| !v.trim().is_empty());
        let audit_checkpoint = match get(ENV_AUDIT_CHECKPOINT_TOKEN).filter(|v| !v.is_empty()) {
            None => None,
            Some(token) => Some(CheckpointKmsConfig {
                addr: openbao_addr
                    .clone()
                    .ok_or(ConfigError::Missing(ENV_OPENBAO_ADDR))?,
                token: SecretString::from(token),
                key: get(ENV_AUDIT_CHECKPOINT_KEY)
                    .filter(|v| !v.trim().is_empty())
                    .unwrap_or_else(|| DEFAULT_CHECKPOINT_KEY.to_owned()),
            }),
        };

        let kms = match openbao_addr {
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

        let agent_signing_key = match get(ENV_AGENT_SIGNING_KEY) {
            None => None,
            Some(v) if v.is_empty() => None,
            Some(v) => {
                let v = SecretString::from(v);
                crate::agent_token::AgentTokenSigner::from_base64_seed(v.expose_secret())
                    .map_err(|_| ConfigError::Invalid(ENV_AGENT_SIGNING_KEY))?;
                Some(v)
            }
        };

        let human_auth = human_auth_from(&get)?;
        let mcp_resource_url = match get(ENV_MCP_RESOURCE_URL)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
        {
            None => None,
            // The issuer settings verify the token, so the resource URL is useless without them.
            Some(_) if human_auth.is_none() => return Err(ConfigError::Missing(ENV_OIDC_ISSUER)),
            Some(v) if !is_http_url(&v) => return Err(ConfigError::Invalid(ENV_MCP_RESOURCE_URL)),
            Some(v) => Some(v),
        };

        Ok(Self {
            database_url,
            database_owner_url,
            bind,
            otlp_endpoint,
            dev_auth,
            kms,
            audit_checkpoint,
            gateway_service_token,
            agent_signing_key,
            human_auth,
            mcp_resource_url,
        })
    }
}

/// All three `LOCKSMITH_OIDC_*` variables or none; an unset or empty issuer means none.
fn human_auth_from(
    get: &impl Fn(&str) -> Option<String>,
) -> Result<Option<HumanAuthConfig>, ConfigError> {
    let value = |var: &'static str| {
        get(var)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    let Some(issuer) = value(ENV_OIDC_ISSUER) else {
        return Ok(None);
    };
    let audience = value(ENV_OIDC_AUDIENCE).ok_or(ConfigError::Missing(ENV_OIDC_AUDIENCE))?;
    let jwks_url = value(ENV_OIDC_JWKS_URL).ok_or(ConfigError::Missing(ENV_OIDC_JWKS_URL))?;
    if !is_http_url(&jwks_url) {
        return Err(ConfigError::Invalid(ENV_OIDC_JWKS_URL));
    }
    Ok(Some(HumanAuthConfig {
        issuer,
        audience,
        jwks_url,
    }))
}

fn is_http_url(s: &str) -> bool {
    s.parse::<http::Uri>()
        .is_ok_and(|u| matches!(u.scheme_str(), Some("http" | "https")) && u.authority().is_some())
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
    fn oidc_is_off_unless_an_issuer_is_set() {
        let c = Config::from_lookup(lookup(&DB)).ok().unwrap();
        assert!(c.human_auth.is_none());
    }

    #[test]
    fn mcp_resource_url_needs_the_oidc_issuer_and_a_url() {
        let url = (ENV_MCP_RESOURCE_URL, "https://hub.example/mcp");
        let err = Config::from_lookup(lookup(&with(&[url]))).err().unwrap();
        assert_eq!(err, ConfigError::Missing(ENV_OIDC_ISSUER));
        let oidc = [
            (ENV_OIDC_ISSUER, "https://idp.example/realms/x"),
            (ENV_OIDC_AUDIENCE, "api"),
            (ENV_OIDC_JWKS_URL, "http://localhost:8081/certs"),
        ];
        let mut bad = oidc.to_vec();
        bad.push((ENV_MCP_RESOURCE_URL, "not a url"));
        let err = Config::from_lookup(lookup(&with(&bad))).err().unwrap();
        assert_eq!(err, ConfigError::Invalid(ENV_MCP_RESOURCE_URL));
        let mut ok = oidc.to_vec();
        ok.push(url);
        let c = Config::from_lookup(lookup(&with(&ok))).ok().unwrap();
        assert_eq!(
            c.mcp_resource_url.as_deref(),
            Some("https://hub.example/mcp")
        );
    }

    #[test]
    fn oidc_needs_all_three_variables() {
        let issuer = (ENV_OIDC_ISSUER, "https://idp.example/realms/x");
        let err = Config::from_lookup(lookup(&with(&[issuer]))).err().unwrap();
        assert_eq!(err, ConfigError::Missing(ENV_OIDC_AUDIENCE));
        let err = Config::from_lookup(lookup(&with(&[issuer, (ENV_OIDC_AUDIENCE, "api")])))
            .err()
            .unwrap();
        assert_eq!(err, ConfigError::Missing(ENV_OIDC_JWKS_URL));
        let c = Config::from_lookup(lookup(&with(&[
            issuer,
            (ENV_OIDC_AUDIENCE, "api"),
            (ENV_OIDC_JWKS_URL, "http://localhost:8081/certs"),
        ])))
        .ok()
        .unwrap();
        let h = c.human_auth.unwrap();
        assert_eq!(h.issuer, "https://idp.example/realms/x");
        assert_eq!(h.audience, "api");
    }

    #[test]
    fn oidc_jwks_url_must_be_http_or_https() {
        for bad in ["ftp://h/x", "not a url", "/relative", "file:///etc/passwd"] {
            let err = Config::from_lookup(lookup(&with(&[
                (ENV_OIDC_ISSUER, "https://idp.example"),
                (ENV_OIDC_AUDIENCE, "api"),
                (ENV_OIDC_JWKS_URL, bad),
            ])))
            .err()
            .unwrap();
            assert_eq!(err, ConfigError::Invalid(ENV_OIDC_JWKS_URL), "{bad}");
        }
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
    fn release_build_refuses_dev_auth_without_override() {
        assert_eq!(
            check_release_dev_auth(true, true, false),
            Err(ConfigError::DevAuthInRelease)
        );
        assert!(check_release_dev_auth(true, true, true).is_ok());
        assert!(check_release_dev_auth(true, false, false).is_ok());
        assert!(check_release_dev_auth(false, true, false).is_ok());
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
    fn audit_checkpoint_signing_is_optional_and_needs_the_openbao_address() {
        let c = Config::from_lookup(lookup(&DB)).ok().unwrap();
        assert!(c.audit_checkpoint.is_none());
        let err = Config::from_lookup(lookup(&with(&[(
            ENV_AUDIT_CHECKPOINT_TOKEN,
            "tok-hunter9",
        )])))
        .err()
        .unwrap();
        assert_eq!(err, ConfigError::Missing(ENV_OPENBAO_ADDR));
        assert!(!err.to_string().contains("hunter"));
        let c = Config::from_lookup(lookup(&with(&[
            (ENV_OPENBAO_ADDR, "http://127.0.0.1:8200"),
            (ENV_OPENBAO_TOKEN, "tok-hunter4"),
            (ENV_AUDIT_CHECKPOINT_TOKEN, "tok-hunter9"),
        ])))
        .ok()
        .unwrap();
        let ck = c.audit_checkpoint.unwrap();
        assert_eq!(
            (ck.addr.as_str(), ck.key.as_str(), ck.token.expose_secret()),
            ("http://127.0.0.1:8200", "audit-checkpoint", "tok-hunter9")
        );
        let c = Config::from_lookup(lookup(&with(&[
            (ENV_OPENBAO_ADDR, "http://127.0.0.1:8200"),
            (ENV_OPENBAO_TOKEN, "tok-hunter4"),
            (ENV_AUDIT_CHECKPOINT_TOKEN, "tok-hunter9"),
            (ENV_AUDIT_CHECKPOINT_KEY, "other-key"),
        ])))
        .ok()
        .unwrap();
        assert_eq!(c.audit_checkpoint.unwrap().key, "other-key");
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
    fn agent_signing_key_is_optional_and_must_be_a_32_byte_seed() {
        let c = Config::from_lookup(lookup(&DB)).ok().unwrap();
        assert!(c.agent_signing_key.is_none());
        for bad in ["hunter8", "aHVudGVyOA", "aHVudGVyOC1ub3QtMzItYnl0ZXM="] {
            let err = Config::from_lookup(lookup(&with(&[(ENV_AGENT_SIGNING_KEY, bad)])))
                .err()
                .unwrap();
            assert_eq!(err, ConfigError::Invalid(ENV_AGENT_SIGNING_KEY));
            assert!(!err.to_string().contains(bad));
        }
        let c = Config::from_lookup(lookup(&with(&[(
            ENV_AGENT_SIGNING_KEY,
            "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        )])))
        .ok()
        .unwrap();
        assert!(c.agent_signing_key.is_some());
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
