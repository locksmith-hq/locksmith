//! Configuration: environment variables for service settings, a TOML file for bindings
//! (S3 design decision 4). Errors name the variable or the field, never a value.
//!
//! No type here derives `Debug` or `Clone` where it holds a token or a URL with credentials.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::net::SocketAddr;

use ls_mcp_server::upstream::{ToolDecision, valid_tool_name};
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
/// STS endpoint override for `/v1/aws/credentials` (D2): local and test use only (Floci or a stub). Unset in
/// production, where the regional `https://sts.<region>.amazonaws.com/` is called.
pub const ENV_AWS_STS_ENDPOINT: &str = "LOCKSMITH_GATEWAY_AWS_STS_ENDPOINT";
/// Postgres listener address (D3). Unset: no listener.
pub const ENV_PG_LISTEN: &str = "LOCKSMITH_GATEWAY_PG_LISTEN";
/// PEM certificate chain the Postgres listener presents (required with [`ENV_PG_LISTEN`]).
pub const ENV_PG_TLS_CERT: &str = "LOCKSMITH_GATEWAY_PG_TLS_CERT";
/// PEM private key for [`ENV_PG_TLS_CERT`] (required with [`ENV_PG_LISTEN`]).
pub const ENV_PG_TLS_KEY: &str = "LOCKSMITH_GATEWAY_PG_TLS_KEY";
/// Comma-separated public host names (`host` or `host:port`) `/mcp` accepts in the `Host`
/// header, on top of loopback (DNS rebinding protection). Optional.
pub const ENV_MCP_ALLOWED_HOSTS: &str = "LOCKSMITH_GATEWAY_MCP_ALLOWED_HOSTS";
/// Comma-separated console origins (`scheme://host[:port]`) that may start OAuth connections
/// (C1). Setting it turns the OAuth endpoints on; unset, `/v1/oauth/*` and `/oauth/callback`
/// answer `503`.
pub const ENV_OAUTH_CONSOLE_ORIGINS: &str = "LOCKSMITH_GATEWAY_OAUTH_CONSOLE_ORIGINS";
/// The gateway's public callback URL registered with every provider app
/// (`https://gateway.example.com/oauth/callback`). Required with [`ENV_OAUTH_CONSOLE_ORIGINS`].
pub const ENV_OAUTH_REDIRECT_URL: &str = "LOCKSMITH_GATEWAY_OAUTH_REDIRECT_URL";
/// The OpenBao token that may encrypt and decrypt on the `oauth-connections` transit key only.
pub const ENV_OPENBAO_OAUTH_TOKEN: &str = "OPENBAO_GATEWAY_OAUTH_TOKEN";
/// The dev mock provider's issuer (the Keycloak realm). The registry's `mock` entry is enabled
/// only when it is set, with every URL derived from it.
pub const ENV_OAUTH_MOCK_ISSUER: &str = "LOCKSMITH_OAUTH_MOCK_ISSUER";
/// Human tokens at `/v1/oauth/*` are verified with the control plane's issuer settings.
pub use ls_control_plane::config::{ENV_OIDC_AUDIENCE, ENV_OIDC_ISSUER, ENV_OIDC_JWKS_URL};

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
    /// A `[[pg]]` binding is invalid; names the binding's index and the field.
    PgBinding {
        index: usize,
        field: &'static str,
    },
    /// An `[[mcp_upstream]]` is invalid; names the upstream's index and the field.
    McpUpstream {
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
            Self::PgBinding { index, field } => {
                write!(f, "pg binding #{index} has an invalid `{field}`")
            }
            Self::McpUpstream { index, field } => {
                write!(f, "mcp upstream #{index} has an invalid `{field}`")
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
    /// [`ENV_AWS_STS_ENDPOINT`]: tests and the local Floci smoke only.
    pub aws_sts_endpoint: Option<String>,
    /// The Postgres listener (D3), when [`ENV_PG_LISTEN`] is set.
    pub pg_listen: Option<PgListenConfig>,
    /// Extra `Host` values `/mcp` accepts ([`ENV_MCP_ALLOWED_HOSTS`]).
    pub mcp_allowed_hosts: Vec<String>,
    /// OAuth connections (C1), when [`ENV_OAUTH_CONSOLE_ORIGINS`] is set.
    pub oauth: Option<OAuthConfig>,
}

/// OAuth connection settings (C1 task 3.3). No `Debug`/`Clone`: it holds client secrets and an
/// OpenBao token.
pub struct OAuthConfig {
    /// Origins (`scheme://host[:port]`, no trailing slash) a `return_to` must be on. The first
    /// is also where a callback with an unknown `state` lands.
    pub console_origins: Vec<url::Origin>,
    /// The callback URL registered with the providers.
    pub redirect_url: Url,
    /// Person tokens: the same issuer settings as the control plane (`LOCKSMITH_OIDC_*`).
    pub human_auth: ls_control_plane::auth::human::HumanAuthConfig,
    /// May encrypt and decrypt on the `oauth-connections` transit key only.
    pub openbao_token: SecretString,
    /// The enabled providers: registry entries with client credentials configured.
    pub providers: Vec<OAuthProviderConfig>,
}

/// One enabled provider: its registry entry (the mock's URLs derived from its issuer) and the
/// provider app's client credentials.
pub struct OAuthProviderConfig {
    pub def: ls_oauth::ProviderDef,
    pub client_id: String,
    pub client_secret: SecretString,
}

/// `LOCKSMITH_OAUTH_<ID>_CLIENT_ID` / `_CLIENT_SECRET` for registry provider `id`.
pub fn oauth_client_vars(id: &str) -> (String, String) {
    let id = id.to_ascii_uppercase().replace('-', "_");
    (
        format!("LOCKSMITH_OAUTH_{id}_CLIENT_ID"),
        format!("LOCKSMITH_OAUTH_{id}_CLIENT_SECRET"),
    )
}

/// Where the Postgres listener binds and the TLS files it serves (paths only; the key is read
/// at startup).
pub struct PgListenConfig {
    pub addr: SocketAddr,
    pub cert_path: String,
    pub key_path: String,
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

/// TLS mode for the upstream Postgres leg of a `[[pg]]` binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PgTls {
    Require,
    VerifyFull,
    Disable,
}

fn default_pg_port() -> u16 {
    5432
}

fn default_pg_tls() -> PgTls {
    PgTls::Require
}

fn default_pg_version() -> u32 {
    1
}

/// One Postgres database an agent may reach through the relay (D3). There is deliberately no
/// password field: the password is the secret `secret_id`, decrypted per session.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PgBinding {
    /// The client's `database` startup parameter.
    pub name: String,
    pub secret_id: Uuid,
    /// Secret version decrypted for the session (as `[[git_binding]]`). Default 1.
    #[serde(default = "default_pg_version")]
    pub version: u32,
    pub host: String,
    #[serde(default = "default_pg_port")]
    pub port: u16,
    pub user: String,
    pub database: String,
    #[serde(default = "default_pg_tls")]
    pub tls: PgTls,
    #[serde(default)]
    pub allow_private_hosts: bool,
}

fn default_mcp_decision() -> ToolDecision {
    ToolDecision::Hide
}

/// One upstream MCP server the gateway proxies at `/mcp/upstream/{name}` (change m2-mcp-gateway).
/// The credential is the secret `secret_id`, injected per request; it is never published in the
/// inventory.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpUpstream {
    /// `[a-z0-9-]{1,32}`, unique: the path segment and the ledger code.
    pub name: String,
    /// Exact Streamable HTTP endpoint: https, no credentials, query or fragment (http only with
    /// `allow_private_hosts`).
    pub url: String,
    /// The agent needs an unexpired `relay` grant on this secret.
    pub secret_id: Uuid,
    pub header: String,
    /// Header value with exactly one `{secret}` placeholder.
    pub template: String,
    /// Decision for a tool without a rule in `tools`. Default `hide`.
    #[serde(default = "default_mcp_decision")]
    pub default: ToolDecision,
    #[serde(default)]
    pub allow_private_hosts: bool,
    /// Secret version injected (MCP requests carry none, as `[[git_binding]]`). Default 1.
    #[serde(default = "default_pg_version")]
    pub version: u32,
    /// Per-tool decisions; keys are exact, case-sensitive tool names.
    #[serde(default)]
    pub tools: BTreeMap<String, ToolDecision>,
}

fn valid_mcp_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl McpUpstream {
    fn validate(&self) -> Result<(), &'static str> {
        if !valid_mcp_name(&self.name) {
            return Err("name");
        }
        let url = Url::parse(&self.url).map_err(|_| "url")?;
        let scheme_ok =
            url.scheme() == "https" || (url.scheme() == "http" && self.allow_private_hosts);
        if !scheme_ok
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("url");
        }
        if !valid_header_name(&self.header) {
            return Err("header");
        }
        if self.template.matches("{secret}").count() != 1
            || self.template.chars().any(|c| c.is_control())
        {
            return Err("template");
        }
        if self.version == 0 {
            return Err("version");
        }
        if !self.tools.keys().all(|k| valid_tool_name(k)) {
            return Err("tools");
        }
        Ok(())
    }
}

/// The bindings file: the org the gateway acts for, and its bindings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bindings {
    pub org_id: Uuid,
    #[serde(default, rename = "binding")]
    pub bindings: Vec<Binding>,
    /// AWS credential-vending bindings (D2); none by default.
    #[serde(default, rename = "aws_binding")]
    pub aws_bindings: Vec<crate::aws_policy::AwsBinding>,
    #[serde(default, rename = "pg")]
    pub pg: Vec<PgBinding>,
    /// Git repositories a secret may be used for through `/git/...` (D1).
    #[serde(default, rename = "git_binding")]
    pub git_bindings: Vec<crate::git::GitBinding>,
    /// Upstream MCP servers proxied at `/mcp/upstream/{name}`; none by default.
    #[serde(default, rename = "mcp_upstream")]
    pub mcp_upstreams: Vec<McpUpstream>,
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
        let mut aws_seen = HashSet::new();
        for (index, a) in self.aws_bindings.iter().enumerate() {
            a.validate()
                .map_err(|field| ConfigError::Binding { index, field })?;
            if !aws_seen.insert(a.secret_id) {
                return Err(ConfigError::Binding {
                    index,
                    field: "aws_binding.secret_id",
                });
            }
        }
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
        let mut mcp_names = HashSet::new();
        let mut mcp_secrets = HashSet::new();
        for (index, m) in self.mcp_upstreams.iter().enumerate() {
            let bad = |field| ConfigError::McpUpstream { index, field };
            m.validate().map_err(bad)?;
            if !mcp_names.insert(m.name.as_str()) {
                return Err(bad("name"));
            }
            if !mcp_secrets.insert(m.secret_id) {
                return Err(bad("secret_id"));
            }
        }
        let mut names = HashSet::new();
        let mut pg_secrets = HashSet::new();
        for (index, b) in self.pg.iter().enumerate() {
            let bad = |field| ConfigError::PgBinding { index, field };
            if b.name.is_empty() || !names.insert(b.name.as_str()) {
                return Err(bad("name"));
            }
            if !pg_secrets.insert(b.secret_id) {
                return Err(bad("secret_id"));
            }
            if b.version == 0 {
                return Err(bad("version"));
            }
            if b.host.is_empty()
                || b.host
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || c == '/')
            {
                return Err(bad("host"));
            }
            if b.user.is_empty() || b.database.is_empty() {
                return Err(bad("user"));
            }
            if b.tls == PgTls::Disable && !b.allow_private_hosts {
                return Err(bad("tls"));
            }
        }
        Ok(())
    }

    /// The AWS binding for `secret_id`, if any.
    pub fn aws_for_secret(&self, secret_id: Uuid) -> Option<&crate::aws_policy::AwsBinding> {
        self.aws_bindings.iter().find(|b| b.secret_id == secret_id)
    }

    /// The Postgres binding named `name`, if any.
    pub fn pg_by_name(&self, name: &str) -> Option<&PgBinding> {
        self.pg.iter().find(|b| b.name == name)
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

        let aws_sts_endpoint = match get(ENV_AWS_STS_ENDPOINT).filter(|v| !v.trim().is_empty()) {
            None => None,
            Some(v) => Some(
                Url::parse(&v)
                    .ok()
                    .filter(|u| {
                        matches!(u.scheme(), "http" | "https")
                            && u.host_str().is_some()
                            && u.username().is_empty()
                            && u.password().is_none()
                    })
                    .map(|_| v)
                    .ok_or(ConfigError::Invalid(ENV_AWS_STS_ENDPOINT))?,
            ),
        };

        let pg_listen = match get(ENV_PG_LISTEN).filter(|v| !v.trim().is_empty()) {
            None => None,
            Some(v) => Some(PgListenConfig {
                addr: v.parse().map_err(|_| ConfigError::Invalid(ENV_PG_LISTEN))?,
                cert_path: required(ENV_PG_TLS_CERT)?,
                key_path: required(ENV_PG_TLS_KEY)?,
            }),
        };

        let mcp_allowed_hosts = get(ENV_MCP_ALLOWED_HOSTS)
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|h| !h.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();

        let oauth = oauth_from(&get)?;

        Ok(Self {
            bind,
            database_url,
            otlp_endpoint,
            control_plane_url,
            service_token,
            openbao,
            bindings,
            aws_sts_endpoint,
            pg_listen,
            mcp_allowed_hosts,
            oauth,
        })
    }
}

fn http_url(v: &str) -> Option<Url> {
    Url::parse(v).ok().filter(|u| {
        matches!(u.scheme(), "http" | "https")
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none()
    })
}

/// The OAuth settings, when [`ENV_OAUTH_CONSOLE_ORIGINS`] is set. Errors name variables only.
fn oauth_from(get: &impl Fn(&str) -> Option<String>) -> Result<Option<OAuthConfig>, ConfigError> {
    let value = |var: &str| {
        get(var)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    let Some(origins) = value(ENV_OAUTH_CONSOLE_ORIGINS) else {
        return Ok(None);
    };
    let mut console_origins = Vec::new();
    for o in origins.split(',').map(str::trim).filter(|o| !o.is_empty()) {
        let url = http_url(o)
            .filter(|u| u.path() == "/" && u.query().is_none())
            .ok_or(ConfigError::Invalid(ENV_OAUTH_CONSOLE_ORIGINS))?;
        console_origins.push(url.origin());
    }
    if console_origins.is_empty() {
        return Err(ConfigError::Invalid(ENV_OAUTH_CONSOLE_ORIGINS));
    }
    let required = |var: &'static str| value(var).ok_or(ConfigError::Missing(var));
    let redirect_url = http_url(&required(ENV_OAUTH_REDIRECT_URL)?)
        .filter(|u| u.query().is_none())
        .ok_or(ConfigError::Invalid(ENV_OAUTH_REDIRECT_URL))?;
    let human_auth = ls_control_plane::auth::human::HumanAuthConfig {
        issuer: required(ENV_OIDC_ISSUER)?,
        audience: required(ENV_OIDC_AUDIENCE)?,
        jwks_url: http_url(&required(ENV_OIDC_JWKS_URL)?)
            .ok_or(ConfigError::Invalid(ENV_OIDC_JWKS_URL))?
            .to_string(),
    };
    let openbao_token = SecretString::from(required(ENV_OPENBAO_OAUTH_TOKEN)?);

    let registry = ls_oauth::Registry::embedded()
        .map_err(|_| ConfigError::Invalid(ENV_OAUTH_CONSOLE_ORIGINS))?;
    let mut providers = Vec::new();
    for def in registry.provider {
        let mut def = def;
        if def.id == "mock" {
            let Some(issuer) = value(ENV_OAUTH_MOCK_ISSUER) else {
                continue;
            };
            def = mock_def(def, &issuer).ok_or(ConfigError::Invalid(ENV_OAUTH_MOCK_ISSUER))?;
        }
        let (id_var, secret_var) = oauth_client_vars(&def.id);
        match (value(&id_var), value(&secret_var)) {
            (Some(client_id), Some(secret)) => providers.push(OAuthProviderConfig {
                def,
                client_id,
                client_secret: SecretString::from(secret),
            }),
            (None, None) if def.id != "mock" => {}
            // The mock issuer without its client, or only half of a provider's credentials.
            _ => return Err(ConfigError::Missing(ENV_OAUTH_CLIENT_CREDENTIALS)),
        }
    }
    Ok(Some(OAuthConfig {
        console_origins,
        redirect_url,
        human_auth,
        openbao_token,
        providers,
    }))
}

/// Named when a provider's client credentials are incomplete (the variable names are derived
/// from the provider id, so the error names the pattern).
pub const ENV_OAUTH_CLIENT_CREDENTIALS: &str =
    "LOCKSMITH_OAUTH_<PROVIDER>_CLIENT_ID and _CLIENT_SECRET";

/// The `mock` entry with every URL derived from the Keycloak realm `issuer`.
fn mock_def(mut def: ls_oauth::ProviderDef, issuer: &str) -> Option<ls_oauth::ProviderDef> {
    let url = http_url(issuer).filter(|u| u.query().is_none())?;
    let base = url.as_str().trim_end_matches('/');
    let host = url.host_str()?;
    def.authorize_url = format!("{base}/protocol/openid-connect/auth");
    def.token_url = format!("{base}/protocol/openid-connect/token");
    def.revoke_url = Some(format!("{base}/protocol/openid-connect/revoke"));
    def.account_url = format!("{base}/protocol/openid-connect/userinfo");
    def.api_hosts = vec![match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_owned(),
    }];
    Some(def)
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

    fn oauth_env() -> HashMap<&'static str, String> {
        let mut e = env();
        e.insert(
            ENV_OAUTH_CONSOLE_ORIGINS,
            "http://localhost:5173, http://127.0.0.1:5173".to_owned(),
        );
        e.insert(
            ENV_OAUTH_REDIRECT_URL,
            "http://127.0.0.1:8090/oauth/callback".to_owned(),
        );
        e.insert(
            ENV_OIDC_ISSUER,
            "http://localhost:8180/realms/acme".to_owned(),
        );
        e.insert(ENV_OIDC_AUDIENCE, "locksmith-api".to_owned());
        e.insert(
            ENV_OIDC_JWKS_URL,
            "http://127.0.0.1:8180/realms/acme/certs".to_owned(),
        );
        e.insert(ENV_OPENBAO_OAUTH_TOKEN, "bao-oauth-token".to_owned());
        e
    }

    #[test]
    fn oauth_config_is_off_unless_console_origins_are_set() {
        let c = load(&env(), &bindings_toml("")).expect("valid");
        assert!(c.oauth.is_none());
    }

    #[test]
    fn oauth_config_loads_and_enables_the_mock_only_with_its_issuer() {
        let c = load(&oauth_env(), &bindings_toml("")).expect("valid");
        let o = c.oauth.expect("oauth on");
        assert_eq!(o.console_origins.len(), 2);
        assert_eq!(
            o.redirect_url.as_str(),
            "http://127.0.0.1:8090/oauth/callback"
        );
        assert!(o.providers.is_empty(), "no provider without credentials");

        let mut e = oauth_env();
        e.insert(
            ENV_OAUTH_MOCK_ISSUER,
            "http://kc.test:8180/realms/acme".to_owned(),
        );
        assert_eq!(
            load(&e, &bindings_toml("")).err(),
            Some(ConfigError::Missing(ENV_OAUTH_CLIENT_CREDENTIALS)),
            "the mock issuer needs its client"
        );
        let (id_var, secret_var) = oauth_client_vars("mock");
        assert_eq!(
            (id_var.as_str(), secret_var.as_str()),
            (
                "LOCKSMITH_OAUTH_MOCK_CLIENT_ID",
                "LOCKSMITH_OAUTH_MOCK_CLIENT_SECRET"
            )
        );
        e.insert("LOCKSMITH_OAUTH_MOCK_CLIENT_ID", "acme-mock".to_owned());
        e.insert(
            "LOCKSMITH_OAUTH_MOCK_CLIENT_SECRET",
            "acme-mock-secret".to_owned(),
        );
        let o = load(&e, &bindings_toml("")).expect("valid").oauth.unwrap();
        assert_eq!(o.providers.len(), 1);
        let def = &o.providers[0].def;
        assert_eq!(def.id, "mock");
        let base = "http://kc.test:8180/realms/acme/protocol/openid-connect";
        assert_eq!(def.authorize_url, format!("{base}/auth"));
        assert_eq!(def.token_url, format!("{base}/token"));
        assert_eq!(
            def.revoke_url.as_deref(),
            Some(format!("{base}/revoke").as_str())
        );
        assert_eq!(def.account_url, format!("{base}/userinfo"));
        assert_eq!(def.api_hosts, vec!["kc.test:8180".to_owned()]);
    }

    #[test]
    fn oauth_config_rejects_bad_values() {
        for (var, bad) in [
            (ENV_OAUTH_CONSOLE_ORIGINS, "localhost:5173"),
            (ENV_OAUTH_CONSOLE_ORIGINS, "http://localhost:5173/app"),
            (ENV_OAUTH_CONSOLE_ORIGINS, " , "),
            (ENV_OAUTH_REDIRECT_URL, "not a url"),
            (ENV_OIDC_JWKS_URL, "ftp://x/certs"),
        ] {
            let mut e = oauth_env();
            e.insert(var, bad.to_owned());
            let err = load(&e, &bindings_toml("")).err();
            assert_eq!(err, Some(ConfigError::Invalid(var)), "{var}={bad}");
        }
        for var in [
            ENV_OAUTH_REDIRECT_URL,
            ENV_OIDC_ISSUER,
            ENV_OPENBAO_OAUTH_TOKEN,
        ] {
            let mut e = oauth_env();
            e.remove(var);
            assert_eq!(
                load(&e, &bindings_toml("")).err(),
                Some(ConfigError::Missing(var))
            );
        }
    }

    const PG: &str = "\n[[pg]]\nname = \"app\"\nsecret_id = \"0197c1f0-0000-7000-8000-000000000003\"\nhost = \"postgres\"\nuser = \"app_rw\"\ndatabase = \"app\"\n";

    #[test]
    fn pg_config_accepts_fixture_and_defaults() {
        let c = load(&env(), &bindings_toml(PG)).expect("valid");
        let b = c.bindings.pg_by_name("app").expect("binding");
        assert_eq!(
            (b.port, b.tls, b.allow_private_hosts, b.version),
            (5432, PgTls::Require, false, 1)
        );
        assert!(c.pg_listen.is_none(), "the pg listener is off by default");
    }

    #[test]
    fn pg_config_listener_needs_an_address_and_tls_files() {
        let mut e = env();
        e.insert(ENV_PG_LISTEN, "127.0.0.1:6432".to_owned());
        assert_eq!(
            load(&e, &bindings_toml("")).err(),
            Some(ConfigError::Missing(ENV_PG_TLS_CERT))
        );
        e.insert(ENV_PG_TLS_CERT, "/etc/pg.crt".to_owned());
        assert_eq!(
            load(&e, &bindings_toml("")).err(),
            Some(ConfigError::Missing(ENV_PG_TLS_KEY))
        );
        e.insert(ENV_PG_TLS_KEY, "/etc/pg.key".to_owned());
        let c = load(&e, &bindings_toml("")).expect("valid");
        let l = c.pg_listen.expect("listener configured");
        assert_eq!(l.addr, "127.0.0.1:6432".parse().unwrap());
        e.insert(ENV_PG_LISTEN, "not an address".to_owned());
        assert_eq!(
            load(&e, &bindings_toml("")).err(),
            Some(ConfigError::Invalid(ENV_PG_LISTEN))
        );
    }

    #[test]
    fn pg_config_rejects_bad_bindings() {
        let err = |extra: &str| load(&env(), &bindings_toml(extra)).err();
        let field = |f| Some(ConfigError::PgBinding { index: 1, field: f });
        // Password fields do not exist.
        assert!(err(&format!("{PG}password = \"x\"\n")).is_some());
        // Duplicate name.
        let dup_name = PG.replace("000000000003", "000000000004");
        assert_eq!(err(&format!("{PG}{dup_name}")), field("name"));
        // Duplicate secret.
        let dup_secret = PG.replace("\"app\"\nsecret", "\"app2\"\nsecret");
        assert_eq!(err(&format!("{PG}{dup_secret}")), field("secret_id"));
        // tls disable only with allow_private_hosts.
        let off = format!("{PG}tls = \"disable\"\n");
        assert_eq!(
            err(&off),
            Some(ConfigError::PgBinding {
                index: 0,
                field: "tls"
            })
        );
        assert!(err(&format!("{off}allow_private_hosts = true\n")).is_none());
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

    const MCP_SECRET: &str = "0197c1f0-0000-7000-8000-0000000000aa";

    fn mcp_toml(body: &str) -> String {
        format!(
            "org_id = \"{ORG}\"\n[[mcp_upstream]]\nname = \"github\"\nurl = \"https://api.githubcopilot.com/mcp/\"\nsecret_id = \"{MCP_SECRET}\"\nheader = \"Authorization\"\ntemplate = \"Bearer {{secret}}\"\n{body}"
        )
    }

    fn mcp_err(toml: &str) -> Option<ConfigError> {
        Bindings::parse(toml).err()
    }

    fn mcp_bad(field: &'static str) -> Option<ConfigError> {
        Some(ConfigError::McpUpstream { index: 0, field })
    }

    #[test]
    fn mcp_upstream_parses_with_defaults_and_rules() {
        let b = Bindings::parse(&mcp_toml(
            "default = \"deny\"\n[mcp_upstream.tools]\nlist_issues = \"allow\"\ncreate_issue = \"hold\"\ndelete_repository = \"deny\"\n",
        ))
        .expect("valid");
        let m = &b.mcp_upstreams[0];
        assert_eq!(m.default, ToolDecision::Deny);
        assert_eq!(m.tools["create_issue"], ToolDecision::Hold);
        assert!(!m.allow_private_hosts);
        assert_eq!(m.version, 1);
        let d = Bindings::parse(&mcp_toml("")).unwrap();
        assert_eq!(d.mcp_upstreams[0].default, ToolDecision::Hide);
        assert!(d.mcp_upstreams[0].tools.is_empty());
    }

    #[test]
    fn mcp_upstream_rejects_bad_fields() {
        for name in ["", "Github", "git_hub", "a b", &"x".repeat(33), "g\u{e9}"] {
            let t = mcp_toml("").replace("name = \"github\"", &format!("name = \"{name}\""));
            assert_eq!(mcp_err(&t), mcp_bad("name"), "{name:?}");
        }
        for url in [
            "http://api.example.com/mcp",
            "ftp://api.example.com/mcp",
            "https://user:pw@api.example.com/mcp",
            "https://api.example.com/mcp?x=1",
            "https://api.example.com/mcp#f",
            "api.example.com/mcp",
        ] {
            let t = mcp_toml("").replace("https://api.githubcopilot.com/mcp/", url);
            assert_eq!(mcp_err(&t), mcp_bad("url"), "{url}");
        }
        let t = mcp_toml("allow_private_hosts = true").replace(
            "https://api.githubcopilot.com/mcp/",
            "http://127.0.0.1:9000/mcp",
        );
        assert!(Bindings::parse(&t).is_ok());
        let t = mcp_toml("").replace("Authorization", "Bad Header");
        assert_eq!(mcp_err(&t), mcp_bad("header"));
        for tpl in ["no placeholder", "{secret}{secret}", "Bearer {secret}\\n"] {
            let t = mcp_toml("").replace("Bearer {secret}", tpl);
            assert_eq!(mcp_err(&t), mcp_bad("template"), "{tpl}");
        }
        let t = mcp_toml("[mcp_upstream.tools]\n\"bad name\" = \"allow\"\n");
        assert_eq!(mcp_err(&t), mcp_bad("tools"));
        assert_eq!(mcp_err(&mcp_toml("version = 0")), mcp_bad("version"));
        for bad in [
            "default = \"permit\"",
            "default = \"Allow\"",
            "[mcp_upstream.tools]\nx = \"maybe\"",
            "extra = 1",
        ] {
            assert_eq!(
                mcp_err(&mcp_toml(bad)),
                Some(ConfigError::BindingsUnreadable),
                "{bad}"
            );
        }
    }

    #[test]
    fn mcp_upstream_names_and_secrets_are_unique() {
        let one = mcp_toml("");
        let dup_name = format!(
            "{one}\n[[mcp_upstream]]\nname = \"github\"\nurl = \"https://b.example.com/mcp\"\nsecret_id = \"{SECRET}\"\nheader = \"X-Key\"\ntemplate = \"{{secret}}\"\n"
        );
        assert_eq!(
            mcp_err(&dup_name),
            Some(ConfigError::McpUpstream {
                index: 1,
                field: "name"
            })
        );
        let dup_secret = format!(
            "{one}\n[[mcp_upstream]]\nname = \"other\"\nurl = \"https://b.example.com/mcp\"\nsecret_id = \"{MCP_SECRET}\"\nheader = \"X-Key\"\ntemplate = \"{{secret}}\"\n"
        );
        assert_eq!(
            mcp_err(&dup_secret),
            Some(ConfigError::McpUpstream {
                index: 1,
                field: "secret_id"
            })
        );
    }

    #[test]
    fn mcp_upstream_error_never_shows_a_value() {
        let t = mcp_toml("").replace("Bearer {secret}", "tok-12345-no-placeholder");
        let e = mcp_err(&t).unwrap().to_string();
        assert_eq!(e, "mcp upstream #0 has an invalid `template`");
        assert!(!e.contains("tok-12345"));
    }
}
