//! Provider registry schema (C1 design decision 3). Embedded, strict, empty for now.

use serde::Deserialize;

/// How a provider refreshes: `rotating` issues a new refresh token on each refresh,
/// `static` keeps one, `none` has no refresh token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshKind {
    Rotating,
    Static,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDef {
    pub id: String,
    pub name: String,
    pub authorize_url: String,
    pub token_url: String,
    #[serde(default)]
    pub revoke_url: Option<String>,
    pub account_url: String,
    pub refresh: RefreshKind,
    pub api_hosts: Vec<String>,
    pub default_scopes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    #[serde(default)]
    pub provider: Vec<ProviderDef>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RegistryError(pub String);

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "provider registry: {}", self.0)
    }
}

impl std::error::Error for RegistryError {}

const EMBEDDED: &str = include_str!("../providers.toml");

impl Registry {
    /// The registry embedded at build time.
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(EMBEDDED)
    }

    /// Parse and validate: HTTPS endpoints (except `mock`), exact API hosts, scopes present.
    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        let reg: Self = toml::from_str(text).map_err(|e| RegistryError(e.message().to_string()))?;
        reg.validate()?;
        Ok(reg)
    }

    fn validate(&self) -> Result<(), RegistryError> {
        let mut seen = std::collections::HashSet::new();
        for p in &self.provider {
            let bad = |what: &str| RegistryError(format!("{}: {what}", p.id));
            if p.id.is_empty() || !seen.insert(p.id.as_str()) {
                return Err(bad("id empty or duplicated"));
            }
            let dev = p.id == "mock";
            let urls = [
                Some(&p.authorize_url),
                Some(&p.token_url),
                p.revoke_url.as_ref(),
                Some(&p.account_url),
            ];
            for url in urls.into_iter().flatten() {
                let ok = url.starts_with("https://") || (dev && url.starts_with("http://"));
                if !ok || url.contains('*') {
                    return Err(bad("endpoint must be https"));
                }
            }
            if p.api_hosts.is_empty() {
                return Err(bad("api_hosts empty"));
            }
            for h in &p.api_hosts {
                let exact = !h.is_empty()
                    && h.chars().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | ':')
                    });
                if !exact || h.starts_with('.') || h.starts_with('-') {
                    return Err(bad("api host must be an exact host name"));
                }
            }
            // GitHub App permissions are set at registration, so it requests no scopes.
            if p.default_scopes.is_empty() && p.id != "github" {
                return Err(bad("default_scopes empty"));
            }
            if p.default_scopes
                .iter()
                .any(|s| s.is_empty() || s.contains(char::is_whitespace))
            {
                return Err(bad("scope empty or contains whitespace"));
            }
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&ProviderDef> {
        self.provider.iter().find(|p| p.id == id)
    }
}
