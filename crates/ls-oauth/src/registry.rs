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

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        toml::from_str(text).map_err(|e| RegistryError(e.message().to_string()))
    }

    pub fn get(&self, id: &str) -> Option<&ProviderDef> {
        self.provider.iter().find(|p| p.id == id)
    }
}
