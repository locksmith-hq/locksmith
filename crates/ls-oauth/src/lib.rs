//! OAuth connections contract (C1 group 1).
//!
//! The provider registry schema and the request and response types of the gateway's
//! `/v1/oauth/*` endpoints. No type here carries a token, an authorization code or a PKCE
//! verifier: those live only in the gateway, sealed (C1 design decisions 6 and 7).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod registry;
#[cfg(feature = "testing")]
pub mod testing;

pub use registry::{ProviderDef, RefreshKind, Registry, RegistryError};

/// Name of the relay request field that selects a person's connection instead of a vault secret.
pub const RELAY_CONNECTION_FIELD: &str = "connection_id";

/// Closed set of error slugs the gateway answers with. Never provider or upstream text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSlug {
    UnknownProvider,
    ReturnToNotAllowed,
    FlowExpired,
    FlowNotFound,
    WrongPerson,
    ProviderError,
    ExchangeFailed,
    ConnectionNeedsReconnect,
    NoGrant,
    HostNotAllowed,
}

impl ErrorSlug {
    pub const ALL: [ErrorSlug; 10] = [
        Self::UnknownProvider,
        Self::ReturnToNotAllowed,
        Self::FlowExpired,
        Self::FlowNotFound,
        Self::WrongPerson,
        Self::ProviderError,
        Self::ExchangeFailed,
        Self::ConnectionNeedsReconnect,
        Self::NoGrant,
        Self::HostNotAllowed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownProvider => "unknown_provider",
            Self::ReturnToNotAllowed => "return_to_not_allowed",
            Self::FlowExpired => "flow_expired",
            Self::FlowNotFound => "flow_not_found",
            Self::WrongPerson => "wrong_person",
            Self::ProviderError => "provider_error",
            Self::ExchangeFailed => "exchange_failed",
            Self::ConnectionNeedsReconnect => "connection_needs_reconnect",
            Self::NoGrant => "no_grant",
            Self::HostNotAllowed => "host_not_allowed",
        }
    }
}

/// Error body of every `/v1/oauth/*` endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub error: ErrorSlug,
}

/// A provider the gateway has enabled, as served to the console (`oauth_providers`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSummary {
    pub provider: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub revoke_supported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Connected,
    RefreshFailed,
    Revoked,
}

/// One person's connection to a provider account. Timestamps are RFC 3339 strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSummary {
    pub id: Uuid,
    pub provider: String,
    pub account_login: String,
    pub account_id: String,
    pub scopes: Vec<String>,
    pub status: ConnectionStatus,
    pub connected_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_refreshed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_code: Option<String>,
    /// Only on a disconnect answer: whether the provider confirmed the revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_provider: Option<bool>,
}

/// A person's permission for an agent to relay through one of their connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionGrant {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub connection_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub created_by: Uuid,
    pub created_at: String,
}

/// A connection grant as listed by `GET /v1/grants`: ids, provider and the person's display
/// name, never a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionGrantListing {
    pub connection_id: Uuid,
    pub provider: String,
    pub person_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// `POST /v1/oauth/connect`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectRequest {
    pub provider: String,
    pub return_to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectResponse {
    pub flow_id: Uuid,
    pub authorize_url: String,
}

/// What the callback puts in the `result` query parameter of the redirect to `return_to`
/// (with `flow=<id>`): `pending_confirm` or an error slug, nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CallbackResult {
    Pending(PendingConfirm),
    Error(ErrorSlug),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingConfirm {
    PendingConfirm,
}

/// `POST /v1/oauth/flows/{id}/confirm` and `/connections/{id}/disconnect` answer with a
/// [`ConnectionSummary`].
pub type ConfirmResponse = ConnectionSummary;
pub type DisconnectResponse = ConnectionSummary;
