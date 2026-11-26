//! Owner-only honey token reveal (t5-honey-tokens task 2.4, design decision 7).
//!
//! `smith honey plant <name> --into <path>` needs the decoy value of a honey token to write it
//! into a file. The value is sealed like any secret, and only the gateway can open it, so the
//! gateway serves it, to the org's owner only:
//!
//! - `GET /v1/honey-tokens?name=<name>`: the org's honey tokens with that name (ids, names,
//!   templates; never a value), so the CLI can resolve a name to an id.
//! - `GET /v1/honey-tokens/{id}/value`: the decoy value, as `application/octet-stream`.
//!
//! Who may call: a person, with the same OIDC access token the console API accepts, who is the
//! owner of the org this gateway serves. The gateway does not verify that token itself: it
//! forwards it to the control plane's internal honey routes (`X-Locksmith-User-Authorization`,
//! next to the service token), which verify it with the one human verifier and resolve the user.
//! Agent tokens (EdDSA JWTs) and short-lived credentials (`lsst_`) are refused here with `403`
//! before anything is forwarded, so an agent, or an MCP tool acting for one, never reaches a
//! honey value. Hub MCP tokens carry the MCP resource audience, which the API verifier refuses.
//!
//! Order on `value`: the control plane checks the secret is of kind `honey` (`409` otherwise,
//! `404` when it does not exist in the org), not disabled and minted, and appends
//! `honey.revealed` (owner, token, version, template) in the same transaction; only then does the
//! gateway decrypt. A ledger that cannot be written means no value. The value exists only in
//! [`SecretBytes`] and a zeroize-on-drop response buffer; nothing here logs, traces or
//! serializes it, and no type that holds it implements `Debug`, `Display` or `Clone`.

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::app::AppState;
use crate::decrypt::{BoxFuture, ControlPlane, Internal};
use crate::relay::error;

/// Header carrying the person's own `Bearer` token on the internal honey routes (the control
/// plane's `USER_AUTHORIZATION_HEADER`).
pub const USER_AUTHORIZATION_HEADER: &str = "x-locksmith-user-authorization";

/// Largest internal honey response read (metadata only).
const MAX_HONEY_RESPONSE: usize = 256 * 1024;

/// One honey token as the owner names it. Never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoneyTokenRef {
    #[serde(alias = "secret_id")]
    pub id: Uuid,
    pub name: String,
    pub template: String,
    pub disabled: bool,
}

/// The version the control plane authorized for decryption (after recording the reveal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reveal {
    pub secret_id: Uuid,
    pub version: u32,
}

/// Why the control plane refused or failed. Status classes only, never a response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerError {
    /// The person's token (or the service token) was not accepted.
    Unauthenticated,
    /// A valid person who is not the org's owner (or has no verified email).
    Forbidden,
    /// No such secret in the org.
    NotFound,
    /// Not a honey token, disabled, or not minted.
    Conflict,
    /// The request was malformed (e.g. an empty name).
    Invalid,
    /// Unreachable, timed out, or an unexpected answer.
    Unavailable,
}

impl OwnerError {
    fn response(self, request_id: &str) -> Response {
        let (status, slug) = match self {
            Self::Unauthenticated => (StatusCode::UNAUTHORIZED, "unauthenticated"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "not_owner"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "not_a_revealable_honey_token"),
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        error(status, slug, request_id)
    }

    fn from_status(status: u16) -> Self {
        match status {
            400 => Self::Invalid,
            401 => Self::Unauthenticated,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            409 => Self::Conflict,
            _ => Self::Unavailable,
        }
    }
}

/// The control plane's owner-only honey routes. `user` is the person's `Authorization` value,
/// forwarded unchanged.
pub trait HoneyOwnerSource: Send + Sync {
    fn find<'a>(
        &'a self,
        user: &'a HeaderValue,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Vec<HoneyTokenRef>, OwnerError>>;

    /// Authorize the reveal and append `honey.revealed`; the version to decrypt.
    fn authorize_reveal<'a>(
        &'a self,
        user: &'a HeaderValue,
        secret_id: Uuid,
    ) -> BoxFuture<'a, Result<Reveal, OwnerError>>;
}

#[derive(Deserialize)]
struct RefsJson {
    items: Vec<HoneyTokenRef>,
}

#[derive(Deserialize)]
struct RevealJson {
    secret_id: Uuid,
    version: u32,
}

impl ControlPlane {
    async fn honey_call(
        &self,
        method: reqwest::Method,
        path: &str,
        user: &HeaderValue,
    ) -> Result<Vec<u8>, OwnerError> {
        let (status, body) = self
            .internal_as_user(
                method,
                path,
                (USER_AUTHORIZATION_HEADER, user),
                MAX_HONEY_RESPONSE,
            )
            .await
            .map_err(|e| match e {
                Internal::Unavailable | Internal::BadResponse | Internal::NotFound => {
                    OwnerError::Unavailable
                }
                Internal::Denied => OwnerError::Unauthenticated,
            })?;
        match status {
            200 => Ok(body),
            s => Err(OwnerError::from_status(s)),
        }
    }
}

impl HoneyOwnerSource for ControlPlane {
    fn find<'a>(
        &'a self,
        user: &'a HeaderValue,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Vec<HoneyTokenRef>, OwnerError>> {
        Box::pin(async move {
            let query: String = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("name", name)
                .finish();
            let body = self
                .honey_call(
                    reqwest::Method::GET,
                    &format!("internal/v1/honey/tokens?{query}"),
                    user,
                )
                .await?;
            let refs: RefsJson =
                serde_json::from_slice(&body).map_err(|_| OwnerError::Unavailable)?;
            Ok(refs.items)
        })
    }

    fn authorize_reveal<'a>(
        &'a self,
        user: &'a HeaderValue,
        secret_id: Uuid,
    ) -> BoxFuture<'a, Result<Reveal, OwnerError>> {
        Box::pin(async move {
            let body = self
                .honey_call(
                    reqwest::Method::POST,
                    &format!("internal/v1/honey/tokens/{secret_id}/reveal"),
                    user,
                )
                .await?;
            let r: RevealJson =
                serde_json::from_slice(&body).map_err(|_| OwnerError::Unavailable)?;
            if r.secret_id != secret_id || r.version == 0 {
                return Err(OwnerError::Unavailable);
            }
            Ok(Reveal {
                secret_id,
                version: r.version,
            })
        })
    }
}

/// Why a caller is refused before anything is forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerRefused {
    /// No `Authorization: Bearer` credential.
    Missing,
    /// An agent token (EdDSA JWT, the only kind the control plane mints for agents).
    AgentToken,
    /// A short-lived credential issued over MCP.
    ShortLived,
}

impl CallerRefused {
    fn response(self, request_id: &str) -> Response {
        match self {
            Self::Missing => error(StatusCode::UNAUTHORIZED, "unauthenticated", request_id),
            Self::AgentToken => error(StatusCode::FORBIDDEN, "agent_token_refused", request_id),
            Self::ShortLived => error(
                StatusCode::FORBIDDEN,
                "agent_credential_refused",
                request_id,
            ),
        }
    }
}

/// The person's `Authorization` value to forward, or why the caller is refused. Agent tokens are
/// recognised by shape (an EdDSA JWT header; the human verifier accepts RS256 and ES256 only, so
/// no person's token looks like one), whether or not they would verify, so no agent credential is
/// ever forwarded.
pub fn person_credential(headers: &HeaderMap) -> Result<HeaderValue, CallerRefused> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or(CallerRefused::Missing)?;
    let token = ls_control_plane::auth::bearer(value.as_bytes()).ok_or(CallerRefused::Missing)?;
    let token = std::str::from_utf8(token).map_err(|_| CallerRefused::Missing)?;
    if token.starts_with(crate::short_lived::PREFIX) {
        return Err(CallerRefused::ShortLived);
    }
    if jsonwebtoken::decode_header(token).is_ok_and(|h| h.alg == jsonwebtoken::Algorithm::EdDSA) {
        return Err(CallerRefused::AgentToken);
    }
    let mut forwarded = value.clone();
    forwarded.set_sensitive(true);
    Ok(forwarded)
}

/// Query of `GET /v1/honey-tokens`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindQuery {
    pub name: String,
}

/// `GET /v1/honey-tokens` answer.
#[derive(Serialize)]
struct FindResponse {
    items: Vec<HoneyTokenRef>,
}

/// `GET /v1/honey-tokens?name=<name>`: the owner's honey tokens with that name.
pub async fn find_route(
    State(state): State<AppState>,
    query: Result<Query<FindQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let user = match person_credential(&headers) {
        Ok(u) => u,
        Err(r) => {
            tracing::info!(reason = ?r, "honey token lookup refused");
            return r.response(&request_id);
        }
    };
    let Ok(Query(query)) = query else {
        return error(StatusCode::BAD_REQUEST, "invalid_request", &request_id);
    };
    let Some(relay) = state.relay() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", &request_id);
    };
    let Some(source) = relay.honey() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", &request_id);
    };
    match source.find(&user, &query.name).await {
        Ok(items) => Json(FindResponse { items }).into_response(),
        Err(e) => e.response(&request_id),
    }
}

/// A response body that wipes its buffer when hyper drops it.
struct WipeOnDrop(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for WipeOnDrop {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// `GET /v1/honey-tokens/{id}/value`: the decoy value, for the org's owner only.
pub async fn value_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let user = match person_credential(&headers) {
        Ok(u) => u,
        Err(r) => {
            tracing::info!(reason = ?r, "honey reveal refused");
            return r.response(&request_id);
        }
    };
    // A malformed id cannot name a secret.
    let Ok(secret_id) = Uuid::parse_str(&id) else {
        return error(StatusCode::NOT_FOUND, "not_found", &request_id);
    };
    let Some(relay) = state.relay() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", &request_id);
    };
    let Some(source) = relay.honey() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", &request_id);
    };
    // Kind check and `honey.revealed` first; no decrypt without both.
    let reveal = match source.authorize_reveal(&user, secret_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::info!(secret.id = %secret_id, reason = ?e, "honey reveal refused");
            return e.response(&request_id);
        }
    };
    let value = match relay
        .decryptor()
        .decrypt_honey(reveal.secret_id, reveal.version)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(secret.id = %secret_id, error = %e, "honey value did not decrypt");
            return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", &request_id);
        }
    };
    let buf = WipeOnDrop(Zeroizing::new(value.expose().to_vec()));
    drop(value);
    tracing::info!(secret.id = %secret_id, secret.version = reveal.version, "honey value revealed to the owner");
    let mut resp = Response::new(Body::from(Bytes::from_owner(buf)));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        h.insert("x-request-id", v);
    }
    resp
}

#[cfg(test)]
#[path = "honey_tests.rs"]
mod tests;
