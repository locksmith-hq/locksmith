//! Seal-to-browser contract (T7): `GET .../environments/{id}/seal-key` and the sealed version
//! create. Contract only for now (task 1.3): both handlers answer `503` until the seal-key
//! lifecycle and the sealed write land (T7 tasks 2.1-2.3).
//!
//! The sealed create carries ciphertext and a wrapped DEK, never a plaintext value, so its body
//! types hold no secret. Both byte fields are standard base64 strings.

use axum::extract::State;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::extract::{ApiJson, ApiPath, ApiQuery};
use super::responses::{SealKeyErrors, SealedVersionWriteErrors};
use super::versions::SecretVersion;
use crate::app::AppState;
use crate::auth::OrgBinding;
use crate::problem::{ApiError, Kind};

/// The environment's active seal key: the public half a client seals a DEK to.
#[derive(Debug, Serialize, ToSchema)]
pub struct SealKey {
    /// Id of the seal key; stored on every version sealed to it.
    pub key_id: String,
    /// The X25519 public key, standard base64 (32 bytes).
    pub public_key: String,
    /// The version number the next write to this secret must carry (1 for a new secret). The
    /// number is part of the sealed binding, so a client seals for exactly this version.
    pub next_version: u32,
    /// Ed25519 signature by the gateway identity key over `(org, environment, key_id, public
    /// key)`, standard base64 (64 bytes). Stored and returned unchanged; clients verify it
    /// against a pinned gateway verifying key before sealing (message format in `ls-envelope`
    /// `seal_key_message`).
    pub signature: String,
    /// Id of the gateway identity key that made `signature`, so a client picks the pinned
    /// verifying key; the key itself is never served by the control plane.
    pub signing_key_id: String,
}

#[derive(Debug, Deserialize, IntoParams)]
#[allow(dead_code)] // Read by the real handler (T7 task 2.3); the contract stub ignores it.
#[into_params(parameter_in = Query)]
pub struct SealKeyParams {
    /// The secret the next version is for. Omit for a new secret (`next_version` is 1).
    pub secret_id: Option<Uuid>,
}

/// Request body of a sealed version write: ciphertext only, nothing the server can open.
#[derive(Debug, Deserialize, ToSchema)]
#[allow(dead_code)] // Read by the real handler (T7 task 2.3); the contract stub ignores it.
#[serde(deny_unknown_fields)]
pub struct NewSealedSecretVersion {
    /// Must equal the secret's `next_version`, else `409`.
    pub version: u32,
    /// The sealed payload (A0-7 format), standard base64.
    pub ciphertext: String,
    /// The DEK wrapped to the environment's seal key (`seal-key` `key_id`), standard base64.
    pub wrapped_dek: String,
}

#[utoipa::path(
    get,
    path = "/v1/projects/{project_id}/environments/{environment_id}/seal-key",
    operation_id = "get_environment_seal_key",
    tag = "environments",
    summary = "Get the environment's public seal key and the next version number",
    params(
        ("project_id" = Uuid, Path, description = "Project id"),
        ("environment_id" = Uuid, Path, description = "Environment id"),
        SealKeyParams,
    ),
    responses(
        (status = 200, description = "The active seal key", body = SealKey),
        SealKeyErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn get_seal_key(
    State(_state): State<AppState>,
    _org: OrgBinding,
    ApiPath((_project_id, _environment_id)): ApiPath<(Uuid, Uuid)>,
    ApiQuery(_params): ApiQuery<SealKeyParams>,
) -> Result<axum::Json<SealKey>, ApiError> {
    Err(ApiError::new(
        Kind::Unavailable,
        "the environment seal key is not available yet",
    ))
}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_id}/environments/{environment_id}/secrets/{secret_id}/sealed-versions",
    operation_id = "create_sealed_secret_version",
    tag = "secrets",
    summary = "Write a sealed secret version (ciphertext and wrapped key; the server never sees the value)",
    params(("project_id" = Uuid, Path, description = "Project id"), ("environment_id" = Uuid, Path, description = "Environment id"), ("secret_id" = Uuid, Path, description = "Secret id")),
    request_body = NewSealedSecretVersion,
    responses(
        (status = 201, description = "Created; version metadata only", body = SecretVersion, headers(("Location" = String, description = "URL of the secret's versions"))),
        SealedVersionWriteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn create_sealed(
    State(_state): State<AppState>,
    _org: OrgBinding,
    ApiPath((_project_id, _environment_id, _secret_id)): ApiPath<(Uuid, Uuid, Uuid)>,
    ApiJson(_input): ApiJson<NewSealedSecretVersion>,
) -> Result<axum::response::Response, ApiError> {
    Err(ApiError::new(
        Kind::Unavailable,
        "sealed secret writes are not available yet",
    ))
}
