//! Service-to-service routes under `/internal/v1` (S3 design decision 2).
//!
//! The gateway fetches the stored envelope of one secret version here: the A0-7 ciphertext, the
//! KMS-wrapped DEK and the key id. None of it is plaintext, and the control plane cannot unwrap
//! the DEK (its KMS token may only encrypt, S2 decision 4), so this route returns no secret
//! value. It is reachable only with the gateway service token ([`ServiceOrgBinding`]), and the
//! read runs in a tenant transaction for the org the gateway names, so another org's secret is a
//! `404`, the same as one that does not exist.

use axum::Json;
use axum::extract::State;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use super::extract::ApiPath;
use super::one;
use super::responses::InternalReadErrors;
use crate::app::AppState;
use crate::auth::ServiceOrgBinding;
use crate::db::sql::{self, Row};
use crate::problem::ApiError;

/// The stored envelope of one secret version. Ciphertext and a wrapped data key only: never the
/// value, and never an unwrapped key.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecretVersionMaterial {
    pub secret_id: Uuid,
    pub version: u32,
    /// The KMS key the data key is wrapped under, e.g. `gateway:v1`.
    pub key_id: String,
    /// A0-7 ciphertext blob (header, nonce, ciphertext, tag), standard base64 with padding.
    #[schema(content_encoding = "base64")]
    pub ciphertext: String,
    /// A0-7 `dek-wrap` blob (the KMS-wrapped data key), standard base64 with padding.
    #[schema(content_encoding = "base64")]
    pub wrapped_dek: String,
}

#[utoipa::path(
    get,
    path = "/internal/v1/secrets/{secret_id}/versions/{version}/material",
    tag = "internal",
    summary = "Fetch the encrypted material of a secret version (gateway only; no plaintext)",
    params(
        ("secret_id" = Uuid, Path, description = "Secret id"),
        ("version" = u32, Path, description = "Version number, starting at 1", minimum = 1),
        ("X-Locksmith-Org" = Uuid, Header, description = "The org the gateway acts for"),
    ),
    responses(
        (status = 200, description = "Ciphertext, wrapped data key and key id", body = SecretVersionMaterial),
        InternalReadErrors,
    ),
    security(("service_token" = []))
)]
pub async fn material(
    State(state): State<AppState>,
    org: ServiceOrgBinding,
    ApiPath((secret_id, version)): ApiPath<(Uuid, u32)>,
) -> Result<Json<SecretVersionMaterial>, ApiError> {
    // Stored versions are 1..=i32::MAX; anything else cannot exist.
    let stored = i32::try_from(version)
        .ok()
        .filter(|v| *v >= 1)
        .ok_or_else(ApiError::not_found)?;
    let org_id = org.org_id;
    let material = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                // RLS limits the read to the bound org; the explicit org_id is belt and braces.
                let row = sql::query(
                    "SELECT ciphertext, wrapped_dek, key_id FROM secret_versions \
                     WHERE org_id = $1 AND secret_id = $2 AND version = $3",
                )
                .bind(org_id)
                .bind(secret_id)
                .bind(stored)
                .fetch_optional(c)
                .await?;
                one(row, |r| {
                    let ciphertext: Vec<u8> = r.try_get("ciphertext")?;
                    let wrapped_dek: Vec<u8> = r.try_get("wrapped_dek")?;
                    Ok(SecretVersionMaterial {
                        secret_id,
                        version,
                        key_id: r.try_get("key_id")?,
                        ciphertext: STANDARD.encode(ciphertext),
                        wrapped_dek: STANDARD.encode(wrapped_dek),
                    })
                })
            })
        })
        .await?;
    // Ids only: never the material.
    tracing::info!(
        secret.id = %secret_id,
        secret.version = version,
        "secret version material served"
    );
    Ok(Json(material))
}
