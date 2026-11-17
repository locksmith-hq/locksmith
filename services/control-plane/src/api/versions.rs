//! Write-only secret versions (S2 design decisions 5 and 6).
//!
//! `POST .../secrets/{secret_id}/versions` takes a value straight into [`SecretBytes`], seals it
//! under a fresh DEK ([`ls_envelope::seal_version`]), wraps the DEK with the gateway's KMS key
//! (the control plane's credential can only wrap), stores ciphertext and wrapped DEK, and drops
//! (zeroizes) the plaintext and DEK before answering. Responses carry version metadata only:
//! no value, DEK, ciphertext or wrapped DEK is ever returned or logged.

use axum::Json;
use axum::extract::State;
use axum::response::Response;
use ls_envelope::{Binding, Purpose, SecretBytes, WrapError, seal_version};
use serde::Serialize;
use serde::de::{self, Deserialize, Deserializer, Visitor};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::extract::{ApiPath, SecretJson};
use super::responses::{ReadErrors, VersionWriteErrors};
use super::{created, exists_or_404, utc};
use crate::app::AppState;
use crate::auth::OrgBinding;
use crate::db::sql::{self, PgConnection, Row};
use crate::kms::DekWrapper;
use crate::problem::{ApiError, Kind};

/// Metadata of one stored version. Never carries the value or any key material.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecretVersion {
    pub secret_id: Uuid,
    /// 1 for the first version, then 2, 3, ...
    pub version: u32,
    /// The KMS key the version's data key is wrapped under, e.g. `gateway:v1`.
    pub key_id: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
}

/// All versions of a secret, oldest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecretVersionList {
    pub items: Vec<SecretVersion>,
}

/// Request body of a version write.
// No `Debug`, `Clone` or `Serialize`: it owns the value.
#[derive(serde::Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewSecretVersion {
    /// The secret value (UTF-8). Write-only: no endpoint ever returns it.
    #[schema(value_type = String, format = Password, write_only)]
    pub value: SecretValue,
}

/// A value read from the request body directly into [`SecretBytes`] (zeroized on drop). No
/// `Debug`, `Display`, `Clone` or `Serialize`.
pub struct SecretValue(SecretBytes);

impl SecretValue {
    fn into_inner(self) -> SecretBytes {
        self.0
    }
}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = SecretValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<SecretValue, E> {
                Ok(SecretValue(SecretBytes::new(s.as_bytes().to_vec())))
            }
            // Takes ownership without another copy.
            fn visit_string<E: de::Error>(self, s: String) -> Result<SecretValue, E> {
                Ok(SecretValue(SecretBytes::new(s.into_bytes())))
            }
        }
        d.deserialize_string(V)
    }
}

fn from_row(secret_id: Uuid, r: &sql::PgRow) -> sql::Result<SecretVersion> {
    let version: i32 = r.try_get("version")?;
    Ok(SecretVersion {
        secret_id,
        version: u32::try_from(version).unwrap_or_default(),
        key_id: r.try_get("key_id")?,
        created_at: utc(r, "created_at")?,
    })
}

/// `404` unless the secret exists under the project and environment for the bound org. With
/// `lock`, the secret row is locked until the transaction ends, so concurrent writes to one
/// secret get consecutive version numbers.
async fn require_secret(
    c: &mut PgConnection,
    project_id: Uuid,
    environment_id: Uuid,
    secret_id: Uuid,
    lock: bool,
) -> Result<(), ApiError> {
    let q = if lock {
        "SELECT 1 FROM secrets WHERE id = $1 AND project_id = $2 AND environment_id = $3 FOR UPDATE"
    } else {
        "SELECT 1 FROM secrets WHERE id = $1 AND project_id = $2 AND environment_id = $3"
    };
    exists_or_404(
        c,
        sql::query_scalar(q)
            .bind(secret_id)
            .bind(project_id)
            .bind(environment_id),
    )
    .await
}

/// Seal `value` for (org, secret, version) and wrap its DEK. The DEK is dropped (zeroized)
/// before this returns; the caller drops the value.
async fn seal_and_wrap(
    kms: &dyn DekWrapper,
    org_id: Uuid,
    secret_id: Uuid,
    version: u32,
    value: &SecretBytes,
) -> Result<(Vec<u8>, Vec<u8>, String), ApiError> {
    let payload = Binding {
        org_id: *org_id.as_bytes(),
        secret_id: *secret_id.as_bytes(),
        version,
        purpose: Purpose::SecretPayload,
    };
    let sealed = seal_version(&payload, value).map_err(|e| {
        tracing::error!(error = %e, "sealing a secret version failed");
        ApiError::bare(Kind::Internal)
    })?;
    let (ciphertext, dek) = sealed.into_parts();
    let wrap_binding = Binding {
        purpose: Purpose::DekWrap,
        ..payload
    };
    let wrapped = kms.wrap(&dek, &wrap_binding).await;
    drop(dek);
    let wrapped = wrapped.map_err(kms_error)?;
    let key_id = wrapped.key_id().to_string();
    Ok((ciphertext, wrapped.into_bytes(), key_id))
}

/// A KMS failure as a problem. `WrapError` carries no token, DEK or response body.
fn kms_error(e: WrapError) -> ApiError {
    match e {
        WrapError::Transport(_) => {
            tracing::warn!(error = %e, "KMS unavailable while wrapping a DEK");
            ApiError::new(Kind::Unavailable, "the key service is unavailable")
        }
        _ => {
            tracing::error!(error = %e, "KMS refused to wrap a DEK");
            ApiError::bare(Kind::Internal)
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/projects/{project_id}/environments/{environment_id}/secrets/{secret_id}/versions",
    tag = "secrets",
    summary = "Write a new secret version (the value is encrypted and never returned)",
    params(("project_id" = Uuid, Path, description = "Project id"), ("environment_id" = Uuid, Path, description = "Environment id"), ("secret_id" = Uuid, Path, description = "Secret id")),
    request_body = NewSecretVersion,
    responses(
        (status = 201, description = "Created; version metadata only", body = SecretVersion, headers(("Location" = String, description = "URL of the secret's versions"))),
        VersionWriteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn create(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath((project_id, environment_id, secret_id)): ApiPath<(Uuid, Uuid, Uuid)>,
    SecretJson(input): SecretJson<NewSecretVersion>,
) -> Result<Response, ApiError> {
    let value = input.value.into_inner();
    if value.expose().is_empty() {
        return Err(ApiError::validation("`value` must not be empty"));
    }
    let Some(kms) = state.kms().cloned() else {
        return Err(ApiError::new(
            Kind::Unavailable,
            "secret version storage is not configured (no key service)",
        ));
    };
    let org_id = org.org_id;
    let version = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                require_secret(c, project_id, environment_id, secret_id, true).await?;
                let next: i32 = sql::query_scalar(
                    "SELECT COALESCE(max(version), 0) + 1 FROM secret_versions \
                     WHERE org_id = $1 AND secret_id = $2",
                )
                .bind(org_id)
                .bind(secret_id)
                .fetch_one(&mut *c)
                .await?;
                let number = u32::try_from(next).map_err(|_| ApiError::bare(Kind::Internal))?;
                let sealed = seal_and_wrap(kms.as_ref(), org_id, secret_id, number, &value).await;
                drop(value);
                let (ciphertext, wrapped_dek, key_id) = sealed?;
                let row = sql::query(
                    "INSERT INTO secret_versions \
                     (org_id, secret_id, version, ciphertext, wrapped_dek, key_id) \
                     VALUES ($1, $2, $3, $4, $5, $6) RETURNING version, key_id, created_at",
                )
                .bind(org_id)
                .bind(secret_id)
                .bind(next)
                .bind(ciphertext)
                .bind(wrapped_dek)
                .bind(key_id)
                .fetch_one(&mut *c)
                .await?;
                Ok::<_, ApiError>(from_row(secret_id, &row)?)
            })
        })
        .await?;
    tracing::info!(
        secret.id = %secret_id,
        secret.version = version.version,
        "secret version stored"
    );
    Ok(created(
        format!(
            "/v1/projects/{project_id}/environments/{environment_id}/secrets/{secret_id}/versions"
        ),
        version,
    ))
}

#[utoipa::path(
    get,
    path = "/v1/projects/{project_id}/environments/{environment_id}/secrets/{secret_id}/versions",
    tag = "secrets",
    summary = "List secret versions (metadata only, never a value)",
    params(("project_id" = Uuid, Path, description = "Project id"), ("environment_id" = Uuid, Path, description = "Environment id"), ("secret_id" = Uuid, Path, description = "Secret id")),
    responses(
        (status = 200, description = "Every version, oldest first", body = SecretVersionList),
        ReadErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath((project_id, environment_id, secret_id)): ApiPath<(Uuid, Uuid, Uuid)>,
) -> Result<Json<SecretVersionList>, ApiError> {
    let items = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                require_secret(c, project_id, environment_id, secret_id, false).await?;
                let rows = sql::query(
                    "SELECT version, key_id, created_at \
                     FROM secret_versions WHERE secret_id = $1 ORDER BY version",
                )
                .bind(secret_id)
                .fetch_all(c)
                .await?;
                rows.iter()
                    .map(|r| from_row(secret_id, r))
                    .collect::<sql::Result<Vec<_>>>()
                    .map_err(ApiError::from)
            })
        })
        .await?;
    Ok(Json(SecretVersionList { items }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::marker::PhantomData;

    /// Compile-time trait probe: the inherent const applies only when `T` has the trait,
    /// otherwise the blanket trait const (false) is used.
    struct Probe<T>(PhantomData<T>);
    trait Fallback {
        const DEBUG: bool = false;
        const CLONE: bool = false;
        const SERIALIZE: bool = false;
    }
    impl<T> Fallback for Probe<T> {}
    #[allow(dead_code)]
    impl<T: std::fmt::Debug> Probe<T> {
        const DEBUG: bool = true;
    }
    struct ProbeClone<T>(PhantomData<T>);
    impl<T> Fallback for ProbeClone<T> {}
    #[allow(dead_code)]
    impl<T: Clone> ProbeClone<T> {
        const CLONE: bool = true;
    }
    struct ProbeSer<T>(PhantomData<T>);
    impl<T> Fallback for ProbeSer<T> {}
    #[allow(dead_code)]
    impl<T: Serialize> ProbeSer<T> {
        const SERIALIZE: bool = true;
    }

    /// Task 3.3: the value-carrying types cannot be formatted, cloned or serialized.
    #[test]
    fn value_types_have_no_debug_clone_or_serialize() {
        const { assert!(!Probe::<NewSecretVersion>::DEBUG) };
        const { assert!(!Probe::<SecretValue>::DEBUG) };
        const { assert!(!ProbeClone::<NewSecretVersion>::CLONE) };
        const { assert!(!ProbeClone::<SecretValue>::CLONE) };
        const { assert!(!ProbeSer::<NewSecretVersion>::SERIALIZE) };
        const { assert!(!ProbeSer::<SecretValue>::SERIALIZE) };
        // The probe itself works: response metadata does derive Debug and Serialize.
        const { assert!(Probe::<SecretVersion>::DEBUG) };
        const { assert!(ProbeSer::<SecretVersion>::SERIALIZE) };
    }

    #[test]
    fn value_deserializes_into_secret_bytes() {
        let v: NewSecretVersion = serde_json::from_str(r#"{"value":"a\"b"}"#).unwrap();
        assert!(v.value.into_inner().expose() == b"a\"b");
        let v: NewSecretVersion = serde_json::from_str(r#"{"value":"plain"}"#).unwrap();
        assert!(v.value.into_inner().expose() == b"plain");
        assert!(serde_json::from_str::<NewSecretVersion>(r#"{"value":1}"#).is_err());
    }
}
