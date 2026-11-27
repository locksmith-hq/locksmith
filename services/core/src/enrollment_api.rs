//! `POST /v1/enrollment-secrets/generate` and `/verify` (lead ruling B1-5): agent enrollment
//! secrets, moved from the control plane (`services/control-plane/src/enrollment.rs`) so the
//! NestJS API never runs Argon2id or builds a secret itself.
//!
//! The types below are copied from the control plane unchanged in behaviour (format, hash,
//! parse, verify and the dummy-hash path). The core stores nothing: `generate` hands the caller
//! the secret text to show once plus the PHC hash to store, and `verify` checks a presented
//! secret against the hash the caller looked up (or `null` for an unknown agent, which spends
//! the same Argon2id work against a dummy hash). Verify never echoes the secret. Secrets are
//! never logged or recorded on spans, and every response is `no-store`. A secret that does not
//! verify is a 200 with `valid: false` and a coarse reason, never an error.

use std::sync::OnceLock;

use axum::Json;
use axum::body::Bytes;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::{HeaderValue, StatusCode, header};
use secrecy::{ExposeSecret, SecretString};
use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::{Serialize, Serializer};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit_api::problem;

// ---- Copied from services/control-plane/src/enrollment.rs (keep the two in step). ----------
//
// Format: `lse_` + base64url (no padding) of `org_id(16) || agent_id(16) || random(32)`. The
// ids are routing data, not secret: they let the caller find the agent's row under row-level
// security without a second credential. The hash covers all 64 bytes, so the ids cannot be
// swapped. The 256 random bits are what make the secret unguessable.

pub const PREFIX: &str = "lse_";
const RANDOM_BYTES: usize = 32;
const RAW_BYTES: usize = 16 + 16 + RANDOM_BYTES;

/// Why a secret could not be made or hashed. No secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollmentError;

/// A freshly generated enrollment secret, to be shown once. No `Debug`, `Display` or `Clone`.
///
/// It is `Serialize` only so that the one generate response can carry it; nothing else holds
/// one.
pub struct EnrollmentSecret(SecretString);

impl EnrollmentSecret {
    /// A new secret for `agent_id` in `org_id`, and the Argon2id PHC hash to store. CPU-heavy
    /// (Argon2id): call from a blocking task.
    pub fn generate(org_id: Uuid, agent_id: Uuid) -> Result<(Self, String), EnrollmentError> {
        let random = ls_crypto::SecretKey32::random().map_err(|_| EnrollmentError)?;
        let mut raw = Zeroizing::new(Vec::with_capacity(RAW_BYTES));
        raw.extend_from_slice(org_id.as_bytes());
        raw.extend_from_slice(agent_id.as_bytes());
        raw.extend_from_slice(random.expose());
        let hash = ls_crypto::verifier::hash_bearer_secret(&raw).map_err(|_| EnrollmentError)?;
        let mut text = String::with_capacity(PREFIX.len() + 86);
        text.push_str(PREFIX);
        URL_SAFE_NO_PAD.encode_string(raw.as_slice(), &mut text);
        Ok((Self(SecretString::from(text)), hash))
    }

    /// The secret text (for tests that exchange it).
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl Serialize for EnrollmentSecret {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.0.expose_secret())
    }
}

/// A presented enrollment secret, parsed. No `Debug`, `Display` or `Clone`.
pub struct PresentedSecret {
    pub org_id: Uuid,
    pub agent_id: Uuid,
    raw: Zeroizing<Vec<u8>>,
}

impl PresentedSecret {
    /// Parse `text`; `None` for anything that is not a well-formed enrollment secret.
    pub fn parse(text: &str) -> Option<Self> {
        let body = text.trim().strip_prefix(PREFIX)?;
        let raw = Zeroizing::new(URL_SAFE_NO_PAD.decode(body).ok()?);
        if raw.len() != RAW_BYTES {
            return None;
        }
        let org_id = Uuid::from_slice(&raw[..16]).ok()?;
        let agent_id = Uuid::from_slice(&raw[16..32]).ok()?;
        Some(Self {
            org_id,
            agent_id,
            raw,
        })
    }

    /// True when this secret matches `phc`. CPU-heavy (Argon2id): call from a blocking task.
    pub fn verify(&self, phc: &str) -> bool {
        ls_crypto::verifier::verify_bearer_secret(&self.raw, phc)
    }

    /// Spend the same Argon2id work as [`Self::verify`] against a hash nothing matches, so an
    /// unknown agent takes as long to refuse as a wrong secret.
    pub fn verify_against_dummy(&self) {
        static DUMMY: OnceLock<Option<String>> = OnceLock::new();
        let dummy = DUMMY.get_or_init(|| {
            ls_crypto::verifier::hash_bearer_secret(b"locksmith-enrollment-dummy").ok()
        });
        if let Some(phc) = dummy {
            let _ = ls_crypto::verifier::verify_bearer_secret(&self.raw, phc);
        }
    }
}

/// The request field that carries an enrollment secret: read straight into a `SecretString`.
/// No `Debug`, `Display`, `Clone` or `Serialize`.
pub struct EnrollmentInput(SecretString);

impl EnrollmentInput {
    pub fn parse(&self) -> Option<PresentedSecret> {
        PresentedSecret::parse(self.0.expose_secret())
    }
}

impl<'de> Deserialize<'de> for EnrollmentInput {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = EnrollmentInput;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<EnrollmentInput, E> {
                Ok(EnrollmentInput(SecretString::from(s)))
            }
            fn visit_string<E: de::Error>(self, s: String) -> Result<EnrollmentInput, E> {
                Ok(EnrollmentInput(SecretString::from(s)))
            }
        }
        d.deserialize_string(V)
    }
}

// ---- HTTP operations. -----------------------------------------------------------------------

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerateRequest {
    org_id: Uuid,
    agent_id: Uuid,
}

/// No `Debug`: it carries the secret, shown once.
#[derive(Serialize)]
struct GenerateResponse {
    enrollment_secret: EnrollmentSecret,
    enrollment_hash: String,
}

/// No `Debug`: it carries the presented secret.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyRequest {
    enrollment_secret: EnrollmentInput,
    /// The stored PHC hash, or `null` when the caller found no agent. Required (not defaulted),
    /// so a caller cannot skip the lookup by leaving it out.
    #[serde(deserialize_with = "Option::deserialize")]
    enrollment_hash: Option<String>,
}

#[derive(Serialize)]
struct Verdict {
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

fn no_store(body: impl Serialize) -> Response {
    (
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(body),
    )
        .into_response()
}

fn unavailable() -> Response {
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "enrollment secret hashing unavailable",
    )
}

/// A new secret for `agent_id` in `org_id` and the hash to store; Argon2id on a blocking thread.
pub async fn generate(body: Bytes) -> Response {
    let Ok(req) = serde_json::from_slice::<GenerateRequest>(&body) else {
        return problem(StatusCode::BAD_REQUEST, "malformed request");
    };
    let (org_id, agent_id) = (req.org_id, req.agent_id);
    match tokio::task::spawn_blocking(move || EnrollmentSecret::generate(org_id, agent_id)).await {
        Ok(Ok((secret, hash))) => no_store(GenerateResponse {
            enrollment_secret: secret,
            enrollment_hash: hash,
        }),
        Ok(Err(EnrollmentError)) | Err(_) => unavailable(),
    }
}

/// Check a presented secret against the caller's stored hash (or the dummy hash for an unknown
/// agent), exactly as the control plane's token exchange does.
pub async fn verify(body: Bytes) -> Response {
    let Ok(req) = serde_json::from_slice::<VerifyRequest>(&body) else {
        return problem(StatusCode::BAD_REQUEST, "malformed request");
    };
    let VerifyRequest {
        enrollment_secret,
        enrollment_hash,
    } = req;
    let Some(presented) = enrollment_secret.parse() else {
        return no_store(Verdict {
            valid: false,
            org_id: None,
            agent_id: None,
            reason: Some("malformed"),
        });
    };
    drop(enrollment_secret);
    let (org_id, agent_id) = (presented.org_id, presented.agent_id);
    let found = enrollment_hash.is_some();
    let verified = tokio::task::spawn_blocking(move || match enrollment_hash {
        Some(phc) => presented.verify(&phc),
        None => {
            presented.verify_against_dummy();
            false
        }
    })
    .await;
    let Ok(verified) = verified else {
        return unavailable();
    };
    no_store(Verdict {
        valid: verified,
        org_id: Some(org_id),
        agent_id: Some(agent_id),
        reason: match (found, verified) {
            (_, true) => None,
            (true, false) => Some("wrong_secret"),
            (false, false) => Some("unknown_agent"),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_parses_back_to_its_ids_and_verifies() {
        let (org, agent) = (Uuid::now_v7(), Uuid::now_v7());
        let (secret, phc) = EnrollmentSecret::generate(org, agent).unwrap();
        assert!(secret.expose().starts_with(PREFIX));
        assert_eq!(secret.expose().len(), PREFIX.len() + 86);
        assert!(phc.starts_with("$argon2id$"));
        assert!(!phc.contains(&secret.expose()[PREFIX.len()..]));
        let p = PresentedSecret::parse(secret.expose()).unwrap();
        assert_eq!((p.org_id, p.agent_id), (org, agent));
        assert!(p.verify(&phc));

        // Swapping the agent id (keeping the random part) no longer verifies.
        let mut raw = URL_SAFE_NO_PAD
            .decode(&secret.expose()[PREFIX.len()..])
            .unwrap();
        raw[16..32].copy_from_slice(Uuid::now_v7().as_bytes());
        let swapped = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(&raw));
        assert!(!PresentedSecret::parse(&swapped).unwrap().verify(&phc));
    }

    #[test]
    fn malformed_secrets_do_not_parse() {
        for bad in [
            "",
            "lse_",
            "lse_!!!",
            "lsx_AAAA",
            &format!("lse_{}", URL_SAFE_NO_PAD.encode([0u8; 63])),
        ] {
            assert!(PresentedSecret::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn serializes_as_the_plain_string_only() {
        let (secret, _) = EnrollmentSecret::generate(Uuid::now_v7(), Uuid::now_v7()).unwrap();
        let json = serde_json::to_string(&secret).unwrap();
        assert_eq!(json, format!("\"{}\"", secret.expose()));
    }
}
