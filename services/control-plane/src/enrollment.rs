//! Agent enrollment secrets (S4 design decisions 2 and 3).
//!
//! Registering an agent returns an enrollment secret exactly once; only its Argon2id hash is
//! stored (`agents.enrollment_hash`, via `ls-crypto`). The human or launcher hands it to
//! `smith login --agent`, which exchanges it for short-lived agent tokens. It is not a vault
//! secret and Locksmith never places it in an agent's reach.
//!
//! Format: `lse_` + base64url (no padding) of `org_id(16) || agent_id(16) || random(32)`. The
//! ids are routing data, not secret: they let the token endpoint find the agent's row under
//! row-level security without a second credential. The hash covers all 64 bytes, so the ids
//! cannot be swapped. The 256 random bits are what make the secret unguessable.

use std::sync::OnceLock;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::{ExposeSecret, SecretString};
use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::{Serialize, Serializer};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const PREFIX: &str = "lse_";
const RANDOM_BYTES: usize = 32;
const RAW_BYTES: usize = 16 + 16 + RANDOM_BYTES;

/// Why a secret could not be made or hashed. No secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollmentError;

/// A freshly generated enrollment secret, to be shown once. No `Debug`, `Display` or `Clone`.
///
/// It is `Serialize` only so that the one registration (or rotation) response can carry it;
/// nothing else holds one.
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
