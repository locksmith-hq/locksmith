//! Agent tokens (S4 design decision 1): short-lived EdDSA JWTs (RFC 7519, RFC 8037) that the
//! control plane mints for a registered agent and the gateway verifies through the published
//! JWKS.
//!
//! A token carries only the agent id (`sub`), the org id (`org`), the audience (`aud`, always
//! [`AUDIENCE`]) and its issue and expiry times. It never carries a secret, a grant or a name.
//! Honest label: containment, not prevention. A stolen token works until it expires
//! ([`DEFAULT_TTL`]); grants are checked on every relay call, so revoking a grant stops it
//! sooner.
//!
//! The signing key is an Ed25519 seed held only by the control plane. [`AgentTokenSigner`] has
//! no `Debug`, `Display` or `Clone`; the key lives in a zeroize-on-drop `EncodingKey` and the
//! seed bytes are wiped once it is built. The key id is the RFC 7638 JWK thumbprint of the
//! public key, so rotating the key changes the `kid` without any configuration.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The only audience agent tokens are minted for.
pub const AUDIENCE: &str = "gateway";
/// Lifetime of a minted token (S4 design decision 1).
pub const DEFAULT_TTL: Duration = Duration::from_secs(15 * 60);
/// Clock skew a verifier tolerates on `exp`.
pub const LEEWAY_SECS: u64 = 30;

/// The claims of an agent token. Ids and times only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentClaims {
    /// The agent id.
    pub sub: Uuid,
    /// The agent's org id.
    pub org: Uuid,
    /// Always [`AUDIENCE`].
    pub aud: String,
    /// Issued at (seconds since the Unix epoch).
    pub iat: i64,
    /// Expiry (seconds since the Unix epoch).
    pub exp: i64,
}

/// The validation every verifier of agent tokens must use: EdDSA only (no algorithm
/// negotiation), audience [`AUDIENCE`], `exp`, `aud` and `sub` required, `exp` enforced with
/// [`LEEWAY_SECS`] of skew.
pub fn validation() -> Validation {
    let mut v = Validation::new(Algorithm::EdDSA);
    v.set_audience(&[AUDIENCE]);
    v.set_required_spec_claims(&["exp", "aud", "sub"]);
    v.leeway = LEEWAY_SECS;
    v.validate_exp = true;
    v
}

/// Why a token was refused. Carries no token text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    Expired,
    WrongAudience,
    BadSignature,
    Malformed,
}

/// Verify `token` against one public key with [`validation`]. The gateway picks the key by the
/// header `kid` from the JWKS; this checks signature, algorithm, audience and expiry.
pub fn verify(token: &str, key: &DecodingKey) -> Result<AgentClaims, VerifyError> {
    use jsonwebtoken::errors::ErrorKind;
    jsonwebtoken::decode::<AgentClaims>(token, key, &validation())
        .map(|d| d.claims)
        .map_err(|e| match e.kind() {
            ErrorKind::ExpiredSignature => VerifyError::Expired,
            ErrorKind::InvalidAudience => VerifyError::WrongAudience,
            ErrorKind::InvalidSignature | ErrorKind::InvalidAlgorithm => VerifyError::BadSignature,
            _ => VerifyError::Malformed,
        })
}

/// One public key in the JWKS (RFC 7517, RFC 8037 `OKP`/`Ed25519`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Jwk {
    /// Always `OKP`.
    pub kty: String,
    /// Always `Ed25519`.
    pub crv: String,
    /// The public key, base64url without padding.
    pub x: String,
    /// Key id: the RFC 7638 SHA-256 thumbprint of this key.
    pub kid: String,
    /// Always `EdDSA`.
    pub alg: String,
    /// Always `sig`.
    #[serde(rename = "use")]
    pub use_: String,
}

impl Jwk {
    /// A verifying key for [`verify`]. Errors when `x` is not a 32-byte base64url value.
    pub fn decoding_key(&self) -> Option<DecodingKey> {
        let x = URL_SAFE_NO_PAD.decode(&self.x).ok()?;
        (self.kty == "OKP" && self.crv == "Ed25519" && x.len() == 32)
            .then(|| DecodingKey::from_ed_der(&x))
    }
}

/// The JWK set published at `/.well-known/jwks.json`. Public keys only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// Why a signing key could not be built. Never carries key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerError {
    /// The seed is not 32 bytes of standard or URL-safe base64.
    InvalidSeed,
    /// The OS random source failed.
    Rng,
    /// The key could not be encoded or used.
    Key,
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidSeed => "agent signing key must be 32 bytes, base64-encoded",
            Self::Rng => "system random number generator failed",
            Self::Key => "agent signing key could not be used",
        })
    }
}

impl std::error::Error for SignerError {}

/// A token minted for an agent. No `Debug` or `Clone`: the token is a bearer credential.
pub struct MintedToken {
    pub token: String,
    pub expires_at: OffsetDateTime,
    pub ttl: Duration,
}

/// The control plane's agent-token signing key. No `Debug`, `Display` or `Clone`.
pub struct AgentTokenSigner {
    key: EncodingKey,
    jwk: Jwk,
    ttl: Duration,
}

impl AgentTokenSigner {
    /// Build from a 32-byte Ed25519 seed. The seed is wiped when this returns.
    pub fn from_seed(seed: Zeroizing<[u8; 32]>) -> Result<Self, SignerError> {
        let signing = SigningKey::from_bytes(&seed);
        drop(seed);
        let der = signing.to_pkcs8_der().map_err(|_| SignerError::Key)?;
        let key = EncodingKey::from_ed_der(der.as_bytes());
        // `der` is a zeroizing SecretDocument; `signing` zeroizes on drop.
        let public = signing.verifying_key().to_bytes();
        let x = URL_SAFE_NO_PAD.encode(public);
        Ok(Self {
            key,
            jwk: Jwk {
                kty: "OKP".to_owned(),
                crv: "Ed25519".to_owned(),
                kid: thumbprint(&x),
                x,
                alg: "EdDSA".to_owned(),
                use_: "sig".to_owned(),
            },
            ttl: DEFAULT_TTL,
        })
    }

    /// Build from a base64 (standard or URL-safe, padding optional) 32-byte seed, as given in
    /// `LOCKSMITH_AGENT_SIGNING_KEY`.
    pub fn from_base64_seed(encoded: &str) -> Result<Self, SignerError> {
        let trimmed = encoded.trim().trim_end_matches('=');
        let decoded = Zeroizing::new(
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(trimmed)
                .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
                .map_err(|_| SignerError::InvalidSeed)?,
        );
        let mut seed = Zeroizing::new([0u8; 32]);
        if decoded.len() != seed.len() {
            return Err(SignerError::InvalidSeed);
        }
        seed.copy_from_slice(&decoded);
        Self::from_seed(seed)
    }

    /// A fresh random key (dev only: tokens stop verifying when the process restarts).
    pub fn generate() -> Result<Self, SignerError> {
        let key = ls_crypto::SecretKey32::random().map_err(|_| SignerError::Rng)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(key.expose());
        Self::from_seed(seed)
    }

    /// Use `ttl` instead of [`DEFAULT_TTL`] (tests).
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// The public key, for the JWKS.
    pub fn jwk(&self) -> &Jwk {
        &self.jwk
    }

    /// Sign `claims` as-is (tests use this to build expired or wrong-audience tokens).
    pub fn sign(&self, claims: &AgentClaims) -> Result<String, SignerError> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.jwk.kid.clone());
        jsonwebtoken::encode(&header, claims, &self.key).map_err(|_| SignerError::Key)
    }

    /// Mint a token for `agent_id` in `org_id`, valid from `now` for the configured TTL.
    pub fn mint(
        &self,
        agent_id: Uuid,
        org_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<MintedToken, SignerError> {
        let iat = now.unix_timestamp();
        let ttl_secs = i64::try_from(self.ttl.as_secs()).map_err(|_| SignerError::Key)?;
        let exp = iat + ttl_secs;
        let token = self.sign(&AgentClaims {
            sub: agent_id,
            org: org_id,
            aud: AUDIENCE.to_owned(),
            iat,
            exp,
        })?;
        let expires_at = OffsetDateTime::from_unix_timestamp(exp).map_err(|_| SignerError::Key)?;
        Ok(MintedToken {
            token,
            expires_at,
            ttl: self.ttl,
        })
    }
}

/// RFC 7638 thumbprint of an Ed25519 JWK: SHA-256 over the required members in lexicographic
/// order, base64url without padding.
fn thumbprint(x: &str) -> String {
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> AgentTokenSigner {
        AgentTokenSigner::from_seed(Zeroizing::new([9u8; 32])).unwrap()
    }

    #[test]
    fn rfc8037_appendix_a_key_and_thumbprint() {
        // RFC 8037 A.1-A.3: seed, public key `x`, and the RFC 7638 thumbprint.
        let seed = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
        let s = AgentTokenSigner::from_base64_seed(seed).unwrap();
        assert_eq!(s.jwk().x, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        assert_eq!(s.jwk().kid, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
        assert_eq!(
            (s.jwk().kty.as_str(), s.jwk().crv.as_str()),
            ("OKP", "Ed25519")
        );
    }

    #[test]
    fn seed_must_be_32_bytes_of_base64() {
        for bad in ["", "not base64!", "AAAA", &"A".repeat(60)] {
            assert_eq!(
                AgentTokenSigner::from_base64_seed(bad).err(),
                Some(SignerError::InvalidSeed)
            );
        }
        // Standard alphabet with padding works too.
        let std = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        assert!(AgentTokenSigner::from_base64_seed(&std).is_ok());
    }

    #[test]
    fn minted_token_verifies_with_the_published_key_and_carries_only_ids() {
        let s = signer();
        let (agent, org) = (Uuid::now_v7(), Uuid::now_v7());
        let now = OffsetDateTime::now_utc();
        let minted = s.mint(agent, org, now).unwrap();
        assert_eq!(minted.ttl, DEFAULT_TTL);
        let header = jsonwebtoken::decode_header(&minted.token).unwrap();
        assert_eq!(header.alg, Algorithm::EdDSA);
        assert_eq!(header.kid.as_deref(), Some(s.jwk().kid.as_str()));
        let claims = verify(&minted.token, &s.jwk().decoding_key().unwrap()).unwrap();
        assert_eq!(claims.sub, agent);
        assert_eq!(claims.org, org);
        assert_eq!(claims.aud, AUDIENCE);
        assert_eq!(claims.exp - claims.iat, 900);
        assert_eq!(claims.exp, minted.expires_at.unix_timestamp());
    }

    #[test]
    fn expired_wrong_audience_and_foreign_key_are_refused() {
        let s = signer();
        let key = s.jwk().decoding_key().unwrap();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = |aud: &str, exp: i64| AgentClaims {
            sub: Uuid::now_v7(),
            org: Uuid::now_v7(),
            aud: aud.to_owned(),
            iat: exp - 900,
            exp,
        };
        let expired = s.sign(&claims(AUDIENCE, now - 120)).unwrap();
        assert_eq!(verify(&expired, &key), Err(VerifyError::Expired));
        let wrong_aud = s.sign(&claims("control-plane", now + 600)).unwrap();
        assert_eq!(verify(&wrong_aud, &key), Err(VerifyError::WrongAudience));
        let other = AgentTokenSigner::from_seed(Zeroizing::new([8u8; 32])).unwrap();
        let forged = other.sign(&claims(AUDIENCE, now + 600)).unwrap();
        assert_eq!(verify(&forged, &key), Err(VerifyError::BadSignature));
        assert_eq!(verify("a.b.c", &key), Err(VerifyError::Malformed));
    }

    #[test]
    fn decoding_key_rejects_wrong_shapes() {
        let mut jwk = signer().jwk().clone();
        jwk.x = URL_SAFE_NO_PAD.encode([1u8; 16]);
        assert!(jwk.decoding_key().is_none());
        let mut jwk = signer().jwk().clone();
        jwk.kty = "EC".to_owned();
        assert!(jwk.decoding_key().is_none());
    }
}
