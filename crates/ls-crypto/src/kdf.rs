//! Argon2id passphrase derivation and HKDF-SHA256 domain-separated expansion.

use crate::{CryptoError, SecretKey32};
use serde::{Deserialize, Serialize};

pub const ARGON2_ALG: argon2::Algorithm = argon2::Algorithm::Argon2id;
pub const ARGON2_VERSION: argon2::Version = argon2::Version::V0x13;

/// HKDF info labels. Changing any of these breaks every existing vault.
pub mod label {
    pub const PASSPHRASE_WRAP: &str = "locksmith-v6-passphrase-wrap";
    pub const RECOVERY_WRAP: &str = "locksmith-v6-recovery-wrap";
    pub const AUDIT_ROOT: &str = "locksmith-v6-audit-root";
    pub const SQLCIPHER: &str = "locksmith-v6-sqlcipher";
    pub const HEADER_MAC: &str = "locksmith-v6-header-mac";
}

/// Argon2id cost, stored next to each passphrase wrap so it can be raised later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// The floor from spec vault-crypto "Memory-hard passphrase derivation".
    pub const MINIMUM: KdfParams = KdfParams {
        m_kib: 64 * 1024,
        t: 3,
        p: 4,
    };

    pub fn meets_minimum(&self) -> bool {
        self.m_kib >= Self::MINIMUM.m_kib && self.t >= Self::MINIMUM.t && self.p >= Self::MINIMUM.p
    }
}

/// Derive the 32-byte master key from a passphrase. Refuses parameters below the minimum
/// unless `allow_weak` (tests only — never wire this to user input).
pub fn argon2id(
    passphrase: &[u8],
    salt: &[u8; 32],
    params: KdfParams,
    allow_weak: bool,
) -> Result<SecretKey32, CryptoError> {
    if !allow_weak && !params.meets_minimum() {
        return Err(CryptoError::Params(format!(
            "argon2id below minimum: {params:?}"
        )));
    }
    let p = argon2::Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| CryptoError::Params(e.to_string()))?;
    let mut out = [0u8; 32];
    argon2::Argon2::new(ARGON2_ALG, ARGON2_VERSION, p)
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| CryptoError::Params(e.to_string()))?;
    Ok(SecretKey32::from_bytes(out))
}

/// HKDF-SHA256 with no salt (inputs are already uniformly random keys) and a fixed label.
pub fn hkdf(ikm: &[u8], info: &str) -> SecretKey32 {
    let mut out = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, ikm)
        .expand(info.as_bytes(), &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    SecretKey32::from_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9106 §5.3 Argon2id test vector: proves algorithm and version selection.
    #[test]
    fn argon2id_rfc9106_vector() {
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[0x04; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let a = argon2::Argon2::new_with_secret(&[0x03; 8], ARGON2_ALG, ARGON2_VERSION, params)
            .unwrap();
        let mut out = [0u8; 32];
        a.hash_password_into(&[0x01; 32], &[0x02; 16], &mut out)
            .unwrap();
        assert_eq!(
            hex::encode(out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    /// RFC 5869 test case 3 (no salt, empty info); our 32-byte output is the OKM prefix.
    #[test]
    fn hkdf_rfc5869_case3() {
        let k = hkdf(&[0x0b; 22], "");
        assert_eq!(
            hex::encode(k.expose()),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        );
    }

    #[test]
    fn labels_are_domain_separated() {
        let ikm = [7u8; 32];
        let a = hkdf(&ikm, label::PASSPHRASE_WRAP);
        let b = hkdf(&ikm, label::SQLCIPHER);
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn weak_params_rejected() {
        let weak = KdfParams {
            m_kib: 1024,
            t: 1,
            p: 1,
        };
        assert!(matches!(
            argon2id(b"pw", &[0; 32], weak, false),
            Err(CryptoError::Params(_))
        ));
        assert!(argon2id(b"pw", &[0; 32], weak, true).is_ok());
    }
}
