//! Argon2id verifiers for server-issued bearer secrets (S4: agent enrollment secrets).
//!
//! The server stores only the PHC string (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`); the
//! secret itself is shown once and never stored. The secrets hashed here are 256-bit random
//! values, not passwords, so the cost follows the OWASP Password Storage Cheat Sheet's first
//! Argon2id option (m=19 MiB, t=2, p=1) rather than the vault's passphrase floor
//! ([`crate::kdf::KdfParams::MINIMUM`]): an unauthenticated exchange endpoint runs it per call.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

use crate::CryptoError;
use crate::kdf::{ARGON2_ALG, ARGON2_VERSION, KdfParams};

/// Cost of a bearer-secret verifier (OWASP: Argon2id, m=19456 KiB, t=2, p=1).
pub const BEARER_PARAMS: KdfParams = KdfParams {
    m_kib: 19 * 1024,
    t: 2,
    p: 1,
};

fn hasher(params: KdfParams) -> Result<argon2::Argon2<'static>, CryptoError> {
    let p = argon2::Params::new(params.m_kib, params.t, params.p, None)
        .map_err(|e| CryptoError::Params(e.to_string()))?;
    Ok(argon2::Argon2::new(ARGON2_ALG, ARGON2_VERSION, p))
}

/// Hash `secret` with Argon2id ([`BEARER_PARAMS`], fresh 16-byte random salt) into a PHC
/// string. The string holds no part of the secret.
pub fn hash_bearer_secret(secret: &[u8]) -> Result<String, CryptoError> {
    let salt = crate::random_bytes::<16>()?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| CryptoError::Params(e.to_string()))?;
    let hash = hasher(BEARER_PARAMS)?
        .hash_password(secret, &salt)
        .map_err(|e| CryptoError::Params(e.to_string()))?;
    Ok(hash.to_string())
}

/// True when `secret` matches the Argon2id PHC string `phc`. The comparison of the derived
/// output is constant time (`password-hash`). Anything that is not an Argon2id v19 PHC string,
/// or uses parameters below [`BEARER_PARAMS`], is a mismatch rather than an error.
pub fn verify_bearer_secret(secret: &[u8], phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    if parsed.algorithm != argon2::ARGON2ID_IDENT || parsed.version != Some(0x13) {
        return false;
    }
    let Ok(params) = argon2::Params::try_from(&parsed) else {
        return false;
    };
    if params.m_cost() < BEARER_PARAMS.m_kib
        || params.t_cost() < BEARER_PARAMS.t
        || params.p_cost() < BEARER_PARAMS.p
    {
        return false;
    }
    let argon = argon2::Argon2::new(ARGON2_ALG, ARGON2_VERSION, params);
    argon.verify_password(secret, &parsed).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_verifies_only_the_same_secret() {
        let phc = hash_bearer_secret(b"enrollment-secret-hunter6").unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
        assert!(!phc.contains("hunter6"));
        assert!(verify_bearer_secret(b"enrollment-secret-hunter6", &phc));
        assert!(!verify_bearer_secret(b"enrollment-secret-hunter7", &phc));
        assert!(!verify_bearer_secret(b"", &phc));
    }

    #[test]
    fn salts_differ_per_hash() {
        let a = hash_bearer_secret(b"same").unwrap();
        let b = hash_bearer_secret(b"same").unwrap();
        assert_ne!(a, b);
        assert!(verify_bearer_secret(b"same", &a) && verify_bearer_secret(b"same", &b));
    }

    #[test]
    fn other_algorithms_weak_params_and_garbage_do_not_verify() {
        assert!(!verify_bearer_secret(b"x", ""));
        assert!(!verify_bearer_secret(b"x", "not a phc string"));
        // The same secret hashed with argon2i, and with argon2id below the cost floor.
        let salt = SaltString::encode_b64(&[7u8; 16]).unwrap();
        let argon2i = argon2::Argon2::new(
            argon2::Algorithm::Argon2i,
            ARGON2_VERSION,
            argon2::Params::new(BEARER_PARAMS.m_kib, 2, 1, None).unwrap(),
        )
        .hash_password(b"x", &salt)
        .unwrap()
        .to_string();
        assert!(!verify_bearer_secret(b"x", &argon2i));
        let weak = hasher(KdfParams {
            m_kib: 1024,
            t: 1,
            p: 1,
        })
        .unwrap()
        .hash_password(b"x", &salt)
        .unwrap()
        .to_string();
        assert!(!verify_bearer_secret(b"x", &weak));
    }
}
