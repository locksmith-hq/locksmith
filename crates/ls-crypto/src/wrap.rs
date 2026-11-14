//! Vault-key (VK) wraps and data-key (DEK) wraps.

use crate::aead::{self, Aad, Sealed};
use crate::kdf::{self, KdfParams, label};
use crate::recovery::RecoveryPhrase;
use crate::{CryptoError, SecretKey32};

pub const WRAP_PASSPHRASE: &str = "passphrase";
pub const WRAP_RECOVERY: &str = "recovery_phrase";

fn to_key(b: crate::SecretBytes) -> Result<SecretKey32, CryptoError> {
    let arr: [u8; 32] = b.expose().try_into().map_err(|_| CryptoError::Integrity)?;
    Ok(SecretKey32::from_bytes(arr))
}

/// PWK = HKDF(Argon2id(passphrase), "locksmith-v6-passphrase-wrap").
pub fn passphrase_key(
    passphrase: &[u8],
    salt: &[u8; 32],
    params: KdfParams,
    allow_weak: bool,
) -> Result<SecretKey32, CryptoError> {
    let mk = kdf::argon2id(passphrase, salt, params, allow_weak)?;
    Ok(kdf::hkdf(mk.expose(), label::PASSPHRASE_WRAP))
}

pub fn wrap_vk(
    wrapping: &SecretKey32,
    vk: &SecretKey32,
    wrap_type: &str,
    vk_version: u32,
) -> Result<Sealed, CryptoError> {
    aead::seal(wrapping, vk.expose(), &Aad::vk_wrap(wrap_type, vk_version))
}

pub fn unwrap_vk(
    wrapping: &SecretKey32,
    sealed: &Sealed,
    wrap_type: &str,
    vk_version: u32,
) -> Result<SecretKey32, CryptoError> {
    to_key(aead::open(
        wrapping,
        sealed,
        &Aad::vk_wrap(wrap_type, vk_version),
    )?)
}

pub fn recovery_wrap(
    phrase: &RecoveryPhrase,
    vk: &SecretKey32,
    vk_version: u32,
) -> Result<Sealed, CryptoError> {
    wrap_vk(&phrase.wrapping_key(), vk, WRAP_RECOVERY, vk_version)
}

pub fn recovery_unwrap(
    phrase: &RecoveryPhrase,
    sealed: &Sealed,
    vk_version: u32,
) -> Result<SecretKey32, CryptoError> {
    unwrap_vk(&phrase.wrapping_key(), sealed, WRAP_RECOVERY, vk_version)
}

/// Wrap a fresh per-version data key under the vault key, bound to its identity.
pub fn wrap_dek(
    vk: &SecretKey32,
    dek: &SecretKey32,
    secret_id: &[u8; 16],
    version_id: &[u8; 16],
    vk_version: u32,
) -> Result<Sealed, CryptoError> {
    aead::seal(
        vk,
        dek.expose(),
        &Aad::dek_wrap(secret_id, version_id, vk_version),
    )
}

pub fn unwrap_dek(
    vk: &SecretKey32,
    sealed: &Sealed,
    secret_id: &[u8; 16],
    version_id: &[u8; 16],
    vk_version: u32,
) -> Result<SecretKey32, CryptoError> {
    to_key(aead::open(
        vk,
        sealed,
        &Aad::dek_wrap(secret_id, version_id, vk_version),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEAK: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    #[test]
    fn passphrase_wrap_roundtrip_and_wrong_passphrase() {
        let vk = SecretKey32::random().unwrap();
        let salt = [5u8; 32];
        let pwk = passphrase_key(b"correct horse", &salt, WEAK, true).unwrap();
        let w = wrap_vk(&pwk, &vk, WRAP_PASSPHRASE, 1).unwrap();
        assert_eq!(
            unwrap_vk(&pwk, &w, WRAP_PASSPHRASE, 1).unwrap().expose(),
            vk.expose()
        );
        let bad = passphrase_key(b"wrong", &salt, WEAK, true).unwrap();
        assert_eq!(
            unwrap_vk(&bad, &w, WRAP_PASSPHRASE, 1).err(),
            Some(CryptoError::Integrity)
        );
    }

    #[test]
    fn wrap_type_and_version_are_bound() {
        let vk = SecretKey32::random().unwrap();
        let k = SecretKey32::random().unwrap();
        let w = wrap_vk(&k, &vk, WRAP_PASSPHRASE, 1).unwrap();
        assert!(unwrap_vk(&k, &w, WRAP_RECOVERY, 1).is_err());
        assert!(unwrap_vk(&k, &w, WRAP_PASSPHRASE, 2).is_err());
    }

    #[test]
    fn recovery_restores_same_vk_after_passphrase_change() {
        let vk = SecretKey32::random().unwrap();
        let phrase = RecoveryPhrase::generate().unwrap();
        let rw = recovery_wrap(&phrase, &vk, 1).unwrap();
        // "Lost passphrase": re-parse the phrase from its words, unwrap, rewrap with a new passphrase.
        let typed = RecoveryPhrase::parse(&phrase.words().join(" ")).unwrap();
        let restored = recovery_unwrap(&typed, &rw, 1).unwrap();
        let new_pwk = passphrase_key(b"new pass", &[9; 32], WEAK, true).unwrap();
        let pw = wrap_vk(&new_pwk, &restored, WRAP_PASSPHRASE, 1).unwrap();
        assert_eq!(
            unwrap_vk(&new_pwk, &pw, WRAP_PASSPHRASE, 1)
                .unwrap()
                .expose(),
            vk.expose()
        );
    }

    #[test]
    fn dek_wrap_bound_to_secret_and_version() {
        let vk = SecretKey32::random().unwrap();
        let dek = SecretKey32::random().unwrap();
        let w = wrap_dek(&vk, &dek, &[1; 16], &[1; 16], 1).unwrap();
        assert_eq!(
            unwrap_dek(&vk, &w, &[1; 16], &[1; 16], 1).unwrap().expose(),
            dek.expose()
        );
        assert!(
            unwrap_dek(&vk, &w, &[2; 16], &[1; 16], 1).is_err(),
            "moved to another secret"
        );
        assert!(
            unwrap_dek(&vk, &w, &[1; 16], &[2; 16], 1).is_err(),
            "moved to another version"
        );
    }
}
