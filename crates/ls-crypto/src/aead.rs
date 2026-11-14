//! AES-256-GCM with random 96-bit nonces and canonical, length-prefixed associated data.

use crate::{CryptoError, SecretBytes, SecretKey32};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

pub const SCHEMA: &[u8] = b"v6";

/// Canonical AAD: each field is a big-endian u16 length followed by its bytes, so field
/// boundaries can never be shifted to make two different tuples encode identically.
#[derive(Default)]
pub struct Aad(Vec<u8>);

impl Aad {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn field(mut self, f: &[u8]) -> Self {
        let len = u16::try_from(f.len()).expect("AAD field shorter than 64 KiB");
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(f);
        self
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// AAD for a data key wrapped by the vault key (design D3).
    pub fn dek_wrap(secret_id: &[u8; 16], version_id: &[u8; 16], vk_version: u32) -> Self {
        Self::new()
            .field(SCHEMA)
            .field(b"dek-wrap")
            .field(secret_id)
            .field(version_id)
            .field(&vk_version.to_be_bytes())
    }

    /// AAD for a secret payload encrypted by its data key (design D3).
    pub fn payload(secret_id: &[u8; 16], version_id: &[u8; 16], environment_id: &[u8; 16]) -> Self {
        Self::new()
            .field(SCHEMA)
            .field(b"payload")
            .field(secret_id)
            .field(version_id)
            .field(environment_id)
    }

    /// AAD for a vault-key wrap of a given type (passphrase, recovery, hardware).
    pub fn vk_wrap(wrap_type: &str, vk_version: u32) -> Self {
        Self::new()
            .field(SCHEMA)
            .field(b"vk-wrap")
            .field(wrap_type.as_bytes())
            .field(&vk_version.to_be_bytes())
    }
}

/// Ciphertext with its nonce. The 16-byte GCM tag is appended to `ct`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; 12],
    pub ct: Vec<u8>,
}

pub fn seal(key: &SecretKey32, plaintext: &[u8], aad: &Aad) -> Result<Sealed, CryptoError> {
    let nonce = crate::random_bytes::<12>()?;
    let ct = Aes256Gcm::new(key.expose().into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::Integrity)?;
    Ok(Sealed { nonce, ct })
}

pub fn open(key: &SecretKey32, sealed: &Sealed, aad: &Aad) -> Result<SecretBytes, CryptoError> {
    Aes256Gcm::new(key.expose().into())
        .decrypt(
            Nonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ct,
                aad: aad.as_bytes(),
            },
        )
        .map(SecretBytes::new)
        .map_err(|_| CryptoError::Integrity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SecretKey32 {
        SecretKey32::from_bytes([b; 32])
    }

    #[test]
    fn roundtrip() {
        let aad = Aad::payload(&[1; 16], &[2; 16], &[3; 16]);
        let s = seal(&key(9), b"sk_live_value", &aad).unwrap();
        assert_eq!(open(&key(9), &s, &aad).unwrap().expose(), b"sk_live_value");
        assert_eq!(s.ct.len(), 13 + 16);
    }

    #[test]
    fn wrong_key_fails() {
        let aad = Aad::new().field(b"x");
        let s = seal(&key(1), b"v", &aad).unwrap();
        assert_eq!(open(&key(2), &s, &aad).err(), Some(CryptoError::Integrity));
    }

    #[test]
    fn transplant_to_other_environment_fails() {
        let dev = Aad::payload(&[1; 16], &[2; 16], &[0xD; 16]);
        let prod = Aad::payload(&[1; 16], &[2; 16], &[0xF; 16]);
        let s = seal(&key(1), b"v", &dev).unwrap();
        assert_eq!(open(&key(1), &s, &prod).err(), Some(CryptoError::Integrity));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let aad = Aad::new().field(b"x");
        let mut s = seal(&key(1), b"value", &aad).unwrap();
        s.ct[0] ^= 1;
        assert_eq!(open(&key(1), &s, &aad).err(), Some(CryptoError::Integrity));
    }

    #[test]
    fn aad_encoding_is_unambiguous() {
        assert_ne!(
            Aad::new().field(b"ab").field(b"c").as_bytes(),
            Aad::new().field(b"a").field(b"bc").as_bytes()
        );
    }

    #[test]
    fn nonces_are_fresh() {
        let aad = Aad::new();
        let a = seal(&key(1), b"v", &aad).unwrap();
        let b = seal(&key(1), b"v", &aad).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ct, b.ct);
    }
}
