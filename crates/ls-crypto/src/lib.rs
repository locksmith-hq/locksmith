//! Key derivation, AEAD and vault-key wraps (design: openspec/changes/m1-local-vault/design.md D1, D3).
//!
//! Every plaintext key or secret lives in [`SecretKey32`] / [`SecretBytes`]: zeroized on drop,
//! best-effort mlocked, and deliberately without `Debug`, `Display`, `Clone` or serde.

pub mod aead;
pub mod kdf;
pub mod recovery;
pub mod secret;
pub mod wrap;

pub use secret::{SecretBytes, SecretKey32};

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Authentication failed: wrong key, tampered ciphertext, or AAD mismatch.
    Integrity,
    /// Parameters rejected (e.g. Argon2 cost below the minimum).
    Params(String),
    /// The OS random source failed.
    Rng,
    /// Recovery phrase is not a valid 24-word BIP-39 mnemonic.
    BadPhrase,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Integrity => {
                f.write_str("integrity check failed (wrong key or tampered data)")
            }
            CryptoError::Params(e) => write!(f, "invalid parameters: {e}"),
            CryptoError::Rng => f.write_str("system random number generator failed"),
            CryptoError::BadPhrase => f.write_str("recovery phrase is not a valid 24-word phrase"),
        }
    }
}
impl std::error::Error for CryptoError {}

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|_| CryptoError::Rng)?;
    Ok(b)
}
