//! 24-word BIP-39 recovery phrase → seed → recovery wrapping key and audit root key.

use crate::kdf::{hkdf, label};
use crate::{CryptoError, SecretBytes, SecretKey32};
use zeroize::Zeroize;

/// A recovery phrase. No Debug/Display: render it only through [`RecoveryPhrase::words`]
/// on the screen the human is looking at.
pub struct RecoveryPhrase(bip39::Mnemonic);

impl RecoveryPhrase {
    /// 256 bits of OS entropy → 24 words.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut entropy = crate::random_bytes::<32>()?;
        let m = bip39::Mnemonic::from_entropy(&entropy).map_err(|_| CryptoError::BadPhrase);
        entropy.zeroize();
        Ok(Self(m?))
    }

    /// Parse user input (any whitespace, case-insensitive); must be exactly 24 valid words.
    pub fn parse(input: &str) -> Result<Self, CryptoError> {
        let mut normalized = input
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        let m = bip39::Mnemonic::parse_normalized(&normalized).map_err(|_| CryptoError::BadPhrase);
        normalized.zeroize();
        let m = m?;
        if m.word_count() != 24 {
            return Err(CryptoError::BadPhrase);
        }
        Ok(Self(m))
    }

    pub fn words(&self) -> Vec<&'static str> {
        self.0.words().collect()
    }

    /// Standard BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds, empty passphrase).
    pub fn seed(&self) -> SecretBytes {
        SecretBytes::new(self.0.to_seed_normalized("").to_vec())
    }

    pub fn wrapping_key(&self) -> SecretKey32 {
        hkdf(self.seed().expose(), label::RECOVERY_WRAP)
    }

    /// Root of the forward-secure audit ratchet (v6 review §2.1). Used once at vault creation.
    pub fn audit_root(&self) -> SecretKey32 {
        hkdf(self.seed().expose(), label::AUDIT_ROOT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trezor reference vector: all-zero 256-bit entropy.
    #[test]
    fn bip39_zero_entropy_vector() {
        let m = bip39::Mnemonic::from_entropy(&[0u8; 32]).unwrap();
        let words: Vec<_> = m.words().collect();
        assert_eq!(words.len(), 24);
        assert!(words[..23].iter().all(|w| *w == "abandon"));
        assert_eq!(words[23], "art");
        assert_eq!(
            hex::encode(m.to_seed_normalized("TREZOR")),
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
        );
    }

    #[test]
    fn parse_roundtrip_and_normalization() {
        let p = RecoveryPhrase::generate().unwrap();
        let typed = format!("  {}  ", p.words().join("   ").to_uppercase());
        let q = RecoveryPhrase::parse(&typed).unwrap();
        assert_eq!(p.wrapping_key().expose(), q.wrapping_key().expose());
        assert_ne!(p.wrapping_key().expose(), p.audit_root().expose());
    }

    #[test]
    fn bad_checksum_and_short_phrases_rejected() {
        // 24 x "abandon" has valid words but a wrong checksum (the valid one ends in "art").
        let bad = vec!["abandon"; 24].join(" ");
        assert_eq!(
            RecoveryPhrase::parse(&bad).err(),
            Some(CryptoError::BadPhrase)
        );
        let twelve = bip39::Mnemonic::from_entropy(&[1u8; 16])
            .unwrap()
            .to_string();
        assert_eq!(
            RecoveryPhrase::parse(&twelve).err(),
            Some(CryptoError::BadPhrase)
        );
        assert_eq!(
            RecoveryPhrase::parse("not a phrase").err(),
            Some(CryptoError::BadPhrase)
        );
    }
}
