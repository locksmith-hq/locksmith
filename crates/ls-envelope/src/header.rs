//! The A0-7 versioned ciphertext header, promoted from `a0-spikes` (S2 design decision 1).
//!
//! ```text
//! magic(2) "LS" | format_ver(1) | alg_id(1) | key_id(16) | nonce(12) | ciphertext | tag(16)
//! ```
//!
//! The AEAD authenticates, as canonical length-prefixed AAD ([`ls_crypto::aead::Aad`]: every
//! field is a big-endian `u16` length then its bytes, so field boundaries cannot shift): a
//! domain label, the 20 header bytes, then `org_id ‖ secret_id ‖ version ‖ purpose`. Binding the
//! header means any header change that still parses fails authentication; binding the context
//! means a ciphertext moved to another org, secret, version or purpose fails to open.

use crate::EnvelopeError;
use ls_crypto::aead::Aad;

pub const MAGIC: [u8; 2] = *b"LS";
pub const FORMAT_V1: u8 = 1;
pub const ALG_AES_256_GCM: u8 = 1;
pub const HEADER_LEN: usize = 20;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// Smallest valid blob: header, nonce and tag around an empty ciphertext.
pub const MIN_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;

const AAD_LABEL: &[u8] = b"locksmith-ct";

/// Identifies the key a blob was sealed under. Not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(pub [u8; 16]);

/// What the ciphertext holds. Part of the AAD, so a blob cannot be reinterpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// A secret value encrypted under its data key.
    SecretPayload,
    /// A data key wrapped by a gateway or KMS key.
    DekWrap,
}

impl Purpose {
    pub fn label(self) -> &'static [u8] {
        match self {
            Purpose::SecretPayload => b"secret-payload",
            Purpose::DekWrap => b"dek-wrap",
        }
    }
}

/// What a ciphertext is bound to. Opening with any other binding fails. Not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    pub org_id: [u8; 16],
    pub secret_id: [u8; 16],
    pub version: u32,
    pub purpose: Purpose,
}

/// Which header byte was not understood.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatField {
    Version,
    Algorithm,
}

/// The parsed fixed-size header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub format_ver: u8,
    pub alg_id: u8,
    pub key_id: KeyId,
}

impl Header {
    pub fn v1(key_id: KeyId) -> Self {
        Self {
            format_ver: FORMAT_V1,
            alg_id: ALG_AES_256_GCM,
            key_id,
        }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[..2].copy_from_slice(&MAGIC);
        h[2] = self.format_ver;
        h[3] = self.alg_id;
        h[4..].copy_from_slice(&self.key_id.0);
        h
    }

    /// Parse and validate the header (no key needed), e.g. to find which key to fetch.
    pub fn parse(blob: &[u8]) -> Result<Self, EnvelopeError> {
        if blob.len() < HEADER_LEN {
            return Err(EnvelopeError::Truncated);
        }
        if blob[..2] != MAGIC {
            return Err(EnvelopeError::BadMagic);
        }
        if blob[2] != FORMAT_V1 {
            return Err(EnvelopeError::UnsupportedFormat {
                field: FormatField::Version,
                value: blob[2],
            });
        }
        if blob[3] != ALG_AES_256_GCM {
            return Err(EnvelopeError::UnsupportedFormat {
                field: FormatField::Algorithm,
                value: blob[3],
            });
        }
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&blob[4..HEADER_LEN]);
        Ok(Self::v1(KeyId(key_id)))
    }
}

/// `label ‖ header ‖ org_id ‖ secret_id ‖ version(u32 BE) ‖ purpose`, each length-prefixed.
pub(crate) fn aad(header: &[u8; HEADER_LEN], b: &Binding) -> Aad {
    Aad::new()
        .field(AAD_LABEL)
        .field(header)
        .field(&b.org_id)
        .field(&b.secret_id)
        .field(&b.version.to_be_bytes())
        .field(b.purpose.label())
}

/// `header ‖ nonce ‖ ciphertext‖tag`.
pub(crate) fn assemble(header: &[u8; HEADER_LEN], nonce: &[u8; NONCE_LEN], ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(header);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ct);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout() {
        let h = Header::v1(KeyId([0x11; 16])).encode();
        assert_eq!(hex::encode(h), "4c53010111111111111111111111111111111111");
        assert_eq!(Header::parse(&h), Ok(Header::v1(KeyId([0x11; 16]))));
    }

    #[test]
    fn aad_is_length_unambiguous() {
        // Moving a byte between adjacent fields must change the encoding.
        let h = Header::v1(KeyId([0; 16])).encode();
        let a = Binding {
            org_id: [1; 16],
            secret_id: [2; 16],
            version: 3,
            purpose: Purpose::SecretPayload,
        };
        let enc = aad(&h, &a);
        let bytes = enc.as_bytes();
        // label, header, org, secret, version, purpose: 6 length prefixes of 2 bytes.
        assert_eq!(bytes.len(), 6 * 2 + 12 + HEADER_LEN + 16 + 16 + 4 + 14);
        let b = Binding {
            purpose: Purpose::DekWrap,
            ..a
        };
        assert_ne!(bytes, aad(&h, &b).as_bytes());
    }
}
