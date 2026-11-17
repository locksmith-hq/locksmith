//! Versioned ciphertext header (design decision 7).
//!
//! ```text
//! magic(2) "LS" | format_ver(1) | alg_id(1) | key_id(16) | nonce(12) | ciphertext | tag(16)
//! ```
//!
//! The AEAD (AES-256-GCM via `ls-crypto`) authenticates, as canonical length-prefixed AAD
//! (`ls_crypto::aead::Aad`): a domain label, the 20 header bytes, then
//! `org_id | secret_id | version | purpose`. Binding the header means any header change that
//! still parses fails authentication; binding the context means a ciphertext moved to another
//! row, secret version, purpose or org fails to open. The DEK wrap uses the same format with
//! [`Purpose::DekWrap`].
//!
//! Errors name the failing check and never carry plaintext.

use ls_crypto::aead::{self, Aad, Sealed};
use ls_crypto::{SecretBytes, SecretKey32};

pub const MAGIC: [u8; 2] = *b"LS";
pub const FORMAT_V1: u8 = 1;
pub const ALG_AES_256_GCM: u8 = 1;
pub const HEADER_LEN: usize = 20;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// Smallest valid blob: header, nonce and tag around an empty ciphertext.
pub const MIN_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;

const AAD_LABEL: &[u8] = b"locksmith-ct";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyId(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// A secret value encrypted under its data key.
    SecretPayload,
    /// A data key wrapped by a gateway or KMS-derived key.
    DekWrap,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Purpose::SecretPayload => b"secret-payload",
            Purpose::DekWrap => b"dek-wrap",
        }
    }
}

/// What a ciphertext is bound to. Opening with any other binding fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    pub org_id: [u8; 16],
    pub secret_id: [u8; 16],
    pub version: u32,
    pub purpose: Purpose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatField {
    Version,
    Algorithm,
}

/// Every way a blob can fail to open. No variant carries plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// Shorter than the header, or than header + nonce + tag.
    Truncated,
    /// The first two bytes are not `"LS"`.
    BadMagic,
    /// Unknown `format_ver` or `alg_id`.
    UnsupportedFormat { field: FormatField, value: u8 },
    /// No key with this `key_id` in the keyring.
    UnknownKeyId,
    /// AEAD authentication failed: the binding (org_id, secret_id, version, purpose) or a
    /// header byte differs from sealing time, or the nonce, ciphertext or tag was changed.
    Integrity,
    /// Sealing failed (random source or AEAD error).
    Seal,
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderError::Truncated => f.write_str("ciphertext truncated"),
            HeaderError::BadMagic => f.write_str("ciphertext header: bad magic"),
            HeaderError::UnsupportedFormat { field, value } => {
                let name = match field {
                    FormatField::Version => "format_ver",
                    FormatField::Algorithm => "alg_id",
                };
                write!(f, "unsupported format: {name} {value}")
            }
            HeaderError::UnknownKeyId => f.write_str("ciphertext header: unknown key_id"),
            HeaderError::Integrity => f.write_str(
                "integrity check failed: AAD (org_id, secret_id, version, purpose), header or ciphertext do not authenticate",
            ),
            HeaderError::Seal => f.write_str("sealing failed"),
        }
    }
}
impl std::error::Error for HeaderError {}

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

    /// Parse and validate the header (no key needed): useful for routing to the right key
    /// during rotation.
    pub fn parse(blob: &[u8]) -> Result<Self, HeaderError> {
        if blob.len() < HEADER_LEN {
            return Err(HeaderError::Truncated);
        }
        if blob[..2] != MAGIC {
            return Err(HeaderError::BadMagic);
        }
        if blob[2] != FORMAT_V1 {
            return Err(HeaderError::UnsupportedFormat {
                field: FormatField::Version,
                value: blob[2],
            });
        }
        if blob[3] != ALG_AES_256_GCM {
            return Err(HeaderError::UnsupportedFormat {
                field: FormatField::Algorithm,
                value: blob[3],
            });
        }
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&blob[4..HEADER_LEN]);
        Ok(Self::v1(KeyId(key_id)))
    }
}

fn aad(header: &[u8; HEADER_LEN], b: &Binding) -> Aad {
    Aad::new()
        .field(AAD_LABEL)
        .field(header)
        .field(&b.org_id)
        .field(&b.secret_id)
        .field(&b.version.to_be_bytes())
        .field(b.purpose.label())
}

fn assemble(header: &[u8; HEADER_LEN], sealed: Sealed) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + sealed.ct.len());
    out.extend_from_slice(header);
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.ct);
    out
}

/// Seal `plaintext` under `key` (identified by `key_id`) with a fresh random nonce.
pub fn seal(
    key_id: KeyId,
    key: &SecretKey32,
    binding: &Binding,
    plaintext: &[u8],
) -> Result<Vec<u8>, HeaderError> {
    let header = Header::v1(key_id).encode();
    let sealed =
        aead::seal(key, plaintext, &aad(&header, binding)).map_err(|_| HeaderError::Seal)?;
    Ok(assemble(&header, sealed))
}

/// Fixed-nonce seal for known-answer tests only. Reusing a nonce under one key breaks GCM.
#[cfg(test)]
fn seal_with_nonce(
    key_id: KeyId,
    key: &SecretKey32,
    binding: &Binding,
    nonce: [u8; NONCE_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let header = Header::v1(key_id).encode();
    let ct = aes_gcm::Aes256Gcm::new(key.expose().into())
        .encrypt(
            aes_gcm::Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: aad(&header, binding).as_bytes(),
            },
        )
        .expect("AES-GCM encrypt");
    assemble(&header, Sealed { nonce, ct })
}

/// Keys the opener may use, looked up by `key_id`.
#[derive(Default)]
pub struct Keyring {
    keys: Vec<(KeyId, SecretKey32)>,
}

impl Keyring {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, id: KeyId, key: SecretKey32) {
        self.keys.retain(|(k, _)| *k != id);
        self.keys.push((id, key));
    }
    fn get(&self, id: &KeyId) -> Option<&SecretKey32> {
        self.keys.iter().find(|(k, _)| k == id).map(|(_, v)| v)
    }
}

/// Open a blob for `binding`. Checks run in order: length, magic, format_ver, alg_id,
/// key_id, then AEAD authentication.
pub fn open(keys: &Keyring, binding: &Binding, blob: &[u8]) -> Result<SecretBytes, HeaderError> {
    let header = Header::parse(blob)?;
    if blob.len() < MIN_LEN {
        return Err(HeaderError::Truncated);
    }
    let key = keys.get(&header.key_id).ok_or(HeaderError::UnknownKeyId)?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[HEADER_LEN..HEADER_LEN + NONCE_LEN]);
    let sealed = Sealed {
        nonce,
        ct: blob[HEADER_LEN + NONCE_LEN..].to_vec(),
    };
    aead::open(key, &sealed, &aad(&header.encode(), binding)).map_err(|_| HeaderError::Integrity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kat_key() -> SecretKey32 {
        SecretKey32::from_bytes(core::array::from_fn(|i| i as u8))
    }
    const KAT_KEY_ID: KeyId = KeyId([0x11; 16]);
    const KAT_NONCE: [u8; 12] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
    ];
    const KAT_PLAINTEXT: &[u8] = b"kat-not-a-secret";
    fn kat_binding() -> Binding {
        Binding {
            org_id: [0x01; 16],
            secret_id: [0x02; 16],
            version: 7,
            purpose: Purpose::SecretPayload,
        }
    }
    /// Computed independently with PyCryptodome 4.5.0 (`AES.MODE_GCM`) over the same key, nonce
    /// and AAD encoding; Rust must reproduce it byte for byte.
    const KAT_BLOB_HEX: &str = concat!(
        "4c53010111111111111111111111111111111111", // magic, format_ver, alg_id, key_id
        "a0a1a2a3a4a5a6a7a8a9aaab",                 // nonce
        "8d7908002ba476920348f4b66408a5aa",         // ciphertext
        "d4e2906a4553e136d4695ed2ace8486f",         // tag
    );
    const KAT_AAD_HEX: &str = concat!(
        "000c6c6f636b736d6974682d6374",                 // "locksmith-ct"
        "00144c53010111111111111111111111111111111111", // header
        "001001010101010101010101010101010101",         // org_id
        "001002020202020202020202020202020202",         // secret_id
        "000400000007",                                 // version
        "000e7365637265742d7061796c6f6164",             // purpose
    );

    #[test]
    fn kat_aad_encoding() {
        let header = Header::v1(KAT_KEY_ID).encode();
        assert_eq!(
            hex::encode(aad(&header, &kat_binding()).as_bytes()),
            KAT_AAD_HEX
        );
    }

    #[test]
    fn kat_seal() {
        let blob = seal_with_nonce(
            KAT_KEY_ID,
            &kat_key(),
            &kat_binding(),
            KAT_NONCE,
            KAT_PLAINTEXT,
        );
        assert_eq!(hex::encode(&blob), KAT_BLOB_HEX);
    }

    #[test]
    fn kat_open() {
        let mut keys = Keyring::new();
        keys.insert(KAT_KEY_ID, kat_key());
        let blob = hex::decode(KAT_BLOB_HEX).unwrap();
        let header = Header::parse(&blob).unwrap();
        assert_eq!(header, Header::v1(KAT_KEY_ID));
        let pt = open(&keys, &kat_binding(), &blob).expect("KAT opens");
        // Compare without printing the plaintext on failure.
        assert!(pt.expose() == KAT_PLAINTEXT, "KAT plaintext mismatch");
    }

    #[test]
    fn kat_header_layout() {
        let h = Header::v1(KAT_KEY_ID).encode();
        assert_eq!(hex::encode(h), "4c53010111111111111111111111111111111111");
    }

    #[test]
    fn display_names_the_field_and_never_plaintext() {
        assert_eq!(
            HeaderError::UnsupportedFormat {
                field: FormatField::Algorithm,
                value: 9
            }
            .to_string(),
            "unsupported format: alg_id 9"
        );
        assert!(HeaderError::Integrity.to_string().contains("AAD"));
    }
}
