//! Per-version envelope encryption (design: openspec/changes/s2-envelope-crypto/design.md
//! decisions 1 and 2; binding decisions A0-6, A0-7).
//!
//! - [`header`]: the A0-7 ciphertext header codec and AAD encoding.
//! - [`seal_version`] / [`open_version`]: AES-256-GCM (via `ls-crypto`) under a fresh random
//!   256-bit data key (DEK) per secret version, with a fresh random 96-bit nonce. One
//!   encryption per DEK keeps the random-nonce collision bound irrelevant.
//! - [`KeyWrapper`]: wraps each DEK with a KMS key into a `dek-wrap` blob ([`WrappedDek`]);
//!   [`OpenBaoTransit`] implements it over OpenBao transit (design decision 3).
//! - [`seal_dek_hpke`] / [`open_dek_hpke`]: a DEK sealed with HPKE (RFC 9180) to an environment
//!   seal key, header `alg_id` 2 (t7 design decision 1). The private half is a
//!   [`SealPrivateKey`].
//!
//! The DEK and plaintext live only in `ls-crypto`'s [`SecretKey32`] / [`SecretBytes`]
//! (zeroized on drop) or in [`DataKey`] / [`SealedVersion`], which wrap them. None of these
//! implement `Debug`, `Display`, `Clone` or serde. Errors name the failing check and never carry
//! plaintext or key bytes.
//!
//! Protection level (design decision 7): containment. A database dump or a compromised control
//! plane yields ciphertext and KMS-wrapped DEKs, not values.

pub mod header;
mod hpke_wrap;
mod openbao;
mod seal_key_sig;
mod version;
mod wrap;

pub use header::{Binding, FormatField, Header, KeyId, Purpose};
pub use hpke_wrap::{
    HPKE_ENC_LEN, HPKE_WRAPPED_DEK_LEN, SealPrivateKey, SealPublicKey, open_dek_hpke, seal_dek_hpke,
};
pub use ls_crypto::{SecretBytes, SecretKey32};
pub use openbao::{BaoToken, OpenBaoTransit, TransitSignature, TransitSigner};
pub use seal_key_sig::{
    GATEWAY_VERIFYING_KEY_LEN, SEAL_KEY_SIG_DOMAIN, SEAL_KEY_SIG_LEN, seal_key_message,
    verify_seal_key,
};
pub use version::{DataKey, SealedVersion, open_version, seal_version};
pub use wrap::{KeyWrapper, TransportKind, WRAPPED_DEK_LEN, WrapError, WrapKeyId, WrappedDek};

/// Every way sealing or opening can fail. No variant carries plaintext or key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Shorter than the header, or than header + nonce + tag.
    Truncated,
    /// The first two bytes are not `"LS"`.
    BadMagic,
    /// Unknown `format_ver` or `alg_id`, or an `alg_id` the called opener does not handle.
    UnsupportedFormat { field: FormatField, value: u8 },
    /// The blob's `key_id` is not the id of the data key offered to open it.
    UnknownKeyId,
    /// AEAD authentication failed: the binding (org_id, secret_id, version, purpose) or a
    /// header byte differs from sealing time, the key is wrong, or the nonce, ciphertext or
    /// tag was changed.
    Integrity,
    /// Sealing failed (random source, AEAD error, or an invalid recipient public key).
    Seal,
    /// The binding's purpose does not fit the format (an HPKE-wrapped DEK needs `dek-wrap`).
    Purpose,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::Truncated => f.write_str("ciphertext truncated"),
            EnvelopeError::BadMagic => f.write_str("ciphertext header: bad magic"),
            EnvelopeError::UnsupportedFormat { field, value } => {
                let name = match field {
                    FormatField::Version => "format_ver",
                    FormatField::Algorithm => "alg_id",
                };
                write!(f, "unsupported format: {name} {value}")
            }
            EnvelopeError::UnknownKeyId => {
                f.write_str("ciphertext header: key_id does not match the data key")
            }
            EnvelopeError::Integrity => f.write_str(
                "integrity check failed: AAD (org_id, secret_id, version, purpose), header, key or ciphertext do not authenticate",
            ),
            EnvelopeError::Seal => f.write_str("sealing failed"),
            EnvelopeError::Purpose => f.write_str("binding purpose does not match the format"),
        }
    }
}
impl std::error::Error for EnvelopeError {}
