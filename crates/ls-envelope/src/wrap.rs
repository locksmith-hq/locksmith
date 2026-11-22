//! Wrapping a version's data key with a KMS key (design decision 3).
//!
//! A wrapped DEK uses the A0-7 header with purpose `dek-wrap`:
//!
//! ```text
//! magic(2) "LS" | format_ver(1) | alg_id(1) | key_id(16) | nonce(12) | wrapped DEK(32) | tag(16)
//! ```
//!
//! `key_id` names the KMS key: its name (1 to 12 bytes of `[A-Za-z0-9_-]`, zero-padded to 12)
//! then its version as a big-endian `u32` ([`WrapKeyId`]). The KMS authenticates the same AAD
//! as a payload ([`crate::header`]): the 20 header bytes and `org_id ‖ secret_id ‖ version ‖
//! dek-wrap`, so a wrapped DEK moved to another row, version or key fails to unwrap.

use crate::header::{self, Binding, HEADER_LEN, Header, KeyId, Purpose};
use crate::{DataKey, EnvelopeError};
use ls_crypto::SecretKey32;
use std::future::Future;

/// Length of a wrapped DEK blob: header, nonce, 32-byte DEK ciphertext and tag.
pub const WRAPPED_DEK_LEN: usize = header::MIN_LEN + 32;

/// Wraps and unwraps data keys with a KMS key. Implementations: [`crate::OpenBaoTransit`].
///
/// Both calls take the version's [`Binding`] with `purpose` [`Purpose::DekWrap`]; any other
/// purpose is refused with [`WrapError::Purpose`] so a payload binding cannot be reused here.
pub trait KeyWrapper {
    /// Wrap `dek` for `binding`. The result is safe to store; its [`WrappedDek::key_id`] is the
    /// KMS key the row records.
    fn wrap(
        &self,
        dek: &DataKey,
        binding: &Binding,
    ) -> impl Future<Output = Result<WrappedDek, WrapError>> + Send;

    /// Unwrap a stored DEK. Rebuild the [`DataKey`] with [`DataKey::from_parts`] and the
    /// payload's header key id ([`crate::Header::parse`]).
    fn unwrap(
        &self,
        wrapped: &WrappedDek,
        binding: &Binding,
    ) -> impl Future<Output = Result<SecretKey32, WrapError>> + Send;
}

/// The KMS key a DEK is wrapped under: a key name and its version. Not secret.
///
/// `Display` gives `name:vN` (for example `gateway:v1`), the form stored in the row's `key_id`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WrapKeyId {
    name: String,
    version: u32,
}

impl WrapKeyId {
    /// Longest key name that fits the 16-byte header `key_id` next to the version.
    pub const MAX_NAME_LEN: usize = 12;

    /// `name` is 1 to [`Self::MAX_NAME_LEN`] bytes of `[A-Za-z0-9_-]`; `version` is at least 1.
    pub fn new(name: &str, version: u32) -> Result<Self, WrapError> {
        if !valid_name(name) || version == 0 {
            return Err(WrapError::InvalidKeyId);
        }
        Ok(Self {
            name: name.to_owned(),
            version,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    /// The 16-byte header form: name zero-padded to 12 bytes, then the version (u32 BE).
    pub fn to_key_id(&self) -> KeyId {
        let mut id = [0u8; 16];
        id[..self.name.len()].copy_from_slice(self.name.as_bytes());
        id[Self::MAX_NAME_LEN..].copy_from_slice(&self.version.to_be_bytes());
        KeyId(id)
    }

    /// Inverse of [`Self::to_key_id`]. Rejects ids that [`Self::to_key_id`] cannot produce.
    pub fn from_key_id(id: KeyId) -> Result<Self, WrapError> {
        let (name, version) = id.0.split_at(Self::MAX_NAME_LEN);
        let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        if name[len..].iter().any(|&b| b != 0) {
            return Err(WrapError::InvalidKeyId);
        }
        let name = std::str::from_utf8(&name[..len]).map_err(|_| WrapError::InvalidKeyId)?;
        let mut v = [0u8; 4];
        v.copy_from_slice(version);
        Self::new(name, u32::from_be_bytes(v))
    }
}

impl std::fmt::Display for WrapKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:v{}", self.name, self.version)
    }
}

pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= WrapKeyId::MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A DEK wrapped by a KMS key, in the `dek-wrap` header format. Not secret, but it is never
/// returned by the API or logged: `Debug` shows only the key id and length.
#[derive(PartialEq, Eq)]
pub struct WrappedDek {
    blob: Vec<u8>,
    key_id: WrapKeyId,
}

impl WrappedDek {
    /// Validate a stored blob: A0-7 v1 header with `alg_id` 1 (an HPKE-wrapped DEK, `alg_id` 2,
    /// is opened with [`crate::open_dek_hpke`] instead), exact length and a well-formed KMS key id.
    pub fn from_bytes(blob: Vec<u8>) -> Result<Self, WrapError> {
        let header = Header::parse(&blob).map_err(WrapError::Format)?;
        header
            .require_alg(header::ALG_AES_256_GCM)
            .map_err(WrapError::Format)?;
        if blob.len() != WRAPPED_DEK_LEN {
            return Err(WrapError::Format(EnvelopeError::Truncated));
        }
        let key_id = WrapKeyId::from_key_id(header.key_id)?;
        Ok(Self { blob, key_id })
    }

    /// Assemble from a header and the KMS output `nonce ‖ ciphertext ‖ tag`.
    pub(crate) fn assemble(key_id: &WrapKeyId, kms_ct: &[u8]) -> Result<Self, WrapError> {
        if HEADER_LEN + kms_ct.len() != WRAPPED_DEK_LEN {
            return Err(WrapError::BadResponse);
        }
        let mut blob = Vec::with_capacity(WRAPPED_DEK_LEN);
        blob.extend_from_slice(&Header::v1(key_id.to_key_id()).encode());
        blob.extend_from_slice(kms_ct);
        Self::from_bytes(blob)
    }

    /// The KMS key this DEK is wrapped under (stored in the row's `key_id`).
    pub fn key_id(&self) -> &WrapKeyId {
        &self.key_id
    }

    /// `header ‖ nonce ‖ ciphertext ‖ tag`, for the row's `wrapped_dek` column.
    pub fn as_bytes(&self) -> &[u8] {
        &self.blob
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.blob
    }

    /// The KMS ciphertext after the header: `nonce ‖ ciphertext ‖ tag`.
    pub(crate) fn kms_ciphertext(&self) -> &[u8] {
        &self.blob[HEADER_LEN..]
    }

    pub(crate) fn header(&self) -> [u8; HEADER_LEN] {
        Header::v1(self.key_id.to_key_id()).encode()
    }
}

impl std::fmt::Debug for WrappedDek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedDek")
            .field("key_id", &format_args!("{}", self.key_id))
            .field("len", &self.blob.len())
            .finish()
    }
}

/// Refuse a binding whose purpose is not `dek-wrap`.
pub(crate) fn require_dek_wrap(binding: &Binding) -> Result<(), WrapError> {
    if binding.purpose == Purpose::DekWrap {
        Ok(())
    } else {
        Err(WrapError::Purpose)
    }
}

/// Why a transport call failed, without the underlying error (which can carry request
/// details).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Connect,
    Timeout,
    Other,
}

/// Every way wrapping or unwrapping can fail. No variant carries a DEK, a token, a wrapped DEK
/// or a KMS response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapError {
    /// A key name or version that does not fit the `dek-wrap` key id, or a malformed key id.
    InvalidKeyId,
    /// Invalid KMS address or mount path.
    InvalidConfig,
    /// The binding's purpose is not `dek-wrap`.
    Purpose,
    /// The wrapped blob's header or length is not a v1 `dek-wrap` blob.
    Format(EnvelopeError),
    /// The wrapped DEK names a different KMS key than this wrapper uses.
    KeyMismatch,
    /// The HTTP client could not be built (TLS configuration).
    Client,
    /// The KMS could not be reached.
    Transport(TransportKind),
    /// The KMS refused the credential (HTTP 401 or 403).
    Denied,
    /// The KMS rejected the request with this HTTP status (for OpenBao, 400 also covers a
    /// failed authentication of the wrapped DEK, e.g. a wrong binding).
    Rejected { status: u16 },
    /// The KMS answered with something this client does not understand.
    BadResponse,
}

impl std::fmt::Display for WrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WrapError::InvalidKeyId => f.write_str(
                "invalid KMS key id: name must be 1-12 bytes of [A-Za-z0-9_-], version >= 1",
            ),
            WrapError::InvalidConfig => f.write_str("invalid KMS address or mount"),
            WrapError::Purpose => f.write_str("DEK wrap binding must have purpose dek-wrap"),
            WrapError::Format(e) => write!(f, "wrapped DEK: {e}"),
            WrapError::KeyMismatch => {
                f.write_str("wrapped DEK names a different KMS key than this wrapper")
            }
            WrapError::Client => f.write_str("could not build the KMS HTTP client"),
            WrapError::Transport(kind) => write!(f, "KMS unreachable ({kind:?})"),
            WrapError::Denied => {
                f.write_str("KMS denied the request (credential lacks permission)")
            }
            WrapError::Rejected { status } => write!(f, "KMS rejected the request: HTTP {status}"),
            WrapError::BadResponse => f.write_str("unexpected KMS response"),
        }
    }
}

impl std::error::Error for WrapError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_layout_and_round_trip() {
        let k = WrapKeyId::new("gateway", 1).unwrap();
        assert_eq!(k.to_string(), "gateway:v1");
        assert_eq!(
            hex::encode(k.to_key_id().0),
            "67617465776179000000000000000001"
        );
        assert_eq!(WrapKeyId::from_key_id(k.to_key_id()), Ok(k));
        let long = WrapKeyId::new("abcdefghijkl", u32::MAX).unwrap();
        assert_eq!(WrapKeyId::from_key_id(long.to_key_id()), Ok(long));
    }

    #[test]
    fn key_id_rejects_bad_names() {
        for (name, v) in [
            ("", 1),
            ("abcdefghijklm", 1),
            ("has space", 1),
            ("a/b", 1),
            ("gateway", 0),
        ] {
            assert_eq!(
                WrapKeyId::new(name, v),
                Err(WrapError::InvalidKeyId),
                "{name}"
            );
        }
        // Bytes after the zero padding, invalid UTF-8, or an empty name.
        let mut id = WrapKeyId::new("gw", 1).unwrap().to_key_id();
        id.0[5] = b'x';
        assert_eq!(WrapKeyId::from_key_id(id), Err(WrapError::InvalidKeyId));
        let mut id = [0u8; 16];
        id[0] = 0xff;
        id[15] = 1;
        assert_eq!(
            WrapKeyId::from_key_id(KeyId(id)),
            Err(WrapError::InvalidKeyId)
        );
        assert_eq!(
            WrapKeyId::from_key_id(KeyId([0; 16])),
            Err(WrapError::InvalidKeyId)
        );
    }

    #[test]
    fn wrapped_dek_validates_length_and_header() {
        let k = WrapKeyId::new("gateway", 3).unwrap();
        let w = WrappedDek::assemble(&k, &[7u8; 60]).unwrap();
        assert_eq!(w.as_bytes().len(), WRAPPED_DEK_LEN);
        assert_eq!(w.key_id(), &k);
        assert_eq!(
            format!("{w:?}"),
            "WrappedDek { key_id: gateway:v3, len: 80 }"
        );
        assert_eq!(
            WrappedDek::from_bytes(w.as_bytes().to_vec()).unwrap(),
            WrappedDek::assemble(&k, &[7u8; 60]).unwrap()
        );
        assert_eq!(
            WrappedDek::assemble(&k, &[7u8; 59]).err(),
            Some(WrapError::BadResponse)
        );
        let mut short = w.as_bytes().to_vec();
        short.pop();
        assert_eq!(
            WrappedDek::from_bytes(short).err(),
            Some(WrapError::Format(EnvelopeError::Truncated))
        );
        let mut bad = w.into_bytes();
        bad[0] = b'X';
        assert_eq!(
            WrappedDek::from_bytes(bad).err(),
            Some(WrapError::Format(EnvelopeError::BadMagic))
        );
    }
}
