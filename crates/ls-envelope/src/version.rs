//! Sealing and opening one secret version under its own data key.

use crate::EnvelopeError;
use crate::header::{self, Binding, HEADER_LEN, Header, KeyId, MIN_LEN, NONCE_LEN};
use ls_crypto::aead::{self, Sealed};
use ls_crypto::{SecretBytes, SecretKey32};

/// A data key and the id written into the header of the blob it seals.
///
/// No `Debug`, `Display`, `Clone` or serde: the key bytes are reachable only through
/// [`DataKey::expose`], and are zeroized when the inner [`SecretKey32`] drops.
pub struct DataKey {
    id: KeyId,
    key: SecretKey32,
}

impl DataKey {
    /// Rebuild a data key from its id (read with [`Header::parse`]) and the key bytes a
    /// `KeyWrapper` returned on unwrap.
    pub fn from_parts(id: KeyId, key: SecretKey32) -> Self {
        Self { id, key }
    }

    /// A fresh random 256-bit key with a fresh random id. Only [`seal_version`] creates keys,
    /// so every version gets its own.
    fn generate() -> Result<Self, EnvelopeError> {
        let key = SecretKey32::random().map_err(|_| EnvelopeError::Seal)?;
        let mut id = [0u8; 16];
        getrandom::getrandom(&mut id).map_err(|_| EnvelopeError::Seal)?;
        Ok(Self { id: KeyId(id), key })
    }

    pub fn id(&self) -> KeyId {
        self.id
    }

    /// Borrow the raw key, e.g. to hand it to a `KeyWrapper`. Keep the borrow short and never
    /// copy it into an unprotected buffer.
    pub fn expose(&self) -> &[u8; 32] {
        self.key.expose()
    }
}

/// The output of [`seal_version`]: the blob to store and the data key to wrap.
///
/// No `Debug`, `Display` or `Clone`: it owns the DEK. Drop it (or the [`DataKey`] from
/// [`SealedVersion::into_parts`]) as soon as the DEK is wrapped.
pub struct SealedVersion {
    ciphertext: Vec<u8>,
    dek: DataKey,
}

impl SealedVersion {
    /// `header ‖ nonce ‖ ciphertext ‖ tag`. Safe to store and log the length of.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn dek(&self) -> &DataKey {
        &self.dek
    }

    pub fn into_parts(self) -> (Vec<u8>, DataKey) {
        (self.ciphertext, self.dek)
    }
}

/// Encrypt one secret version under a fresh DEK and a fresh random nonce, authenticating the
/// header and `binding`.
pub fn seal_version(
    binding: &Binding,
    plaintext: &SecretBytes,
) -> Result<SealedVersion, EnvelopeError> {
    let dek = DataKey::generate()?;
    let header = Header::v1(dek.id).encode();
    let sealed = aead::seal(&dek.key, plaintext.expose(), &header::aad(&header, binding))
        .map_err(|_| EnvelopeError::Seal)?;
    Ok(SealedVersion {
        ciphertext: header::assemble(&header, &sealed.nonce, &sealed.ct),
        dek,
    })
}

/// Decrypt a version blob for `binding`. Checks run in order: length, magic, format_ver,
/// alg_id, key_id against `dek`, then AEAD authentication.
pub fn open_version(
    dek: &DataKey,
    binding: &Binding,
    blob: &[u8],
) -> Result<SecretBytes, EnvelopeError> {
    let header = Header::parse(blob)?;
    header.require_alg(header::ALG_AES_256_GCM)?;
    if blob.len() < MIN_LEN {
        return Err(EnvelopeError::Truncated);
    }
    if header.key_id != dek.id {
        return Err(EnvelopeError::UnknownKeyId);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[HEADER_LEN..HEADER_LEN + NONCE_LEN]);
    let sealed = Sealed {
        nonce,
        ct: blob[HEADER_LEN + NONCE_LEN..].to_vec(),
    };
    aead::open(&dek.key, &sealed, &header::aad(&header.encode(), binding))
        .map_err(|_| EnvelopeError::Integrity)
}

/// Known-answer tests. The fixed key and nonce are injected only here: this module and its
/// `aes-gcm` dependency exist only under `cfg(test)` (a dev-dependency), so no production
/// build can seal with a chosen nonce. Reusing a nonce under one key breaks GCM.
#[cfg(test)]
mod kat {
    use super::*;
    use crate::header::Purpose;
    use aes_gcm::aead::{Aead, KeyInit, Payload};

    /// Same header, AAD and assembly as [`seal_version`]; only the nonce and key are fixed.
    fn seal_fixed(
        dek: &DataKey,
        binding: &Binding,
        nonce: [u8; NONCE_LEN],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let header = Header::v1(dek.id).encode();
        let ct = aes_gcm::Aes256Gcm::new(dek.expose().into())
            .encrypt(
                aes_gcm::Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: header::aad(&header, binding).as_bytes(),
                },
            )
            .expect("AES-GCM encrypt");
        header::assemble(&header, &nonce, &ct)
    }

    #[derive(serde::Deserialize)]
    struct File {
        vectors: Vec<Vector>,
    }

    #[derive(serde::Deserialize)]
    struct Vector {
        name: String,
        key: String,
        key_id: String,
        nonce: String,
        org_id: String,
        secret_id: String,
        version: u32,
        purpose: String,
        plaintext: String,
        aad: String,
        blob: String,
    }

    fn arr<const N: usize>(h: &str) -> [u8; N] {
        hex::decode(h).unwrap().try_into().unwrap()
    }

    impl Vector {
        fn dek(&self) -> DataKey {
            DataKey::from_parts(
                KeyId(arr(&self.key_id)),
                SecretKey32::from_bytes(arr(&self.key)),
            )
        }
        fn binding(&self) -> Binding {
            Binding {
                org_id: arr(&self.org_id),
                secret_id: arr(&self.secret_id),
                version: self.version,
                purpose: match self.purpose.as_str() {
                    "secret-payload" => Purpose::SecretPayload,
                    "dek-wrap" => Purpose::DekWrap,
                    p => panic!("unknown purpose {p}"),
                },
            }
        }
    }

    /// Committed vectors, generated independently by `vectors/gen_vectors.py`
    /// (pyca/cryptography AESGCM). The first one equals the A0-7 spike KAT, which was computed
    /// with PyCryptodome.
    fn vectors() -> Vec<Vector> {
        let f: File = serde_json::from_str(include_str!("../vectors/v1.json")).unwrap();
        assert!(f.vectors.len() >= 4, "vector file lost entries");
        f.vectors
    }

    #[test]
    fn kat_aad_encoding() {
        for v in vectors() {
            let header = Header::v1(KeyId(arr(&v.key_id))).encode();
            assert_eq!(
                hex::encode(header::aad(&header, &v.binding()).as_bytes()),
                v.aad,
                "{}",
                v.name
            );
        }
    }

    #[test]
    fn kat_seal_matches_byte_for_byte() {
        for v in vectors() {
            let pt = hex::decode(&v.plaintext).unwrap();
            let blob = seal_fixed(&v.dek(), &v.binding(), arr(&v.nonce), &pt);
            assert_eq!(hex::encode(blob), v.blob, "{}", v.name);
        }
    }

    #[test]
    fn kat_open_through_production_path() {
        for v in vectors() {
            let blob = hex::decode(&v.blob).unwrap();
            let pt = open_version(&v.dek(), &v.binding(), &blob).expect("KAT opens");
            // Compare without printing bytes on failure.
            assert!(
                pt.expose() == hex::decode(&v.plaintext).unwrap().as_slice(),
                "{}: plaintext mismatch",
                v.name
            );
        }
    }

    #[test]
    fn kat_matches_a0_spike_vector() {
        let v = &vectors()[0];
        assert_eq!(v.name, "a0-spike-payload");
        assert_eq!(
            v.blob,
            concat!(
                "4c53010111111111111111111111111111111111",
                "a0a1a2a3a4a5a6a7a8a9aaab",
                "8d7908002ba476920348f4b66408a5aa",
                "d4e2906a4553e136d4695ed2ace8486f",
            )
        );
    }

    /// The production seal must open with the same code path as the vectors, so a format
    /// drift between the KAT path and `seal_version` shows up here.
    #[test]
    fn production_seal_has_v1_layout() {
        let b = vectors()[0].binding();
        let pt = SecretBytes::new(b"layout".to_vec());
        let s = seal_version(&b, &pt).unwrap();
        let blob = s.ciphertext();
        assert_eq!(blob.len(), MIN_LEN + 6);
        assert_eq!(Header::parse(blob), Ok(Header::v1(s.dek().id())));
        let opened = open_version(s.dek(), &b, blob).unwrap();
        assert!(opened.expose() == b"layout");
    }
}
