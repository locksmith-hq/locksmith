//! A data key sealed with HPKE to an environment seal key (t7 design decision 1, `alg_id` 2).
//!
//! The browser, CLI and SDK seal a version's DEK to the environment's X25519 public key; only
//! the gateway, which holds the private half, can open it. HPKE base mode (RFC 9180) with
//! DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM. Stored form (100 bytes):
//!
//! ```text
//! magic(2) "LS" | format_ver(1) = 1 | alg_id(1) = 2 | key_id(16) | enc(32) | ct(32) | tag(16)
//! ```
//!
//! - `key_id` names the environment seal key (opaque 16 bytes chosen by the key's owner).
//! - `enc` is the HPKE encapsulated key (the sender's ephemeral X25519 public key).
//! - `info` = `org_id ‖ secret_id ‖ version(u32 BE) ‖ "dek-wrap"`, each field a big-endian
//!   `u16` length then its bytes (the [`ls_crypto::aead::Aad`] encoding), so the HPKE key
//!   schedule itself is bound to the version.
//! - AAD = the same length-prefixed AAD every A0-7 blob uses ([`crate::header`]): label, the 20
//!   header bytes, then the binding. Any change to the header (alg_id, key_id) or the binding
//!   fails authentication.
//!
//! The KMS-wrapped format (`alg_id` 1, [`crate::WrappedDek`]) is unchanged; a reader picks the
//! opener by the `alg_id` from [`crate::Header::parse`].
//!
//! The ephemeral key comes from 32 bytes of OS randomness (`getrandom`, fallible) fed to HPKE
//! as its only random input (`DeriveKeyPair(ikmE)`, RFC 9180 section 4.1), so an RNG failure is
//! an error rather than a panic. The seed-taking function is private; only tests call it with chosen bytes.

use crate::header::{self, Binding, HEADER_LEN, Header, KeyId, Purpose, TAG_LEN};
use crate::{DataKey, EnvelopeError};
use hpke::aead::{AeadTag, AesGcm256};
use hpke::inout::InOutBuf;
use hpke::kdf::HkdfSha256;
use hpke::kem::{Kem as _, X25519HkdfSha256};
use hpke::rand_core::{TryCryptoRng, TryRng};
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use ls_crypto::SecretKey32;
use ls_crypto::aead::Aad;
use std::convert::Infallible;
use zeroize::Zeroizing;

type Kem = X25519HkdfSha256;

/// Length of the HPKE encapsulated key (`Nenc` for DHKEM(X25519, HKDF-SHA256)).
pub const HPKE_ENC_LEN: usize = 32;
/// Length of an HPKE-wrapped DEK: header, `enc`, the 32-byte DEK ciphertext and the tag.
pub const HPKE_WRAPPED_DEK_LEN: usize = HEADER_LEN + HPKE_ENC_LEN + 32 + TAG_LEN;

/// An environment seal key's public half. Not secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealPublicKey(<Kem as hpke::Kem>::PublicKey);

impl SealPublicKey {
    /// Any 32 bytes are an X25519 public key; a low-order key makes sealing fail.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(
            <Kem as hpke::Kem>::PublicKey::from_bytes(&bytes)
                .expect("32 bytes is the X25519 public key length"),
        )
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes().into()
    }
}

/// An environment seal key's private half (X25519). Held only by the gateway.
///
/// No `Debug`, `Display`, `Clone` or serde. The inner key is zeroized on drop.
pub struct SealPrivateKey(<Kem as hpke::Kem>::PrivateKey);

impl SealPrivateKey {
    /// Take a private key from its 32 raw bytes (e.g. after the KMS unwraps it). The bytes are
    /// clamped as RFC 7748 requires; `key` is zeroized when it drops here.
    pub fn from_secret(key: SecretKey32) -> Self {
        Self(
            <Kem as hpke::Kem>::PrivateKey::from_bytes(key.expose())
                .expect("32 bytes is the X25519 private key length"),
        )
    }

    /// A fresh random key pair from OS randomness.
    pub fn generate() -> Result<Self, EnvelopeError> {
        let ikm = SecretKey32::random().map_err(|_| EnvelopeError::Seal)?;
        let (sk, _) = Kem::derive_keypair(ikm.expose());
        Ok(Self(sk))
    }

    pub fn public_key(&self) -> SealPublicKey {
        SealPublicKey(Kem::sk_to_pk(&self.0))
    }
}

/// `info` for the HPKE key schedule: `org_id ‖ secret_id ‖ version ‖ purpose`, length-prefixed.
fn info(b: &Binding) -> Aad {
    Aad::new()
        .field(&b.org_id)
        .field(&b.secret_id)
        .field(&b.version.to_be_bytes())
        .field(b.purpose.label())
}

fn require_dek_wrap(b: &Binding) -> Result<(), EnvelopeError> {
    if b.purpose == Purpose::DekWrap {
        Ok(())
    } else {
        Err(EnvelopeError::Purpose)
    }
}

/// Seal `dek` to `recipient` for `binding` (purpose must be [`Purpose::DekWrap`]). `key_id`
/// names the recipient's seal key and goes into the header. Returns the 100-byte stored form.
pub fn seal_dek_hpke(
    dek: &DataKey,
    recipient: &SealPublicKey,
    key_id: KeyId,
    binding: &Binding,
) -> Result<Vec<u8>, EnvelopeError> {
    let ikm_e = SecretKey32::random().map_err(|_| EnvelopeError::Seal)?;
    seal_with_ikm(dek.expose(), recipient, key_id, binding, ikm_e.expose())
}

/// The one sealing path. `ikm_e` is the only randomness HPKE uses (the ephemeral key is
/// `DeriveKeyPair(ikm_e)`); production passes fresh OS randomness, only tests choose it.
fn seal_with_ikm(
    dek: &[u8; 32],
    recipient: &SealPublicKey,
    key_id: KeyId,
    binding: &Binding,
    ikm_e: &[u8; 32],
) -> Result<Vec<u8>, EnvelopeError> {
    require_dek_wrap(binding)?;
    let header = Header::hpke_dek(key_id).encode();
    let mut rng = IkmRng::new(ikm_e);
    // Encrypted in place: after a successful seal the buffer holds ciphertext; on failure it is
    // zeroized on drop.
    let mut buf = Zeroizing::new(*dek);
    let (enc, tag) = hpke::single_shot_seal_inout_detached_with_rng::<AesGcm256, HkdfSha256, Kem>(
        &OpModeS::Base,
        &recipient.0,
        info(binding).as_bytes(),
        InOutBuf::from(&mut buf[..]),
        header::aad(&header, binding).as_bytes(),
        &mut rng,
    )
    .map_err(|_| EnvelopeError::Seal)?;
    if !rng.exactly_consumed() {
        return Err(EnvelopeError::Seal);
    }
    let mut out = Vec::with_capacity(HPKE_WRAPPED_DEK_LEN);
    out.extend_from_slice(&header);
    out.extend_from_slice(&enc.to_bytes());
    out.extend_from_slice(&buf[..]);
    out.extend_from_slice(&tag.to_bytes());
    debug_assert_eq!(out.len(), HPKE_WRAPPED_DEK_LEN);
    Ok(out)
}

/// Open an HPKE-wrapped DEK with the environment's private key for `binding` (purpose must be
/// [`Purpose::DekWrap`]). Checks run in order: length, magic, format_ver, alg_id, then HPKE
/// decapsulation and AEAD authentication (which also covers the header `key_id`).
///
/// Rebuild the [`DataKey`] with [`DataKey::from_parts`] and the payload's header key id.
pub fn open_dek_hpke(
    recipient: &SealPrivateKey,
    binding: &Binding,
    wrapped: &[u8],
) -> Result<SecretKey32, EnvelopeError> {
    require_dek_wrap(binding)?;
    let header = Header::parse(wrapped)?;
    header.require_alg(header::ALG_HPKE_X25519_SHA256_AES256GCM)?;
    if wrapped.len() != HPKE_WRAPPED_DEK_LEN {
        return Err(EnvelopeError::Truncated);
    }
    let (enc, rest) = wrapped[HEADER_LEN..].split_at(HPKE_ENC_LEN);
    let (ct, tag) = rest.split_at(32);
    let enc =
        <Kem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| EnvelopeError::Integrity)?;
    let tag = AeadTag::<AesGcm256>::from_bytes(tag).map_err(|_| EnvelopeError::Integrity)?;
    let mut buf = Zeroizing::new([0u8; 32]);
    buf.copy_from_slice(ct);
    hpke::single_shot_open_inout_detached::<AesGcm256, HkdfSha256, Kem>(
        &OpModeR::Base,
        &recipient.0,
        &enc,
        info(binding).as_bytes(),
        InOutBuf::from(&mut buf[..]),
        header::aad(&header.encode(), binding).as_bytes(),
        &tag,
    )
    .map_err(|_| EnvelopeError::Integrity)?;
    // `from_bytes` wipes its argument; `buf` is zeroized on drop as well.
    Ok(SecretKey32::from_bytes(*buf))
}

/// Hands HPKE exactly the 32 bytes of `ikm_e`. Any other demand is recorded and makes the seal
/// fail, so a change in how the library draws randomness cannot silently weaken the key.
struct IkmRng<'a> {
    ikm: &'a [u8; 32],
    used: usize,
    overdrawn: bool,
}

impl<'a> IkmRng<'a> {
    fn new(ikm: &'a [u8; 32]) -> Self {
        Self {
            ikm,
            used: 0,
            overdrawn: false,
        }
    }

    fn exactly_consumed(&self) -> bool {
        !self.overdrawn && self.used == self.ikm.len()
    }
}

impl TryRng for IkmRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let end = self.used + dst.len();
        if end > self.ikm.len() {
            self.overdrawn = true;
            dst.fill(0);
        } else {
            dst.copy_from_slice(&self.ikm[self.used..end]);
            self.used = end;
        }
        Ok(())
    }
}

// Sound only because `seal_with_ikm` is given fresh OS randomness in production and refuses
// output when the library asked for more than it got.
impl TryCryptoRng for IkmRng<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{ALG_AES_256_GCM, FormatField};
    use crate::{open_version, seal_version};
    use ls_crypto::SecretBytes;

    fn binding() -> Binding {
        Binding {
            org_id: [1; 16],
            secret_id: [2; 16],
            version: 7,
            purpose: Purpose::DekWrap,
        }
    }

    fn pair() -> (SealPrivateKey, SealPublicKey) {
        let sk = SealPrivateKey::generate().unwrap();
        let pk = sk.public_key();
        (sk, pk)
    }

    fn dek() -> DataKey {
        DataKey::from_parts(KeyId([9; 16]), SecretKey32::from_bytes([0x5a; 32]))
    }

    /// Compare keys without printing them on failure.
    fn same_key(a: &SecretKey32, b: &DataKey) -> bool {
        a.expose() == b.expose()
    }

    #[test]
    fn hpke_round_trip() {
        let (sk, pk) = pair();
        let d = dek();
        let w = seal_dek_hpke(&d, &pk, KeyId([3; 16]), &binding()).unwrap();
        assert_eq!(w.len(), HPKE_WRAPPED_DEK_LEN);
        assert_eq!(w.len(), 100);
        assert_eq!(Header::parse(&w), Ok(Header::hpke_dek(KeyId([3; 16]))));
        assert!(same_key(&open_dek_hpke(&sk, &binding(), &w).unwrap(), &d));
        // Fresh ephemeral key per seal.
        let w2 = seal_dek_hpke(&d, &pk, KeyId([3; 16]), &binding()).unwrap();
        assert_ne!(w[HEADER_LEN..], w2[HEADER_LEN..]);
    }

    #[test]
    fn hpke_wrong_binding_fails() {
        let (sk, pk) = pair();
        let w = seal_dek_hpke(&dek(), &pk, KeyId([3; 16]), &binding()).unwrap();
        let b = binding();
        for other in [
            Binding {
                org_id: [9; 16],
                ..b
            },
            Binding {
                secret_id: [9; 16],
                ..b
            },
            Binding { version: 8, ..b },
        ] {
            assert_eq!(
                open_dek_hpke(&sk, &other, &w).err(),
                Some(EnvelopeError::Integrity)
            );
        }
        let payload = Binding {
            purpose: Purpose::SecretPayload,
            ..b
        };
        assert_eq!(
            open_dek_hpke(&sk, &payload, &w).err(),
            Some(EnvelopeError::Purpose)
        );
        assert_eq!(
            seal_dek_hpke(&dek(), &pk, KeyId([3; 16]), &payload).err(),
            Some(EnvelopeError::Purpose)
        );
    }

    #[test]
    fn hpke_tampered_enc_ct_tag_fail() {
        let (sk, pk) = pair();
        let w = seal_dek_hpke(&dek(), &pk, KeyId([3; 16]), &binding()).unwrap();
        // Every byte of enc, ct and tag.
        for i in HEADER_LEN..w.len() {
            let mut t = w.clone();
            t[i] ^= 0x01;
            assert_eq!(
                open_dek_hpke(&sk, &binding(), &t).err(),
                Some(EnvelopeError::Integrity),
                "byte {i}"
            );
        }
    }

    #[test]
    fn hpke_tampered_header_aad_fails() {
        let (sk, pk) = pair();
        let w = seal_dek_hpke(&dek(), &pk, KeyId([3; 16]), &binding()).unwrap();
        // key_id bytes still parse, so only the AAD catches them.
        for i in 4..HEADER_LEN {
            let mut t = w.clone();
            t[i] ^= 0x80;
            assert_eq!(
                open_dek_hpke(&sk, &binding(), &t).err(),
                Some(EnvelopeError::Integrity),
                "header byte {i}"
            );
        }
        let mut t = w.clone();
        t[3] = ALG_AES_256_GCM;
        assert_eq!(
            open_dek_hpke(&sk, &binding(), &t).err(),
            Some(EnvelopeError::UnsupportedFormat {
                field: FormatField::Algorithm,
                value: ALG_AES_256_GCM
            })
        );
        let mut t = w.clone();
        t[2] = 2;
        assert!(matches!(
            open_dek_hpke(&sk, &binding(), &t),
            Err(EnvelopeError::UnsupportedFormat {
                field: FormatField::Version,
                ..
            })
        ));
        let mut t = w;
        t[0] = b'X';
        assert_eq!(
            open_dek_hpke(&sk, &binding(), &t).err(),
            Some(EnvelopeError::BadMagic)
        );
    }

    #[test]
    fn hpke_wrong_private_key_fails() {
        let (_, pk) = pair();
        let (other, _) = pair();
        let w = seal_dek_hpke(&dek(), &pk, KeyId([3; 16]), &binding()).unwrap();
        assert_eq!(
            open_dek_hpke(&other, &binding(), &w).err(),
            Some(EnvelopeError::Integrity)
        );
    }

    #[test]
    fn hpke_truncated_or_extended_input_fails() {
        let (sk, pk) = pair();
        let w = seal_dek_hpke(&dek(), &pk, KeyId([3; 16]), &binding()).unwrap();
        for n in 0..w.len() {
            let r = open_dek_hpke(&sk, &binding(), &w[..n]).err();
            assert_eq!(r, Some(EnvelopeError::Truncated), "len {n}");
        }
        let mut long = w;
        long.push(0);
        assert_eq!(
            open_dek_hpke(&sk, &binding(), &long).err(),
            Some(EnvelopeError::Truncated)
        );
    }

    #[test]
    fn hpke_low_order_public_key_refused() {
        // The all-zero point gives an all-zero DH output, which RFC 9180 requires refusing.
        let pk = SealPublicKey::from_bytes([0; 32]);
        assert_eq!(
            seal_dek_hpke(&dek(), &pk, KeyId([3; 16]), &binding()).err(),
            Some(EnvelopeError::Seal)
        );
    }

    #[test]
    fn hpke_rng_seam_refuses_overdraw() {
        let ikm = [7u8; 32];
        let mut r = IkmRng::new(&ikm);
        let mut b = [0u8; 32];
        r.try_fill_bytes(&mut b).unwrap();
        assert!(r.exactly_consumed());
        r.try_fill_bytes(&mut [0u8; 1]).unwrap();
        assert!(!r.exactly_consumed());
    }

    /// The existing formats still work next to `alg_id` 2: a payload sealed with
    /// `seal_version` opens, a KMS-format wrapped DEK still parses, and neither opener accepts
    /// the other's `alg_id`.
    #[test]
    fn hpke_existing_formats_still_work() {
        let pb = Binding {
            purpose: Purpose::SecretPayload,
            ..binding()
        };
        let s = seal_version(&pb, &SecretBytes::new(b"value".to_vec())).unwrap();
        let (sk, pk) = pair();
        let w = seal_dek_hpke(s.dek(), &pk, KeyId([3; 16]), &binding()).unwrap();
        let dek = DataKey::from_parts(
            Header::parse(s.ciphertext()).unwrap().key_id,
            open_dek_hpke(&sk, &binding(), &w).unwrap(),
        );
        assert!(open_version(&dek, &pb, s.ciphertext()).unwrap().expose() == b"value");

        // A payload blob is not an HPKE-wrapped DEK, and vice versa.
        assert_eq!(
            open_dek_hpke(&sk, &binding(), s.ciphertext()).err(),
            Some(EnvelopeError::UnsupportedFormat {
                field: FormatField::Algorithm,
                value: ALG_AES_256_GCM
            })
        );
        assert_eq!(
            open_version(&dek, &pb, &w).err(),
            Some(EnvelopeError::UnsupportedFormat {
                field: FormatField::Algorithm,
                value: header::ALG_HPKE_X25519_SHA256_AES256GCM
            })
        );
        // The KMS wrapped-DEK parser refuses alg_id 2.
        assert!(matches!(
            crate::WrappedDek::from_bytes(w),
            Err(crate::WrapError::Format(EnvelopeError::UnsupportedFormat {
                field: FormatField::Algorithm,
                ..
            }))
        ));
    }

    /// Known-answer vectors. `seal_with_ikm` is the production sealing path with the ephemeral
    /// input fixed; it is private and only this `cfg(test)` module passes a chosen value.
    mod kat {
        use super::*;

        #[derive(serde::Deserialize)]
        struct File {
            vectors: Vec<Vector>,
        }

        #[derive(serde::Deserialize)]
        struct Vector {
            name: String,
            sk_r: String,
            pk_r: String,
            ikm_e: String,
            key_id: String,
            org_id: String,
            secret_id: String,
            version: u32,
            dek: String,
            info: String,
            aad: String,
            wrapped: String,
        }

        fn arr<const N: usize>(h: &str) -> [u8; N] {
            hex::decode(h).unwrap().try_into().unwrap()
        }

        impl Vector {
            fn binding(&self) -> Binding {
                Binding {
                    org_id: arr(&self.org_id),
                    secret_id: arr(&self.secret_id),
                    version: self.version,
                    purpose: Purpose::DekWrap,
                }
            }
            fn sk(&self) -> SealPrivateKey {
                SealPrivateKey::from_secret(SecretKey32::from_bytes(arr(&self.sk_r)))
            }
        }

        /// Generated independently by `vectors/gen_hpke_vectors.py` (RFC 9180 written out over
        /// pyca/cryptography X25519, HMAC-SHA256 and AESGCM), not by the code under test.
        fn vectors() -> Vec<Vector> {
            let f: File = serde_json::from_str(include_str!("../vectors/hpke-v1.json")).unwrap();
            assert!(f.vectors.len() >= 3, "vector file lost entries");
            f.vectors
        }

        #[test]
        fn hpke_kat_public_key_info_and_aad() {
            for v in vectors() {
                assert_eq!(
                    hex::encode(v.sk().public_key().to_bytes()),
                    v.pk_r,
                    "{}",
                    v.name
                );
                assert_eq!(
                    hex::encode(info(&v.binding()).as_bytes()),
                    v.info,
                    "{}",
                    v.name
                );
                let h = Header::hpke_dek(KeyId(arr(&v.key_id))).encode();
                assert_eq!(
                    hex::encode(header::aad(&h, &v.binding()).as_bytes()),
                    v.aad,
                    "{}",
                    v.name
                );
            }
        }

        #[test]
        fn hpke_kat_seal_matches_byte_for_byte() {
            for v in vectors() {
                let w = seal_with_ikm(
                    &arr(&v.dek),
                    &SealPublicKey::from_bytes(arr(&v.pk_r)),
                    KeyId(arr(&v.key_id)),
                    &v.binding(),
                    &arr(&v.ikm_e),
                )
                .unwrap();
                assert_eq!(hex::encode(w), v.wrapped, "{}", v.name);
            }
        }

        #[test]
        fn hpke_kat_open_through_production_path() {
            for v in vectors() {
                let w = hex::decode(&v.wrapped).unwrap();
                let k = open_dek_hpke(&v.sk(), &v.binding(), &w).expect("KAT opens");
                assert!(
                    k.expose()[..] == hex::decode(&v.dek).unwrap()[..],
                    "{}: DEK mismatch",
                    v.name
                );
            }
        }
    }
}
