//! Header format: round trip and tamper proptests (task 2.4).
//!
//! Plaintexts are derived from a seed inside each case, so a failing case prints only the
//! seed and length, never plaintext bytes. Comparisons use `assert!(a == b)`.

use a0_spikes::header::{
    self, Binding, FormatField, HEADER_LEN, Header, HeaderError, KeyId, Keyring, MIN_LEN,
    NONCE_LEN, Purpose,
};
use ls_crypto::SecretKey32;
use proptest::prelude::*;

fn plaintext(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn key(b: u8) -> SecretKey32 {
    SecretKey32::from_bytes([b; 32])
}

fn purpose() -> impl Strategy<Value = Purpose> {
    prop_oneof![Just(Purpose::SecretPayload), Just(Purpose::DekWrap)]
}

fn binding() -> impl Strategy<Value = Binding> {
    (
        any::<[u8; 16]>(),
        any::<[u8; 16]>(),
        any::<u32>(),
        purpose(),
    )
        .prop_map(|(org_id, secret_id, version, purpose)| Binding {
            org_id,
            secret_id,
            version,
            purpose,
        })
}

struct Fixture {
    keys: Keyring,
    key_id: KeyId,
    binding: Binding,
    blob: Vec<u8>,
}

fn fixture(key_id: [u8; 16], binding: Binding, seed: u64, len: usize) -> Fixture {
    let key_id = KeyId(key_id);
    let blob = header::seal(key_id, &key(7), &binding, &plaintext(seed, len)).unwrap();
    let mut keys = Keyring::new();
    keys.insert(key_id, key(7));
    Fixture {
        keys,
        key_id,
        binding,
        blob,
    }
}

fn open_err(f: &Fixture, binding: &Binding, blob: &[u8]) -> HeaderError {
    match header::open(&f.keys, binding, blob) {
        Ok(_) => panic!("tampered blob opened"),
        Err(e) => e,
    }
}

proptest! {
    #[test]
    fn round_trip(id in any::<[u8; 16]>(), b in binding(), seed in any::<u64>(), len in 0usize..2048) {
        let f = fixture(id, b, seed, len);
        prop_assert_eq!(f.blob.len(), MIN_LEN + len);
        prop_assert_eq!(Header::parse(&f.blob).unwrap(), Header::v1(f.key_id));
        let pt = header::open(&f.keys, &f.binding, &f.blob).expect("round trip opens");
        prop_assert!(pt.expose() == plaintext(seed, len).as_slice(), "plaintext mismatch");
    }

    // --- AAD fields: a moved ciphertext fails with Integrity -------------------------------

    #[test]
    fn tampered_org_id(id in any::<[u8; 16]>(), b in binding(), other in any::<[u8; 16]>(), seed in any::<u64>()) {
        prop_assume!(other != b.org_id);
        let f = fixture(id, b, seed, 32);
        let moved = Binding { org_id: other, ..b };
        prop_assert_eq!(open_err(&f, &moved, &f.blob), HeaderError::Integrity);
    }

    #[test]
    fn tampered_secret_id(id in any::<[u8; 16]>(), b in binding(), other in any::<[u8; 16]>(), seed in any::<u64>()) {
        prop_assume!(other != b.secret_id);
        let f = fixture(id, b, seed, 32);
        let moved = Binding { secret_id: other, ..b };
        prop_assert_eq!(open_err(&f, &moved, &f.blob), HeaderError::Integrity);
    }

    #[test]
    fn tampered_version(id in any::<[u8; 16]>(), b in binding(), other in any::<u32>(), seed in any::<u64>()) {
        prop_assume!(other != b.version);
        let f = fixture(id, b, seed, 32);
        let moved = Binding { version: other, ..b };
        prop_assert_eq!(open_err(&f, &moved, &f.blob), HeaderError::Integrity);
    }

    #[test]
    fn tampered_purpose(id in any::<[u8; 16]>(), b in binding(), seed in any::<u64>()) {
        let f = fixture(id, b, seed, 32);
        let other = match b.purpose {
            Purpose::SecretPayload => Purpose::DekWrap,
            Purpose::DekWrap => Purpose::SecretPayload,
        };
        let moved = Binding { purpose: other, ..b };
        prop_assert_eq!(open_err(&f, &moved, &f.blob), HeaderError::Integrity);
    }

    // --- Header fields: each fails with its own named error --------------------------------

    #[test]
    fn tampered_magic(id in any::<[u8; 16]>(), b in binding(), pos in 0usize..2, flip in 1u8..=255) {
        let f = fixture(id, b, 1, 32);
        let mut blob = f.blob.clone();
        blob[pos] ^= flip;
        prop_assert_eq!(open_err(&f, &b, &blob), HeaderError::BadMagic);
    }

    #[test]
    fn tampered_format_ver(id in any::<[u8; 16]>(), b in binding(), v in any::<u8>()) {
        prop_assume!(v != header::FORMAT_V1);
        let f = fixture(id, b, 1, 32);
        let mut blob = f.blob.clone();
        blob[2] = v;
        prop_assert_eq!(
            open_err(&f, &b, &blob),
            HeaderError::UnsupportedFormat { field: FormatField::Version, value: v }
        );
    }

    #[test]
    fn tampered_alg_id(id in any::<[u8; 16]>(), b in binding(), v in any::<u8>()) {
        prop_assume!(v != header::ALG_AES_256_GCM);
        let f = fixture(id, b, 1, 32);
        let mut blob = f.blob.clone();
        blob[3] = v;
        prop_assert_eq!(
            open_err(&f, &b, &blob),
            HeaderError::UnsupportedFormat { field: FormatField::Algorithm, value: v }
        );
    }

    #[test]
    fn tampered_key_id_unknown(id in any::<[u8; 16]>(), b in binding(), pos in 4usize..HEADER_LEN, flip in 1u8..=255) {
        let f = fixture(id, b, 1, 32);
        let mut blob = f.blob.clone();
        blob[pos] ^= flip;
        prop_assert_eq!(open_err(&f, &b, &blob), HeaderError::UnknownKeyId);
    }

    /// key_id rewritten to another key the opener holds: the header is bound into the AAD
    /// (and the key differs), so it fails authentication.
    #[test]
    fn tampered_key_id_known(id in any::<[u8; 16]>(), other in any::<[u8; 16]>(), b in binding()) {
        prop_assume!(id != other);
        let mut f = fixture(id, b, 1, 32);
        f.keys.insert(KeyId(other), key(7)); // same key bytes: only the header binding differs
        let mut blob = f.blob.clone();
        blob[4..HEADER_LEN].copy_from_slice(&other);
        prop_assert_eq!(open_err(&f, &b, &blob), HeaderError::Integrity);
    }

    #[test]
    fn tampered_nonce_ciphertext_or_tag(id in any::<[u8; 16]>(), b in binding(), len in 0usize..64, pos in any::<prop::sample::Index>(), flip in 1u8..=255) {
        let f = fixture(id, b, 1, len);
        let mut blob = f.blob.clone();
        let i = HEADER_LEN + pos.index(blob.len() - HEADER_LEN);
        blob[i] ^= flip;
        prop_assert_eq!(open_err(&f, &b, &blob), HeaderError::Integrity);
    }

    #[test]
    fn truncated(id in any::<[u8; 16]>(), b in binding(), cut in any::<prop::sample::Index>()) {
        let f = fixture(id, b, 1, 32);
        let n = cut.index(f.blob.len());
        let err = open_err(&f, &b, &f.blob[..n]);
        if n < MIN_LEN {
            prop_assert_eq!(err, HeaderError::Truncated);
        } else {
            prop_assert_eq!(err, HeaderError::Integrity);
        }
    }

    #[test]
    fn wrong_key_bytes(id in any::<[u8; 16]>(), b in binding()) {
        let mut f = fixture(id, b, 1, 32);
        f.keys.insert(KeyId(id), key(8));
        prop_assert_eq!(open_err(&f, &b, &f.blob), HeaderError::Integrity);
    }
}

#[test]
fn nonces_are_fresh() {
    let b = Binding {
        org_id: [1; 16],
        secret_id: [2; 16],
        version: 1,
        purpose: Purpose::SecretPayload,
    };
    let a = header::seal(KeyId([3; 16]), &key(1), &b, b"same").unwrap();
    let c = header::seal(KeyId([3; 16]), &key(1), &b, b"same").unwrap();
    assert_ne!(
        a[HEADER_LEN..HEADER_LEN + NONCE_LEN],
        c[HEADER_LEN..HEADER_LEN + NONCE_LEN]
    );
}

/// The DEK wrap uses the same header with Purpose::DekWrap.
#[test]
fn dek_wrap_round_trip() {
    let kek_id = KeyId([0xEE; 16]);
    let mut keys = Keyring::new();
    keys.insert(kek_id, key(0x42));
    let dek = SecretKey32::random().unwrap();
    let b = Binding {
        org_id: [1; 16],
        secret_id: [2; 16],
        version: 3,
        purpose: Purpose::DekWrap,
    };
    let wrapped = header::seal(kek_id, &key(0x42), &b, dek.expose()).unwrap();
    let unwrapped = header::open(&keys, &b, &wrapped).unwrap();
    assert!(unwrapped.expose() == dek.expose(), "DEK mismatch");
    let as_payload = Binding {
        purpose: Purpose::SecretPayload,
        ..b
    };
    assert_eq!(
        header::open(&keys, &as_payload, &wrapped).err(),
        Some(HeaderError::Integrity)
    );
}
