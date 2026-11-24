//! Envelope properties (task 1.2): round trip, any bit flip fails, each binding field is
//! enforced, nonces and DEKs are never reused.
//!
//! Plaintexts are derived from a seed inside each case, so a failing case prints only the seed
//! and length, never plaintext bytes. Comparisons use `assert!(a == b)`.

use ls_envelope::header::{HEADER_LEN, MIN_LEN, NONCE_LEN};
use ls_envelope::{
    Binding, DataKey, EnvelopeError, Header, KeyId, Purpose, SealedVersion, SecretBytes,
    SecretKey32, open_version, seal_version,
};
use proptest::prelude::*;
use std::collections::HashSet;

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

fn purpose() -> impl Strategy<Value = Purpose> {
    prop_oneof![
        Just(Purpose::SecretPayload),
        Just(Purpose::DekWrap),
        Just(Purpose::OAuthToken)
    ]
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

fn seal(b: &Binding, seed: u64, len: usize) -> SealedVersion {
    seal_version(b, &SecretBytes::new(plaintext(seed, len))).expect("seal")
}

fn open_err(dek: &DataKey, b: &Binding, blob: &[u8]) -> EnvelopeError {
    match open_version(dek, b, blob) {
        Ok(_) => panic!("blob opened when it must not"),
        Err(e) => e,
    }
}

proptest! {
    #[test]
    fn round_trip(b in binding(), seed in any::<u64>(), len in 0usize..2048) {
        let s = seal(&b, seed, len);
        prop_assert_eq!(s.ciphertext().len(), MIN_LEN + len);
        prop_assert_eq!(Header::parse(s.ciphertext()).unwrap(), Header::v1(s.dek().id()));
        let pt = open_version(s.dek(), &b, s.ciphertext()).expect("round trip opens");
        prop_assert!(pt.expose() == plaintext(seed, len).as_slice(), "plaintext mismatch");
    }

    /// Flipping any single bit anywhere in the blob (header, nonce, ciphertext or tag) fails.
    #[test]
    fn any_bit_flip_fails(b in binding(), seed in any::<u64>(), len in 0usize..96, pos in any::<prop::sample::Index>(), bit in 0u8..8) {
        let s = seal(&b, seed, len);
        let mut blob = s.ciphertext().to_vec();
        let i = pos.index(blob.len());
        blob[i] ^= 1 << bit;
        let err = open_err(s.dek(), &b, &blob);
        // Header bytes fail with their named error; everything after the header fails AEAD.
        if i >= HEADER_LEN {
            prop_assert_eq!(err, EnvelopeError::Integrity);
        }
    }

    #[test]
    fn wrong_org_id(b in binding(), other in any::<[u8; 16]>(), seed in any::<u64>()) {
        prop_assume!(other != b.org_id);
        let s = seal(&b, seed, 32);
        let moved = Binding { org_id: other, ..b };
        prop_assert_eq!(open_err(s.dek(), &moved, s.ciphertext()), EnvelopeError::Integrity);
    }

    #[test]
    fn wrong_secret_id(b in binding(), other in any::<[u8; 16]>(), seed in any::<u64>()) {
        prop_assume!(other != b.secret_id);
        let s = seal(&b, seed, 32);
        let moved = Binding { secret_id: other, ..b };
        prop_assert_eq!(open_err(s.dek(), &moved, s.ciphertext()), EnvelopeError::Integrity);
    }

    #[test]
    fn wrong_version(b in binding(), other in any::<u32>(), seed in any::<u64>()) {
        prop_assume!(other != b.version);
        let s = seal(&b, seed, 32);
        let moved = Binding { version: other, ..b };
        prop_assert_eq!(open_err(s.dek(), &moved, s.ciphertext()), EnvelopeError::Integrity);
    }

    #[test]
    fn wrong_purpose(b in binding(), seed in any::<u64>()) {
        let s = seal(&b, seed, 32);
        let other = match b.purpose {
            Purpose::SecretPayload => Purpose::DekWrap,
            Purpose::DekWrap => Purpose::OAuthToken,
            Purpose::OAuthToken => Purpose::SecretPayload,
        };
        let moved = Binding { purpose: other, ..b };
        prop_assert_eq!(open_err(s.dek(), &moved, s.ciphertext()), EnvelopeError::Integrity);
    }

    /// Another version's DEK cannot open this blob, whether or not its id is relabelled.
    #[test]
    fn wrong_dek(b in binding(), seed in any::<u64>()) {
        let s = seal(&b, seed, 32);
        let other = seal(&b, seed, 32);
        prop_assert_eq!(open_err(other.dek(), &b, s.ciphertext()), EnvelopeError::UnknownKeyId);
        let relabelled = DataKey::from_parts(
            s.dek().id(),
            SecretKey32::from_bytes(*other.dek().expose()),
        );
        prop_assert_eq!(open_err(&relabelled, &b, s.ciphertext()), EnvelopeError::Integrity);
    }

    /// Rewriting key_id in the header to match another DEK still fails: the header is in the AAD.
    #[test]
    fn key_id_swapped_to_other_dek(b in binding(), seed in any::<u64>()) {
        let s = seal(&b, seed, 32);
        let other_id = KeyId([0x5A; 16]);
        prop_assume!(other_id != s.dek().id());
        let mut blob = s.ciphertext().to_vec();
        blob[4..HEADER_LEN].copy_from_slice(&other_id.0);
        let same_key = DataKey::from_parts(other_id, SecretKey32::from_bytes(*s.dek().expose()));
        prop_assert_eq!(open_err(&same_key, &b, &blob), EnvelopeError::Integrity);
    }

    #[test]
    fn truncated(b in binding(), cut in any::<prop::sample::Index>()) {
        let s = seal(&b, 1, 32);
        let n = cut.index(s.ciphertext().len());
        let err = open_err(s.dek(), &b, &s.ciphertext()[..n]);
        if n < MIN_LEN {
            prop_assert_eq!(err, EnvelopeError::Truncated);
        } else {
            prop_assert_eq!(err, EnvelopeError::Integrity);
        }
    }

    /// Versions of one secret never share a DEK, a DEK id or a nonce.
    #[test]
    fn deks_and_nonces_are_fresh(b in binding(), n in 2usize..32) {
        let mut nonces = HashSet::new();
        let mut ids = HashSet::new();
        let mut keys = HashSet::new();
        for v in 0..n {
            let s = seal(&Binding { version: v as u32, ..b }, 7, 16);
            let blob = s.ciphertext();
            prop_assert!(nonces.insert(blob[HEADER_LEN..HEADER_LEN + NONCE_LEN].to_vec()));
            prop_assert!(ids.insert(s.dek().id()));
            prop_assert!(keys.insert(*s.dek().expose()), "DEK reused");
        }
    }
}

/// Same binding and plaintext sealed twice: different nonce, DEK and ciphertext.
#[test]
fn identical_inputs_seal_differently() {
    let b = Binding {
        org_id: [1; 16],
        secret_id: [2; 16],
        version: 1,
        purpose: Purpose::SecretPayload,
    };
    let mut nonces = HashSet::new();
    for _ in 0..1000 {
        let s = seal(&b, 3, 8);
        assert!(nonces.insert(s.ciphertext()[HEADER_LEN..HEADER_LEN + NONCE_LEN].to_vec()));
    }
    let a = seal(&b, 3, 8);
    let c = seal(&b, 3, 8);
    assert_ne!(a.ciphertext(), c.ciphertext());
    assert!(a.dek().expose() != c.dek().expose(), "DEK reused");
}

/// Errors name the failing check and carry no plaintext, whichever way they are formatted.
#[test]
fn errors_never_contain_plaintext() {
    let canary = b"CANARY-ls-envelope-0123456789";
    let b = Binding {
        org_id: [1; 16],
        secret_id: [2; 16],
        version: 1,
        purpose: Purpose::SecretPayload,
    };
    let s = seal_version(&b, &SecretBytes::new(canary.to_vec())).unwrap();
    let canary_str = std::str::from_utf8(canary).unwrap();
    let canary_hex: String = canary.iter().map(|x| format!("{x:02x}")).collect();
    let moved = Binding { version: 2, ..b };
    let mut flipped = s.ciphertext().to_vec();
    *flipped.last_mut().unwrap() ^= 1;
    let errs = [
        open_err(s.dek(), &moved, s.ciphertext()),
        open_err(s.dek(), &b, &flipped),
        open_err(s.dek(), &b, &s.ciphertext()[..10]),
    ];
    for e in errs {
        for text in [e.to_string(), format!("{e:?}")] {
            assert!(!text.contains(canary_str), "error text contains plaintext");
            assert!(
                !text.to_lowercase().contains(&canary_hex),
                "error text contains plaintext hex"
            );
        }
    }
}
