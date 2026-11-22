//! The gateway's signature over an environment seal key (t7 design decision 2).
//!
//! The gateway signs `(org, environment, key_id, public key)` with its Ed25519 identity key when
//! it provisions an environment's seal key. Every client pins the gateway's verifying key and
//! calls [`verify_seal_key`] before sealing, so a control plane that serves its own key cannot
//! get a value sealed to it. This crate only verifies; signing lives in the gateway, and the
//! control plane never holds the signing key.
//!
//! Signed message, each field a big-endian `u16` length then its bytes (the
//! [`ls_crypto::aead::Aad`] encoding, so field boundaries cannot shift):
//!
//! ```text
//! "locksmith.seal-key.v1" | org_id(16) | environment_id(16) | key_id(16) | public_key(32)
//! ```
//!
//! The domain tag keeps the signature from being valid for any other gateway-signed message.

use crate::{EnvelopeError, KeyId, SealPublicKey};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ls_crypto::aead::Aad;

/// Domain separation tag, the first field of the signed message.
pub const SEAL_KEY_SIG_DOMAIN: &[u8] = b"locksmith.seal-key.v1";
/// Length of an Ed25519 signature.
pub const SEAL_KEY_SIG_LEN: usize = 64;
/// Length of an Ed25519 verifying key.
pub const GATEWAY_VERIFYING_KEY_LEN: usize = 32;

/// The exact bytes the gateway signs for an environment seal key.
pub fn seal_key_message(
    org_id: &[u8; 16],
    environment_id: &[u8; 16],
    key_id: &KeyId,
    public_key: &SealPublicKey,
) -> Vec<u8> {
    Aad::new()
        .field(SEAL_KEY_SIG_DOMAIN)
        .field(org_id)
        .field(environment_id)
        .field(&key_id.0)
        .field(&public_key.to_bytes())
        .as_bytes()
        .to_vec()
}

/// Check `signature` over the seal key against the pinned gateway verifying key. Any failure
/// (malformed key or signature, or a signature over a different org, environment, key id or
/// public key) is [`EnvelopeError::Integrity`]; the caller must then seal and send nothing.
pub fn verify_seal_key(
    gateway_verifying_key: &[u8; GATEWAY_VERIFYING_KEY_LEN],
    org_id: &[u8; 16],
    environment_id: &[u8; 16],
    key_id: &KeyId,
    public_key: &SealPublicKey,
    signature: &[u8; SEAL_KEY_SIG_LEN],
) -> Result<(), EnvelopeError> {
    let vk =
        VerifyingKey::from_bytes(gateway_verifying_key).map_err(|_| EnvelopeError::Integrity)?;
    let sig = Signature::from_bytes(signature);
    let msg = seal_key_message(org_id, environment_id, key_id, public_key);
    vk.verify_strict(&msg, &sig)
        .map_err(|_| EnvelopeError::Integrity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct File {
        vectors: Vec<Vector>,
    }

    #[derive(serde::Deserialize)]
    struct Vector {
        name: String,
        verifying_key: String,
        org_id: String,
        environment_id: String,
        key_id: String,
        public_key: String,
        message: String,
        signature: String,
    }

    fn arr<const N: usize>(h: &str) -> [u8; N] {
        hex::decode(h).unwrap().try_into().unwrap()
    }

    /// Generated independently by `vectors/gen_seal_key_sig_vectors.py` (hand-written message,
    /// pyca/cryptography Ed25519), not by the code under test.
    fn vectors() -> Vec<Vector> {
        let f: File =
            serde_json::from_str(include_str!("../vectors/seal-key-sig-v1.json")).unwrap();
        assert!(f.vectors.len() >= 3, "vector file lost entries");
        f.vectors
    }

    impl Vector {
        fn parts(&self) -> ([u8; 16], [u8; 16], KeyId, SealPublicKey) {
            (
                arr(&self.org_id),
                arr(&self.environment_id),
                KeyId(arr(&self.key_id)),
                SealPublicKey::from_bytes(arr(&self.public_key)),
            )
        }
    }

    #[test]
    fn seal_key_sig_message_matches_vectors() {
        for v in vectors() {
            let (o, e, k, p) = v.parts();
            assert_eq!(
                hex::encode(seal_key_message(&o, &e, &k, &p)),
                v.message,
                "{}",
                v.name
            );
        }
    }

    #[test]
    fn seal_key_sig_vectors_verify() {
        for v in vectors() {
            let (o, e, k, p) = v.parts();
            verify_seal_key(&arr(&v.verifying_key), &o, &e, &k, &p, &arr(&v.signature))
                .unwrap_or_else(|_| panic!("{} did not verify", v.name));
        }
    }

    #[test]
    fn seal_key_sig_refuses_substituted_inputs() {
        let v = &vectors()[0];
        let (o, e, k, p) = v.parts();
        let vk = arr(&v.verifying_key);
        let sig = arr(&v.signature);
        // A substituted public key (the control plane's own).
        let other_pk = SealPublicKey::from_bytes([7u8; 32]);
        assert_eq!(
            verify_seal_key(&vk, &o, &e, &k, &other_pk, &sig),
            Err(EnvelopeError::Integrity)
        );
        // Another org, environment or key id.
        let mut o2 = o;
        o2[0] ^= 1;
        assert!(verify_seal_key(&vk, &o2, &e, &k, &p, &sig).is_err());
        let mut e2 = e;
        e2[0] ^= 1;
        assert!(verify_seal_key(&vk, &o, &e2, &k, &p, &sig).is_err());
        assert!(verify_seal_key(&vk, &o, &e, &KeyId([9u8; 16]), &p, &sig).is_err());
        // A different (unpinned) verifying key, and a flipped signature bit.
        let other_vk = arr(&vectors()[2].verifying_key);
        assert!(verify_seal_key(&other_vk, &o, &e, &k, &p, &sig).is_err());
        let mut bad = sig;
        bad[10] ^= 1;
        assert!(verify_seal_key(&vk, &o, &e, &k, &p, &bad).is_err());
    }
}
