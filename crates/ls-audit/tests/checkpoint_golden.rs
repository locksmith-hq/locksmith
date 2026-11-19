//! S5 task 4.2: the checkpoint bytes are pinned by a golden vector in
//! `tests/fixtures/checkpoint-v1.json`, which the offline verifier reads too. A change to the
//! layout invalidates every stored checkpoint signature, so it must show up here.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ls_audit::{CHECKPOINT_DOMAIN, CheckpointBody};
use serde_json::Value;
use uuid::Uuid;

/// The fixture's test-only signing seed (documented in the fixture's comment).
const TEST_SEED: [u8; 32] = [0x42; 32];

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/checkpoint-v1.json")).unwrap()
}

fn hex_field<const N: usize>(v: &Value, k: &str) -> [u8; N] {
    let b = hex::decode(v[k].as_str().unwrap()).unwrap();
    <[u8; N]>::try_from(b).unwrap()
}

fn body(v: &Value) -> CheckpointBody {
    CheckpointBody {
        org_id: Uuid::parse_str(v["org_id"].as_str().unwrap()).unwrap(),
        seq: v["seq"].as_u64().unwrap(),
        hash: hex_field(v, "hash"),
        at_micros: v["at_micros"].as_i64().unwrap(),
    }
}

#[test]
fn checkpoint_message_golden_vector() {
    let v = fixture();
    let b = body(&v);
    let m = b.message();
    assert!(m.starts_with(CHECKPOINT_DOMAIN));
    assert_eq!(hex::encode(&m), v["message"].as_str().unwrap());
    assert_eq!(CheckpointBody::from_message(&m), Some(b));
}

#[test]
fn checkpoint_signature_golden_vector() {
    let v = fixture();
    let m = body(&v).message();
    let sk = SigningKey::from_bytes(&TEST_SEED);
    let public: [u8; 32] = hex_field(&v, "ed25519_public");
    assert_eq!(sk.verifying_key().to_bytes(), public);
    // Ed25519 is deterministic, so the fixture's signature is exactly what the key produces.
    let sig = Signature::from_bytes(&hex_field(&v, "signature"));
    assert_eq!(sk.sign(&m), sig);
    let vk = VerifyingKey::from_bytes(&public).unwrap();
    assert!(vk.verify_strict(&m, &sig).is_ok());
    let mut edited = m.clone();
    *edited.last_mut().unwrap() ^= 1;
    assert!(vk.verify_strict(&edited, &sig).is_err());
}

/// Prints the values for the fixture (run with `--ignored --nocapture` after a deliberate change).
#[test]
#[ignore = "generator for tests/fixtures/checkpoint-v1.json"]
fn print_fixture_values() {
    let m = body(&fixture()).message();
    let sk = SigningKey::from_bytes(&TEST_SEED);
    println!("message {}", hex::encode(&m));
    println!(
        "ed25519_public {}",
        hex::encode(sk.verifying_key().to_bytes())
    );
    println!("signature {}", hex::encode(sk.sign(&m).to_bytes()));
}
