//! Shared test helpers: a synthetic ledger, test-only signing keys and a runner for the binary.
#![allow(dead_code)]

use std::path::Path;
use std::process::{Command, Output};

use ed25519_dalek::{Signer, SigningKey};
use ls_audit::{
    Actor, Attrs, CheckpointBody, Code, Event, GENESIS, Host, Record, SignedCheckpoint, Target,
    kind, outcome,
};
use serde_json::Value;
use uuid::Uuid;

/// The test-only seed of the checkpoint golden vector (`ls-audit/tests/fixtures`).
pub const SEED: [u8; 32] = [0x42; 32];
/// A second test-only seed: a key the verifier does not trust.
pub const OTHER_SEED: [u8; 32] = [0x17; 32];
pub const KEY_ID: &str = "audit-checkpoint:1";

pub fn event(n: i64) -> Event {
    Event {
        kind: kind::RELAY_ATTEMPT,
        actor: Actor::Agent(Uuid::from_u128(0xa1)),
        target: Some(Target::Secret(Uuid::from_u128(0xb2))),
        outcome: outcome::PENDING,
        attrs: Attrs::new()
            .host(Code::new("host"), Host::parse("api.example.com").unwrap())
            .int(Code::new("n"), n),
    }
}

/// `n` chained records for `org`.
pub fn ledger(org: Uuid, n: u64) -> Vec<Record> {
    let mut prev = GENESIS;
    (1..=n)
        .map(|seq| {
            let s = i64::try_from(seq).unwrap();
            let r = Record::new(
                org,
                seq,
                Uuid::now_v7(),
                1_763_400_000_000_000 + s,
                &event(s),
                prev,
            );
            prev = r.hash;
            r
        })
        .collect()
}

/// A checkpoint over `(org, seq, hash)` signed with `seed`.
pub fn sign(seed: &[u8; 32], org: Uuid, seq: u64, hash: [u8; 32]) -> SignedCheckpoint {
    let body = CheckpointBody {
        org_id: org,
        seq,
        hash,
        at_micros: 1_763_500_000_000_000,
    };
    SignedCheckpoint {
        body,
        key_id: KEY_ID.into(),
        signature: SigningKey::from_bytes(seed)
            .sign(&body.message())
            .to_bytes(),
    }
}

/// The checkpoint golden vector's public key (the verifying key of [`SEED`]).
pub fn fixture_public_key() -> [u8; 32] {
    let v: Value = serde_json::from_str(include_str!(
        "../../../ls-audit/tests/fixtures/checkpoint-v1.json"
    ))
    .unwrap();
    let public: [u8; 32] = hex::decode(v["ed25519_public"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        SigningKey::from_bytes(&SEED).verifying_key().to_bytes(),
        public
    );
    public
}

/// Write a verifier config trusting the golden vector's key, as `just up` writes it.
pub fn write_config(path: &Path) {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(fixture_public_key());
    let cfg = serde_json::json!({"checkpoint_keys": {KEY_ID: b64}});
    std::fs::write(path, cfg.to_string()).unwrap();
}

pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| panic!("{e}: {}", self.stdout))
    }
}

/// Run the binary with `args` and no inherited verifier env.
pub fn run(args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut c = Command::new(env!("CARGO_BIN_EXE_locksmith-audit"));
    c.args(args)
        .env_remove("LOCKSMITH_AUDIT_DATABASE_URL")
        .env_remove("LOCKSMITH_AUDIT_VERIFIER_CONFIG");
    for (k, v) in env {
        c.env(k, v);
    }
    let Output {
        status,
        stdout,
        stderr,
    } = c.output().unwrap();
    Run {
        code: status.code().unwrap(),
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
}
