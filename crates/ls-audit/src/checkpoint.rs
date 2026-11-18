//! Checkpoint bytes: what a signed checkpoint signs (S5 design decision 4, task 4.2).
//!
//! A checkpoint states "org `org_id`'s chain had `hash` at `seq` at time `at_micros`". Its
//! message is the [`Encoder`] encoding of those four fields, in that order, under its own domain
//! tag [`CHECKPOINT_DOMAIN`], so a checkpoint signature can never be confused with a ledger row
//! encoding (`locksmith-ledger-v1`) or any other signed message:
//!
//! ```text
//! "locksmith-checkpoint-v1"
//! || u32be(16) || org_id (16 bytes, UUID big-endian)
//! || u32be(8)  || seq (u64 big-endian)
//! || u32be(32) || hash (the row hash at seq)
//! || u32be(8)  || at_micros (i64 big-endian, Unix microseconds)
//! ```
//!
//! The control plane signs [`CheckpointBody::message`] with Ed25519 (OpenBao transit) and
//! stores it in `audit_checkpoints`; the offline verifier rebuilds the same bytes. The layout is
//! pinned by the golden vector in `tests/fixtures/checkpoint-v1.json`, which both use. The time
//! is informational (order is by `seq`), but it is signed, so it cannot be edited unnoticed.

use uuid::Uuid;

use crate::{Checkpoint, Encoder, Hash, decode};

/// Domain tag of checkpoint messages.
pub const CHECKPOINT_DOMAIN: &[u8] = b"locksmith-checkpoint-v1";

/// The signed content of a checkpoint. Identifiers and hashes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointBody {
    pub org_id: Uuid,
    /// The latest `seq` the checkpoint covers (>= 1).
    pub seq: u64,
    /// The row hash at `seq`.
    pub hash: Hash,
    /// When the checkpoint was taken, in Unix microseconds.
    pub at_micros: i64,
}

impl CheckpointBody {
    /// The bytes that are signed.
    pub fn message(&self) -> Vec<u8> {
        let mut e = Encoder::new(CHECKPOINT_DOMAIN);
        e.field(self.org_id.as_bytes())
            .field(&self.seq.to_be_bytes())
            .field(&self.hash)
            .field(&self.at_micros.to_be_bytes());
        e.finish()
    }

    /// Parses [`Self::message`] bytes. `None` for another domain tag, a field of the wrong
    /// length, or extra or missing fields.
    pub fn from_message(bytes: &[u8]) -> Option<Self> {
        let fields = decode(CHECKPOINT_DOMAIN, bytes)?;
        let [org, seq, hash, at] = fields.as_slice() else {
            return None;
        };
        Some(Self {
            org_id: Uuid::from_bytes(<[u8; 16]>::try_from(*org).ok()?),
            seq: u64::from_be_bytes(<[u8; 8]>::try_from(*seq).ok()?),
            hash: Hash::try_from(*hash).ok()?,
            at_micros: i64::from_be_bytes(<[u8; 8]>::try_from(*at).ok()?),
        })
    }

    /// The `(seq, hash)` pair the verify walk checks the chain against.
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            seq: self.seq,
            hash: self.hash,
        }
    }
}

/// A stored checkpoint: the body, the signing key's id (`<name>:<version>`, e.g.
/// `audit-checkpoint:1`) and the Ed25519 signature over [`CheckpointBody::message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCheckpoint {
    pub body: CheckpointBody,
    pub key_id: String,
    pub signature: [u8; 64],
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> CheckpointBody {
        CheckpointBody {
            org_id: Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a1),
            seq: 1000,
            hash: [0xab; 32],
            at_micros: 1_763_400_000_000_000,
        }
    }

    #[test]
    fn message_round_trips() {
        let b = body();
        let m = b.message();
        assert!(m.starts_with(CHECKPOINT_DOMAIN));
        assert_eq!(m.len(), CHECKPOINT_DOMAIN.len() + 4 * 4 + 16 + 8 + 32 + 8);
        assert_eq!(CheckpointBody::from_message(&m), Some(b));
        assert_eq!(
            b.checkpoint(),
            Checkpoint {
                seq: 1000,
                hash: [0xab; 32]
            }
        );
    }

    #[test]
    fn from_message_rejects_other_bytes() {
        let m = body().message();
        assert_eq!(CheckpointBody::from_message(&m[..m.len() - 1]), None);
        let mut extra = m.clone();
        extra.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(CheckpointBody::from_message(&extra), None);
        let mut ledger = crate::LEDGER_DOMAIN.to_vec();
        ledger.extend_from_slice(&m[CHECKPOINT_DOMAIN.len()..]);
        assert_eq!(CheckpointBody::from_message(&ledger), None, "ledger domain");
        // A 4-byte seq field instead of 8.
        let mut e = Encoder::new(CHECKPOINT_DOMAIN);
        e.field(&[0; 16])
            .field(&[0; 4])
            .field(&[0; 32])
            .field(&[0; 8]);
        assert_eq!(CheckpointBody::from_message(&e.finish()), None);
    }

    #[test]
    fn every_field_is_covered() {
        let b = body();
        let edits: Vec<fn(&mut CheckpointBody)> = vec![
            |b| b.org_id = Uuid::max(),
            |b| b.seq += 1,
            |b| b.hash[31] ^= 1,
            |b| b.at_micros += 1,
        ];
        for (i, edit) in edits.iter().enumerate() {
            let mut t = b;
            edit(&mut t);
            assert_ne!(t.message(), b.message(), "edit {i} not covered");
        }
    }
}
