//! Verifying one org's ledger against its signed checkpoints (S5 design decision 8, task 5.1).
//!
//! [`verify_org`] first checks each checkpoint's Ed25519 signature under a [`KeyRing`] of public
//! keys (`ed25519-dalek`, strict verification), then walks the records with [`crate::verify`],
//! trusting only the checkpoints whose signature verified. The org fails when:
//! - a record was edited, deleted, reordered or inserted (the walk's first break), or a record
//!   belongs to another org;
//! - a checkpoint's signature does not verify, names an unknown key, or names another org;
//! - a trusted checkpoint does not match the chain, or the chain ends before it (truncation).
//!
//! Pure: callers load the records and checkpoints (database or export directory) and the keys.
//! Public keys only; the signing key never leaves the KMS.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use uuid::Uuid;

use crate::checkpoint::SignedCheckpoint;
use crate::event::{AttrTag, Record, attr, kind};
use crate::{Break, BreakKind, Truncation, verify};

/// A public key that is not a valid Ed25519 point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidKey;

impl std::fmt::Display for InvalidKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not a valid Ed25519 public key")
    }
}

impl std::error::Error for InvalidKey {}

/// Checkpoint public keys by key id (`audit-checkpoint:1`, as in `audit_checkpoints.key_id`).
#[derive(Debug, Clone, Default)]
pub struct KeyRing(BTreeMap<String, VerifyingKey>);

impl KeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        key_id: impl Into<String>,
        public: &[u8; 32],
    ) -> Result<(), InvalidKey> {
        let vk = VerifyingKey::from_bytes(public).map_err(|_| InvalidKey)?;
        self.0.insert(key_id.into(), vk);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check `cp`'s signature under the key it names.
    pub fn check(&self, cp: &SignedCheckpoint) -> Result<(), CheckpointProblem> {
        let vk = self
            .0
            .get(&cp.key_id)
            .ok_or(CheckpointProblem::UnknownKey)?;
        let sig = Signature::from_bytes(&cp.signature);
        vk.verify_strict(&cp.body.message(), &sig)
            .map_err(|_| CheckpointProblem::BadSignature)
    }
}

/// Why a checkpoint is not trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointProblem {
    /// The key id is not in the verifier's key ring.
    UnknownKey,
    /// The signature does not verify under the named key (or the body was edited).
    BadSignature,
    /// The checkpoint names another org.
    OtherOrg,
}

impl CheckpointProblem {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownKey => "unknown_key",
            Self::BadSignature => "bad_signature",
            Self::OtherOrg => "other_org",
        }
    }
}

/// A checkpoint that failed its signature check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadCheckpoint {
    pub seq: u64,
    pub key_id: String,
    pub problem: CheckpointProblem,
}

/// The result for one org.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgReport {
    pub org_id: Uuid,
    /// Events checked.
    pub events: u64,
    /// Checkpoints checked (signature and chain).
    pub checkpoints: u64,
    /// The highest `seq` present (0 for none).
    pub last_seq: u64,
    /// The highest `seq` of a checkpoint whose signature verified.
    pub latest_checkpoint_seq: Option<u64>,
    /// The first broken record or trusted checkpoint in the chain.
    pub broken: Option<Break>,
    /// The chain ends before a trusted checkpoint.
    pub truncated: Option<Truncation>,
    /// Checkpoints whose signature did not verify, in `seq` order.
    pub bad_checkpoints: Vec<BadCheckpoint>,
    /// `relay.attempt` events with no `relay.outcome` naming them (informational: the gateway
    /// may still be retrying, or the upstream call ended without an outcome).
    pub open_attempts: u64,
}

impl OrgReport {
    pub fn ok(&self) -> bool {
        self.broken.is_none() && self.truncated.is_none() && self.bad_checkpoints.is_empty()
    }

    /// The first failure by `seq`: a chain break, a checkpoint with a bad signature (kind
    /// [`BreakKind::Checkpoint`]), in that order on a tie. Truncation is reported apart.
    pub fn first_break(&self) -> Option<Break> {
        let bad = self.bad_checkpoints.first().map(|c| Break {
            seq: c.seq,
            kind: BreakKind::Checkpoint,
        });
        match (self.broken, bad) {
            (Some(a), Some(b)) => Some(if b.seq < a.seq { b } else { a }),
            (a, b) => a.or(b),
        }
    }

    /// The first broken `seq`, counting a truncation as broken at the first missing `seq`.
    pub fn first_broken_seq(&self) -> Option<u64> {
        let t = self.truncated.map(|t| t.last_seq + 1);
        match (self.first_break().map(|b| b.seq), t) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

/// Verify `org_id`'s `records` (in the order the store returned them, which must be ascending
/// `seq`) against its signed `checkpoints` under `keys`.
pub fn verify_org(
    org_id: Uuid,
    records: &[Record],
    checkpoints: &[SignedCheckpoint],
    keys: &KeyRing,
) -> OrgReport {
    let mut bad = Vec::new();
    let mut trusted = Vec::new();
    for cp in checkpoints {
        let checked = if cp.body.org_id == org_id {
            keys.check(cp)
        } else {
            Err(CheckpointProblem::OtherOrg)
        };
        match checked {
            Ok(()) => trusted.push(cp.body.checkpoint()),
            Err(problem) => bad.push(BadCheckpoint {
                seq: cp.body.seq,
                key_id: cp.key_id.clone(),
                problem,
            }),
        }
    }
    bad.sort_by_key(|b| b.seq);

    let walk = verify(records.iter().map(Record::link), &trusted);
    // A record of another org (e.g. a whole chain copied into this org's export) counts as an
    // edited row: its own hash may be intact, but it is not this org's event.
    let foreign = records.iter().find(|r| r.org_id != org_id).map(|r| Break {
        seq: r.seq,
        kind: BreakKind::Hash,
    });
    let broken = match (walk.broken, foreign) {
        (Some(a), Some(b)) => Some(if b.seq < a.seq { b } else { a }),
        (a, b) => a.or(b),
    };

    OrgReport {
        org_id,
        events: walk.rows,
        checkpoints: u64::try_from(checkpoints.len()).unwrap_or(u64::MAX),
        last_seq: walk.last_seq,
        latest_checkpoint_seq: trusted.iter().map(|c| c.seq).max(),
        broken,
        truncated: walk.truncated,
        bad_checkpoints: bad,
        open_attempts: open_attempts(records),
    }
}

fn open_attempts(records: &[Record]) -> u64 {
    let closed: BTreeSet<&str> = records
        .iter()
        .filter(|r| r.kind == kind::RELAY_OUTCOME.as_str())
        .filter_map(|r| r.attrs.as_ref())
        .flat_map(|a| a.entries())
        .filter(|(k, t, _)| k == attr::ATTEMPT_ID.as_str() && *t == AttrTag::Id)
        .map(|(_, _, v)| v.as_str())
        .collect();
    let open = records
        .iter()
        .filter(|r| r.kind == kind::RELAY_ATTEMPT.as_str())
        .filter(|r| !closed.contains(r.id.hyphenated().to_string().as_str()))
        .count();
    u64::try_from(open).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::GENESIS;
    use crate::checkpoint::CheckpointBody;
    use crate::event::{Actor, Attrs, Code, Event, Host, Target, outcome};

    const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_00000000000a);
    const OTHER: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_00000000000b);
    const KEY_ID: &str = "audit-checkpoint:1";
    /// Test-only signing seeds.
    const SEED: [u8; 32] = [0x42; 32];
    const OTHER_SEED: [u8; 32] = [0x17; 32];

    fn event(i: u64) -> Event {
        let (k, o) = if i % 2 == 1 {
            (kind::RELAY_ATTEMPT, outcome::PENDING)
        } else {
            (kind::RELAY_OUTCOME, outcome::OK)
        };
        Event {
            kind: k,
            actor: Actor::Agent(Uuid::from_u128(0xa1)),
            target: Some(Target::Secret(Uuid::from_u128(0xb2))),
            outcome: o,
            attrs: Attrs::new()
                .host(Code::new("host"), Host::parse("api.example.com").unwrap())
                .int(Code::new("status"), 200),
        }
    }

    /// A synthetic ledger of `n` events for `org`: odd seqs are attempts, even seqs the outcome
    /// of the attempt before them.
    fn ledger(org: Uuid, n: u64) -> Vec<Record> {
        let mut out: Vec<Record> = Vec::new();
        let mut prev = GENESIS;
        for seq in 1..=n {
            let mut e = event(seq);
            if seq % 2 == 0 {
                let attempt = out.last().unwrap().id;
                e.attrs = e.attrs.id(attr::ATTEMPT_ID, attempt);
            }
            let id = Uuid::from_u128(org.as_u128().wrapping_add(u128::from(seq) << 64));
            let r = Record::new(
                org,
                seq,
                id,
                1_763_400_000_000_000 + i64::try_from(seq).unwrap(),
                &e,
                prev,
            );
            prev = r.hash;
            out.push(r);
        }
        out
    }

    fn sign(seed: &[u8; 32], r: &Record) -> SignedCheckpoint {
        let body = CheckpointBody {
            org_id: r.org_id,
            seq: r.seq,
            hash: r.hash,
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

    fn keys() -> KeyRing {
        let mut k = KeyRing::new();
        k.insert(
            KEY_ID,
            &SigningKey::from_bytes(&SEED).verifying_key().to_bytes(),
        )
        .unwrap();
        k
    }

    /// Ten events with checkpoints at 4 and 8.
    fn fixture() -> (Vec<Record>, Vec<SignedCheckpoint>) {
        let l = ledger(ORG, 10);
        let cps = vec![sign(&SEED, &l[3]), sign(&SEED, &l[7])];
        (l, cps)
    }

    fn rehash(r: &mut Record) {
        r.hash = r.compute_hash();
    }

    #[test]
    fn intact_ledger_passes() {
        let (l, cps) = fixture();
        let r = verify_org(ORG, &l, &cps, &keys());
        assert!(r.ok(), "{r:?}");
        assert_eq!((r.events, r.checkpoints, r.last_seq), (10, 2, 10));
        assert_eq!(r.latest_checkpoint_seq, Some(8));
        assert_eq!(r.first_broken_seq(), None);
        assert_eq!(r.open_attempts, 0);
        let empty = verify_org(ORG, &[], &[], &keys());
        assert!(empty.ok());
        assert_eq!(empty.events, 0);
    }

    #[test]
    fn edited_field_fails_at_that_seq() {
        let (mut l, cps) = fixture();
        l[5].outcome = "denied".into();
        let r = verify_org(ORG, &l, &cps, &keys());
        assert_eq!(
            r.broken,
            Some(Break {
                seq: 6,
                kind: BreakKind::Hash
            })
        );
        assert_eq!(r.first_broken_seq(), Some(6));
        // Recomputing the edited row's hash moves the break to the next link.
        rehash(&mut l[5]);
        let r = verify_org(ORG, &l, &cps, &keys());
        assert_eq!(
            r.broken,
            Some(Break {
                seq: 7,
                kind: BreakKind::Link
            })
        );
    }

    #[test]
    fn deleted_row_fails_at_its_seq() {
        let (mut l, cps) = fixture();
        l.remove(2);
        let r = verify_org(ORG, &l, &cps, &keys());
        assert_eq!(
            r.broken,
            Some(Break {
                seq: 3,
                kind: BreakKind::Sequence
            })
        );
        assert!(!r.ok());
    }

    #[test]
    fn swapped_seqs_fail_at_the_first_one() {
        let (mut l, cps) = fixture();
        // Swap the seq values of rows 3 and 4 and reorder as `ORDER BY seq` would.
        l[2].seq = 4;
        l[3].seq = 3;
        l.swap(2, 3);
        let r = verify_org(ORG, &l, &cps, &keys());
        assert_eq!(r.first_broken_seq(), Some(3), "{r:?}");
        assert!(!r.ok());
    }

    #[test]
    fn tail_truncation_past_a_checkpoint_is_reported() {
        let (l, cps) = fixture();
        let r = verify_org(ORG, &l[..6], &cps, &keys());
        assert_eq!(r.broken, None);
        assert_eq!(
            r.truncated,
            Some(Truncation {
                checkpoint_seq: 8,
                last_seq: 6
            })
        );
        assert_eq!(r.first_broken_seq(), Some(7));
        assert!(!r.ok());
        // Truncation after the latest checkpoint is not detectable from the chain alone.
        assert!(verify_org(ORG, &l[..9], &cps, &keys()).ok());
    }

    #[test]
    fn rewritten_history_fails_against_a_signed_checkpoint() {
        let (mut l, cps) = fixture();
        // The strongest database-owner edit: rewrite seq 2 and recompute every later link.
        l[1].outcome = "error".into();
        let mut prev = l[0].hash;
        for r in &mut l[1..] {
            r.prev_hash = prev;
            rehash(r);
            prev = r.hash;
        }
        // Without checkpoints the chain is self-consistent.
        assert!(verify_org(ORG, &l, &[], &keys()).ok());
        let r = verify_org(ORG, &l, &cps, &keys());
        assert_eq!(
            r.broken,
            Some(Break {
                seq: 4,
                kind: BreakKind::Checkpoint
            })
        );
    }

    #[test]
    fn bad_checkpoint_signatures_fail() {
        let (l, mut cps) = fixture();
        // Signed with another key.
        cps[1] = sign(&OTHER_SEED, &l[7]);
        let r = verify_org(ORG, &l, &cps, &keys());
        assert_eq!(
            r.bad_checkpoints,
            vec![BadCheckpoint {
                seq: 8,
                key_id: KEY_ID.into(),
                problem: CheckpointProblem::BadSignature
            }]
        );
        assert_eq!(r.latest_checkpoint_seq, Some(4));
        assert_eq!(
            r.first_break(),
            Some(Break {
                seq: 8,
                kind: BreakKind::Checkpoint
            })
        );
        assert!(!r.ok());

        // An edited body (time) under the original signature.
        let (l, mut cps) = fixture();
        cps[0].body.at_micros += 1;
        let r = verify_org(ORG, &l, &cps, &keys());
        assert_eq!(
            r.bad_checkpoints[0].problem,
            CheckpointProblem::BadSignature
        );

        // An unknown key id.
        let (l, mut cps) = fixture();
        cps[0].key_id = "audit-checkpoint:9".into();
        let r = verify_org(ORG, &l, &cps, &keys());
        assert_eq!(r.bad_checkpoints[0].problem, CheckpointProblem::UnknownKey);
        assert_eq!(r.first_broken_seq(), Some(4));

        // Another org's (validly signed) checkpoint.
        let other = ledger(OTHER, 4);
        let (l, mut cps) = fixture();
        cps.push(sign(&SEED, &other[3]));
        let r = verify_org(ORG, &l, &cps, &keys());
        assert_eq!(r.bad_checkpoints[0].problem, CheckpointProblem::OtherOrg);

        // No keys at all: every checkpoint is untrusted.
        let (l, cps) = fixture();
        let r = verify_org(ORG, &l, &cps, &KeyRing::new());
        assert_eq!(r.bad_checkpoints.len(), 2);
    }

    #[test]
    fn another_orgs_chain_is_rejected() {
        let other = ledger(OTHER, 4);
        let r = verify_org(ORG, &other, &[], &keys());
        assert_eq!(
            r.broken,
            Some(Break {
                seq: 1,
                kind: BreakKind::Hash
            })
        );
    }

    #[test]
    fn open_attempts_are_counted() {
        let l = ledger(ORG, 5);
        let r = verify_org(ORG, &l, &[], &keys());
        assert!(r.ok());
        assert_eq!(r.open_attempts, 1, "seq 5 has no outcome");
    }

    #[test]
    fn invalid_public_key_is_refused() {
        let mut k = KeyRing::new();
        // y = 2 is not on the curve (no valid x), so decompression fails.
        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;
        assert_eq!(k.insert("x", &not_a_point), Err(InvalidKey));
        assert!(k.is_empty());
    }
}
