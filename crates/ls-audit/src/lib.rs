//! Hash-chain core shared by the vault audit ledger (`ls-vault`) and the server audit ledger
//! (extracted from `ls-vault` so the server ledger reuses one encoder and verify walk, without
//! pulling SQLCipher into services).
//!
//! Pure: no IO, no clock, no keys. It provides
//! - [`Encoder`]: a deterministic encoding, a domain tag followed by every field as a big-endian
//!   `u32` length and the bytes, in a fixed order chosen by the caller;
//! - [`row_hash`]: `SHA256(canonical || suffix)`, the link the next row stores as `prev_hash`
//!   (the vault passes its MAC as the suffix; the server ledger passes nothing);
//! - [`verify`]: a walk over rows in `seq` order and trusted checkpoints that reports the first
//!   broken `seq` and whether the tail was truncated below a checkpoint.
//!
//! Records carry identifiers only: callers never encode a secret value.
//!
//! [`event`] defines the server ledger's events and records (allow-listed identifier types
//! only). [`checkpoint`] defines the bytes a signed checkpoint signs (domain tag
//! `locksmith-checkpoint-v1`). The `postgres` feature adds [`pg`], the Postgres store with the
//! transactional append; without it the crate stays pure.
//!
//! [`verifier`] checks one org's records against its signed checkpoints under a set of public
//! keys (task 5.1), and [`export`] defines the JSON Lines an export directory holds, so the
//! offline verifier and the exporter read and write the same format.

use sha2::{Digest, Sha256};

pub mod checkpoint;
pub mod event;
pub mod export;
#[cfg(feature = "postgres")]
pub mod pg;
pub mod verifier;

pub use checkpoint::{CHECKPOINT_DOMAIN, CheckpointBody, SignedCheckpoint};
pub use event::{
    Actor, AttrTag, AttrValue, Attrs, Code, Event, Host, InvalidIdentifier, Record, StoredAttrs,
    Target, Text, attr, kind, outcome,
};

/// Domain tag of the server ledger (`audit_events` in Postgres).
pub const LEDGER_DOMAIN: &[u8] = b"locksmith-ledger-v1";

/// A SHA-256 output.
pub type Hash = [u8; 32];

/// `prev_hash` of the first row (seq 1).
pub const GENESIS: Hash = [0u8; 32];

/// Builds a canonical encoding: the domain tag, then each field as `u32` BE length + bytes.
#[derive(Debug, Clone)]
pub struct Encoder {
    out: Vec<u8>,
}

impl Encoder {
    pub fn new(domain: &[u8]) -> Self {
        Self {
            out: domain.to_vec(),
        }
    }

    /// An encoder for the server ledger domain.
    pub fn ledger() -> Self {
        Self::new(LEDGER_DOMAIN)
    }

    /// Appends one field.
    ///
    /// # Panics
    /// If the field is longer than `u32::MAX` bytes (records hold short identifiers only).
    pub fn field(&mut self, b: &[u8]) -> &mut Self {
        let len = u32::try_from(b.len()).expect("audit field longer than u32::MAX bytes");
        self.out.extend_from_slice(&len.to_be_bytes());
        self.out.extend_from_slice(b);
        self
    }

    /// Appends an optional field: `[0]` for `None`, `[1] || bytes` for `Some`.
    pub fn opt_field(&mut self, o: Option<&[u8]>) -> &mut Self {
        match o {
            None => self.field(&[0]),
            Some(b) => {
                let mut v = Vec::with_capacity(b.len() + 1);
                v.push(1);
                v.extend_from_slice(b);
                self.field(&v)
            }
        }
    }

    pub fn finish(self) -> Vec<u8> {
        self.out
    }
}

/// Splits a canonical encoding back into its fields. `None` if the domain tag does not match
/// or the bytes are not a whole number of length-prefixed fields.
pub fn decode<'a>(domain: &[u8], bytes: &'a [u8]) -> Option<Vec<&'a [u8]>> {
    let mut rest = bytes.strip_prefix(domain)?;
    let mut fields = Vec::new();
    while !rest.is_empty() {
        let (len, tail) = rest.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
        if tail.len() < len {
            return None;
        }
        let (f, tail) = tail.split_at(len);
        fields.push(f);
        rest = tail;
    }
    Some(fields)
}

/// Decodes a field written by [`Encoder::opt_field`].
pub fn decode_opt(field: &[u8]) -> Option<Option<&[u8]>> {
    match field.split_first()? {
        (0, []) => Some(None),
        (1, b) => Some(Some(b)),
        _ => None,
    }
}

/// `SHA256(canonical || suffix)`: the hash of a row that the next row links to.
pub fn row_hash(canonical: &[u8], suffix: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(canonical);
    h.update(suffix);
    h.finalize().into()
}

/// One row as the verify walk sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    pub seq: u64,
    /// The `prev_hash` stored in the row.
    pub prev_hash: Hash,
    /// The row hash recomputed from the row's contents ([`row_hash`]).
    pub hash: Hash,
    /// The hash stored in the row, if the store keeps one (the server ledger does).
    pub stored_hash: Option<Hash>,
}

/// A trusted `(seq, hash)` pair, e.g. from a signed checkpoint; `hash` is the row hash at `seq`
/// (seq 0 means the empty chain, hash [`GENESIS`]). Signature checks happen before the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub seq: u64,
    pub hash: Hash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakKind {
    /// The expected `seq` is not next: a row was deleted, duplicated or reordered.
    Sequence,
    /// `prev_hash` does not match the previous row's hash: the previous row was edited, or rows
    /// were deleted or reordered.
    Link,
    /// The stored hash does not match the recomputed one: this row was edited.
    Hash,
    /// The row hash does not match a trusted checkpoint at this `seq`.
    Checkpoint,
}

impl BreakKind {
    /// The stored and printed name (`audit_verify_runs.break_kind`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sequence => "sequence",
            Self::Link => "link",
            Self::Hash => "hash",
            Self::Checkpoint => "checkpoint",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Break {
    /// First `seq` whose check failed (for [`BreakKind::Sequence`], the `seq` that was expected).
    pub seq: u64,
    pub kind: BreakKind,
}

/// The chain ends below a trusted checkpoint: rows after `last_seq` were removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncation {
    /// The highest checkpoint `seq`.
    pub checkpoint_seq: u64,
    /// The highest `seq` present (0 for no rows).
    pub last_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Walk {
    /// Rows consumed.
    pub rows: u64,
    /// The highest `seq` present (0 for no rows).
    pub last_seq: u64,
    /// Hash of the last row verified before any break ([`GENESIS`] if none).
    pub head: Hash,
    pub broken: Option<Break>,
    pub truncated: Option<Truncation>,
}

impl Walk {
    /// No break and no truncation.
    pub fn ok(&self) -> bool {
        self.broken.is_none() && self.truncated.is_none()
    }
}

/// Walks `rows` (in ascending `seq` order, starting at 1) and checks contiguity, `prev_hash`
/// links, stored hashes and every checkpoint the chain reaches. Stops checking at the first
/// break but still consumes the rest to report `rows`, `last_seq` and truncation.
pub fn verify<I>(rows: I, checkpoints: &[Checkpoint]) -> Walk
where
    I: IntoIterator<Item = Link>,
{
    let mut cps: Vec<&Checkpoint> = checkpoints.iter().collect();
    cps.sort_by_key(|c| c.seq);
    let mut cp = 0usize;
    let mut broken = None;
    // Checkpoints at seq 0 pin the empty chain.
    while cp < cps.len() && cps[cp].seq == 0 {
        if cps[cp].hash != GENESIS && broken.is_none() {
            broken = Some(Break {
                seq: 0,
                kind: BreakKind::Checkpoint,
            });
        }
        cp += 1;
    }

    let mut head = GENESIS;
    let mut rows_n = 0u64;
    let mut last_seq = 0u64;
    for r in rows {
        rows_n += 1;
        last_seq = last_seq.max(r.seq);
        if broken.is_some() {
            continue;
        }
        let want = rows_n;
        let kind = if r.seq != want {
            broken = Some(Break {
                seq: want,
                kind: BreakKind::Sequence,
            });
            continue;
        } else if r.prev_hash != head {
            Some(BreakKind::Link)
        } else if r.stored_hash.is_some_and(|h| h != r.hash) {
            Some(BreakKind::Hash)
        } else {
            None
        };
        if let Some(kind) = kind {
            broken = Some(Break { seq: r.seq, kind });
            continue;
        }
        while cp < cps.len() && cps[cp].seq < r.seq {
            cp += 1;
        }
        while cp < cps.len() && cps[cp].seq == r.seq {
            if cps[cp].hash != r.hash {
                broken = Some(Break {
                    seq: r.seq,
                    kind: BreakKind::Checkpoint,
                });
            }
            cp += 1;
        }
        if broken.is_none() {
            head = r.hash;
        }
    }

    let truncated = cps.last().filter(|c| c.seq > last_seq).map(|c| Truncation {
        checkpoint_seq: c.seq,
        last_seq,
    });
    Walk {
        rows: rows_n,
        last_seq,
        head,
        broken,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn encoder_layout() {
        let mut e = Encoder::new(b"d");
        e.field(b"ab")
            .opt_field(None)
            .opt_field(Some(b"x"))
            .field(b"");
        assert_eq!(
            e.finish(),
            b"d\0\0\0\x02ab\0\0\0\x01\0\0\0\0\x02\x01x\0\0\0\0".to_vec()
        );
    }

    #[test]
    fn ledger_domain_tag() {
        assert_eq!(Encoder::ledger().finish(), b"locksmith-ledger-v1".to_vec());
    }

    #[test]
    fn row_hash_is_sha256_of_concatenation() {
        // SHA-256("abc"), FIPS 180-2 appendix B.1.
        let want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(hx(&row_hash(b"abc", b"")), want);
        assert_eq!(hx(&row_hash(b"a", b"bc")), want);
    }

    #[test]
    fn decode_rejects_bad_input() {
        assert_eq!(decode(b"d", b"x"), None, "wrong domain");
        assert_eq!(decode(b"d", b"d\0\0"), None, "short length");
        assert_eq!(decode(b"d", b"d\0\0\0\x03ab"), None, "short field");
        assert_eq!(decode(b"d", b"d"), Some(vec![]));
        assert_eq!(decode_opt(b""), None);
        assert_eq!(decode_opt(b"\0x"), None);
        assert_eq!(decode_opt(b"\x02"), None);
    }

    fn chain(n: u64) -> Vec<Link> {
        let mut prev = GENESIS;
        (1..=n)
            .map(|seq| {
                let mut e = Encoder::ledger();
                e.field(&seq.to_be_bytes()).field(&prev);
                let hash = row_hash(&e.finish(), &[]);
                let l = Link {
                    seq,
                    prev_hash: prev,
                    hash,
                    stored_hash: Some(hash),
                };
                prev = hash;
                l
            })
            .collect()
    }

    #[test]
    fn empty_and_intact_chains_verify() {
        let w = verify(Vec::new(), &[]);
        assert!(w.ok());
        assert_eq!((w.rows, w.last_seq, w.head), (0, 0, GENESIS));
        let c = chain(4);
        let cps = [
            Checkpoint {
                seq: 2,
                hash: c[1].hash,
            },
            Checkpoint {
                seq: 0,
                hash: GENESIS,
            },
        ];
        let w = verify(c.clone(), &cps);
        assert!(w.ok(), "{w:?}");
        assert_eq!((w.rows, w.last_seq, w.head), (4, 4, c[3].hash));
    }

    #[test]
    fn each_break_kind_is_reported_at_the_first_bad_seq() {
        let c = chain(5);
        let mut gap = c.clone();
        gap.remove(2);
        assert_eq!(
            verify(gap, &[]).broken,
            Some(Break {
                seq: 3,
                kind: BreakKind::Sequence
            })
        );
        let mut link = c.clone();
        link[3].prev_hash[0] ^= 1;
        assert_eq!(
            verify(link, &[]).broken,
            Some(Break {
                seq: 4,
                kind: BreakKind::Link
            })
        );
        let mut edited = c.clone();
        edited[1].hash[0] ^= 1;
        assert_eq!(
            verify(edited, &[]).broken,
            Some(Break {
                seq: 2,
                kind: BreakKind::Hash
            })
        );
        let cp = Checkpoint {
            seq: 3,
            hash: [9; 32],
        };
        let w = verify(c.clone(), &[cp]);
        assert_eq!(
            w.broken,
            Some(Break {
                seq: 3,
                kind: BreakKind::Checkpoint
            })
        );
        assert_eq!(w.head, c[1].hash, "head stops before the break");
        let w = verify(
            Vec::new(),
            &[Checkpoint {
                seq: 0,
                hash: [1; 32],
            }],
        );
        assert_eq!(w.broken.map(|b| b.seq), Some(0));
    }

    #[test]
    fn truncation_below_a_checkpoint_is_reported() {
        let c = chain(5);
        let cp = Checkpoint {
            seq: 5,
            hash: c[4].hash,
        };
        let w = verify(c[..3].to_vec(), &[cp]);
        assert_eq!(w.broken, None);
        assert_eq!(
            w.truncated,
            Some(Truncation {
                checkpoint_seq: 5,
                last_seq: 3
            })
        );
        assert!(!w.ok());
        let w = verify(Vec::new(), &[cp]);
        assert_eq!(w.truncated.map(|t| t.last_seq), Some(0));
    }
}
