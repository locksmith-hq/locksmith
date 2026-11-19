//! The export directory format (S5 design decision 7): what `locksmith-audit export` writes
//! (task 5.2) and `locksmith-audit verify --dir` reads (task 5.1).
//!
//! ```text
//! <dir>/<org_id>/events-<first_seq>.jsonl one event per line, in seq order
//! <dir>/<org_id>/checkpoints.jsonl        one signed checkpoint per line
//! <dir>/<org_id>/cursor.json              the org's committed export position (not read by verify)
//! ```
//!
//! The cursor is the commit point of an export batch (task 5.2): event files whose first `seq`
//! is above the cursor's `seq`, and checkpoint lines above its `checkpoint_seq`, were written by
//! a run that stopped before committing, and the next run replaces them. A cursor line:
//!
//! ```json
//! {"org_id":"<uuid>","seq":1500,"hash":"<hex>","checkpoint_seq":1000}
//! ```
//!
//! An event line holds every `audit_events` column, so the row hash can be recomputed offline:
//!
//! ```json
//! {"org_id":"<uuid>","seq":1,"id":"<uuid>","at_micros":1763400000000000,
//!  "kind":"relay.attempt","actor":"agent:<uuid>","target":"secret:<uuid>","outcome":"pending",
//!  "attrs":{"host":{"host":"api.example.com"}},"prev_hash":"<hex>","hash":"<hex>"}
//! ```
//!
//! A checkpoint line holds the signed body plus the key id and signature:
//!
//! ```json
//! {"org_id":"<uuid>","seq":1000,"hash":"<hex>","at_micros":1763400000000000,
//!  "key_id":"audit-checkpoint:1","signature":"<hex>"}
//! ```
//!
//! Lines carry identifiers and hashes only, like the ledger. Parsing is strict about types and
//! does not normalise values, so an edited line either fails to parse or changes the row hash.
//! Pure: callers do the file IO.

use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::checkpoint::{CheckpointBody, SignedCheckpoint};
use crate::event::{Record, StoredAttrs};
use crate::{GENESIS, Hash};

/// File name prefix of an org's event files (`events-<first_seq>.jsonl`).
pub const EVENTS_PREFIX: &str = "events-";
/// File name suffix of event files.
pub const EVENTS_SUFFIX: &str = ".jsonl";
/// An org's checkpoint file.
pub const CHECKPOINTS_FILE: &str = "checkpoints.jsonl";
/// An org's export cursor (`<org_id>/cursor.json`).
pub const CURSOR_FILE: &str = "cursor.json";

/// The first `seq` named by an event file name, e.g. `events-1001.jsonl` gives 1001.
pub fn events_file_first_seq(name: &str) -> Option<u64> {
    let digits = name
        .strip_prefix(EVENTS_PREFIX)?
        .strip_suffix(EVENTS_SUFFIX)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The event file name for a file starting at `first_seq`.
pub fn events_file_name(first_seq: u64) -> String {
    format!("{EVENTS_PREFIX}{first_seq}{EVENTS_SUFFIX}")
}

/// One event line.
pub fn event_line(r: &Record) -> Value {
    json!({
        "org_id": r.org_id.hyphenated().to_string(),
        "seq": r.seq,
        "id": r.id.hyphenated().to_string(),
        "at_micros": r.at_micros,
        "kind": r.kind,
        "actor": r.actor,
        "target": r.target,
        "outcome": r.outcome,
        "attrs": r.attrs.as_ref().map(StoredAttrs::to_json).unwrap_or(Value::Null),
        "prev_hash": hex::encode(r.prev_hash),
        "hash": hex::encode(r.hash),
    })
}

/// Parse an event line. `None` when a field is missing, has the wrong type, or an unknown field
/// is present. Attributes that are not in the stored shape parse to `attrs: None`, so the row
/// hash cannot match (as for the database).
pub fn parse_event_line(v: &Value) -> Option<Record> {
    let o = exact_keys(
        v,
        &[
            "org_id",
            "seq",
            "id",
            "at_micros",
            "kind",
            "actor",
            "target",
            "outcome",
            "attrs",
            "prev_hash",
            "hash",
        ],
    )?;
    let target = match &o["target"] {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        _ => return None,
    };
    Some(Record {
        org_id: uuid(&o["org_id"])?,
        seq: o["seq"].as_u64()?,
        id: uuid(&o["id"])?,
        at_micros: o["at_micros"].as_i64()?,
        kind: o["kind"].as_str()?.to_owned(),
        actor: o["actor"].as_str()?.to_owned(),
        target,
        outcome: o["outcome"].as_str()?.to_owned(),
        attrs: StoredAttrs::from_json(&o["attrs"]),
        prev_hash: hex_array(&o["prev_hash"])?,
        hash: hex_array(&o["hash"])?,
    })
}

/// One checkpoint line.
pub fn checkpoint_line(c: &SignedCheckpoint) -> Value {
    json!({
        "org_id": c.body.org_id.hyphenated().to_string(),
        "seq": c.body.seq,
        "hash": hex::encode(c.body.hash),
        "at_micros": c.body.at_micros,
        "key_id": c.key_id,
        "signature": hex::encode(c.signature),
    })
}

/// Parse a checkpoint line; `None` as for [`parse_event_line`].
pub fn parse_checkpoint_line(v: &Value) -> Option<SignedCheckpoint> {
    let o = exact_keys(
        v,
        &["org_id", "seq", "hash", "at_micros", "key_id", "signature"],
    )?;
    Some(SignedCheckpoint {
        body: CheckpointBody {
            org_id: uuid(&o["org_id"])?,
            seq: o["seq"].as_u64()?,
            hash: hex_array(&o["hash"])?,
            at_micros: o["at_micros"].as_i64()?,
        },
        key_id: o["key_id"].as_str()?.to_owned(),
        signature: hex_array(&o["signature"])?,
    })
}

/// How far an org's export has been committed: every event up to `seq` (whose row hash is
/// `hash`) and every checkpoint up to `checkpoint_seq` (0: none yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub org_id: Uuid,
    pub seq: u64,
    pub hash: Hash,
    pub checkpoint_seq: u64,
}

impl Cursor {
    /// The position before an org's first export.
    pub const fn start(org_id: Uuid) -> Self {
        Self {
            org_id,
            seq: 0,
            hash: GENESIS,
            checkpoint_seq: 0,
        }
    }

    /// The cursor after `events` and `checkpoints` are exported on top of `self`, assuming
    /// [`check_batch`] accepted them.
    pub fn advance(&self, events: &[Record], checkpoints: &[SignedCheckpoint]) -> Self {
        let (seq, hash) = events
            .last()
            .map_or((self.seq, self.hash), |r| (r.seq, r.hash));
        let checkpoint_seq = checkpoints
            .iter()
            .map(|c| c.body.seq)
            .max()
            .map_or(self.checkpoint_seq, |s| s.max(self.checkpoint_seq));
        Self {
            org_id: self.org_id,
            seq,
            hash,
            checkpoint_seq,
        }
    }
}

/// The cursor file's JSON.
pub fn cursor_line(c: &Cursor) -> Value {
    json!({
        "org_id": c.org_id.hyphenated().to_string(),
        "seq": c.seq,
        "hash": hex::encode(c.hash),
        "checkpoint_seq": c.checkpoint_seq,
    })
}

/// Parse a cursor; `None` as for [`parse_event_line`].
pub fn parse_cursor(v: &Value) -> Option<Cursor> {
    let o = exact_keys(v, &["org_id", "seq", "hash", "checkpoint_seq"])?;
    Some(Cursor {
        org_id: uuid(&o["org_id"])?,
        seq: o["seq"].as_u64()?,
        hash: hex_array(&o["hash"])?,
        checkpoint_seq: o["checkpoint_seq"].as_u64()?,
    })
}

/// Why a batch does not continue the exported chain. The exporter refuses such a batch: the
/// database no longer extends what was exported (history was rewritten or rows deleted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchProblem {
    /// An event is for another org.
    WrongOrg { seq: u64 },
    /// The event at this position does not have the next `seq`.
    Sequence { expected: u64 },
    /// The event's `prev_hash` is not the previous event's hash (for the first event of the
    /// batch: not the cursor's hash).
    Link { seq: u64 },
    /// The event's stored hash does not match its recomputed hash.
    Hash { seq: u64 },
    /// A checkpoint is for another org, at or below the cursor's `checkpoint_seq`, above the
    /// last exported event, or out of order.
    Checkpoint { seq: u64 },
}

impl BatchProblem {
    /// The `seq` the problem is at.
    pub const fn seq(self) -> u64 {
        match self {
            Self::Sequence { expected: seq }
            | Self::WrongOrg { seq }
            | Self::Link { seq }
            | Self::Hash { seq }
            | Self::Checkpoint { seq } => seq,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WrongOrg { .. } => "wrong_org",
            Self::Sequence { .. } => "sequence",
            Self::Link { .. } => "link",
            Self::Hash { .. } => "hash",
            Self::Checkpoint { .. } => "checkpoint",
        }
    }
}

/// Check that `events` continue the chain exported up to `cursor` (contiguous `seq`, linked
/// `prev_hash`, recomputed hashes) and that `checkpoints` are new, in order, for this org and
/// covered by the exported events. Checkpoint signatures are not checked here (verify does).
pub fn check_batch(
    cursor: &Cursor,
    events: &[Record],
    checkpoints: &[SignedCheckpoint],
) -> Result<(), BatchProblem> {
    let (mut seq, mut head) = (cursor.seq, cursor.hash);
    for r in events {
        let expected = seq + 1;
        if r.org_id != cursor.org_id {
            return Err(BatchProblem::WrongOrg { seq: r.seq });
        }
        if r.seq != expected {
            return Err(BatchProblem::Sequence { expected });
        }
        if r.prev_hash != head {
            return Err(BatchProblem::Link { seq: r.seq });
        }
        if r.compute_hash() != r.hash {
            return Err(BatchProblem::Hash { seq: r.seq });
        }
        (seq, head) = (r.seq, r.hash);
    }
    let mut cp_seq = cursor.checkpoint_seq;
    for c in checkpoints {
        let s = c.body.seq;
        if c.body.org_id != cursor.org_id || s <= cp_seq || s > seq {
            return Err(BatchProblem::Checkpoint { seq: s });
        }
        cp_seq = s;
    }
    Ok(())
}

fn exact_keys<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Map<String, Value>> {
    let o = v.as_object()?;
    (o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k))).then_some(o)
}

/// A UUID in the hyphenated lower-case form the exporter writes (no other spelling, so the text
/// is not normalised).
fn uuid(v: &Value) -> Option<Uuid> {
    let s = v.as_str()?;
    let u = Uuid::parse_str(s).ok()?;
    (u.hyphenated().to_string() == s).then_some(u)
}

/// Lower-case hex of exactly `N` bytes.
fn hex_array<const N: usize>(v: &Value) -> Option<[u8; N]> {
    let s = v.as_str()?;
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    <[u8; N]>::try_from(hex::decode(s).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GENESIS;
    use crate::event::{Actor, Attrs, Code, Event, Host, Target, kind, outcome};

    const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_00000000000a);

    fn record() -> Record {
        let e = Event {
            kind: kind::RELAY_ATTEMPT,
            actor: Actor::Service(Code::new("gateway")),
            target: Some(Target::Secret(Uuid::from_u128(7))),
            outcome: outcome::PENDING,
            attrs: Attrs::new()
                .host(Code::new("host"), Host::parse("api.example.com").unwrap())
                .int(Code::new("status"), 200),
        };
        Record::new(
            ORG,
            1,
            Uuid::from_u128(9),
            1_763_400_000_000_000,
            &e,
            GENESIS,
        )
    }

    #[test]
    fn event_line_round_trips() {
        let r = record();
        let line = event_line(&r).to_string();
        let back = parse_event_line(&serde_json::from_str(&line).unwrap()).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.compute_hash(), r.hash);
        let mut none = r.clone();
        none.target = None;
        assert_eq!(parse_event_line(&event_line(&none)), Some(none));
    }

    #[test]
    fn event_line_rejects_bad_fields() {
        let good = event_line(&record());
        let edits: Vec<fn(&mut Value)> = vec![
            |v| v["seq"] = json!("1"),
            |v| v["seq"] = json!(-1),
            |v| v["hash"] = json!("00"),
            |v| v["hash"] = json!(v["hash"].as_str().unwrap().to_uppercase()),
            |v| v["org_id"] = json!(ORG.simple().to_string()),
            |v| v["target"] = json!(1),
            |v| {
                v.as_object_mut().unwrap().remove("kind");
            },
            |v| v["extra"] = json!(1),
        ];
        for (i, edit) in edits.iter().enumerate() {
            let mut v = good.clone();
            edit(&mut v);
            assert_eq!(parse_event_line(&v), None, "edit {i}");
        }
        // Attributes out of shape parse, but to `None`, so the hash cannot match.
        let mut v = good;
        v["attrs"] = json!({"host": "api.example.com"});
        let r = parse_event_line(&v).unwrap();
        assert_eq!(r.attrs, None);
        assert_ne!(r.compute_hash(), r.hash);
    }

    #[test]
    fn checkpoint_line_round_trips() {
        let c = SignedCheckpoint {
            body: CheckpointBody {
                org_id: ORG,
                seq: 3,
                hash: [5; 32],
                at_micros: 42,
            },
            key_id: "audit-checkpoint:1".into(),
            signature: [6; 64],
        };
        let v = checkpoint_line(&c);
        assert_eq!(parse_checkpoint_line(&v), Some(c));
        let mut short = v.clone();
        short["signature"] = json!("0606");
        assert_eq!(parse_checkpoint_line(&short), None);
    }

    fn chain(n: u64) -> Vec<Record> {
        let mut prev = GENESIS;
        (1..=n)
            .map(|seq| {
                let e = Event {
                    kind: kind::RELAY_ATTEMPT,
                    actor: Actor::Service(Code::new("gateway")),
                    target: None,
                    outcome: outcome::PENDING,
                    attrs: Attrs::new(),
                };
                let r = Record::new(ORG, seq, Uuid::from_u128(seq.into()), 1, &e, prev);
                prev = r.hash;
                r
            })
            .collect()
    }

    fn cp(seq: u64, hash: Hash) -> SignedCheckpoint {
        SignedCheckpoint {
            body: CheckpointBody {
                org_id: ORG,
                seq,
                hash,
                at_micros: 1,
            },
            key_id: "audit-checkpoint:1".into(),
            signature: [0; 64],
        }
    }

    #[test]
    fn cursor_round_trips_and_advances() {
        let start = Cursor::start(ORG);
        assert_eq!(parse_cursor(&cursor_line(&start)), Some(start));
        let c = chain(3);
        let next = start.advance(&c, &[cp(2, c[1].hash)]);
        assert_eq!(
            (next.seq, next.hash, next.checkpoint_seq),
            (3, c[2].hash, 2)
        );
        assert_eq!(parse_cursor(&cursor_line(&next)), Some(next));
        assert_eq!(next.advance(&[], &[]), next);
        let mut bad = cursor_line(&next);
        bad["seq"] = json!(-1);
        assert_eq!(parse_cursor(&bad), None);
        let mut extra = cursor_line(&next);
        extra["x"] = json!(1);
        assert_eq!(parse_cursor(&extra), None);
    }

    #[test]
    fn check_batch_accepts_a_continuation_only() {
        let c = chain(5);
        let start = Cursor::start(ORG);
        assert_eq!(check_batch(&start, &c, &[cp(4, c[3].hash)]), Ok(()));
        let mid = start.advance(&c[..2], &[]);
        assert_eq!(check_batch(&mid, &c[2..], &[]), Ok(()));
        assert_eq!(check_batch(&mid, &[], &[cp(2, c[1].hash)]), Ok(()));

        // Overlap with the exported range: never written twice.
        assert_eq!(
            check_batch(&mid, &c[1..], &[]),
            Err(BatchProblem::Sequence { expected: 3 })
        );
        // Gap.
        assert_eq!(
            check_batch(&mid, &c[3..], &[]),
            Err(BatchProblem::Sequence { expected: 3 })
        );
        // The database chain no longer extends the exported head.
        let mut moved = mid;
        moved.hash = [7; 32];
        assert_eq!(
            check_batch(&moved, &c[2..], &[]),
            Err(BatchProblem::Link { seq: 3 })
        );
        let mut edited = c.clone();
        edited[3].outcome = "ok".into();
        assert_eq!(
            check_batch(&start, &edited, &[]),
            Err(BatchProblem::Hash { seq: 4 })
        );
        let mut other = c.clone();
        other[0].org_id = Uuid::nil();
        assert_eq!(
            check_batch(&start, &other, &[]),
            Err(BatchProblem::WrongOrg { seq: 1 })
        );
        // Checkpoints: already exported, beyond the events, out of order.
        let done = start.advance(&c[..2], &[cp(2, c[1].hash)]);
        for (events, cps) in [
            (&c[2..], vec![cp(2, c[1].hash)]),
            (&c[2..3], vec![cp(4, c[3].hash)]),
            (&c[2..], vec![cp(4, c[3].hash), cp(3, c[2].hash)]),
        ] {
            assert!(
                matches!(
                    check_batch(&done, events, &cps),
                    Err(BatchProblem::Checkpoint { .. })
                ),
                "{cps:?}"
            );
        }
    }

    #[test]
    fn event_file_names() {
        assert_eq!(events_file_name(1001), "events-1001.jsonl");
        assert_eq!(events_file_first_seq("events-1001.jsonl"), Some(1001));
        for bad in [
            "events-.jsonl",
            "events-+1.jsonl",
            "events-1.json",
            "x-1.jsonl",
        ] {
            assert_eq!(events_file_first_seq(bad), None, "{bad}");
        }
    }
}
