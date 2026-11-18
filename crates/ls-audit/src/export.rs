//! The export directory format (S5 design decision 7): what `locksmith-audit export` writes
//! (task 5.2) and `locksmith-audit verify --dir` reads (task 5.1).
//!
//! ```text
//! <dir>/cursor.json                       export progress (not read by verify)
//! <dir>/<org_id>/events-<first_seq>.jsonl one event per line, in seq order
//! <dir>/<org_id>/checkpoints.jsonl        one signed checkpoint per line
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

/// File name prefix of an org's event files (`events-<first_seq>.jsonl`).
pub const EVENTS_PREFIX: &str = "events-";
/// File name suffix of event files.
pub const EVENTS_SUFFIX: &str = ".jsonl";
/// An org's checkpoint file.
pub const CHECKPOINTS_FILE: &str = "checkpoints.jsonl";
/// The export cursor at the top of the directory.
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
