//! OCSF mapping (t10-audit-streaming task 1.1): every ledger kind is mapped, the golden fixtures
//! match the mapping byte for byte, and every fixture validates against the pinned OCSF 1.3
//! JSON Schema of its class (`tests/fixtures/ocsf/schema/`, fetched from schema.ocsf.io).
//!
//! Regenerate the golden files after an intended mapping change: `OCSF_BLESS=1 cargo test -p
//! ls-audit --test ocsf`, then review the diff.

use std::path::PathBuf;

use ls_audit::event::{Actor, Attrs, Event, Host, Record, Target, Text};
use ls_audit::ocsf::{self, Class, STREAMED_ATTRS};
use ls_audit::{Code, GENESIS, attr, kind, outcome};
use serde_json::Value;
use uuid::Uuid;

const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_00000000000a);
const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a1);
const SECRET: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000b2);
const ID: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000c3);

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ocsf")
}

/// A record of `kind_code` with one attribute of each type, including `claims`, which must not
/// be streamed.
fn sample(kind_code: Code, out: Code) -> Record {
    let attrs = Attrs::new()
        .id(attr::SECRET_ID, SECRET)
        .int(attr::STATUS, 403)
        .code(attr::REASON, Code::new("no_grant"))
        .host(attr::HOST, Host::parse("api.example.com").expect("host"))
        .text(
            attr::CLAIMS,
            Text::parse("email=person@example.com").expect("text"),
        );
    let event = Event {
        kind: kind_code,
        actor: Actor::Agent(AGENT),
        target: Some(Target::Secret(SECRET)),
        outcome: out,
        attrs,
    };
    Record::new(ORG, 42, ID, 1_764_000_000_123_456, &event, GENESIS)
}

fn outcome_for(k: Code) -> Code {
    if k.as_str().ends_with("denied") || k == kind::AUTH_VERIFY_FAILED {
        outcome::DENIED
    } else {
        outcome::OK
    }
}

#[test]
fn every_kind_is_mapped_and_nothing_else_is() {
    for k in kind::ALL {
        assert!(
            ocsf::mapping(k.as_str()).is_some(),
            "kind `{}` has no OCSF mapping",
            k.as_str()
        );
    }
    assert!(ocsf::mapping("not.a.kind").is_none());
    let r = sample(kind::GIT_FETCH, outcome::OK);
    let mut unknown = r.clone();
    unknown.kind = "not.a.kind".into();
    assert!(ocsf::map_record(&unknown).is_err());
}

#[test]
fn every_attribute_is_streamed_or_deliberately_not() {
    for a in attr::ALL {
        let streamed = STREAMED_ATTRS.contains(a);
        assert!(
            streamed || *a == attr::CLAIMS,
            "attribute `{}` is neither in STREAMED_ATTRS nor excluded",
            a.as_str()
        );
    }
}

#[test]
fn claims_never_leave_the_ledger() {
    let ev = ocsf::map_record(&sample(kind::WORKLOAD_IDENTITY_EXCHANGED, outcome::OK)).unwrap();
    let text = ev.to_string();
    assert!(!text.contains("person@example.com"), "{text}");
    assert!(ev["unmapped"].get("claims").is_none());
}

#[test]
fn metadata_uid_is_the_ledger_sequence_id() {
    let ev = ocsf::map_record(&sample(kind::GIT_FETCH, outcome::OK)).unwrap();
    assert_eq!(ev["metadata"]["uid"], "42");
    assert_eq!(ev["time"], 1_764_000_000_123_i64);
}

fn schema(class: Class) -> jsonschema::Validator {
    let p = dir()
        .join("schema")
        .join(format!("{}.json", class.schema_name()));
    let v: Value = serde_json::from_slice(&std::fs::read(&p).expect("schema file")).unwrap();
    jsonschema::validator_for(&v).expect("schema compiles")
}

#[test]
fn golden_fixtures_match_and_validate() {
    let bless = std::env::var_os("OCSF_BLESS").is_some();
    let validators: Vec<_> = Class::ALL.iter().map(|c| (*c, schema(*c))).collect();
    for k in kind::ALL {
        let rec = sample(*k, outcome_for(*k));
        let ev = ocsf::map_record(&rec).unwrap();
        let class = ocsf::mapping(k.as_str()).unwrap().class;
        assert_eq!(ev["class_uid"], class.uid());

        let (_, validator) = validators.iter().find(|(c, _)| *c == class).unwrap();
        let errors: Vec<String> = validator.iter_errors(&ev).map(|e| e.to_string()).collect();
        assert!(errors.is_empty(), "{} fails OCSF: {errors:?}", k.as_str());

        let path = dir().join(format!("{}.json", k.as_str()));
        let pretty = format!("{}\n", serde_json::to_string_pretty(&ev).unwrap());
        if bless {
            std::fs::write(&path, &pretty).unwrap();
        }
        let golden = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!("missing fixture {}; run with OCSF_BLESS=1", path.display())
        });
        assert_eq!(
            golden,
            pretty,
            "{} drifted from its golden file",
            k.as_str()
        );
        let parsed: Value = serde_json::from_str(&golden).unwrap();
        assert!(
            validator.is_valid(&parsed),
            "{} fixture invalid",
            k.as_str()
        );
    }
}
