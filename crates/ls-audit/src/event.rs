//! Server ledger events (S5 design decision 1) and their canonical encoding.
//!
//! An event names who did what to which object with which result, using allow-listed
//! identifier types only:
//! - [`Code`]: a short static code (`relay.attempt`, `ok`, `denied_host`). It can only be built
//!   from a `&'static str`, so a string taken from a request cannot become one;
//! - [`Actor`] and [`Target`]: a UUID with its object type, or a service code;
//! - [`AttrValue`]: a UUID, an integer, a code or a validated [`Host`].
//!
//! There is no free-form string anywhere, so a secret value, a header value, a body or a query
//! string has no field to land in.
//!
//! A stored row is a [`Record`]. Its hash is `SHA256(canonical)` (no MAC suffix) over the
//! [`LEDGER_DOMAIN`](crate::LEDGER_DOMAIN) encoding of every column in a fixed order, and its
//! `prev_hash` is the previous record's hash ([`GENESIS`](crate::GENESIS) for seq 1).

use std::collections::BTreeMap;
use std::fmt;

use uuid::Uuid;

use crate::{Encoder, Hash, Link, row_hash};

/// A value that is not an allow-listed identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidIdentifier;

impl fmt::Display for InvalidIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not an allow-listed audit identifier")
    }
}

impl std::error::Error for InvalidIdentifier {}

/// A static code: `[a-z][a-z0-9_.]{0,63}`. Event kinds, outcomes, service names and attribute
/// keys are codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Code(&'static str);

const fn is_code(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 || !b[0].is_ascii_lowercase() {
        return false;
    }
    let mut i = 1;
    while i < b.len() {
        let c = b[i];
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'.') {
            return false;
        }
        i += 1;
    }
    true
}

impl Code {
    /// A code from a literal. In a `const` this fails to compile when `s` is not a code.
    ///
    /// # Panics
    /// If `s` is not `[a-z][a-z0-9_.]{0,63}`.
    pub const fn new(s: &'static str) -> Self {
        assert!(is_code(s), "audit code must match [a-z][a-z0-9_.]{{0,63}}");
        Self(s)
    }

    /// A code from a static string checked at run time.
    pub const fn try_new(s: &'static str) -> Result<Self, InvalidIdentifier> {
        if is_code(s) {
            Ok(Self(s))
        } else {
            Err(InvalidIdentifier)
        }
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// Event kinds known so far. New kinds are new constants; the schema only checks the shape.
pub mod kind {
    use super::Code;
    pub const RELAY_ATTEMPT: Code = Code::new("relay.attempt");
    pub const RELAY_OUTCOME: Code = Code::new("relay.outcome");
    pub const RELAY_DENIED: Code = Code::new("relay.denied");
    pub const GIT_FETCH: Code = Code::new("git.fetch");
    pub const GIT_PUSH: Code = Code::new("git.push");
    pub const GIT_DENIED: Code = Code::new("git.denied");
    pub const AGENT_CREATED: Code = Code::new("agent.created");
    pub const AGENT_ROTATED: Code = Code::new("agent.rotated");
    pub const AGENT_DELETED: Code = Code::new("agent.deleted");
    pub const GRANT_CREATED: Code = Code::new("grant.created");
    pub const GRANT_REVOKED: Code = Code::new("grant.revoked");
    /// A workload identity trust policy was created or deleted (D4 task 1.3).
    pub const WORKLOAD_IDENTITY_CREATED: Code = Code::new("workload_identity.created");
    pub const WORKLOAD_IDENTITY_DELETED: Code = Code::new("workload_identity.deleted");
    /// A human signed in (T1 task 5.1). Actor `user:<id>`, target the personal org.
    pub const AUTH_SIGN_IN: Code = Code::new("auth.sign_in");
    pub const AUTH_SIGN_OUT: Code = Code::new("auth.sign_out");
    /// A verified identity was refused (e.g. unverified email); `reason` says why.
    pub const AUTH_VERIFY_FAILED: Code = Code::new("auth.verify_failed");
    /// A first sign-in created the user's personal org.
    pub const ORG_PERSONAL_CREATED: Code = Code::new("org.personal_created");
}

/// Common outcomes.
pub mod outcome {
    use super::Code;
    pub const OK: Code = Code::new("ok");
    pub const PENDING: Code = Code::new("pending");
    pub const DENIED: Code = Code::new("denied");
    pub const ERROR: Code = Code::new("error");
}

/// Attribute keys in use. New keys are new constants.
pub mod attr {
    use super::Code;
    pub const AGENT_ID: Code = Code::new("agent_id");
    pub const SECRET_ID: Code = Code::new("secret_id");
    pub const VERSION: Code = Code::new("version");
    pub const MODE: Code = Code::new("mode");
    /// Unix seconds.
    pub const EXPIRES_AT: Code = Code::new("expires_at");
    pub const GRANTS_REVOKED: Code = Code::new("grants_revoked");
    pub const HOST: Code = Code::new("host");
    pub const PORT: Code = Code::new("port");
    pub const METHOD: Code = Code::new("method");
    pub const STATUS: Code = Code::new("status");
    /// Links a relay `outcome` event to its `attempt` event.
    pub const ATTEMPT_ID: Code = Code::new("attempt_id");
    /// Host name of the OIDC issuer that vouched for a human identity (never a token).
    pub const ISSUER: Code = Code::new("issuer");
    /// Static reason code for a refusal.
    pub const REASON: Code = Code::new("reason");
}

/// Who acted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    Agent(Uuid),
    User(Uuid),
    /// A Locksmith service acting on its own (`gateway`, `control_plane`).
    Service(Code),
}

impl Actor {
    /// The stored form: `agent:<uuid>`, `user:<uuid>` or `service:<code>`.
    pub fn to_text(&self) -> String {
        match self {
            Self::Agent(id) => format!("agent:{}", id.hyphenated()),
            Self::User(id) => format!("user:{}", id.hyphenated()),
            Self::Service(c) => format!("service:{}", c.as_str()),
        }
    }
}

/// What was acted on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Org(Uuid),
    Secret(Uuid),
    Agent(Uuid),
    Grant(Uuid),
    WorkloadIdentity(Uuid),
}

impl Target {
    /// The stored form: `<type>:<uuid>`.
    pub fn to_text(&self) -> String {
        let (t, id) = match self {
            Self::Org(id) => ("org", id),
            Self::Secret(id) => ("secret", id),
            Self::Agent(id) => ("agent", id),
            Self::Grant(id) => ("grant", id),
            Self::WorkloadIdentity(id) => ("workload", id),
        };
        format!("{t}:{}", id.hyphenated())
    }
}

/// A validated, lower-cased host name or IP literal (no port, path or query): DNS labels of
/// `[a-z0-9-]`, an IPv4 address, or a bracketed IPv6 address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host(String);

impl Host {
    pub fn parse(s: &str) -> Result<Self, InvalidIdentifier> {
        let h = s.to_ascii_lowercase();
        let ok = if let Some(inner) = h.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            inner.parse::<std::net::Ipv6Addr>().is_ok()
        } else {
            let name = h.strip_suffix('.').unwrap_or(&h);
            !name.is_empty()
                && name.len() <= 253
                && name.split('.').all(|l| {
                    !l.is_empty()
                        && l.len() <= 63
                        && !l.starts_with('-')
                        && !l.ends_with('-')
                        && l.bytes()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                })
        };
        if ok {
            Ok(Self(h))
        } else {
            Err(InvalidIdentifier)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An attribute value. Only identifier types exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrValue {
    Id(Uuid),
    Int(i64),
    Code(Code),
    Host(Host),
}

/// The type tag of a stored attribute (its JSON key and its encoded tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrTag {
    Id,
    Int,
    Code,
    Host,
}

impl AttrTag {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Id => "id",
            Self::Int => "int",
            Self::Code => "code",
            Self::Host => "host",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "id" => Self::Id,
            "int" => Self::Int,
            "code" => Self::Code,
            "host" => Self::Host,
            _ => return None,
        })
    }
}

impl AttrValue {
    fn stored(&self) -> (AttrTag, String) {
        match self {
            Self::Id(id) => (AttrTag::Id, id.hyphenated().to_string()),
            Self::Int(i) => (AttrTag::Int, i.to_string()),
            Self::Code(c) => (AttrTag::Code, c.as_str().to_owned()),
            Self::Host(h) => (AttrTag::Host, h.as_str().to_owned()),
        }
    }
}

/// Event attributes keyed by code, e.g. `secret_id`, `host`, `status`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attrs(BTreeMap<Code, AttrValue>);

impl Attrs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, key: Code, value: AttrValue) -> Self {
        self.0.insert(key, value);
        self
    }

    pub fn id(self, key: Code, id: Uuid) -> Self {
        self.with(key, AttrValue::Id(id))
    }

    pub fn int(self, key: Code, i: i64) -> Self {
        self.with(key, AttrValue::Int(i))
    }

    pub fn code(self, key: Code, c: Code) -> Self {
        self.with(key, AttrValue::Code(c))
    }

    pub fn host(self, key: Code, h: Host) -> Self {
        self.with(key, AttrValue::Host(h))
    }

    /// The stored form.
    pub fn stored(&self) -> StoredAttrs {
        StoredAttrs(
            self.0
                .iter()
                .map(|(k, v)| {
                    let (t, s) = v.stored();
                    (k.as_str().to_owned(), t, s)
                })
                .collect(),
        )
    }
}

/// Attributes as stored and read back: `(key, tag, text)` sorted by key. Reading never
/// normalises the text, so any edit to a stored value changes the hash.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredAttrs(Vec<(String, AttrTag, String)>);

impl StoredAttrs {
    /// `{"<key>": {"<tag>": <value>}}`; `int` values are JSON integers, the rest strings.
    pub fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        for (k, t, s) in &self.0 {
            let v = match t {
                AttrTag::Int => serde_json::Value::Number(
                    s.parse::<i64>()
                        .expect("int attrs are written from i64")
                        .into(),
                ),
                _ => serde_json::Value::String(s.clone()),
            };
            let mut inner = serde_json::Map::new();
            inner.insert(t.as_str().to_owned(), v);
            m.insert(k.clone(), serde_json::Value::Object(inner));
        }
        serde_json::Value::Object(m)
    }

    /// Parse the stored JSON; `None` when it is not in the shape [`Self::to_json`] writes.
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        let mut out = Vec::new();
        for (k, inner) in v.as_object()? {
            let inner = inner.as_object()?;
            if inner.len() != 1 {
                return None;
            }
            let (t, val) = inner.iter().next()?;
            let tag = AttrTag::parse(t)?;
            let text = match tag {
                AttrTag::Int => val.as_i64()?.to_string(),
                _ => val.as_str()?.to_owned(),
            };
            out.push((k.clone(), tag, text));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Some(Self(out))
    }

    pub fn entries(&self) -> &[(String, AttrTag, String)] {
        &self.0
    }

    fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(b"");
        let n = u32::try_from(self.0.len()).expect("fewer than u32::MAX attributes");
        e.field(&n.to_be_bytes());
        for (k, t, s) in &self.0 {
            e.field(k.as_bytes())
                .field(t.as_str().as_bytes())
                .field(s.as_bytes());
        }
        e.finish()
    }
}

/// An event to append. The store assigns `seq`, `id`, `at` and the hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub kind: Code,
    pub actor: Actor,
    pub target: Option<Target>,
    pub outcome: Code,
    pub attrs: Attrs,
}

/// One stored `audit_events` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub org_id: Uuid,
    pub seq: u64,
    pub id: Uuid,
    /// Microseconds since the Unix epoch (Postgres `timestamptz` precision).
    pub at_micros: i64,
    pub kind: String,
    pub actor: String,
    pub target: Option<String>,
    pub outcome: String,
    /// `None` when the stored JSON does not parse; the hash then cannot match.
    pub attrs: Option<StoredAttrs>,
    pub prev_hash: Hash,
    /// The stored hash.
    pub hash: Hash,
}

impl Record {
    /// Build the next record for `event` and compute its hash.
    pub fn new(
        org_id: Uuid,
        seq: u64,
        id: Uuid,
        at_micros: i64,
        event: &Event,
        prev_hash: Hash,
    ) -> Self {
        let mut r = Self {
            org_id,
            seq,
            id,
            at_micros,
            kind: event.kind.as_str().to_owned(),
            actor: event.actor.to_text(),
            target: event.target.map(|t| t.to_text()),
            outcome: event.outcome.as_str().to_owned(),
            attrs: Some(event.attrs.stored()),
            prev_hash,
            hash: [0; 32],
        };
        r.hash = r.compute_hash();
        r
    }

    /// The canonical encoding of every column except `hash`, in a fixed order.
    pub fn canonical(&self) -> Vec<u8> {
        let mut e = Encoder::ledger();
        e.field(self.org_id.as_bytes())
            .field(&self.seq.to_be_bytes())
            .field(self.id.as_bytes())
            .field(&self.at_micros.to_be_bytes())
            .field(self.kind.as_bytes())
            .field(self.actor.as_bytes())
            .opt_field(self.target.as_deref().map(str::as_bytes))
            .field(self.outcome.as_bytes())
            .opt_field(self.attrs.as_ref().map(StoredAttrs::encode).as_deref())
            .field(&self.prev_hash);
        e.finish()
    }

    /// `SHA256(canonical)`: the server ledger has no MAC suffix.
    pub fn compute_hash(&self) -> Hash {
        row_hash(&self.canonical(), &[])
    }

    /// The row as the verify walk sees it.
    pub fn link(&self) -> Link {
        Link {
            seq: self.seq,
            prev_hash: self.prev_hash,
            hash: self.compute_hash(),
            stored_hash: Some(self.hash),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GENESIS, verify};

    const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_00000000000a);
    const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a1);
    const SECRET: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000b2);

    fn event() -> Event {
        Event {
            kind: kind::RELAY_ATTEMPT,
            actor: Actor::Agent(AGENT),
            target: Some(Target::Secret(SECRET)),
            outcome: outcome::PENDING,
            attrs: Attrs::new()
                .host(Code::new("host"), Host::parse("API.Example.com").unwrap())
                .int(Code::new("status"), 200)
                .code(Code::new("method"), Code::new("get"))
                .id(Code::new("grant_id"), SECRET),
        }
    }

    #[test]
    fn codes_are_checked() {
        assert!(Code::try_new("relay.attempt").is_ok());
        for bad in [
            "",
            "Ok",
            "1x",
            "a b",
            "a-b",
            "x?y=1",
            &*"a".repeat(65).leak(),
        ] {
            assert_eq!(Code::try_new(bad), Err(InvalidIdentifier), "{bad}");
        }
    }

    #[test]
    fn hosts_are_checked() {
        assert_eq!(
            Host::parse("API.example.COM").unwrap().as_str(),
            "api.example.com"
        );
        assert!(Host::parse("10.0.0.1").is_ok());
        assert!(Host::parse("[::1]").is_ok());
        for bad in [
            "",
            "api.example.com:443",
            "api.example.com/v1",
            "a..b",
            "-a.com",
            "x?token=1",
            "user@host",
            "[nope]",
            "sk_live_abc def",
        ] {
            assert_eq!(Host::parse(bad), Err(InvalidIdentifier), "{bad}");
        }
    }

    #[test]
    fn actor_and_target_text() {
        assert_eq!(
            Actor::Agent(AGENT).to_text(),
            "agent:0197c1f0-0000-7000-8000-0000000000a1"
        );
        assert_eq!(
            Actor::Service(Code::new("gateway")).to_text(),
            "service:gateway"
        );
        assert_eq!(
            Target::Grant(SECRET).to_text(),
            "grant:0197c1f0-0000-7000-8000-0000000000b2"
        );
    }

    #[test]
    fn attrs_json_round_trips() {
        let s = event().attrs.stored();
        let j = s.to_json();
        assert_eq!(
            j.to_string(),
            r#"{"grant_id":{"id":"0197c1f0-0000-7000-8000-0000000000b2"},"host":{"host":"api.example.com"},"method":{"code":"get"},"status":{"int":200}}"#
        );
        assert_eq!(StoredAttrs::from_json(&j), Some(s));
        for bad in [
            r#"[]"#,
            r#"{"a":"x"}"#,
            r#"{"a":{"text":"x"}}"#,
            r#"{"a":{"int":1.5}}"#,
            r#"{"a":{"id":"x","int":1}}"#,
        ] {
            let v: serde_json::Value = serde_json::from_str(bad).unwrap();
            assert_eq!(StoredAttrs::from_json(&v), None, "{bad}");
        }
    }

    /// Pins the record encoding: a change to the field order or layout breaks every stored
    /// chain, so it must show up here.
    #[test]
    fn record_hash_golden_vector() {
        let id = Uuid::from_u128(0x0197c1f0_0000_7000_8000_000000000001);
        let r = Record::new(ORG, 1, id, 1_763_400_000_000_000, &event(), GENESIS);
        let hex: String = r.hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, GOLDEN);
        assert_eq!(r.link().stored_hash, Some(r.link().hash));
    }
    /// Cross-checked against an independent Python implementation of the encoding.
    const GOLDEN: &str = "ca9a902281bf312cc2706305a70aa9decb37c479dd1dc2f8548241b8922f9f28";

    #[test]
    fn every_column_is_covered_by_the_hash() {
        let r = Record::new(ORG, 1, Uuid::nil(), 1, &event(), GENESIS);
        let edits: Vec<fn(&mut Record)> = vec![
            |r| r.org_id = Uuid::max(),
            |r| r.seq = 2,
            |r| r.id = Uuid::max(),
            |r| r.at_micros += 1,
            |r| r.kind.push('x'),
            |r| r.actor.push('x'),
            |r| r.target = None,
            |r| r.outcome = "ok".into(),
            |r| r.attrs = None,
            |r| r.attrs = Some(StoredAttrs::default()),
            |r| r.prev_hash = [1; 32],
        ];
        for (i, edit) in edits.iter().enumerate() {
            let mut t = r.clone();
            edit(&mut t);
            assert_ne!(t.compute_hash(), r.hash, "edit {i} not covered");
            assert!(!verify([t.link()], &[]).ok(), "edit {i} verifies");
        }
        assert!(verify([r.link()], &[]).ok());
    }
}
