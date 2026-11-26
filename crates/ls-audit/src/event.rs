//! Server ledger events (S5 design decision 1) and their canonical encoding.
//!
//! An event names who did what to which object with which result, using allow-listed
//! identifier types only:
//! - [`Code`]: a short static code (`relay.attempt`, `ok`, `denied_host`). It can only be built
//!   from a `&'static str`, so a string taken from a request cannot become one;
//! - [`Actor`] and [`Target`]: a UUID with its object type, or a service code;
//! - [`AttrValue`]: a UUID, an integer, a code, a validated [`Host`] or a bounded [`Text`].
//!
//! [`Text`] is the one place caller-supplied text can land: at most [`Text::MAX_LEN`] printable
//! ASCII characters, so it can hold a short non-secret label (a verified claim such as a
//! repository name) but not a body, a header block or a multi-line value. Callers must only put
//! non-secret identifying values in it.
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
    /// Short-lived AWS credentials issued by the gateway (D2).
    pub const AWS_CREDENTIALS_ISSUED: Code = Code::new("aws.credentials.issued");
    /// A refused or failed AWS credential request (D2).
    pub const AWS_CREDENTIALS_DENIED: Code = Code::new("aws.credentials.denied");
    /// A refused session on the gateway's Postgres listener (D3).
    pub const DB_SESSION_DENIED: Code = Code::new("db.session.denied");
    /// A relayed Postgres session was established (D3).
    pub const DB_SESSION_OPENED: Code = Code::new("db.session.opened");
    /// A relayed Postgres session ended (D3): `reason`, duration and byte counts.
    pub const DB_SESSION_CLOSED: Code = Code::new("db.session.closed");
    pub const AGENT_CREATED: Code = Code::new("agent.created");
    pub const AGENT_ROTATED: Code = Code::new("agent.rotated");
    pub const AGENT_DELETED: Code = Code::new("agent.deleted");
    pub const GRANT_CREATED: Code = Code::new("grant.created");
    pub const GRANT_REVOKED: Code = Code::new("grant.revoked");
    /// A workload identity trust policy was created or deleted (D4 task 1.3).
    pub const WORKLOAD_IDENTITY_CREATED: Code = Code::new("workload_identity.created");
    pub const WORKLOAD_IDENTITY_DELETED: Code = Code::new("workload_identity.deleted");
    /// An external workload token was exchanged for an agent token, or refused (D4 task 3.2).
    pub const WORKLOAD_IDENTITY_EXCHANGED: Code = Code::new("workload_identity.exchanged");
    pub const WORKLOAD_IDENTITY_DENIED: Code = Code::new("workload_identity.denied");
    /// A human signed in (T1 task 5.1). Actor `user:<id>`, target the personal org.
    pub const AUTH_SIGN_IN: Code = Code::new("auth.sign_in");
    pub const AUTH_SIGN_OUT: Code = Code::new("auth.sign_out");
    /// A verified identity was refused (e.g. unverified email); `reason` says why.
    pub const AUTH_VERIFY_FAILED: Code = Code::new("auth.verify_failed");
    /// A first sign-in created the user's personal org.
    pub const ORG_PERSONAL_CREATED: Code = Code::new("org.personal_created");
    /// A remote MCP tool call (allowed, refused or failed). Records the layer, the tool name and
    /// the outcome only, never the call's arguments or result.
    pub const MCP_CALL: Code = Code::new("mcp.call");
    /// A call through the gateway's MCP upstream proxy (change m2-mcp-gateway), recorded before it
    /// is forwarded (outcome `pending`), or alone with outcome `denied` when it is refused. Records
    /// the upstream's configured name, the tool, the decision and a static reason; never arguments,
    /// results or the upstream credential.
    pub const MCP_UPSTREAM_CALL: Code = Code::new("mcp.upstream_call");
    /// How a forwarded MCP upstream call ended (`ok` or `error`), linked by `attempt_id`.
    pub const MCP_UPSTREAM_OUTCOME: Code = Code::new("mcp.upstream_outcome");
    /// The gateway issued a short-lived credential to an agent (MCP
    /// `issue_short_lived_credential`, decision H1-2). Records the credential's id, the secret it
    /// is scoped to and its expiry, never the credential.
    pub const CREDENTIAL_ISSUED: Code = Code::new("credential.issued");
    /// After a hub MCP client was revoked, the control plane asked the OIDC issuer to revoke the
    /// person's consent for it (m1-remote-mcp task 4.2). Outcome `ok`, or `error` when the issuer
    /// call failed (the database revoke still stands). Records the layer and a static reason only.
    pub const MCP_ISSUER_REVOKE: Code = Code::new("mcp.issuer_revoke");

    /// Every code in this module: the allow-list a request string is checked against.
    pub const ALL: &[Code] = &[
        RELAY_ATTEMPT,
        RELAY_OUTCOME,
        RELAY_DENIED,
        GIT_FETCH,
        GIT_PUSH,
        GIT_DENIED,
        AWS_CREDENTIALS_ISSUED,
        AWS_CREDENTIALS_DENIED,
        DB_SESSION_DENIED,
        DB_SESSION_OPENED,
        DB_SESSION_CLOSED,
        AGENT_CREATED,
        AGENT_ROTATED,
        AGENT_DELETED,
        GRANT_CREATED,
        GRANT_REVOKED,
        WORKLOAD_IDENTITY_CREATED,
        WORKLOAD_IDENTITY_DELETED,
        WORKLOAD_IDENTITY_EXCHANGED,
        WORKLOAD_IDENTITY_DENIED,
        AUTH_SIGN_IN,
        AUTH_SIGN_OUT,
        AUTH_VERIFY_FAILED,
        ORG_PERSONAL_CREATED,
        MCP_CALL,
        CREDENTIAL_ISSUED,
        MCP_ISSUER_REVOKE,
    ];

    /// The code spelled `s`, if it is on the allow-list.
    pub fn lookup(s: &str) -> Option<Code> {
        ALL.iter().copied().find(|c| c.as_str() == s)
    }
}

/// Common outcomes.
pub mod outcome {
    use super::Code;
    pub const OK: Code = Code::new("ok");
    pub const PENDING: Code = Code::new("pending");
    pub const DENIED: Code = Code::new("denied");
    pub const ERROR: Code = Code::new("error");

    /// Every code in this module: the allow-list a request string is checked against.
    pub const ALL: &[Code] = &[OK, PENDING, DENIED, ERROR];

    /// The code spelled `s`, if it is on the allow-list.
    pub fn lookup(s: &str) -> Option<Code> {
        ALL.iter().copied().find(|c| c.as_str() == s)
    }
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
    /// AWS region of vended credentials (D2), stored as a validated host label.
    pub const REGION: Code = Code::new("region");
    /// Lifetime of vended credentials in seconds (D2).
    pub const DURATION_SECS: Code = Code::new("duration_secs");
    /// Session length in milliseconds.
    pub const DURATION_MS: Code = Code::new("duration_ms");
    /// Bytes relayed from the client to the upstream.
    pub const BYTES_IN: Code = Code::new("bytes_in");
    /// Bytes relayed from the upstream to the client.
    pub const BYTES_OUT: Code = Code::new("bytes_out");
    /// The MCP server layer (`hub` or `agent`).
    pub const LAYER: Code = Code::new("layer");
    /// The MCP tool name: from the registry for the agent layer, a [`Text`](super::Text) that passed
    /// the MCP tool-name rule for an upstream call; `unknown` for any other name.
    pub const TOOL: Code = Code::new("tool");
    /// The configured name of an MCP upstream (a [`Text`](super::Text) the control plane checks
    /// against `[a-z0-9-]{1,32}`; a name has hyphens and may start with a digit, so it is not a
    /// [`Code`]).
    pub const UPSTREAM: Code = Code::new("upstream");
    /// The tool decision applied to an MCP upstream call (`allow`, `hide`, `deny` or `hold`).
    pub const DECISION: Code = Code::new("decision");
    /// The id of a short-lived credential (never the credential itself).
    pub const CREDENTIAL_ID: Code = Code::new("credential_id");
    /// The `name=value` pairs of the verified external-token claims a workload identity policy
    /// names (a [`Text`](super::Text)); nothing else from the token.
    pub const CLAIMS: Code = Code::new("claims");

    /// Every code in this module: the allow-list a request string is checked against.
    pub const ALL: &[Code] = &[
        AGENT_ID,
        SECRET_ID,
        VERSION,
        MODE,
        EXPIRES_AT,
        GRANTS_REVOKED,
        HOST,
        PORT,
        METHOD,
        STATUS,
        ATTEMPT_ID,
        ISSUER,
        REASON,
        REGION,
        DURATION_SECS,
        DURATION_MS,
        BYTES_IN,
        BYTES_OUT,
        LAYER,
        TOOL,
        CREDENTIAL_ID,
        CLAIMS,
    ];

    /// The code spelled `s`, if it is on the allow-list.
    pub fn lookup(s: &str) -> Option<Code> {
        ALL.iter().copied().find(|c| c.as_str() == s)
    }
}

/// Service names that may appear as `Actor::Service`.
pub mod service {
    use super::Code;
    pub const GATEWAY: Code = Code::new("gateway");
    pub const CONTROL_PLANE: Code = Code::new("control_plane");
    pub const DEV_AUTH: Code = Code::new("dev_auth");

    /// Every service code: the allow-list a request string is checked against.
    pub const ALL: &[Code] = &[GATEWAY, CONTROL_PLANE, DEV_AUTH];

    /// The code spelled `s`, if it is on the allow-list.
    pub fn lookup(s: &str) -> Option<Code> {
        ALL.iter().copied().find(|c| c.as_str() == s)
    }
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

/// A short non-secret label: 1 to [`Text::MAX_LEN`] printable ASCII characters (`0x20..=0x7e`),
/// so no control character, newline or non-ASCII byte. Used for identifying claim values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Text(String);

impl Text {
    /// The longest accepted text, in characters.
    pub const MAX_LEN: usize = 256;

    pub fn parse(s: &str) -> Result<Self, InvalidIdentifier> {
        if !s.is_empty()
            && s.len() <= Self::MAX_LEN
            && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
        {
            Ok(Self(s.to_owned()))
        } else {
            Err(InvalidIdentifier)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An attribute value: identifier types and a bounded [`Text`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrValue {
    Id(Uuid),
    Int(i64),
    Code(Code),
    Host(Host),
    Text(Text),
}

/// The type tag of a stored attribute (its JSON key and its encoded tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrTag {
    Id,
    Int,
    Code,
    Host,
    Text,
}

impl AttrTag {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Id => "id",
            Self::Int => "int",
            Self::Code => "code",
            Self::Host => "host",
            Self::Text => "text",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "id" => Self::Id,
            "int" => Self::Int,
            "code" => Self::Code,
            "host" => Self::Host,
            "text" => Self::Text,
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
            Self::Text(t) => (AttrTag::Text, t.as_str().to_owned()),
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

    pub fn text(self, key: Code, t: Text) -> Self {
        self.with(key, AttrValue::Text(t))
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
            r#"{"a":{"bogus":"x"}}"#,
            r#"{"a":{"int":1.5}}"#,
            r#"{"a":{"id":"x","int":1}}"#,
        ] {
            let v: serde_json::Value = serde_json::from_str(bad).unwrap();
            assert_eq!(StoredAttrs::from_json(&v), None, "{bad}");
        }
    }

    /// Every constant in a registry module's source is on its `ALL` list (a new constant that
    /// is not listed would be refused by the core service).
    #[test]
    fn registries_list_every_constant() {
        let src = include_str!("event.rs");
        for (name, all) in [
            ("kind", kind::ALL),
            ("outcome", outcome::ALL),
            ("attr", attr::ALL),
            ("service", service::ALL),
        ] {
            let start = src.find(&format!("pub mod {name} {{")).unwrap();
            let body = &src[start..];
            let body = &body[..body.find("\n}\n").unwrap()];
            let mut declared: Vec<&str> = body
                .lines()
                .filter(|l| l.trim_start().starts_with("pub const ") && !l.contains("const ALL:"))
                .map(|l| {
                    l.split("Code::new(\"")
                        .nth(1)
                        .unwrap()
                        .split('"')
                        .next()
                        .unwrap()
                })
                .collect();
            let mut listed: Vec<&str> = all.iter().map(|c| c.as_str()).collect();
            declared.sort_unstable();
            listed.sort_unstable();
            assert_eq!(declared, listed, "{name}::ALL out of date");
        }
    }

    #[test]
    fn lookup_accepts_only_listed_codes() {
        assert_eq!(kind::lookup("agent.created"), Some(kind::AGENT_CREATED));
        assert_eq!(outcome::lookup("ok"), Some(outcome::OK));
        assert_eq!(attr::lookup("agent_id"), Some(attr::AGENT_ID));
        assert_eq!(service::lookup("gateway"), Some(service::GATEWAY));
        for bad in [
            "",
            "unknown.kind",
            "AGENT.CREATED",
            "agent.created ",
            "ok;drop",
        ] {
            assert_eq!(kind::lookup(bad), None, "{bad:?}");
        }
        assert_eq!(service::lookup("agent.created"), None);
    }

    #[test]
    fn text_is_bounded_printable_ascii() {
        assert_eq!(
            Text::parse("repository=acme/api ref=refs/heads/main")
                .unwrap()
                .as_str(),
            "repository=acme/api ref=refs/heads/main"
        );
        assert!(Text::parse(&"a".repeat(Text::MAX_LEN)).is_ok());
        for bad in [
            "",
            "a\nb",
            "a\tb",
            "a\u{7f}b",
            "caf\u{e9}",
            "a\0b",
            &"a".repeat(Text::MAX_LEN + 1),
        ] {
            assert_eq!(Text::parse(bad), Err(InvalidIdentifier), "{bad:?}");
        }
    }

    #[test]
    fn text_attr_round_trips_and_is_hashed() {
        let text = Text::parse("repository=acme/api").unwrap();
        let mut e = event();
        e.attrs = e.attrs.text(attr::CLAIMS, text);
        let stored = e.attrs.stored();
        let j = stored.to_json();
        assert_eq!(
            j["claims"],
            serde_json::json!({"text": "repository=acme/api"})
        );
        assert_eq!(StoredAttrs::from_json(&j), Some(stored));
        let r = Record::new(ORG, 1, Uuid::nil(), 1, &e, GENESIS);
        let mut t = r.clone();
        t.attrs = Some(
            event()
                .attrs
                .text(attr::CLAIMS, Text::parse("repository=acme/web").unwrap())
                .stored(),
        );
        assert_ne!(t.compute_hash(), r.hash);
        assert!(verify([r.link()], &[]).ok());
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
