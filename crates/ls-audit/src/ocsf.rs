//! OCSF mapping for audit streaming (change t10-audit-streaming, task 1.1).
//!
//! Maps one stored ledger [`Record`] to an OCSF 1.3 event as JSON. Pure: no IO, no clock.
//!
//! Only allow-listed fields leave the ledger: the class and activity, the actor and target
//! identifiers, the outcome, and the attributes in [`STREAMED_ATTRS`]. The ledger itself holds
//! identifiers only (see [`crate::event`]), so nothing here can add a secret; the allow-list keeps
//! it that way when a new attribute key appears (it is not streamed until it is listed here and
//! reviewed). `metadata.uid` is the ledger sequence id, so a receiver can order and deduplicate.

use serde_json::{Value, json};

use crate::event::{Record, attr, kind};

/// The OCSF schema version the mapping targets (fixtures validate against this version).
pub const OCSF_VERSION: &str = "1.3.0";

/// Attribute keys copied to the event's `unmapped` object. [`attr::CLAIMS`] is left out: it holds
/// external token claim values, which can be personal data.
pub const STREAMED_ATTRS: &[crate::Code] = &[
    attr::AGENT_ID,
    attr::SECRET_ID,
    attr::VERSION,
    attr::MODE,
    attr::EXPIRES_AT,
    attr::GRANTS_REVOKED,
    attr::HOST,
    attr::PORT,
    attr::METHOD,
    attr::STATUS,
    attr::ATTEMPT_ID,
    attr::ISSUER,
    attr::REASON,
    attr::REGION,
    attr::DURATION_SECS,
    attr::DURATION_MS,
    attr::BYTES_IN,
    attr::BYTES_OUT,
    attr::LAYER,
    attr::TOOL,
    attr::CREDENTIAL_ID,
    attr::UPSTREAM,
    attr::DECISION,
];

/// The OCSF class a ledger kind maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// 6003, category Application Activity.
    ApiActivity,
    /// 3002, category Identity & Access Management.
    Authentication,
    /// 3001, category Identity & Access Management.
    AccountChange,
    /// 2004, category Findings.
    DetectionFinding,
}

impl Class {
    pub const ALL: [Class; 4] = [
        Self::ApiActivity,
        Self::Authentication,
        Self::AccountChange,
        Self::DetectionFinding,
    ];

    pub const fn uid(self) -> i64 {
        match self {
            Self::ApiActivity => 6003,
            Self::Authentication => 3002,
            Self::AccountChange => 3001,
            Self::DetectionFinding => 2004,
        }
    }

    pub const fn category_uid(self) -> i64 {
        match self {
            Self::ApiActivity => 6,
            Self::Authentication | Self::AccountChange => 3,
            Self::DetectionFinding => 2,
        }
    }

    /// File stem of the pinned schema under `tests/fixtures/ocsf/schema/`.
    pub const fn schema_name(self) -> &'static str {
        match self {
            Self::ApiActivity => "api_activity",
            Self::Authentication => "authentication",
            Self::AccountChange => "account_change",
            Self::DetectionFinding => "detection_finding",
        }
    }
}

/// How a ledger kind is described in OCSF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub class: Class,
    /// The class's `activity_id` (99 is Other).
    pub activity_id: i64,
}

const fn m(class: Class, activity_id: i64) -> Option<Mapping> {
    Some(Mapping { class, activity_id })
}

/// The mapping for a kind, `None` for a kind this version does not know.
pub fn mapping(kind_text: &str) -> Option<Mapping> {
    use Class::DetectionFinding as Find;
    use Class::{AccountChange as Acct, ApiActivity as Api, Authentication as Auth};
    match kind_text {
        // API Activity: 1 Create, 2 Read, 3 Update, 4 Delete, 99 Other.
        k if k == kind::RELAY_ATTEMPT.as_str() => m(Api, 99),
        k if k == kind::RELAY_OUTCOME.as_str() => m(Api, 99),
        k if k == kind::GIT_FETCH.as_str() => m(Api, 2),
        k if k == kind::GIT_PUSH.as_str() => m(Api, 3),
        k if k == kind::AWS_CREDENTIALS_ISSUED.as_str() => m(Api, 1),
        k if k == kind::DB_SESSION_OPENED.as_str() => m(Api, 1),
        k if k == kind::DB_SESSION_CLOSED.as_str() => m(Api, 4),
        k if k == kind::MCP_CALL.as_str() => m(Api, 99),
        k if k == kind::MCP_UPSTREAM_CALL.as_str() => m(Api, 99),
        k if k == kind::MCP_UPSTREAM_OUTCOME.as_str() => m(Api, 99),
        k if k == kind::CREDENTIAL_ISSUED.as_str() => m(Api, 1),
        k if k == kind::MCP_ISSUER_REVOKE.as_str() => m(Api, 4),
        // Detection Finding: 1 Create. A refusal is a finding with action Denied.
        k if k == kind::RELAY_DENIED.as_str() => m(Find, 1),
        k if k == kind::GIT_DENIED.as_str() => m(Find, 1),
        k if k == kind::AWS_CREDENTIALS_DENIED.as_str() => m(Find, 1),
        k if k == kind::DB_SESSION_DENIED.as_str() => m(Find, 1),
        k if k == kind::WORKLOAD_IDENTITY_DENIED.as_str() => m(Find, 1),
        // Authentication: 1 Logon, 2 Logoff.
        k if k == kind::AUTH_SIGN_IN.as_str() => m(Auth, 1),
        k if k == kind::AUTH_SIGN_OUT.as_str() => m(Auth, 2),
        k if k == kind::AUTH_VERIFY_FAILED.as_str() => m(Auth, 1),
        k if k == kind::WORKLOAD_IDENTITY_EXCHANGED.as_str() => m(Auth, 1),
        // Account Change: 1 Create, 3 Password Change, 6 Delete, 7 Attach Policy, 8 Detach Policy.
        k if k == kind::AGENT_CREATED.as_str() => m(Acct, 1),
        k if k == kind::AGENT_ROTATED.as_str() => m(Acct, 3),
        k if k == kind::AGENT_DELETED.as_str() => m(Acct, 6),
        k if k == kind::GRANT_CREATED.as_str() => m(Acct, 7),
        k if k == kind::GRANT_REVOKED.as_str() => m(Acct, 8),
        k if k == kind::WORKLOAD_IDENTITY_CREATED.as_str() => m(Acct, 1),
        k if k == kind::WORKLOAD_IDENTITY_DELETED.as_str() => m(Acct, 6),
        k if k == kind::ORG_PERSONAL_CREATED.as_str() => m(Acct, 1),
        _ => None,
    }
}

/// A kind the mapping does not know (a newer ledger than this build).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmapped(pub String);

impl std::fmt::Display for Unmapped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no OCSF mapping for audit kind `{}`", self.0)
    }
}

impl std::error::Error for Unmapped {}

fn severity_and_status(outcome: &str) -> (i64, i64) {
    // severity: 1 Informational, 3 Medium, 4 High. status: 1 Success, 2 Failure, 99 Other.
    match outcome {
        "ok" => (1, 1),
        "denied" => (3, 2),
        "error" => (4, 2),
        _ => (1, 99),
    }
}

/// Map one ledger record to an OCSF event.
///
/// # Errors
/// [`Unmapped`] when the record's kind has no mapping; the caller decides whether to skip it.
pub fn map_record(rec: &Record) -> Result<Value, Unmapped> {
    let Mapping { class, activity_id } =
        mapping(&rec.kind).ok_or_else(|| Unmapped(rec.kind.clone()))?;
    let (severity_id, status_id) = severity_and_status(&rec.outcome);
    let denied = rec.outcome == "denied";

    let mut unmapped = serde_json::Map::new();
    if let Some(attrs) = &rec.attrs {
        for (k, tag, v) in attrs.entries() {
            if !STREAMED_ATTRS.iter().any(|a| a.as_str() == k) {
                continue;
            }
            let value = match tag {
                crate::AttrTag::Int => v.parse::<i64>().map_or(Value::Null, Value::from),
                _ => Value::String(v.clone()),
            };
            unmapped.insert(k.clone(), value);
        }
    }

    let mut ev = json!({
        "class_uid": class.uid(),
        "category_uid": class.category_uid(),
        "activity_id": activity_id,
        "type_uid": class.uid() * 100 + activity_id,
        "time": rec.at_micros.div_euclid(1000),
        "severity_id": severity_id,
        "message": rec.kind,
        "cloud": { "provider": "Locksmith" },
        "osint": [],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": rec.seq.to_string(),
            "tenant_uid": rec.org_id.hyphenated().to_string(),
            "product": { "vendor_name": "Locksmith", "name": "Locksmith audit ledger" },
        },
        "unmapped": Value::Object(unmapped),
    });
    let o = ev.as_object_mut().expect("object literal");

    match class {
        Class::ApiActivity => {
            o.insert("status_id".into(), status_id.into());
            o.insert("api".into(), json!({ "operation": rec.kind }));
            o.insert("actor".into(), json!({ "user": { "uid": rec.actor } }));
            o.insert("src_endpoint".into(), json!({ "uid": rec.actor }));
            if let Some(t) = &rec.target {
                o.insert("resources".into(), json!([{ "uid": t }]));
            }
        }
        Class::Authentication | Class::AccountChange => {
            o.insert("status_id".into(), status_id.into());
            // The person or service the event is about; an account change names its target.
            let subject = rec.target.as_deref().unwrap_or(&rec.actor);
            o.insert("user".into(), json!({ "uid": subject }));
            o.insert("actor".into(), json!({ "user": { "uid": rec.actor } }));
            if class == Class::Authentication {
                // OCSF requires a `service` or a `dst_endpoint` on an authentication event.
                o.insert("service".into(), json!({ "name": "Locksmith" }));
            }
        }
        Class::DetectionFinding => {
            // action_id: 1 Allowed, 2 Denied.
            o.insert("action_id".into(), (if denied { 2 } else { 1 }).into());
            o.insert(
                "finding_info".into(),
                json!({ "title": rec.kind, "uid": rec.id.hyphenated().to_string() }),
            );
            o.insert("actor".into(), json!({ "user": { "uid": rec.actor } }));
            if let Some(t) = &rec.target {
                o.insert("resources".into(), json!([{ "uid": t }]));
            }
        }
    }
    Ok(ev)
}
