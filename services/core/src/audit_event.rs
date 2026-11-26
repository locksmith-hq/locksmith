//! Turns an `AppendAuditEventRequest` into an `ls_audit::Event` (task 3.1).
//!
//! No string from a request reaches the ledger as-is: kinds, outcomes, attribute keys and
//! service actors go through `ls_audit`'s allow-lists, target types map to the five `Target`
//! variants, and attribute values become ids, integers or validated text. Anything else is
//! [`Refused`] (HTTP 400). Booleans are refused: the ledger has no boolean attribute.

use std::collections::BTreeMap;

use ls_audit::event::service;
use ls_audit::{Actor, AttrValue, Attrs, Event, Target, Text, attr, kind, outcome};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

/// Why a request was refused. Static text only: never an echo of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused(pub &'static str);

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActorIn {
    Agent { id: Uuid },
    User { id: Uuid },
    Service { code: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetIn {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendRequest {
    pub org_id: Uuid,
    pub kind: String,
    pub outcome: String,
    pub actor: ActorIn,
    #[serde(default)]
    pub target: Option<TargetIn>,
    pub attrs: BTreeMap<String, Value>,
    #[serde(default)]
    pub idempotency_key: Option<Uuid>,
}

impl AppendRequest {
    /// The ledger event for this request.
    pub fn to_event(&self) -> Result<Event, Refused> {
        let kind = kind::lookup(&self.kind).ok_or(Refused("unknown kind"))?;
        let outcome = outcome::lookup(&self.outcome).ok_or(Refused("unknown outcome"))?;
        let actor = match &self.actor {
            ActorIn::Agent { id } => Actor::Agent(*id),
            ActorIn::User { id } => Actor::User(*id),
            ActorIn::Service { code } => {
                Actor::Service(service::lookup(code).ok_or(Refused("unknown service"))?)
            }
        };
        let target = self
            .target
            .as_ref()
            .map(|t| {
                let id = t.id;
                Ok(match t.kind.as_str() {
                    "org" => Target::Org(id),
                    "secret" => Target::Secret(id),
                    "agent" => Target::Agent(id),
                    "grant" => Target::Grant(id),
                    "workload" => Target::WorkloadIdentity(id),
                    _ => return Err(Refused("unknown target type")),
                })
            })
            .transpose()?;
        let mut attrs = Attrs::new();
        for (k, v) in &self.attrs {
            let key = attr::lookup(k).ok_or(Refused("unknown attribute"))?;
            let value = match v {
                Value::Number(n) => AttrValue::Int(n.as_i64().ok_or(Refused("bad integer"))?),
                Value::String(s) => match Uuid::try_parse(s) {
                    Ok(id) => AttrValue::Id(id),
                    Err(_) if s.chars().count() <= 128 => {
                        AttrValue::Text(Text::parse(s).map_err(|_| Refused("bad text"))?)
                    }
                    Err(_) => return Err(Refused("bad text")),
                },
                _ => return Err(Refused("unsupported attribute value")),
            };
            attrs = attrs.with(key, value);
        }
        Ok(Event {
            kind,
            actor,
            target,
            outcome,
            attrs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn req(v: Value) -> Result<AppendRequest, serde_json::Error> {
        serde_json::from_value(v)
    }

    fn base() -> Value {
        json!({
            "org_id": "11111111-1111-4111-8111-111111111111",
            "kind": "agent.created",
            "outcome": "ok",
            "actor": {"type": "service", "code": "control_plane"},
            "target": {"type": "agent", "id": "22222222-2222-4222-8222-222222222222"},
            "attrs": {"grants_revoked": 2, "agent_id": "33333333-3333-4333-8333-333333333333"}
        })
    }

    #[test]
    fn maps_a_valid_request() {
        let e = req(base()).unwrap().to_event().unwrap();
        assert_eq!(e.kind, kind::AGENT_CREATED);
        assert_eq!(e.outcome, outcome::OK);
        assert_eq!(e.actor, Actor::Service(service::CONTROL_PLANE));
        assert!(matches!(e.target, Some(Target::Agent(_))));
    }

    #[test]
    fn matches_what_the_control_plane_builds() {
        let org_agent: Uuid = "22222222-2222-4222-8222-222222222222".parse().unwrap();
        let direct = Event {
            kind: kind::AGENT_DELETED,
            actor: Actor::Service(service::CONTROL_PLANE),
            target: Some(Target::Agent(org_agent)),
            outcome: outcome::OK,
            attrs: Attrs::new().int(attr::GRANTS_REVOKED, 2),
        };
        let mut v = base();
        v["kind"] = json!("agent.deleted");
        v["attrs"] = json!({"grants_revoked": 2});
        assert_eq!(req(v).unwrap().to_event().unwrap(), direct);
    }

    #[test]
    fn refuses_what_is_not_allow_listed() {
        for (field, value, why) in [
            ("kind", json!("made.up"), "unknown kind"),
            ("outcome", json!("great"), "unknown outcome"),
            (
                "actor",
                json!({"type": "service", "code": "evil"}),
                "unknown service",
            ),
            (
                "target",
                json!({"type": "vault", "id": "22222222-2222-4222-8222-222222222222"}),
                "unknown target type",
            ),
            ("attrs", json!({"password": "x"}), "unknown attribute"),
            (
                "attrs",
                json!({"mode": true}),
                "unsupported attribute value",
            ),
            (
                "attrs",
                json!({"mode": null}),
                "unsupported attribute value",
            ),
            ("attrs", json!({"mode": [1]}), "unsupported attribute value"),
            ("attrs", json!({"mode": "bad\u{7f}"}), "bad text"),
            ("attrs", json!({"mode": "x".repeat(129)}), "bad text"),
            ("attrs", json!({"version": 1.5}), "bad integer"),
        ] {
            let mut v = base();
            v[field] = value;
            assert_eq!(req(v).unwrap().to_event().unwrap_err(), Refused(why));
        }
    }

    #[test]
    fn unknown_fields_are_rejected_at_parse() {
        let mut v = base();
        v["extra"] = json!(1);
        assert!(req(v).is_err());
    }
}
