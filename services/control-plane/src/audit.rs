//! Appending to the audit ledger from request code (S5 design decisions 1, 2 and 5).
//!
//! Every append runs inside the caller's [`crate::db::Database::with_org`] transaction through
//! `ls_audit::pg::append_in_tx`, so an admin change and its audit event commit or roll back
//! together. Events are built only from `ls_audit`'s allow-listed types ([`Code`], [`Actor`],
//! [`Target`], ids, integers, validated hosts): no string from a request reaches the ledger.

use ls_audit::pg::{Appended, append_in_tx};
use ls_audit::{Actor, Attrs, Code, Event, Host, Target, attr, kind, outcome};
use time::OffsetDateTime;
use tracing::Instrument;
use uuid::Uuid;

use crate::db::sql::{self, PgConnection};

/// The actor of admin requests while the org binding is the dev-only header: it names no user.
/// T1 replaces this with `Actor::User` from the verified session.
pub const DEV_AUTH_ACTOR: Actor = Actor::Service(Code::new("dev_auth"));

/// Append `event` to `org_id`'s chain inside the caller's transaction (already bound to
/// `org_id`). Holds the org's head row lock until that transaction ends.
pub async fn append(
    c: &mut PgConnection,
    org_id: Uuid,
    event: &Event,
) -> Result<Appended, sql::Error> {
    let span = tracing::info_span!(
        "audit.append",
        org.id = %org_id,
        audit.kind = event.kind.as_str(),
        audit.outcome = event.outcome.as_str(),
        audit.seq = tracing::field::Empty,
    );
    let appended = append_in_tx(c, org_id, event)
        .instrument(span.clone())
        .await?;
    // u64 seq as i64 for OTel (exported as an int); seqs stay far below i64::MAX.
    span.record("audit.seq", i64::try_from(appended.seq).unwrap_or(i64::MAX));
    Ok(appended)
}

/// What an idempotent append did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Once {
    /// The event was appended.
    Appended(Appended),
    /// An identical event was already stored under the key; nothing was appended.
    Existing(Appended),
    /// A different event is already stored under the key; nothing was appended.
    Conflict,
}

/// `(id, seq, hash, actor, target, outcome, attrs)` of a stored `relay.outcome`.
type StoredOutcome = (Uuid, i64, Vec<u8>, String, Option<String>, String, String);

/// Append a `relay.outcome` `event` unless one is already stored for `attempt_id` (S5 design
/// decision 5: the gateway retries outcomes, so a retry after a lost response must not append a
/// second one). Takes the org's head lock first, so the check and the append see no concurrent
/// append; the partial unique index from migration 0009 is the backstop. An existing outcome
/// with the same actor, target, outcome and attributes is returned as [`Once::Existing`], one
/// that differs is [`Once::Conflict`].
pub async fn append_outcome_once(
    c: &mut PgConnection,
    org_id: Uuid,
    attempt_id: Uuid,
    event: &Event,
) -> Result<Once, sql::Error> {
    ls_audit::pg::lock_head(c, org_id).await?;
    let existing: Option<StoredOutcome> = sql::query_as(
        "SELECT id, seq, hash, actor, target, outcome, attrs::text FROM audit_events \
             WHERE org_id = $1 AND kind = $2 AND (attrs -> 'attempt_id' ->> 'id') = $3",
    )
    .bind(org_id)
    .bind(kind::RELAY_OUTCOME.as_str())
    .bind(attempt_id.hyphenated().to_string())
    .fetch_optional(&mut *c)
    .await?;
    let Some((id, seq, hash, actor, target, outcome, attrs)) = existing else {
        return append(c, org_id, event).await.map(Once::Appended);
    };
    let stored_attrs = serde_json::from_str(&attrs)
        .ok()
        .and_then(|v| ls_audit::StoredAttrs::from_json(&v));
    let same = event.kind == kind::RELAY_OUTCOME
        && actor == event.actor.to_text()
        && target == event.target.map(|t| t.to_text())
        && outcome == event.outcome.as_str()
        && stored_attrs.as_ref() == Some(&event.attrs.stored());
    if !same {
        tracing::warn!(org.id = %org_id, "conflicting relay outcome for an attempt refused");
        return Ok(Once::Conflict);
    }
    let (Ok(seq), Ok(hash)) = (u64::try_from(seq), ls_audit::Hash::try_from(&hash[..])) else {
        return Err(sql::Error::Decode("stored audit row out of range".into()));
    };
    Ok(Once::Existing(Appended { seq, id, hash }))
}

fn admin(kind: Code, actor: Actor, target: Target, attrs: Attrs) -> Event {
    Event {
        kind,
        actor,
        target: Some(target),
        outcome: outcome::OK,
        attrs,
    }
}

/// `agent.created`.
pub fn agent_created(actor: Actor, agent_id: Uuid) -> Event {
    admin(
        kind::AGENT_CREATED,
        actor,
        Target::Agent(agent_id),
        Attrs::new(),
    )
}

/// `agent.rotated`: the enrollment secret was replaced.
pub fn agent_rotated(actor: Actor, agent_id: Uuid) -> Event {
    admin(
        kind::AGENT_ROTATED,
        actor,
        Target::Agent(agent_id),
        Attrs::new(),
    )
}

/// `agent.deleted`, with the number of grants the delete revoked (they cascade).
pub fn agent_deleted(actor: Actor, agent_id: Uuid, grants_revoked: i64) -> Event {
    admin(
        kind::AGENT_DELETED,
        actor,
        Target::Agent(agent_id),
        Attrs::new().int(attr::GRANTS_REVOKED, grants_revoked),
    )
}

/// `workload_identity.created`: the policy, the agent it maps to and the issuer host.
pub fn workload_identity_created(
    actor: Actor,
    policy_id: Uuid,
    agent_id: Uuid,
    issuer: &str,
) -> Event {
    let mut attrs = Attrs::new().id(attr::AGENT_ID, agent_id);
    if let Some(h) = issuer_host(issuer) {
        attrs = attrs.host(attr::ISSUER, h);
    }
    admin(
        kind::WORKLOAD_IDENTITY_CREATED,
        actor,
        Target::WorkloadIdentity(policy_id),
        attrs,
    )
}

/// `workload_identity.deleted`.
pub fn workload_identity_deleted(actor: Actor, policy_id: Uuid, agent_id: Uuid) -> Event {
    admin(
        kind::WORKLOAD_IDENTITY_DELETED,
        actor,
        Target::WorkloadIdentity(policy_id),
        Attrs::new().id(attr::AGENT_ID, agent_id),
    )
}

/// `workload_identity.exchanged`: an external token matched the policy and an agent token was
/// minted. Actor is the agent the policy maps to; only ids and the issuer host are recorded (the
/// ledger has no field for claim text).
pub fn workload_identity_exchanged(policy_id: Uuid, agent_id: Uuid, issuer: &str) -> Event {
    let mut attrs = Attrs::new().id(attr::AGENT_ID, agent_id);
    if let Some(h) = issuer_host(issuer) {
        attrs = attrs.host(attr::ISSUER, h);
    }
    Event {
        kind: kind::WORKLOAD_IDENTITY_EXCHANGED,
        actor: Actor::Agent(agent_id),
        target: Some(Target::WorkloadIdentity(policy_id)),
        outcome: outcome::OK,
        attrs,
    }
}

/// `workload_identity.denied`: an exchange for this policy was refused. `reason` is a static
/// code (the verifier's refusal label or `claims`). The agent is not authenticated, so the
/// actor is the control plane.
pub fn workload_identity_denied(
    policy_id: Uuid,
    agent_id: Uuid,
    issuer: &str,
    reason: Code,
) -> Event {
    let mut attrs = Attrs::new()
        .id(attr::AGENT_ID, agent_id)
        .code(attr::REASON, reason);
    if let Some(h) = issuer_host(issuer) {
        attrs = attrs.host(attr::ISSUER, h);
    }
    Event {
        kind: kind::WORKLOAD_IDENTITY_DENIED,
        actor: Actor::Service(Code::new("control_plane")),
        target: Some(Target::WorkloadIdentity(policy_id)),
        outcome: outcome::DENIED,
        attrs,
    }
}

/// `grant.created`: the agent, the secret, the mode and the expiry (Unix seconds), if any.
pub fn grant_created(
    actor: Actor,
    grant_id: Uuid,
    agent_id: Uuid,
    secret_id: Uuid,
    mode: Code,
    expires_at: Option<OffsetDateTime>,
) -> Event {
    let mut attrs = Attrs::new()
        .id(attr::AGENT_ID, agent_id)
        .id(attr::SECRET_ID, secret_id)
        .code(attr::MODE, mode);
    if let Some(t) = expires_at {
        attrs = attrs.int(attr::EXPIRES_AT, t.unix_timestamp());
    }
    admin(kind::GRANT_CREATED, actor, Target::Grant(grant_id), attrs)
}

/// `grant.revoked`.
pub fn grant_revoked(actor: Actor, grant_id: Uuid, agent_id: Uuid) -> Event {
    admin(
        kind::GRANT_REVOKED,
        actor,
        Target::Grant(grant_id),
        Attrs::new().id(attr::AGENT_ID, agent_id),
    )
}

/// `mcp.call`: one remote MCP tool call by `user` in `org_id`. Only the layer, the tool name
/// (a registry name, or `unknown`), the outcome and a static `reason` are recorded: never the
/// call's arguments or result.
pub fn mcp_call(
    user: Uuid,
    org_id: Uuid,
    layer: Code,
    tool: Code,
    outcome: Code,
    reason: Option<Code>,
) -> Event {
    let mut attrs = Attrs::new().code(attr::LAYER, layer).code(attr::TOOL, tool);
    if let Some(r) = reason {
        attrs = attrs.code(attr::REASON, r);
    }
    Event {
        kind: kind::MCP_CALL,
        actor: Actor::User(user),
        target: Some(Target::Org(org_id)),
        outcome,
        attrs,
    }
}

/// `mcp.issuer_revoke`: the issuer-side consent revoke that follows a hub MCP client revoke
/// (task 4.2). `outcome` is `ok` or `error`; a failure carries a static `reason` and nothing
/// the issuer said.
pub fn mcp_issuer_revoke(actor: Actor, org_id: Uuid, outcome: Code, reason: Option<Code>) -> Event {
    let mut attrs = Attrs::new().code(attr::LAYER, Code::new("hub"));
    if let Some(r) = reason {
        attrs = attrs.code(attr::REASON, r);
    }
    Event {
        kind: kind::MCP_ISSUER_REVOKE,
        actor,
        target: Some(Target::Org(org_id)),
        outcome,
        attrs,
    }
}

/// Host name of an OIDC issuer URL, if it is one the ledger accepts. The issuer is the only
/// identity attribute recorded besides the user id: no subject, email, token or claim text.
fn issuer_host(issuer: &str) -> Option<Host> {
    let rest = issuer.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = host.split(':').next()?;
    Host::parse(host).ok()
}

fn auth(
    kind: Code,
    user: Uuid,
    org_id: Uuid,
    outcome: Code,
    issuer: &str,
    reason: Option<Code>,
) -> Event {
    let mut attrs = Attrs::new();
    if let Some(h) = issuer_host(issuer) {
        attrs = attrs.host(attr::ISSUER, h);
    }
    if let Some(r) = reason {
        attrs = attrs.code(attr::REASON, r);
    }
    Event {
        kind,
        actor: Actor::User(user),
        target: Some(Target::Org(org_id)),
        outcome,
        attrs,
    }
}

/// `auth.sign_in`: a verified human started a session.
pub fn auth_sign_in(user: Uuid, org_id: Uuid, issuer: &str) -> Event {
    auth(kind::AUTH_SIGN_IN, user, org_id, outcome::OK, issuer, None)
}

/// `auth.sign_out`: the human ended the session (the client discards its tokens).
pub fn auth_sign_out(user: Uuid, org_id: Uuid, issuer: &str) -> Event {
    auth(kind::AUTH_SIGN_OUT, user, org_id, outcome::OK, issuer, None)
}

/// `auth.verify_failed`: a known user's identity was refused; `reason` is a static code.
pub fn auth_verify_failed(user: Uuid, org_id: Uuid, issuer: &str, reason: Code) -> Event {
    auth(
        kind::AUTH_VERIFY_FAILED,
        user,
        org_id,
        outcome::DENIED,
        issuer,
        Some(reason),
    )
}

/// `org.personal_created`: a first sign-in created the user's personal org.
pub fn org_personal_created(user: Uuid, org_id: Uuid, issuer: &str) -> Event {
    auth(
        kind::ORG_PERSONAL_CREATED,
        user,
        org_id,
        outcome::OK,
        issuer,
        None,
    )
}
