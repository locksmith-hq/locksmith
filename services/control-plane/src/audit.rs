//! Appending to the audit ledger from request code (S5 design decisions 1, 2 and 5).
//!
//! Every append runs inside the caller's [`crate::db::Database::with_org`] transaction through
//! `ls_audit::pg::append_in_tx`, so an admin change and its audit event commit or roll back
//! together. Events are built only from `ls_audit`'s allow-listed types ([`Code`], [`Actor`],
//! [`Target`], ids, integers, validated hosts): no string from a request reaches the ledger.

use ls_audit::pg::{Appended, append_in_tx};
use ls_audit::{Actor, Attrs, Code, Event, Target, attr, kind, outcome};
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
