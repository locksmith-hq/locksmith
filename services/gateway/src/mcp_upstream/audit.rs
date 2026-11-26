//! Task 4.2 of m2-mcp-gateway (design decision 8): the ledger events of a proxied `tools/call`.
//!
//! - An allowed call appends `mcp.upstream_call` (`pending`) before anything is forwarded and is
//!   refused with `audit_unavailable` when that append fails ([`CallAudit::begin`]).
//! - After the upstream answers or the hop fails it appends `mcp.upstream_outcome` (`ok` or
//!   `error`) naming the pending event's id, retried like `relay.outcome` (the relay's retry
//!   count and backoff); the control plane makes it idempotent on that id ([`CallAudit::finish`]).
//! - A refusal (`hide`, `deny`, `hold`, a name outside the catalogue, a policy or catalogue that
//!   could not answer) appends one `mcp.upstream_call` with outcome `denied` and the decision
//!   and a reason ([`CallAudit::refused`]). The call is already refused, so a failed append is
//!   logged, not fatal.
//!
//! An event holds the agent, the upstream's configured name, a catalogue tool name (else
//! `unknown`), the decision and a closed reason. It is built from those and nothing else: no
//! argument, result, upstream text or credential is in reach of this module.

use ls_mcp_server::upstream::ToolDecision;
use rmcp::ErrorData as McpError;
use uuid::Uuid;

use super::hop::HopError;
use crate::audit::{
    AuditError, McpUpstreamEvent, McpUpstreamOutcome, McpUpstreamPhase, McpUpstreamReason,
};
use crate::auth::AgentIdentity;
use crate::relay::Relay;

/// The tool recorded for a name the catalogue does not hold (never agent-supplied text).
pub(super) const UNKNOWN_TOOL: &str = "unknown";

/// The error an agent gets when the `pending` event could not be appended.
pub(super) fn audit_unavailable() -> McpError {
    McpError::internal_error("audit_unavailable", None)
}

/// The audit of one call: the agent and upstream it is for.
pub(super) struct CallAudit<'a> {
    relay: &'a Relay,
    agent: AgentIdentity,
    upstream: &'a str,
}

impl<'a> CallAudit<'a> {
    pub(super) fn new(relay: &'a Relay, agent: AgentIdentity, upstream: &'a str) -> Self {
        Self {
            relay,
            agent,
            upstream,
        }
    }

    fn event(
        &self,
        phase: McpUpstreamPhase,
        tool: &str,
        decision: ToolDecision,
        outcome: McpUpstreamOutcome,
        reason: Option<McpUpstreamReason>,
        attempt_id: Option<Uuid>,
    ) -> McpUpstreamEvent {
        McpUpstreamEvent {
            phase,
            agent_id: self.agent.agent_id,
            upstream: self.upstream.to_owned(),
            tool: tool.to_owned(),
            decision,
            outcome,
            reason,
            attempt_id,
        }
    }

    /// Append the `pending` event of an allowed call; its id keys the outcome. `Err` means the
    /// call must be refused (`audit_unavailable`) and nothing forwarded. Not retried: the agent
    /// can retry the call.
    pub(super) async fn begin(&self, tool: &str) -> Result<Uuid, McpError> {
        let ev = self.event(
            McpUpstreamPhase::Call,
            tool,
            ToolDecision::Allow,
            McpUpstreamOutcome::Pending,
            None,
            None,
        );
        self.relay
            .audit()
            .append_mcp_upstream(ev)
            .await
            .map_err(|e| {
                tracing::warn!(upstream = self.upstream, error = %e, "mcp.upstream_call not appended; call refused");
                audit_unavailable()
            })
    }

    /// Append the outcome of a forwarded call, retrying failures that may be transient.
    pub(super) async fn finish(&self, tool: &str, attempt: Uuid, result: Result<(), HopError>) {
        let (outcome, reason) = match result {
            Ok(()) => (McpUpstreamOutcome::Ok, None),
            Err(e) => (McpUpstreamOutcome::Error, Some(McpUpstreamReason::Hop(e))),
        };
        let ev = self.event(
            McpUpstreamPhase::Outcome,
            tool,
            ToolDecision::Allow,
            outcome,
            reason,
            Some(attempt),
        );
        let options = self.relay.options();
        let mut wait = options.outcome_retry_backoff;
        for try_no in 0..=options.outcome_retries {
            match self.relay.audit().append_mcp_upstream(ev.clone()).await {
                Ok(_) => return,
                Err(AuditError::Rejected) => {
                    tracing::error!(
                        upstream = self.upstream,
                        "mcp.upstream_outcome refused by the ledger"
                    );
                    return;
                }
                Err(AuditError::Unavailable) => {
                    tracing::warn!(
                        upstream = self.upstream,
                        attempt = try_no + 1,
                        "mcp.upstream_outcome not appended"
                    );
                    if try_no < options.outcome_retries {
                        tokio::time::sleep(wait).await;
                        wait = wait.saturating_mul(2);
                    }
                }
            }
        }
    }

    /// Append the one `denied` event of a refused call. `tool` is a catalogue name or
    /// [`UNKNOWN_TOOL`]; `decision` is the policy's (`hide` for a name it did not decide).
    pub(super) async fn refused(
        &self,
        tool: &str,
        decision: ToolDecision,
        reason: McpUpstreamReason,
    ) {
        let ev = self.event(
            McpUpstreamPhase::Call,
            tool,
            decision,
            McpUpstreamOutcome::Denied,
            Some(reason),
            None,
        );
        if let Err(e) = self.relay.audit().append_mcp_upstream(ev).await {
            tracing::warn!(upstream = self.upstream, error = %e, "denied mcp.upstream_call not appended");
        }
    }
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
