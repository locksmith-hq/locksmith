//! `explain_block` for both MCP layers (m1-remote-mcp task 2.2, lead ruling on rescue #519).
//!
//! A static table from a refusal code to a plain explanation and next step. The caller passes the
//! reason it already received, so no block history is stored. No I/O and no secret material; the
//! caller's text is never echoed back (it can hold anything the caller pasted).

use serde_json::{Value, json};

/// What a refusal code means and what the caller does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Explanation {
    /// The matched code, or `None` when nothing known matched.
    pub rule: Option<&'static str>,
    pub explanation: &'static str,
    pub next_step: &'static str,
}

const ASK_HUMAN: &str = "Ask the human who manages this agent.";

/// Rows are tried in order and the first code found in the normalized reason wins, so a code that
/// contains another (`denied_address` and `denied`, `short_lived_unknown_or_expired` and
/// `expired`) comes first. Codes are the ones the gateway relay, the MCP layer and
/// `locksmith-mcp` really emit.
const TABLE: &[(&str, &str, &str)] = &[
    (
        "short_lived_unknown_or_expired",
        "That short-lived credential does not exist or has expired.",
        "Issue a new short-lived credential and use it before it expires.",
    ),
    (
        "denied_address",
        "The destination resolves to an address the relay never contacts (private, loopback or link-local).",
        "Use a public https host. Do not look for a way around the address rule; ask the human if the host is legitimate.",
    ),
    (
        "allowed_origin",
        "The request origin is not the one allowed for that credential.",
        "Send the request to the origin the credential was issued for, or issue a new credential.",
    ),
    (
        "grants_unavailable",
        "The grants service could not be read, so the request was refused to be safe.",
        "Retry later. If it keeps happening, tell the human.",
    ),
    (
        "secret_unavailable",
        "The key is not available right now.",
        "Retry later, or ask the human to check the key.",
    ),
    (
        "secret_unusable",
        "The key exists but cannot be used for this request.",
        "Do not retry with other values; ask the human to check the key.",
    ),
    (
        "audit_unavailable",
        "The request was not sent because it could not be recorded in the audit log.",
        "Retry later. If it keeps happening, tell the human.",
    ),
    (
        "response_withheld",
        "The upstream response was withheld because it could not be made safe to return.",
        "Do not retry in a loop; ask the human to review the request.",
    ),
    (
        "upstream_timeout",
        "The upstream service did not answer in time.",
        "Retry later with a smaller request.",
    ),
    (
        "upstream_unreachable",
        "The upstream service could not be reached.",
        "Check the url and retry later.",
    ),
    (
        "audit_failed",
        "The request could not be recorded in the audit log, so it was not completed.",
        "Retry later. If it keeps happening, tell the human.",
    ),
    (
        "upstream_error",
        "The upstream service answered with an error.",
        "Check the request and retry later.",
    ),
    (
        "bad_request",
        "The request was malformed.",
        "Fix the arguments (see the tool schema) and send it again.",
    ),
    (
        "not_found",
        "The key or version does not exist or is not visible to this agent.",
        "Check the id with list_my_keys; otherwise ask the human.",
    ),
    (
        "internal",
        "The server failed on its side.",
        "Retry later. If it keeps happening, tell the human.",
    ),
    (
        "unavailable",
        "The service is not available right now.",
        "Retry later. If it keeps happening, tell the human.",
    ),
    (
        "unauthenticated",
        "The agent token is missing, invalid or expired.",
        "Sign in again to get a new token.",
    ),
    (
        "no_grant",
        "This agent has no grant for that key, version or host.",
        "Do not retry. Ask the human to grant access to that key for this agent.",
    ),
    (
        "not_available",
        "That tool or feature is not available in this deployment.",
        ASK_HUMAN,
    ),
    (
        "tool_off",
        "That tool is switched off for your organization.",
        "Ask the human to switch the tool on in the console.",
    ),
    (
        "relay_only",
        "That key is relay-only for agent sessions: it is never injected into a command.",
        "Send the request through the relay. Only the human can change that in the agent policy.",
    ),
    (
        "relay_host",
        "A key goes only to hosts the human lists for it in the agent policy.",
        "Do not edit files to add hosts; ask the human.",
    ),
    (
        "http_host_not_bound",
        "That host is not approved for the key.",
        "Ask the human to approve the host and start a new session.",
    ),
    (
        "agent_policy",
        "The agent policy does not allow that request.",
        "Do not retry with other values; ask the human to change the policy.",
    ),
    (
        "revoked",
        "This client or session was revoked.",
        "Stop and ask the human.",
    ),
    (
        "expired",
        "The session or lease expired.",
        "Ask the human to start a new session.",
    ),
    (
        "locked",
        "The vault is locked or no session covers this process.",
        "Ask the human to unlock and start a session.",
    ),
    (
        "attestation",
        "The caller is not an attested Locksmith binary.",
        "Use `smith` or the MCP server.",
    ),
    (
        "denied",
        "The request was denied by policy.",
        "Do not retry or look for a workaround; ask the human.",
    ),
    (
        "role",
        "That request is not available to agents.",
        "Use the MCP tools or `smith run`.",
    ),
];

/// Every code with a row, for tests and callers that list them.
pub fn codes() -> impl Iterator<Item = &'static str> {
    TABLE.iter().map(|(c, _, _)| *c)
}

/// Explain `reason`: lower-case it, turn `-` into `_`, and take the first known code it contains.
pub fn lookup(reason: &str) -> Explanation {
    let r = reason.to_lowercase().replace('-', "_");
    TABLE.iter().find(|(code, _, _)| r.contains(code)).map_or(
        Explanation {
            rule: None,
            explanation: "No known rule matches that reason.",
            next_step: ASK_HUMAN,
        },
        |(code, explanation, next_step)| Explanation {
            rule: Some(code),
            explanation,
            next_step,
        },
    )
}

/// The tool result body (`rule`, `explanation`, `next_step`).
pub fn to_json(e: &Explanation) -> Value {
    json!({"rule": e.rule, "explanation": e.explanation, "next_step": e.next_step})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_normalized_codes_and_prefers_the_longer_one() {
        assert_eq!(lookup("no_grant").rule, Some("no_grant"));
        assert_eq!(lookup("NO-GRANT: key X").rule, Some("no_grant"));
        assert_eq!(lookup("denied_address").rule, Some("denied_address"));
        assert_eq!(lookup("denied").rule, Some("denied"));
        assert_eq!(
            lookup("short_lived_unknown_or_expired").rule,
            Some("short_lived_unknown_or_expired")
        );
        assert_eq!(lookup("expired").rule, Some("expired"));
        assert_eq!(
            lookup("http_host_not_bound:evil.com").rule,
            Some("http_host_not_bound")
        );
    }

    #[test]
    fn every_gateway_relay_code_has_a_row() {
        for code in [
            "no_grant",
            "denied_address",
            "allowed_origin",
            "expired",
            "unauthenticated",
            "secret_unusable",
            "secret_unavailable",
            "grants_unavailable",
            "short_lived_unknown_or_expired",
            "upstream_timeout",
            "upstream_unreachable",
            "response_withheld",
            "audit_unavailable",
            "denied",
            "bad_request",
            "not_found",
            "audit_failed",
            "upstream_error",
            "internal",
            "unavailable",
        ] {
            assert_eq!(lookup(code).rule, Some(code), "{code}");
        }
        assert!(codes().count() >= 20);
    }

    #[test]
    fn unknown_falls_back_and_input_is_never_echoed() {
        let e = lookup("zzz SENTINEL-pasted-text");
        assert_eq!(e.rule, None);
        assert!(e.next_step.contains("Ask the human"));
        let body = to_json(&lookup("no_grant SENTINEL-pasted-text")).to_string();
        assert!(!body.contains("SENTINEL"));
        assert!(!to_json(&e).to_string().contains("SENTINEL"));
    }
}
