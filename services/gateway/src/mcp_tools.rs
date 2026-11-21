//! The gateway's MCP tools, run as the agent behind the verified token: the default-on
//! `list_my_keys`, `relay_http_request` and `explain_block` (m1-remote-mcp task 3.2), and the
//! off-by-default `issue_short_lived_credential` (task 3.3, decision H1-2).
//!
//! No tool returns a stored secret value. `list_my_keys` returns ids, names, modes and origins
//! (the same view as `GET /v1/grants`). `relay_http_request` goes through the very function
//! `/v1/relay` uses ([`crate::relay::handle_as`]), so the grant check, the origin and address
//! guards, the audit events and the response redaction are not re-implemented; its result is
//! the redacted upstream response. `explain_block` looks the caller's refusal code up in the
//! static table shared with the hub (`ls_mcp_server::explain`); it does no I/O.
//!
//! `issue_short_lived_credential` returns a credential the gateway mints ([`crate::short_lived`]),
//! never the stored value: it decrypts nothing and touches no KMS. It needs an unexpired relay
//! grant and a binding for the secret, lives 60 to 900 seconds and never past the grant, and is
//! usable only on `POST /v1/relay` for that one secret. The `credential.issued` audit event (the
//! agent, the secret, the credential's id and expiry) is appended before the credential is
//! stored, so a ledger that cannot take it means nothing was issued (fail closed).

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::StatusCode;
use bytes::Bytes;
use rmcp::ErrorData as McpError;
use rmcp::model::{CallToolResult, JsonObject};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use secrecy::ExposeSecret as _;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::audit::{EventKind, Issued, RelayEvent};
use crate::auth::AgentIdentity;
use crate::grants::{self, GrantView, MODE_RELAY};
use crate::relay::{self, Relay};
use crate::short_lived::{self, MAX_TTL_SECS, MIN_TTL_SECS, StoreError};

/// Default and largest page for `list_my_keys`.
const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 100;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainArgs {
    reason: String,
}

/// A typed tool error: a fixed code and status, never upstream or internal text.
fn tool_error(code: &str, status: u16) -> CallToolResult {
    CallToolResult::structured_error(json!({"error": {"code": code, "status": status}}))
}

/// The tool error for a call refused before it ran (an unreadable switch).
pub(crate) fn unavailable_result(code: &str) -> CallToolResult {
    tool_error(code, 503)
}

fn parse<T: for<'de> Deserialize<'de>>(args: Option<JsonObject>) -> Result<T, McpError> {
    serde_json::from_value(Value::Object(args.unwrap_or_default()))
        .map_err(|_| McpError::invalid_params("invalid arguments", None))
}

fn key_item(g: &GrantView) -> Value {
    json!({
        "secret_id": g.secret_id,
        "name": g.secret_name,
        "mode": g.mode,
        "allowed_origin": g.allowed_origin,
        "grant_expires_at": g.expires_at.and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339).ok()
        }),
    })
}

async fn list_my_keys(
    relay: &Relay,
    agent: &AgentIdentity,
    args: Option<JsonObject>,
) -> Result<CallToolResult, McpError> {
    let a: ListArgs = parse(args)?;
    let limit = a
        .limit
        .map_or(DEFAULT_LIMIT, |l| (l as usize).clamp(1, MAX_LIMIT));
    // The cursor is an offset into the agent's grants; anything else is refused.
    let offset: usize = match a.cursor.as_deref() {
        None | Some("") => 0,
        Some(c) => c
            .parse()
            .map_err(|_| McpError::invalid_params("invalid cursor", None))?,
    };
    let grants = match relay.grants().grants(agent.agent_id).await {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(reason = e.as_str(), "agent grants could not be read");
            return Ok(tool_error("grants_unavailable", 502));
        }
    };
    let views = grants::grant_views(relay, grants);
    let page: Vec<Value> = views
        .iter()
        .skip(offset)
        .take(limit)
        .map(key_item)
        .collect();
    let next = (offset + limit < views.len()).then(|| (offset + limit).to_string());
    tracing::info!(grants = views.len(), "agent keys listed over mcp");
    Ok(CallToolResult::structured(
        json!({"items": page, "next_cursor": next}),
    ))
}

async fn relay_http_request(
    relay: &Arc<Relay>,
    agent: &AgentIdentity,
    args: Option<JsonObject>,
) -> Result<CallToolResult, McpError> {
    // The tool arguments are the relay's own request shape (`deny_unknown_fields` there too).
    let body = serde_json::to_vec(&Value::Object(args.unwrap_or_default()))
        .map_err(|_| McpError::invalid_params("invalid arguments", None))?;
    let limit = relay.options().max_response_body.saturating_mul(2) + 64 * 1024;
    let response = relay::handle_as(
        relay.clone(),
        *agent,
        Uuid::new_v4().to_string(),
        Bytes::from(body),
    )
    .await;
    let status = response.status();
    let bytes = match to_bytes(response.into_body(), limit).await {
        Ok(b) => b,
        Err(_) => return Ok(tool_error("response_withheld", 502)),
    };
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if status == StatusCode::OK {
        return Ok(CallToolResult::structured(parsed));
    }
    // A refusal carries a fixed slug and a request id, never upstream text.
    let code = parsed
        .get("error")
        .and_then(Value::as_str)
        .filter(|s| s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
        .unwrap_or("relay_failed");
    Ok(tool_error(code, status.as_u16()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueArgs {
    secret_id: Uuid,
    job: String,
    ttl_secs: u32,
}

/// A job label: 1 to 128 of `A-Z a-z 0-9 . _ : / -` (the input schema's pattern). It is echoed
/// back in `scope` only; never logged or audited.
fn valid_job(job: &str) -> bool {
    (1..=128).contains(&job.len())
        && job
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}

async fn issue_short_lived_credential(
    relay: &Relay,
    agent: &AgentIdentity,
    args: Option<JsonObject>,
) -> Result<CallToolResult, McpError> {
    let a: IssueArgs = parse(args)?;
    if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&a.ttl_secs) || !valid_job(&a.job) {
        return Err(McpError::invalid_params("invalid arguments", None));
    }
    let now = OffsetDateTime::now_utc();
    // The same grant the relay will check: an unexpired relay grant for this secret. The
    // credential never outlives the longest such grant.
    let grants = match relay.grants().grants(agent.agent_id).await {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(reason = e.as_str(), "agent grants could not be read");
            return Ok(tool_error("grants_unavailable", 502));
        }
    };
    let matching: Vec<Option<OffsetDateTime>> = grants
        .iter()
        .filter(|g| g.secret_id == a.secret_id && g.mode == MODE_RELAY && g.active_at(now))
        .map(|g| g.expires_at)
        .collect();
    if matching.is_empty() {
        return Ok(tool_error("no_grant", 403));
    }
    let grant_expires = if matching.iter().any(Option::is_none) {
        None
    } else {
        matching.into_iter().flatten().max()
    };
    // A credential for a secret the gateway cannot relay would be useless: refuse it.
    if relay.bindings().for_secret(a.secret_id).is_none() {
        return Ok(tool_error("denied", 403));
    }
    let expires_at = short_lived::expiry(now, a.ttl_secs, grant_expires);
    let minted =
        match relay
            .short_lived()
            .mint(agent.agent_id, agent.org_id, a.secret_id, expires_at, now)
        {
            Ok(m) => m,
            Err(StoreError::TooMany) => return Ok(tool_error("too_many_credentials", 429)),
            Err(StoreError::Rng) => return Ok(tool_error("internal", 500)),
        };
    let scope = minted.scope;
    // Audit first: if the ledger does not take the issue, the credential is never stored.
    let event = RelayEvent {
        kind: EventKind::CredentialIssued,
        agent_id: agent.agent_id,
        secret_id: a.secret_id,
        version: 0,
        method: None,
        host: None,
        port: None,
        status: None,
        attempt_id: None,
        issued: Some(Issued {
            credential_id: scope.credential_id,
            expires_at: expires_at.unix_timestamp(),
        }),
    };
    if relay.audit().append(event).await.is_err() {
        tracing::error!("credential.issued event not appended; nothing issued");
        return Ok(tool_error("audit_unavailable", 503));
    }
    if let Err(e) = relay.short_lived().insert(&minted, now) {
        tracing::warn!(
            ?e,
            "short-lived credential not stored after its audit event"
        );
        return Ok(tool_error("too_many_credentials", 429));
    }
    let Ok(expires) = expires_at.format(&Rfc3339) else {
        return Ok(tool_error("internal", 500));
    };
    tracing::info!(
        credential.id = %scope.credential_id,
        secret.id = %a.secret_id,
        expires_at = expires_at.unix_timestamp(),
        "short-lived credential issued"
    );
    Ok(CallToolResult::structured(json!({
        "credential": minted.token().expose_secret(),
        "credential_id": scope.credential_id,
        "expires_at": expires,
        "scope": format!("relay secret_id={} job={}", a.secret_id, a.job),
    })))
}

/// Run tool `name` as `agent`. `Err` is a protocol error (bad arguments, unknown
/// tool); a refused or failed relay is an `Ok` tool error.
pub(crate) async fn call(
    relay: Option<&Arc<Relay>>,
    agent: &AgentIdentity,
    name: &str,
    args: Option<JsonObject>,
) -> Result<CallToolResult, McpError> {
    if name == "explain_block" {
        let a: ExplainArgs = parse(args)?;
        return Ok(CallToolResult::structured(ls_mcp_server::explain::to_json(
            &ls_mcp_server::explain::lookup(&a.reason),
        )));
    }
    let Some(relay) = relay else {
        return Ok(tool_error("unavailable", 503));
    };
    match name {
        "list_my_keys" => list_my_keys(relay, agent, args).await,
        "relay_http_request" => relay_http_request(relay, agent, args).await,
        // Reached only when the switch is on (`mcp_endpoint` authorizes against the registry).
        "issue_short_lived_credential" => issue_short_lived_credential(relay, agent, args).await,
        _ => Err(McpError::invalid_params("unknown tool", None)),
    }
}
