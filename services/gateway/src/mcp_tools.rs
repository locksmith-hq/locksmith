//! The gateway's default-on MCP tools (m1-remote-mcp task 3.2): `list_my_keys`,
//! `relay_http_request` and `explain_block`, run as the agent behind the verified token.
//!
//! No tool returns a stored secret value. `list_my_keys` returns ids, names, modes and origins
//! (the same view as `GET /v1/grants`). `relay_http_request` goes through the very function
//! `/v1/relay` uses ([`crate::relay::handle_as`]), so the grant check, the origin and address
//! guards, the audit events and the response redaction are not re-implemented; its result is
//! the redacted upstream response. `explain_block` has no backing service on the gateway (no
//! block explanations are recorded anywhere yet), so it answers a typed `not_available`, as the
//! hub's does.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::StatusCode;
use bytes::Bytes;
use rmcp::ErrorData as McpError;
use rmcp::model::{CallToolResult, JsonObject};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::AgentIdentity;
use crate::grants::{self, GrantView};
use crate::relay::{self, Relay};

const NOT_AVAILABLE_EXPLAIN_BLOCK: &str = "No block explanations are recorded by the gateway \
    yet; the refusal slug in a relay result (for example `no_grant` or `denied`) names the cause.";

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
    #[allow(dead_code)]
    reason: String,
}

/// A typed tool error: a fixed code and status, never upstream or internal text.
fn tool_error(code: &str, status: u16) -> CallToolResult {
    CallToolResult::structured_error(json!({"error": {"code": code, "status": status}}))
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

/// Run default-on tool `name` as `agent`. `Err` is a protocol error (bad arguments, unknown
/// tool); a refused or failed relay is an `Ok` tool error.
pub(crate) async fn call(
    relay: Option<&Arc<Relay>>,
    agent: &AgentIdentity,
    name: &str,
    args: Option<JsonObject>,
) -> Result<CallToolResult, McpError> {
    if name == "explain_block" {
        let _a: ExplainArgs = parse(args)?;
        return Ok(CallToolResult::structured_error(json!({"error": {
            "code": "not_available",
            "status": 501,
            "message": NOT_AVAILABLE_EXPLAIN_BLOCK,
        }})));
    }
    let Some(relay) = relay else {
        return Ok(tool_error("unavailable", 503));
    };
    match name {
        "list_my_keys" => list_my_keys(relay, agent, args).await,
        "relay_http_request" => relay_http_request(relay, agent, args).await,
        _ => Err(McpError::invalid_params("unknown tool", None)),
    }
}
