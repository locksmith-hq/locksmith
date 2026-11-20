//! Hub MCP read tools (change m1-remote-mcp, task 2.2).
//!
//! Each tool is the console's own handler called as the person: the verified identity of the
//! `/mcp` request is resolved to its org exactly as a console sign-in does
//! ([`crate::users::resolve`]), and the REST handler is invoked with that [`OrgBinding`], so
//! authorization is org-scoped through the same `Database::with_org` row-level security as the
//! console. The tools only reshape the handlers' metadata responses; none of them touches a
//! secret value, and no tool argument is echoed back.
//!
//! Out of scope here: the per-org tool switch (task 2.3, so only the registry's defaults apply)
//! and the audit event per call (task 2.5).

use axum::Json;
use axum::extract::State;
use rmcp::ErrorData as McpError;
use rmcp::model::{CallToolResult, JsonObject};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::api::agents::{self, AgentGrant};
use crate::api::audit::{self, AuditEventParams};
use crate::api::extract::{ApiPath, ApiQuery};
use crate::api::{PageParams, environments, projects, secrets, versions};
use crate::app::AppState;
use crate::auth::OrgBinding;
use crate::mcp_endpoint::McpPrincipal;
use crate::problem::{ApiError, Kind};
use crate::users;

/// A tool that is in the hub registry but has no service code behind it yet.
const NOT_AVAILABLE_EXPLAIN_BLOCK: &str = "No block explanations are recorded on the hub yet; \
    the gateway's explain_block tool covers blocks of an agent's own requests.";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageArgs {
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretNamesArgs {
    project_id: Uuid,
    environment_id: Uuid,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantsArgs {
    agent_id: Uuid,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainArgs {
    // Read so the shape is checked, never stored or echoed.
    #[allow(dead_code)]
    reason: String,
}

/// Arguments must match the tool's input schema. The message names no value.
fn parse<T: DeserializeOwned>(args: Option<JsonObject>) -> Result<T, McpError> {
    serde_json::from_value(Value::Object(args.unwrap_or_default())).map_err(|_| {
        McpError::invalid_params("arguments do not match the tool's input schema", None)
    })
}

/// `cursor` and `limit` as the REST query type `T` (`PageParams` or `AuditEventParams`).
fn paging<T: DeserializeOwned>(cursor: Option<String>, limit: Option<u32>) -> Result<T, ApiError> {
    let mut v = serde_json::Map::new();
    if let Some(c) = cursor {
        v.insert("cursor".into(), Value::String(c));
    }
    if let Some(l) = limit {
        v.insert("limit".into(), Value::from(l));
    }
    serde_json::from_value(Value::Object(v)).map_err(|_| ApiError::validation("invalid paging"))
}

fn ts(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

fn page(items: Vec<Value>, next: Option<String>) -> Value {
    json!({"items": items, "next_cursor": next})
}

/// A failed read as a tool error: the REST status and problem slug, the REST detail (which never
/// carries request data other than a field name), nothing else.
fn tool_error(e: ApiError) -> CallToolResult {
    let detail = match e.kind {
        Kind::Internal | Kind::Unavailable => None,
        _ => e.detail,
    };
    CallToolResult::structured_error(json!({"error": {
        "code": e.kind.slug(),
        "status": e.kind.status().as_u16(),
        "message": detail,
    }}))
}

/// The tool result for a handled call.
pub fn result(r: Result<Value, ApiError>) -> CallToolResult {
    match r {
        Ok(v) => CallToolResult::structured(v),
        Err(e) => tool_error(e),
    }
}

/// Run hub read tool `name` as `principal`. `Err` is a protocol error (bad arguments, unknown
/// tool); a failed read is an `Ok` tool error, like the REST handlers' problem responses.
pub async fn call(
    state: &AppState,
    principal: &McpPrincipal,
    name: &str,
    args: Option<JsonObject>,
) -> Result<CallToolResult, McpError> {
    // Parse first: a bad call fails before any person is resolved.
    match name {
        "list_projects" | "read_activity" | "list_agents" => {
            let a: PageArgs = parse(args)?;
            Ok(result(run_page(state, principal, name, a).await))
        }
        "list_secret_names" => {
            let a: SecretNamesArgs = parse(args)?;
            Ok(result(list_secret_names(state, principal, a).await))
        }
        "list_grants" => {
            let a: GrantsArgs = parse(args)?;
            Ok(result(list_grants(state, principal, a).await))
        }
        "explain_block" => {
            let _a: ExplainArgs = parse(args)?;
            Ok(CallToolResult::structured_error(json!({"error": {
                "code": "not_available",
                "status": 501,
                "message": NOT_AVAILABLE_EXPLAIN_BLOCK,
            }})))
        }
        _ => Err(McpError::invalid_params("unknown tool", None)),
    }
}

/// The person's org, resolved as a console sign-in does (`403` for an unverified email).
async fn org_of(state: &AppState, principal: &McpPrincipal) -> Result<OrgBinding, ApiError> {
    let user = users::resolve(state.db(), &principal.0).await?;
    Ok(OrgBinding {
        org_id: user.org_id,
    })
}

async fn run_page(
    state: &AppState,
    principal: &McpPrincipal,
    name: &str,
    a: PageArgs,
) -> Result<Value, ApiError> {
    let org = org_of(state, principal).await?;
    match name {
        "list_projects" => list_projects(state, org, paging(a.cursor, a.limit)?).await,
        "read_activity" => read_activity(state, org, paging(a.cursor, a.limit)?).await,
        _ => list_agents(state, org, paging(a.cursor, a.limit)?).await,
    }
}

async fn list_projects(
    state: &AppState,
    org: OrgBinding,
    q: PageParams,
) -> Result<Value, ApiError> {
    let Json(p) = projects::list(State(state.clone()), org, ApiQuery(q)).await?;
    let mut items = Vec::new();
    for project in p.items {
        let envs: PageParams = paging(None, Some(100))?;
        let Json(e) = environments::list(
            State(state.clone()),
            org,
            ApiPath(project.id),
            ApiQuery(envs),
        )
        .await?;
        items.push(json!({
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "environments": e.items.iter()
                .map(|e| json!({"id": e.id, "name": e.name})).collect::<Vec<_>>(),
        }));
    }
    Ok(page(items, p.next))
}

async fn list_secret_names(
    state: &AppState,
    principal: &McpPrincipal,
    a: SecretNamesArgs,
) -> Result<Value, ApiError> {
    let org = org_of(state, principal).await?;
    let q: PageParams = paging(a.cursor, a.limit)?;
    let Json(p) = secrets::list(
        State(state.clone()),
        org,
        ApiPath((a.project_id, a.environment_id)),
        ApiQuery(q),
    )
    .await?;
    let mut items = Vec::new();
    for s in p.items {
        let Json(v) = versions::list(
            State(state.clone()),
            org,
            ApiPath((a.project_id, a.environment_id, s.id)),
        )
        .await?;
        let latest = v.items.iter().map(|v| v.version).max();
        items.push(json!({
            "secret_id": s.id,
            "name": s.name,
            "description": s.description,
            "latest_version": latest,
            "versions": v.items.iter()
                .map(|v| json!({"version": v.version, "created_at": ts(v.created_at)}))
                .collect::<Vec<_>>(),
            "updated_at": ts(s.updated_at),
        }));
    }
    Ok(page(items, p.next))
}

async fn read_activity(
    state: &AppState,
    org: OrgBinding,
    q: AuditEventParams,
) -> Result<Value, ApiError> {
    let Json(p) = audit::list_events(State(state.clone()), org, ApiQuery(q)).await?;
    let items = p
        .items
        .into_iter()
        .map(|e| {
            let mut v = json!({
                "event_id": e.id, "seq": e.seq, "at": ts(e.at), "action": e.kind,
                "actor": e.actor, "outcome": e.outcome,
            });
            if let (Some(t), Some(o)) = (e.target, v.as_object_mut()) {
                o.insert("target".into(), Value::String(t));
            }
            v
        })
        .collect();
    Ok(page(items, p.next))
}

async fn list_agents(state: &AppState, org: OrgBinding, q: PageParams) -> Result<Value, ApiError> {
    let Json(p) = agents::list(State(state.clone()), org, ApiQuery(q)).await?;
    let items = p
        .items
        .into_iter()
        .map(|a| {
            json!({"agent_id": a.id, "name": a.name, "description": a.description,
                   "created_at": ts(a.created_at)})
        })
        .collect();
    Ok(page(items, p.next))
}

async fn list_grants(
    state: &AppState,
    principal: &McpPrincipal,
    a: GrantsArgs,
) -> Result<Value, ApiError> {
    let org = org_of(state, principal).await?;
    let q: PageParams = paging(a.cursor, a.limit)?;
    let Json(p) =
        agents::list_grants(State(state.clone()), org, ApiPath(a.agent_id), ApiQuery(q)).await?;
    let items = p
        .items
        .into_iter()
        .map(|g: AgentGrant| {
            json!({"grant_id": g.id, "agent_id": g.agent_id, "secret_id": g.secret_id,
                   "secret_name": g.secret_name, "mode": g.mode.as_str(),
                   "expires_at": g.expires_at.map(ts), "created_at": ts(g.created_at)})
        })
        .collect();
    Ok(page(items, p.next))
}
