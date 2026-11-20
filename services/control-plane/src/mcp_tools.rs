//! Hub MCP read tools (change m1-remote-mcp, task 2.2).
//!
//! Each tool is the console's own handler called as the person: the verified identity of the
//! `/mcp` request is resolved to its org exactly as a console sign-in does
//! ([`crate::users::resolve`]), and the REST handler is invoked with that [`OrgBinding`], so
//! authorization is org-scoped through the same `Database::with_org` row-level security as the
//! console. The tools only reshape the handlers' metadata responses; none of them touches a
//! secret value, and no tool argument is echoed back.
//!
//! The per-org tool switch (task 2.3) is read by [`tool_overrides`] and the signed-in client is
//! recorded by [`record_client`]. Every call, allowed or refused, is appended to the audit ledger
//! by [`record_call`] (task 2.5): layer, tool name, person, outcome, never the arguments.

use std::collections::HashMap;

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
use crate::audit as ledger;
use crate::auth::OrgBinding;
use crate::db::sql::{self, Row};
use crate::mcp_endpoint::McpPrincipal;
use crate::problem::{ApiError, Kind};
use crate::users::{self, ResolvedUser};
use ls_audit::{Actor, Code, outcome};

/// A tool that is in the hub registry but has no service code behind it yet.
const NOT_AVAILABLE_EXPLAIN_BLOCK: &str = "No block explanations are recorded on the hub yet; \
    the gateway's explain_block tool will cover blocks of an agent's own requests.";

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
struct RevokeGrantArgs {
    grant_id: Uuid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PauseAgentsArgs {
    // Read so the shape is checked, never stored or echoed.
    #[allow(dead_code)]
    agent_ids: Option<Vec<Uuid>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainArgs {
    // Read so the shape is checked, never stored or echoed.
    #[allow(dead_code)]
    reason: String,
}

/// The agent-pause endpoint belongs to change t8-sessions-and-revoke; until it lands the tool
/// is a typed error (it is off by default, so only an org that switched it on sees this).
const NOT_AVAILABLE_PAUSE_AGENTS: &str = "Pausing agents is not available yet; it arrives with \
    the session and revoke change. Revoke the agent's grants instead.";

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
        "revoke_grant" => {
            let a: RevokeGrantArgs = parse(args)?;
            Ok(result(revoke_grant(state, principal, a).await))
        }
        "pause_agents" => {
            let _a: PauseAgentsArgs = parse(args)?;
            Ok(CallToolResult::structured_error(json!({"error": {
                "code": "not_available",
                "status": 501,
                "message": NOT_AVAILABLE_PAUSE_AGENTS,
            }})))
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

/// The person behind the token, resolved as a console sign-in does (`403` for an unverified
/// email, which has no user or org to attribute anything to).
pub async fn caller(state: &AppState, principal: &McpPrincipal) -> Result<ResolvedUser, ApiError> {
    users::resolve(state.db(), &principal.0).await
}

/// The person's org, resolved as a console sign-in does (`403` for an unverified email).
async fn org_of(state: &AppState, principal: &McpPrincipal) -> Result<OrgBinding, ApiError> {
    let user = caller(state, principal).await?;
    Ok(OrgBinding {
        org_id: user.org_id,
    })
}

/// Append an `mcp.call` event to the org's ledger. `tool` is a registry name (or `unknown`),
/// never text from the request. Arguments and results are not recorded.
pub async fn record_call(
    state: &AppState,
    user: &ResolvedUser,
    layer: &'static str,
    tool: &'static str,
    outcome: Code,
    reason: Option<Code>,
) -> Result<(), ApiError> {
    let event = ledger::mcp_call(
        user.user_id,
        user.org_id,
        Code::try_new(layer).unwrap_or(Code::new("unknown")),
        Code::try_new(tool).unwrap_or(Code::new("unknown")),
        outcome,
        reason,
    );
    let org_id = user.org_id;
    state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                ledger::append(c, org_id, &event).await?;
                Ok::<_, ApiError>(())
            })
        })
        .await
}

/// The audit outcome of a finished call: `ok`; `denied` for a tool error the REST API would give
/// as `401`/`403`; `error` for any other failure. The reason is a static code.
pub fn call_outcome(result: &Result<CallToolResult, McpError>) -> (Code, Option<Code>) {
    match result {
        Err(_) => (outcome::ERROR, Some(Code::new("invalid_arguments"))),
        Ok(r) if r.is_error != Some(true) => (outcome::OK, None),
        Ok(r) => {
            let status = r
                .structured_content
                .as_ref()
                .and_then(|v| v["error"]["status"].as_u64());
            match status {
                Some(401 | 403) => (outcome::DENIED, Some(Code::new("forbidden"))),
                Some(501) => (outcome::ERROR, Some(Code::new("not_available"))),
                _ => (outcome::ERROR, Some(Code::new("tool_error"))),
            }
        }
    }
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

/// Revoke one grant as the person: the console's own delete handler (which appends the audit
/// event), after looking up the grant's agent inside the person's org.
async fn revoke_grant(
    state: &AppState,
    principal: &McpPrincipal,
    a: RevokeGrantArgs,
) -> Result<Value, ApiError> {
    let user = caller(state, principal).await?;
    let org = OrgBinding {
        org_id: user.org_id,
    };
    let grant_id = a.grant_id;
    let agent_id = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let row = sql::query("SELECT agent_id FROM agent_grants WHERE id = $1")
                    .bind(grant_id)
                    .fetch_optional(&mut *c)
                    .await?;
                match row {
                    Some(r) => Ok::<_, ApiError>(r.try_get::<Uuid, _>("agent_id")?),
                    None => Err(ApiError::not_found()),
                }
            })
        })
        .await?;
    // The event is attributed to the person, not the dev actor.
    agents::revoke_grant_as(state, org, Actor::User(user.user_id), agent_id, grant_id).await?;
    Ok(json!({"grant_id": grant_id, "revoked_at": ts(OffsetDateTime::now_utc())}))
}

/// The org's hub tool switches (`mcp_tool_settings`): only the overrides of a tool's default.
pub async fn tool_overrides(
    state: &AppState,
    principal: &McpPrincipal,
) -> Result<HashMap<String, bool>, ApiError> {
    overrides_for(state, caller(state, principal).await?.org_id).await
}

/// As [`tool_overrides`] for an org already resolved.
pub async fn overrides_for(
    state: &AppState,
    org_id: Uuid,
) -> Result<HashMap<String, bool>, ApiError> {
    let rows = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                let rows =
                    sql::query("SELECT tool, enabled FROM mcp_tool_settings WHERE layer = 'hub'")
                        .fetch_all(c)
                        .await?;
                rows.iter()
                    .map(|r| {
                        Ok((
                            r.try_get::<String, _>("tool")?,
                            r.try_get::<bool, _>("enabled")?,
                        ))
                    })
                    .collect::<sql::Result<HashMap<_, _>>>()
            })
        })
        .await?;
    Ok(rows)
}

/// Record the client on `initialize`: insert on first sight, refresh the name and last-seen time
/// afterwards. A revoked row stays revoked (`revoked_at` is never touched here). Keyed by the
/// token's OAuth client id and the person, never by a session id; a token with no client id
/// records nothing. The name is informational and length-capped; no token text is stored.
pub async fn record_client(
    state: &AppState,
    principal: &McpPrincipal,
    client_name: &str,
) -> Result<(), ApiError> {
    let Some(client_id) = principal.0.client_id.clone() else {
        return Ok(());
    };
    let org = org_of(state, principal).await?;
    let who = format!("{}|{}", principal.0.issuer, principal.0.subject);
    let name: String = client_name.chars().take(200).collect();
    state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                sql::query(
                    "INSERT INTO mcp_clients (org_id, layer, client_id, principal, client_name) \
                     VALUES ($1, 'hub', $2, $3, $4) \
                     ON CONFLICT (org_id, layer, client_id, principal) \
                     DO UPDATE SET client_name = EXCLUDED.client_name, last_seen_at = now()",
                )
                .bind(org.org_id)
                .bind(client_id)
                .bind(who)
                .bind(name)
                .execute(c)
                .await?;
                Ok::<_, ApiError>(())
            })
        })
        .await
}

/// Whether this token's client has been revoked for the person. A client row is keyed by the
/// token's OAuth client id and the person; a revoked row refuses every token issued before the
/// revoke (`auth_time` older than `revoked_at`, or absent). A fresh sign-in after the revoke
/// carries a newer `auth_time` and is let through. A token with no client id, or no row yet, is
/// not revoked. A person who cannot be resolved is left to the tool handlers to refuse.
pub async fn client_revoked(state: &AppState, principal: &McpPrincipal) -> Result<bool, ApiError> {
    let Some(client_id) = principal.0.client_id.clone() else {
        return Ok(false);
    };
    // An unverified email has no org and no client row: the handlers refuse it as the console
    // does. Any other failure fails closed (the middleware answers 401).
    let user = match caller(state, principal).await {
        Ok(user) => user,
        Err(e) if e.kind == Kind::EmailVerificationRequired => return Ok(false),
        Err(e) => return Err(e),
    };
    let who = format!("{}|{}", principal.0.issuer, principal.0.subject);
    let revoked_at: Option<OffsetDateTime> = state
        .db()
        .with_org(user.org_id, move |c| {
            Box::pin(async move {
                let row = sql::query(
                    "SELECT revoked_at FROM mcp_clients \
                     WHERE layer = 'hub' AND client_id = $1 AND principal = $2",
                )
                .bind(client_id)
                .bind(who)
                .fetch_optional(c)
                .await?;
                match row {
                    Some(r) => Ok::<_, ApiError>(r.try_get("revoked_at")?),
                    None => Ok(None),
                }
            })
        })
        .await?;
    let Some(revoked_at) = revoked_at else {
        return Ok(false);
    };
    // Compared at full precision: a sign-in is only newer if it is at or after the revoke. An
    // `auth_time` out of range counts as old.
    Ok(
        match principal
            .0
            .auth_time
            .map(OffsetDateTime::from_unix_timestamp)
        {
            Some(Ok(signed_in)) => signed_in < revoked_at,
            _ => true,
        },
    )
}
