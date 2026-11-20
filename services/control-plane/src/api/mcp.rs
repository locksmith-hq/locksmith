//! MCP tool switches and signed-in MCP clients (change m1-remote-mcp, task 1.4).
//!
//! - `GET /v1/mcp/tools` lists every tool of both layers with its default and the org's current
//!   switch. Defaults come from `ls-mcp-server`; `mcp_tool_settings` stores only overrides, so
//!   an absent row means the default.
//! - `PUT /v1/mcp/tools/{layer}/{tool}` sets one switch. An unknown layer or tool is a `404`.
//! - `GET /v1/mcp/clients` lists the clients that signed in; `POST /v1/mcp/clients/{id}/revoke`
//!   marks one revoked (idempotent: the first revoke time is kept).
//!
//! Org-scoped through [`OrgBinding`] like every `/v1` resource. No response or table carries a
//! token or a secret value: ids, names, switches and times only.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::agents::optional_utc;
use super::extract::{ApiJson, ApiPath, ApiQuery};
use super::responses::{ListErrors, ReadErrors, WriteErrors};
use super::{Page, PageParams, Paged, all, one, utc};
use crate::app::AppState;
use crate::audit::DEV_AUTH_ACTOR;
use crate::auth::OrgBinding;
use crate::db::sql::{self, Row};
use crate::problem::ApiError;

/// Which MCP server a tool or client belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum McpLayer {
    /// The control-plane server a person signs in to.
    Hub,
    /// The gateway server an enrolled agent signs in to.
    Agent,
}

impl McpLayer {
    const ALL: [McpLayer; 2] = [McpLayer::Hub, McpLayer::Agent];

    fn as_str(self) -> &'static str {
        match self {
            McpLayer::Hub => "hub",
            McpLayer::Agent => "agent",
        }
    }

    fn parse(s: &str) -> sql::Result<Self> {
        match s {
            "hub" => Ok(McpLayer::Hub),
            "agent" => Ok(McpLayer::Agent),
            other => Err(sql::Error::Decode(
                format!("unknown mcp layer {other:?}").into(),
            )),
        }
    }

    /// The tools this layer's registry offers: `(name, description, default)`.
    fn tools(self) -> Vec<(&'static str, &'static str, bool)> {
        let defs = match self {
            McpLayer::Hub => ls_mcp_server::hub_tools(),
            McpLayer::Agent => ls_mcp_server::agent_tools(),
        };
        defs.into_iter()
            .map(|t| (t.name, t.description, t.default_enabled))
            .collect()
    }
}

/// One tool and whether it is on for this org.
#[derive(Debug, Serialize, ToSchema)]
pub struct McpToolSetting {
    pub layer: McpLayer,
    /// The tool's name.
    pub tool: String,
    pub description: String,
    /// What the tool does when the org has not changed it.
    pub default_enabled: bool,
    /// The effective switch: the org's override, else the default.
    pub enabled: bool,
    /// Whether the org has changed the switch from the default.
    pub overridden: bool,
}

/// Every tool of both layers.
#[derive(Debug, Serialize, ToSchema)]
pub struct McpToolSettingList {
    pub items: Vec<McpToolSetting>,
}

/// Body of `PUT /v1/mcp/tools/{layer}/{tool}`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct McpToolSettingUpdate {
    pub enabled: bool,
}

/// A client that signed in to an MCP server. Never carries a token.
#[derive(Debug, Serialize, ToSchema)]
pub struct McpClient {
    pub id: Uuid,
    pub layer: McpLayer,
    /// The OAuth client id (hub) or the agent id (agent layer).
    pub client_id: String,
    /// The signed-in person (hub) or the agent id (agent layer).
    pub principal: String,
    /// Display name from registration; may be empty.
    pub client_name: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub first_seen_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub last_seen_at: OffsetDateTime,
    /// Set when the client was revoked; absent while active.
    #[serde(
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub revoked_at: Option<OffsetDateTime>,
}

const CLIENT_COLS: &str =
    "id, layer, client_id, principal, client_name, first_seen_at, last_seen_at, revoked_at";

fn client_from_row(r: &sql::PgRow) -> sql::Result<McpClient> {
    Ok(McpClient {
        id: r.try_get("id")?,
        layer: McpLayer::parse(r.try_get::<&str, _>("layer")?)?,
        client_id: r.try_get("client_id")?,
        principal: r.try_get("principal")?,
        client_name: r.try_get("client_name")?,
        first_seen_at: utc(r, "first_seen_at")?,
        last_seen_at: utc(r, "last_seen_at")?,
        revoked_at: optional_utc(r, "revoked_at")?,
    })
}

fn setting(
    layer: McpLayer,
    (tool, description, default_enabled): (&str, &str, bool),
    over: Option<bool>,
) -> McpToolSetting {
    McpToolSetting {
        layer,
        tool: tool.to_owned(),
        description: description.to_owned(),
        default_enabled,
        enabled: over.unwrap_or(default_enabled),
        overridden: over.is_some_and(|o| o != default_enabled),
    }
}

#[utoipa::path(
    get,
    path = "/v1/mcp/tools",
    operation_id = "list_mcp_tool_settings",
    tag = "mcp",
    summary = "List MCP tools with their default and current switch",
    responses(
        (status = 200, description = "Every tool of the hub and agent servers", body = McpToolSettingList),
        ListErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn list_tools(
    State(state): State<AppState>,
    org: OrgBinding,
) -> Result<Json<McpToolSettingList>, ApiError> {
    let rows = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let rows = sql::query("SELECT layer, tool, enabled FROM mcp_tool_settings")
                    .fetch_all(c)
                    .await?;
                all(&rows, |r| {
                    Ok((
                        r.try_get::<String, _>("layer")?,
                        r.try_get::<String, _>("tool")?,
                        r.try_get::<bool, _>("enabled")?,
                    ))
                })
            })
        })
        .await?;
    let items = McpLayer::ALL
        .into_iter()
        .flat_map(|layer| {
            let overrides = &rows;
            layer.tools().into_iter().map(move |t| {
                let over = overrides
                    .iter()
                    .find(|(l, name, _)| l == layer.as_str() && name == t.0)
                    .map(|(_, _, e)| *e);
                setting(layer, t, over)
            })
        })
        .collect();
    Ok(Json(McpToolSettingList { items }))
}

#[utoipa::path(
    put,
    path = "/v1/mcp/tools/{layer}/{tool}",
    operation_id = "update_mcp_tool_setting",
    tag = "mcp",
    summary = "Turn one MCP tool on or off for the org",
    description = "Enforced by the server: a client cannot list or call a tool that is off.",
    params(
        ("layer" = McpLayer, Path, description = "`hub` or `agent`"),
        ("tool" = String, Path, description = "Tool name"),
    ),
    request_body = McpToolSettingUpdate,
    responses(
        (status = 200, description = "The tool with its new switch", body = McpToolSetting),
        WriteErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn update_tool(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath((layer, tool)): ApiPath<(McpLayer, String)>,
    ApiJson(input): ApiJson<McpToolSettingUpdate>,
) -> Result<Json<McpToolSetting>, ApiError> {
    let def = layer
        .tools()
        .into_iter()
        .find(|t| t.0 == tool)
        .ok_or_else(ApiError::not_found)?;
    let enabled = input.enabled;
    state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                sql::query(
                    "INSERT INTO mcp_tool_settings (org_id, layer, tool, enabled) \
                     VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (org_id, layer, tool) \
                     DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = now()",
                )
                .bind(org.org_id)
                .bind(layer.as_str())
                .bind(def.0)
                .bind(enabled)
                .execute(c)
                .await?;
                Ok::<_, ApiError>(())
            })
        })
        .await?;
    tracing::info!(
        mcp.layer = layer.as_str(),
        mcp.tool = def.0,
        enabled,
        "mcp tool switch set"
    );
    Ok(Json(setting(layer, def, Some(enabled))))
}

#[utoipa::path(
    get,
    path = "/v1/mcp/clients",
    operation_id = "list_mcp_clients",
    tag = "mcp",
    summary = "List MCP clients that signed in, including revoked ones",
    params(PageParams),
    responses(
        (status = 200, description = "A page of clients", body = Paged<McpClient>),
        ListErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn list_clients(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiQuery(params): ApiQuery<PageParams>,
) -> Result<Json<Paged<McpClient>>, ApiError> {
    let page: Page = params.resolve()?;
    let rows = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let rows = sql::query(sqlx_core::sql_str::AssertSqlSafe(format!(
                    "SELECT {CLIENT_COLS} FROM mcp_clients \
                     WHERE ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2"
                )))
                .bind(page.after)
                .bind(page.fetch())
                .fetch_all(c)
                .await?;
                all(&rows, client_from_row)
            })
        })
        .await?;
    Ok(Json(Paged::new(rows, page, |c| c.id)))
}

#[utoipa::path(
    post,
    path = "/v1/mcp/clients/{client_row_id}/revoke",
    operation_id = "revoke_mcp_client",
    tag = "mcp",
    summary = "Revoke an MCP client",
    description = "Marks the client revoked. Its next call, and a fresh initialize, are refused. Revoking again keeps the first revoke time.",
    params(("client_row_id" = Uuid, Path, description = "Client row id from the list")),
    responses(
        (status = 200, description = "The revoked client", body = McpClient),
        ReadErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn revoke_client(
    State(state): State<AppState>,
    org: OrgBinding,
    ApiPath(row_id): ApiPath<Uuid>,
) -> Result<Json<McpClient>, ApiError> {
    let client = state
        .db()
        .with_org(org.org_id, move |c| {
            Box::pin(async move {
                let row = sql::query(sqlx_core::sql_str::AssertSqlSafe(format!(
                    "UPDATE mcp_clients SET revoked_at = now() \
                     WHERE id = $1 RETURNING {CLIENT_COLS}"
                )))
                .bind(row_id)
                .fetch_optional(c)
                .await?;
                one(row, client_from_row)
            })
        })
        .await?;
    tracing::info!(mcp.client.row = %row_id, "mcp client revoked");
    if client.layer == McpLayer::Hub {
        revoke_consent_at_issuer(&state, org.org_id, &client).await;
    }
    Ok(Json(client))
}

/// Best-effort issuer step after the database revoke (task 4.2). The revoke has committed and the
/// `auth_time` rule enforces it, so nothing here changes the API's answer: a failure is logged
/// with a static reason and recorded as an `mcp.issuer_revoke` event with outcome `error`.
/// Skipped when no issuer admin is configured (it was logged once at start).
async fn revoke_consent_at_issuer(state: &AppState, org_id: Uuid, client: &McpClient) {
    let Some(admin) = state.issuer_admin() else {
        return;
    };
    let result = admin
        .revoke_consent(&client.principal, &client.client_id)
        .await;
    let (outcome, reason) = match result {
        Ok(()) => (ls_audit::outcome::OK, None),
        Err(e) => {
            tracing::warn!(
                mcp.client.row = %client.id,
                reason = e.reason(),
                "issuer consent revoke failed; the database revoke stands"
            );
            (
                ls_audit::outcome::ERROR,
                ls_audit::Code::try_new(e.reason()).ok(),
            )
        }
    };
    let event = crate::audit::mcp_issuer_revoke(DEV_AUTH_ACTOR, org_id, outcome, reason);
    let appended = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                crate::audit::append(c, org_id, &event).await?;
                Ok::<_, ApiError>(())
            })
        })
        .await;
    if appended.is_err() {
        tracing::warn!(mcp.client.row = %client.id, "mcp.issuer_revoke event not appended");
    }
}
