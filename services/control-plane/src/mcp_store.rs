//! The SQL behind MCP clients and tool switches, in one place.
//!
//! The hub MCP endpoint, the agent-layer internal API and the console list all read the same two
//! tables, `mcp_clients` and `mcp_tool_settings`. Each function takes the connection of a
//! `Database::with_org` closure, so the caller keeps its own transaction and error type.
//! `revoked_at` is only ever read here; revoking is `api::mcp::revoke_client`'s job.

use sqlx_core::row::Row;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::sql::{self, PgConnection};

/// The longest client display name stored, in characters.
pub const CLIENT_NAME_MAX_CHARS: usize = 200;

/// Insert the client on first sight; refresh its name and last-seen time afterwards. Returns the
/// row's `revoked_at` (a revoked row stays revoked: it is never written). The name is cut to
/// [`CLIENT_NAME_MAX_CHARS`] characters.
pub async fn upsert_client(
    c: &mut PgConnection,
    org_id: Uuid,
    layer: &str,
    client_id: &str,
    principal: &str,
    name: &str,
) -> sql::Result<Option<OffsetDateTime>> {
    let name: String = name.chars().take(CLIENT_NAME_MAX_CHARS).collect();
    let row = sql::query(
        "INSERT INTO mcp_clients (org_id, layer, client_id, principal, client_name) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (org_id, layer, client_id, principal) \
         DO UPDATE SET client_name = EXCLUDED.client_name, last_seen_at = now() \
         RETURNING revoked_at",
    )
    .bind(org_id)
    .bind(layer)
    .bind(client_id)
    .bind(principal)
    .bind(name)
    .fetch_one(c)
    .await?;
    row.try_get("revoked_at")
}

/// The org's overrides for one layer, as `(tool, enabled)` ordered by tool.
pub async fn layer_settings(
    c: &mut PgConnection,
    org_id: Uuid,
    layer: &str,
) -> sql::Result<Vec<(String, bool)>> {
    let rows = sql::query(
        "SELECT tool, enabled FROM mcp_tool_settings \
         WHERE org_id = $1 AND layer = $2 ORDER BY tool",
    )
    .bind(org_id)
    .bind(layer)
    .fetch_all(c)
    .await?;
    rows.iter()
        .map(|r| Ok((r.try_get("tool")?, r.try_get("enabled")?)))
        .collect()
}

/// The org's overrides across every layer, as `(layer, tool, enabled)`.
pub async fn all_settings(
    c: &mut PgConnection,
    org_id: Uuid,
) -> sql::Result<Vec<(String, String, bool)>> {
    let rows = sql::query(
        "SELECT layer, tool, enabled FROM mcp_tool_settings WHERE org_id = $1 ORDER BY layer, tool",
    )
    .bind(org_id)
    .fetch_all(c)
    .await?;
    rows.iter()
        .map(|r| {
            Ok((
                r.try_get("layer")?,
                r.try_get("tool")?,
                r.try_get("enabled")?,
            ))
        })
        .collect()
}
