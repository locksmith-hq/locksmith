//! The gateway's binding inventory (change d3-db-relay, task 6.1: the contract).
//!
//! `GET /v1/bindings` lists, for the caller's org, the bindings the gateway reports (decision
//! 10): one [`BindingSummary`] per binding, non-secret fields only. A summary never carries a
//! password, a header template, a secret id or any key material. The console and desktop read
//! only this endpoint.
//!
//! Task 6.2: the gateway publishes its inventory at startup with
//! `PUT /internal/v1/gateway/bindings` (service token, D3-1). The control plane keeps the latest
//! snapshot per org, replaced whole, and `GET /v1/bindings` serves it; until a snapshot exists
//! the list is empty. The snapshot type refuses unknown fields, so a gateway cannot store a
//! password, template or any other field this contract does not name.
//!
//! d2 task 5.1 (d2 design decision 8): an `aws` row is published with its base-credential secret
//! id, the join key to the org's `delegate` grants. `GET /v1/bindings` never serves that id; it
//! serves `allowed_actions` instead, the action names of the org's unexpired delegate grants on
//! that secret (no resources, no policy).

use std::collections::{BTreeMap, BTreeSet};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::extract::ApiJson;
use super::responses::{InternalWriteErrors, ReadErrors};
use crate::app::AppState;
use crate::auth::{OrgBinding, ServiceOrgBinding};
use crate::db::sql::{self, Row};
use crate::problem::{ApiError, Kind};

/// The most bindings one snapshot may hold.
const MAX_ITEMS: usize = 1000;
/// The longest any text field of a binding may be, in bytes.
const MAX_TEXT: usize = 512;

/// What a binding lets the gateway do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum BindingKind {
    /// Inject a secret into an HTTP request to one origin.
    Http,
    /// Inject a secret into Git smart-HTTP requests to one repository or owner.
    Git,
    /// Relay a Postgres session with the stored password.
    Pg,
    /// Vend or relay AWS access through a role.
    Aws,
    /// Proxy an upstream MCP server with per-tool decisions. There is no `secret_id` on this kind:
    /// the gateway keeps the upstream credential's id to itself.
    Mcp,
}

/// What the gateway's tool policy does with an MCP tool (`mcp` bindings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ToolDecision {
    /// Listed and callable.
    Allow,
    /// Not listed; a call gets the unknown-tool error.
    Hide,
    /// Listed; a call is refused.
    Deny,
    /// Listed; a call needs approval.
    Hold,
}

/// One per-tool rule of an `mcp` binding. The tool name is the upstream's own, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolRule {
    #[schema(min_length = 1, max_length = 128, pattern = "^[A-Za-z0-9_.-]+$")]
    pub name: String,
    pub decision: ToolDecision,
}

/// The most tool rules one `mcp` binding may hold.
const MAX_TOOL_RULES: usize = 500;

/// How the gateway reaches a Postgres upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BindingTls {
    Require,
    VerifyFull,
    Disable,
}

/// One gateway binding, non-secret fields only. Which optional fields are set depends on `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BindingSummary {
    pub kind: BindingKind,
    /// Display name: the database name (`pg`), the origin or host (`http`, `git`), the role (`aws`).
    pub name: String,
    /// `http`: the exact upstream origin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// `http`: the header the secret is injected into (never its value or template).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// `git`: `owner` or `owner/repo`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// `pg`, `git`: the upstream host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// `pg`: the upstream port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// `pg`: the bound database user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// `pg`: the bound database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// `pg`: the upstream TLS mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<BindingTls>,
    /// `aws`: the role ARN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// `aws`: the region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// `aws`: whether short-lived credentials may be vended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vend: Option<bool>,
    /// `aws`: the longest vended session, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_secs: Option<u32>,
    /// `aws`: the IAM actions the org's unexpired `delegate` grants on this binding allow
    /// (sorted, de-duplicated; names only, never resources). Computed on read, never published.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_actions: Option<Vec<String>>,
    /// `mcp`: the per-tool rules, in name order. Refused on every other kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(max_items = 500)]
    pub tools: Option<Vec<ToolRule>>,
    /// `mcp`: the decision for a tool without a rule. Refused on every other kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_decision: Option<ToolDecision>,
}

/// One binding as the gateway publishes it: the [`BindingSummary`] fields plus, for `aws` only,
/// the binding's base-credential secret id. That id is stored as the join key to the org's
/// `delegate` grants (d2 design decision 8) and is never served.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishedBinding {
    pub kind: BindingKind,
    /// Display name: the database name (`pg`), the origin or host (`http`, `git`), the role (`aws`).
    pub name: String,
    /// `http`: the exact upstream origin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// `http`: the header the secret is injected into (never its value or template).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// `git`: `owner` or `owner/repo`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// `pg`, `git`: the upstream host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// `pg`: the upstream port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// `pg`: the bound database user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// `pg`: the bound database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// `pg`: the upstream TLS mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<BindingTls>,
    /// `aws`: the role ARN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// `aws`: the region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// `aws`: whether short-lived credentials may be vended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vend: Option<bool>,
    /// `aws`: the longest vended session, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_secs: Option<u32>,
    /// `mcp`: the per-tool rules, in name order. Refused on every other kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(max_items = 500)]
    pub tools: Option<Vec<ToolRule>>,
    /// `mcp`: the decision for a tool without a rule. Refused on every other kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_decision: Option<ToolDecision>,
    /// `aws`: the base-credential secret id (an id, never a value). Refused on other kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<Uuid>,
}

impl PublishedBinding {
    /// The served summary, without the secret id.
    fn summary(self, allowed_actions: Option<Vec<String>>) -> BindingSummary {
        BindingSummary {
            kind: self.kind,
            name: self.name,
            origin: self.origin,
            header: self.header,
            repo: self.repo,
            host: self.host,
            port: self.port,
            user: self.user,
            database: self.database,
            tls: self.tls,
            role: self.role,
            region: self.region,
            vend: self.vend,
            max_duration_secs: self.max_duration_secs,
            allowed_actions,
            tools: self.tools,
            default_decision: self.default_decision,
        }
    }
}

/// Every binding the gateway reports for the org.
#[derive(Debug, Serialize, ToSchema)]
pub struct BindingList {
    pub items: Vec<BindingSummary>,
}

#[utoipa::path(
    get,
    path = "/v1/bindings",
    operation_id = "list_bindings",
    tag = "bindings",
    summary = "List the gateway's bindings (non-secret fields only)",
    responses(
        (status = 200, description = "The org's bindings", body = BindingList),
        ReadErrors,
    ),
    security(("dev_org" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    org: OrgBinding,
) -> Result<Json<BindingList>, ApiError> {
    let org_id = org.org_id;
    let (stored, actions) = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                let row = sql::query("SELECT items::text AS items FROM gateway_bindings")
                    .fetch_optional(&mut *c)
                    .await?;
                let Some(row) = row else {
                    return Ok::<_, ApiError>((None, BTreeMap::new()));
                };
                let stored: String = row.try_get("items")?;
                // Actions of the org's unexpired delegate grants, by secret (RLS keeps this org's).
                let rows = sql::query(
                    "SELECT g.secret_id, a.action FROM agent_grants g \
                     CROSS JOIN LATERAL jsonb_array_elements_text(g.scope -> 'actions') AS a(action) \
                     WHERE g.mode = 'delegate' AND (g.expires_at IS NULL OR g.expires_at > now())",
                )
                .fetch_all(c)
                .await?;
                let mut actions: BTreeMap<Uuid, BTreeSet<String>> = BTreeMap::new();
                for r in &rows {
                    actions
                        .entry(r.try_get("secret_id")?)
                        .or_default()
                        .insert(r.try_get("action")?);
                }
                Ok((Some(stored), actions))
            })
        })
        .await?;
    let published: Vec<PublishedBinding> = match stored {
        Some(text) => serde_json::from_str(&text).map_err(|_| ApiError::bare(Kind::Internal))?,
        None => Vec::new(),
    };
    let items = published
        .into_iter()
        .map(|b| {
            // No secret id (a snapshot from an older gateway): unknown, so no field, not "none".
            let allowed = b
                .secret_id
                .filter(|_| b.kind == BindingKind::Aws)
                .map(|id| {
                    actions
                        .get(&id)
                        .map(|a| a.iter().cloned().collect())
                        .unwrap_or_default()
                });
            b.summary(allowed)
        })
        .collect();
    Ok(Json(BindingList { items }))
}

/// The gateway's full inventory. It replaces the org's previous snapshot.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BindingSnapshot {
    #[schema(max_items = 1000)]
    pub items: Vec<PublishedBinding>,
}

impl BindingSnapshot {
    fn validate(&self) -> Result<(), ApiError> {
        if self.items.len() > MAX_ITEMS {
            return Err(ApiError::validation("too many bindings"));
        }
        for b in &self.items {
            let texts = [
                Some(&b.name),
                b.origin.as_ref(),
                b.header.as_ref(),
                b.repo.as_ref(),
                b.host.as_ref(),
                b.user.as_ref(),
                b.database.as_ref(),
                b.role.as_ref(),
                b.region.as_ref(),
            ];
            if b.name.trim().is_empty() {
                return Err(ApiError::validation("a binding needs a `name`"));
            }
            if texts.iter().flatten().any(|t| t.len() > MAX_TEXT) {
                return Err(ApiError::validation("a binding field is too long"));
            }
            if b.secret_id.is_some() && b.kind != BindingKind::Aws {
                return Err(ApiError::validation(
                    "only an `aws` binding carries a `secret_id`",
                ));
            }
            if b.kind != BindingKind::Mcp && (b.tools.is_some() || b.default_decision.is_some()) {
                return Err(ApiError::validation(
                    "only an `mcp` binding carries `tools` or `default_decision`",
                ));
            }
            if let Some(tools) = &b.tools {
                let mut seen = BTreeSet::new();
                if tools.len() > MAX_TOOL_RULES
                    || !tools.iter().all(|t| {
                        (1..=128).contains(&t.name.len())
                            && t.name.bytes().all(|c| {
                                c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-')
                            })
                            && seen.insert(t.name.as_str())
                    })
                {
                    return Err(ApiError::validation("an `mcp` binding has invalid `tools`"));
                }
            }
        }
        Ok(())
    }
}

#[utoipa::path(
    put,
    path = "/internal/v1/gateway/bindings",
    operation_id = "put_gateway_bindings",
    tag = "internal",
    summary = "Replace the org's binding inventory (gateway only)",
    description = "The gateway publishes its non-secret binding inventory at startup. The body replaces the org's latest snapshot, which `GET /v1/bindings` serves. Fields are names, hosts, ports, users, databases, header names and similar; a password, header template, a `secret_id` on any kind but `aws`, or any unknown field is a `400`; the `aws` secret id is stored as the join key to `delegate` grants and never served.",
    params(
        ("X-Locksmith-Org" = Uuid, Header, description = "The org the gateway acts for (the token's `org`)"),
    ),
    request_body = BindingSnapshot,
    responses(
        (status = 204, description = "Stored"),
        InternalWriteErrors,
    ),
    security(("service_token" = []))
)]
pub async fn put_snapshot(
    State(state): State<AppState>,
    org: ServiceOrgBinding,
    ApiJson(input): ApiJson<BindingSnapshot>,
) -> Result<StatusCode, ApiError> {
    input.validate()?;
    let items = serde_json::to_string(&input.items).map_err(|_| ApiError::bare(Kind::Internal))?;
    let org_id = org.org_id;
    state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                sql::query(
                    "INSERT INTO gateway_bindings (org_id, items) VALUES ($1, $2::jsonb) \
                     ON CONFLICT (org_id) DO UPDATE SET items = EXCLUDED.items, updated_at = now()",
                )
                .bind(org_id)
                .bind(items)
                .execute(c)
                .await?;
                Ok::<_, ApiError>(())
            })
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mcp() -> serde_json::Value {
        serde_json::json!({
            "kind": "mcp",
            "name": "github",
            "origin": "https://api.githubcopilot.com/mcp/",
            "default_decision": "hide",
            "tools": [
                {"name": "create_issue", "decision": "hold"},
                {"name": "delete_repository", "decision": "deny"},
                {"name": "list_issues", "decision": "allow"}
            ]
        })
    }

    fn snapshot(items: Vec<serde_json::Value>) -> Result<BindingSnapshot, ApiError> {
        let s: BindingSnapshot = serde_json::from_value(serde_json::json!({ "items": items }))
            .map_err(|_| ApiError::validation("not a snapshot"))?;
        s.validate()?;
        Ok(s)
    }

    #[test]
    fn mcp_binding_round_trips_to_the_served_summary_without_a_secret_id() {
        let s = snapshot(vec![mcp()]).expect("valid");
        let served = s.items[0].clone().summary(None);
        assert_eq!(served.kind, BindingKind::Mcp);
        assert_eq!(served.default_decision, Some(ToolDecision::Hide));
        assert_eq!(served.tools.as_ref().map(Vec::len), Some(3));
        let json = serde_json::to_value(&served).unwrap();
        assert!(json.get("secret_id").is_none());
        assert_eq!(json["tools"][1]["decision"], "deny");
    }

    #[test]
    fn mcp_binding_refuses_a_secret_id_and_bad_rules() {
        let mut with_secret = mcp();
        with_secret["secret_id"] = "0197c1f0-0000-7000-8000-0000000000aa".into();
        assert!(snapshot(vec![with_secret]).is_err());
        for bad_name in ["", "has space", "caf\u{e9}", &"x".repeat(129)] {
            let mut m = mcp();
            m["tools"] = serde_json::json!([{"name": bad_name, "decision": "allow"}]);
            assert!(snapshot(vec![m]).is_err(), "{bad_name:?}");
        }
        let mut dup = mcp();
        dup["tools"] = serde_json::json!([
            {"name": "a", "decision": "allow"},
            {"name": "a", "decision": "deny"}
        ]);
        assert!(snapshot(vec![dup]).is_err());
        let mut bad_decision = mcp();
        bad_decision["tools"] = serde_json::json!([{"name": "a", "decision": "maybe"}]);
        assert!(snapshot(vec![bad_decision]).is_err());
    }

    #[test]
    fn tools_and_default_decision_are_refused_on_every_other_kind() {
        for kind in ["http", "git", "pg", "aws"] {
            for extra in [
                ("tools", serde_json::json!([])),
                ("default_decision", serde_json::json!("allow")),
            ] {
                let mut item = serde_json::json!({"kind": kind, "name": "x"});
                item[extra.0] = extra.1;
                assert!(snapshot(vec![item]).is_err(), "{kind} {}", extra.0);
            }
        }
    }
}
