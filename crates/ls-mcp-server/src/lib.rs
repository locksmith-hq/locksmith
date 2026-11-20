//! Shared rules for the Hub and Agent remote MCP servers (change m1-remote-mcp, task 1.3).
//!
//! A tool registry per layer, the default on/off table, the switch check that both `tools/list`
//! and `tools/call` use ("a client cannot list or call a tool that is off", Hub design section 6),
//! and the no-value schema check. Tools return ids, names, metadata and relay results, never a
//! stored secret value (decision D-2).

use serde_json::Value;
use std::collections::HashMap;

/// Which MCP server a tool belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Layer {
    Hub,
    Agent,
}

/// One tool: name, description, JSON schemas and whether it ships on.
#[derive(Debug, Clone)]
pub struct ToolDef {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
    pub output_schema: Option<Value>,
    pub default_enabled: bool,
}

/// Field names no tool input or output schema may contain (any nesting depth, any case).
pub const FORBIDDEN_FIELDS: [&str; 10] = [
    "value",
    "secret",
    "password",
    "passphrase",
    "token_value",
    "api_key",
    "secret_value",
    "token",
    "credential",
    "private_key",
];

/// First forbidden field found in a schema, if any.
pub fn find_value_like_field(schema: &Value) -> Option<String> {
    match schema {
        Value::Object(o) => o.iter().find_map(|(k, v)| {
            let lk = k.to_lowercase();
            if FORBIDDEN_FIELDS.contains(&lk.as_str()) {
                Some(lk)
            } else {
                find_value_like_field(v)
            }
        }),
        Value::Array(a) => a.iter().find_map(find_value_like_field),
        _ => None,
    }
}

impl ToolDef {
    /// Error naming the offending field if an input or output schema could carry a value.
    pub fn check_no_value_field(&self) -> Result<(), String> {
        for s in std::iter::once(&self.input_schema).chain(self.output_schema.as_ref()) {
            if let Some(f) = find_value_like_field(s) {
                return Err(format!("tool `{}` schema has a `{f}` field", self.name));
            }
        }
        Ok(())
    }
}

/// Why a tool call is refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Unknown,
    Disabled,
}

/// Registry for one layer. Per-org overrides (`mcp_tool_settings`) are passed in at call time.
#[derive(Debug)]
pub struct Registry {
    layer: Layer,
    tools: Vec<ToolDef>,
}

impl Registry {
    /// Build a registry; fails if any tool schema could carry a value or a name repeats.
    pub fn new(layer: Layer, tools: Vec<ToolDef>) -> Result<Self, String> {
        let mut seen = std::collections::HashSet::new();
        for t in &tools {
            t.check_no_value_field()?;
            if !seen.insert(t.name) {
                return Err(format!("duplicate tool `{}`", t.name));
            }
        }
        Ok(Self { layer, tools })
    }

    pub fn layer(&self) -> Layer {
        self.layer
    }

    /// The default on/off table.
    pub fn defaults(&self) -> HashMap<&'static str, bool> {
        self.tools
            .iter()
            .map(|t| (t.name, t.default_enabled))
            .collect()
    }

    fn enabled(t: &ToolDef, overrides: &HashMap<String, bool>) -> bool {
        overrides.get(t.name).copied().unwrap_or(t.default_enabled)
    }

    /// Tools a client may see: off tools are left out.
    pub fn list<'a>(&'a self, overrides: &HashMap<String, bool>) -> Vec<&'a ToolDef> {
        self.tools
            .iter()
            .filter(|t| Self::enabled(t, overrides))
            .collect()
    }

    /// Check a call. An off tool is refused exactly like a call to a tool that does not exist
    /// from the listing's point of view, but the reason stays typed for the audit event.
    pub fn authorize(
        &self,
        name: &str,
        overrides: &HashMap<String, bool>,
    ) -> Result<&ToolDef, Refusal> {
        let t = self
            .tools
            .iter()
            .find(|t| t.name == name)
            .ok_or(Refusal::Unknown)?;
        if Self::enabled(t, overrides) {
            Ok(t)
        } else {
            Err(Refusal::Disabled)
        }
    }
}

fn tool(name: &'static str, description: &'static str, on: bool) -> ToolDef {
    ToolDef {
        name,
        description,
        input_schema: serde_json::json!({"type": "object", "properties": {}}),
        output_schema: None,
        default_enabled: on,
    }
}

/// Hub tools (design section 6): read tools on, mutating tools off.
pub fn hub_tools() -> Vec<ToolDef> {
    vec![
        tool("list_projects", "List projects.", true),
        tool(
            "list_secret_names",
            "Secret names and versions. Never values.",
            true,
        ),
        tool("read_activity", "Recent activity events.", true),
        tool("list_findings", "Open findings.", true),
        tool(
            "list_waiting_requests",
            "Requests waiting for a decision.",
            true,
        ),
        tool("explain_block", "Why a request was blocked.", true),
        tool(
            "approve_or_deny_request",
            "Approve or deny a waiting request.",
            false,
        ),
        tool("revoke_grant", "Revoke a grant.", false),
        tool("rotate_secret", "Start a secret rotation.", false),
        tool("pause_agents", "Pause agents.", false),
    ]
}

fn with_schema(mut t: ToolDef, input_schema: Value) -> ToolDef {
    t.input_schema = input_schema;
    t
}

/// Agent tools: the seven that exist today in `locksmith-mcp` (names and input schemas copied
/// from it) on, plus the short-lived credential off (decision H1-2). `locksmith_issue_token`
/// mints an opaque `lsk_` token (not a value) and stays on, as today.
pub fn agent_tools() -> Vec<ToolDef> {
    use serde_json::json;
    vec![
        tool(
            "locksmith_list_keys",
            "Key names for this project. Never values.",
            true,
        ),
        tool("locksmith_status", "Active sessions.", true),
        with_schema(
            tool(
                "locksmith_issue_token",
                "Mint an opaque lsk_ token for a key.",
                true,
            ),
            json!({"type": "object", "required": ["key"], "properties": {
                "key": {"type": "string"}, "provider": {"type": "string"},
                "hosts": {"type": "array", "items": {"type": "string"}},
                "placement": {"type": "string"}}}),
        ),
        with_schema(
            tool(
                "locksmith_start_session",
                "Start a session within policy.",
                true,
            ),
            json!({"type": "object", "required": ["project", "env", "scopes", "ttl_secs"], "properties": {
                "project": {"type": "string"}, "env": {"type": "string"},
                "scopes": {"type": "array", "items": {"type": "string", "enum": ["run", "git", "http", "db", "aws"]}},
                "ttl_secs": {"type": "integer", "minimum": 1},
                "agent": {"type": "string", "maxLength": 64}, "model": {"type": "string", "maxLength": 64}}}),
        ),
        with_schema(
            tool(
                "locksmith_explain_block",
                "Why an action was blocked.",
                true,
            ),
            json!({"type": "object", "required": ["reason"], "properties": {"reason": {"type": "string"}}}),
        ),
        tool("list_grants", "Grants for this agent. Never values.", true),
        with_schema(
            tool(
                "relay_request",
                "Relay an HTTP request; the gateway injects the credential.",
                true,
            ),
            json!({"type": "object", "required": ["secret_id", "url"], "properties": {
                "secret_id": {"type": "string"}, "version": {"type": "integer", "minimum": 1},
                "method": {"type": "string"}, "url": {"type": "string"},
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                "body": {"type": "string"}}}),
        ),
        tool(
            "issue_short_lived_credential",
            "Mint a short-lived scoped credential.",
            false,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reg(l: Layer) -> Registry {
        let t = if l == Layer::Hub {
            hub_tools()
        } else {
            agent_tools()
        };
        Registry::new(l, t).unwrap()
    }

    #[test]
    fn shipped_registries_carry_no_value_field() {
        reg(Layer::Hub);
        reg(Layer::Agent);
    }

    #[test]
    fn no_value_check_fails_on_nested_and_output_fields() {
        let mut t = tool("bad", "x", true);
        t.input_schema =
            json!({"type":"object","properties":{"a":{"items":[{"properties":{"Password":{}}}]}}});
        assert!(
            Registry::new(Layer::Hub, vec![t])
                .unwrap_err()
                .contains("password")
        );
        let mut t = tool("bad2", "x", true);
        t.output_schema = Some(json!({"properties":{"value":{"type":"string"}}}));
        assert!(Registry::new(Layer::Agent, vec![t]).is_err());
    }

    #[test]
    fn shipped_agent_schemas_are_real_not_empty() {
        let r = reg(Layer::Agent);
        let relay = r.authorize("relay_request", &HashMap::new()).unwrap();
        assert!(relay.input_schema["properties"]["url"].is_object());
        assert!(relay.input_schema["properties"]["body"].is_object());
    }

    #[test]
    fn broader_value_like_names_are_caught() {
        for k in [
            "api_key",
            "secret_value",
            "token",
            "credential",
            "private_key",
        ] {
            let s = json!({"properties": {k: {}}});
            assert!(find_value_like_field(&s).is_some(), "{k}");
        }
    }

    #[test]
    fn duplicate_names_rejected() {
        assert!(Registry::new(Layer::Hub, vec![tool("a", "", true), tool("a", "", true)]).is_err());
    }

    #[test]
    fn defaults_hub_mutating_off_reads_on() {
        let d = reg(Layer::Hub).defaults();
        for n in [
            "list_projects",
            "list_secret_names",
            "read_activity",
            "list_findings",
            "list_waiting_requests",
            "explain_block",
        ] {
            assert!(d[n], "{n}");
        }
        for n in [
            "approve_or_deny_request",
            "revoke_grant",
            "rotate_secret",
            "pause_agents",
        ] {
            assert!(!d[n], "{n}");
        }
    }

    #[test]
    fn defaults_agent_seven_existing_on_credential_off() {
        let d = reg(Layer::Agent).defaults();
        assert!(!d["issue_short_lived_credential"]);
        let mut on: Vec<_> = d.iter().filter(|(_, on)| **on).map(|(n, _)| *n).collect();
        on.sort();
        assert_eq!(
            on,
            [
                "list_grants",
                "locksmith_explain_block",
                "locksmith_issue_token",
                "locksmith_list_keys",
                "locksmith_start_session",
                "locksmith_status",
                "relay_request"
            ]
        );
    }

    #[test]
    fn off_tool_is_hidden_and_refused_and_switch_turns_it_on() {
        let r = reg(Layer::Hub);
        let none = HashMap::new();
        assert!(!r.list(&none).iter().any(|t| t.name == "revoke_grant"));
        assert_eq!(
            r.authorize("revoke_grant", &none).unwrap_err(),
            Refusal::Disabled
        );
        assert_eq!(r.authorize("nope", &none).unwrap_err(), Refusal::Unknown);
        let on = HashMap::from([("revoke_grant".to_string(), true)]);
        assert!(r.list(&on).iter().any(|t| t.name == "revoke_grant"));
        assert!(r.authorize("revoke_grant", &on).is_ok());
        let off = HashMap::from([("list_projects".to_string(), false)]);
        assert_eq!(
            r.authorize("list_projects", &off).unwrap_err(),
            Refusal::Disabled
        );
    }
}
