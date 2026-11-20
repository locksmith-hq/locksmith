//! Shared rules for the Hub and Agent remote MCP servers (change m1-remote-mcp, task 1.3).
//!
//! A tool registry per layer, the default on/off table, the switch check that both `tools/list`
//! and `tools/call` use ("a client cannot list or call a tool that is off", Hub design section 6),
//! and the no-value schema check. Tools return ids, names, metadata and relay results, never a
//! stored secret value (decision D-2).

use serde_json::{Value, json};
use std::collections::HashMap;

/// Which MCP server a tool belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Layer {
    Hub,
    Agent,
}

impl Layer {
    /// The layer's stable lower-case name (audit attribute, `mcp_tool_settings.layer`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hub => "hub",
            Self::Agent => "agent",
        }
    }
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

/// Words that, as the last word of a schema property name, mark a field that could hold a secret
/// value or key material. Names are split into words first (`apiKey`, `api-key`, `API_KEY` and
/// `api.key` all become `api key`), so the check does not depend on spelling style. A name whose
/// last word is metadata (`secret_id`, `key_name`, `token_expires_at`) is allowed.
pub const FORBIDDEN_LAST_WORDS: [&str; 16] = [
    "value",
    "values",
    "secret",
    "secrets",
    "password",
    "passwords",
    "passphrase",
    "passphrases",
    "token",
    "tokens",
    "credential",
    "credentials",
    "key",
    "keys",
    "pem",
    "jwt",
];

/// Split a property name into lower-case words on `_`, `-`, `.`, spaces and camelCase humps.
pub fn name_words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = name.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_alphanumeric() {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            continue;
        }
        // Start a new word at a lower->Upper hump (`apiKey`) or at the last capital of an
        // acronym run followed by lower case (`APIKey` -> `api key`).
        let prev = i.checked_sub(1).map(|j| chars[j]);
        let next = chars.get(i + 1).copied();
        let hump = c.is_uppercase()
            && !cur.is_empty()
            && (prev.is_some_and(|p| p.is_lowercase() || p.is_ascii_digit())
                || (prev.is_some_and(char::is_uppercase) && next.is_some_and(char::is_lowercase)));
        if hump {
            words.push(std::mem::take(&mut cur));
        }
        cur.extend(c.to_lowercase());
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

/// True if a property name could hold a secret value (its last word is a forbidden word).
pub fn is_value_like_name(name: &str) -> bool {
    name_words(name)
        .last()
        .is_some_and(|w| FORBIDDEN_LAST_WORDS.contains(&w.as_str()))
}

/// First value-like property name in a JSON schema, at any depth. Property names are the keys
/// of every `properties` object; schema keywords are not property names. An open map
/// (`patternProperties`, or `additionalProperties` other than `false`) is refused too, because
/// its field names are not known and could be anything, `password` included.
pub fn find_value_like_field(schema: &Value) -> Option<String> {
    find_in(schema, &[])
}

fn is_object_schema(o: &serde_json::Map<String, Value>) -> bool {
    o.contains_key("properties")
        || match o.get("type") {
            Some(Value::String(t)) => t == "object",
            Some(Value::Array(ts)) => ts.iter().any(|t| t == "object"),
            _ => false,
        }
}

/// The exception field must be exactly a string, so nothing else can hide inside it.
fn is_plain_string_schema(v: &Value) -> bool {
    v.as_object().is_some_and(|o| {
        o.get("type") == Some(&Value::String("string".into()))
            && o.keys().all(|k| k == "type" || k == "description")
    })
}

fn find_in(schema: &Value, allowed_top: &[&str]) -> Option<String> {
    match schema {
        // `true` and `{}` accept anything, an object of any shape included.
        Value::Bool(true) => Some("open schema".to_string()),
        Value::Object(o) if o.is_empty() => Some("open schema".to_string()),
        Value::Object(o) => {
            if is_object_schema(o) && o.get("additionalProperties") != Some(&Value::Bool(false)) {
                return Some("object without additionalProperties: false (open map)".to_string());
            }
            o.iter().find_map(|(k, v)| match k.as_str() {
                "properties" => v.as_object().and_then(|props| {
                    props.iter().find_map(|(name, sub)| {
                        let excepted =
                            allowed_top.contains(&name.as_str()) && is_plain_string_schema(sub);
                        if is_value_like_name(name) && !excepted {
                            Some(name.clone())
                        } else {
                            find_in(sub, &[])
                        }
                    })
                }),
                "patternProperties" => Some("patternProperties (open map)".to_string()),
                "additionalProperties" | "unevaluatedProperties" if *v != Value::Bool(false) => {
                    Some(format!("{k} (open map)"))
                }
                // Keyword values that are not schemas.
                "required" | "enum" | "const" | "default" | "examples" | "type" | "format"
                | "description" | "title" | "pattern" => None,
                "additionalProperties" | "unevaluatedProperties" => None,
                _ => find_in(v, &[]),
            })
        }
        Value::Array(a) => a.iter().find_map(|v| find_in(v, &[])),
        _ => None,
    }
}

/// The one tool allowed to return a credential (decision H1-2), and the only output field it
/// may return it in. Everything else in its schemas is checked like any other tool.
pub const SHORT_LIVED_TOOL: &str = "issue_short_lived_credential";
pub const SHORT_LIVED_OUTPUT_FIELD: &str = "credential";

impl ToolDef {
    /// Error naming the offending field if an input or output schema could carry a value.
    /// Every shipped tool must declare an output schema, so the output half always runs.
    pub fn check_no_value_field(&self, layer: Layer) -> Result<(), String> {
        if let Some(f) = find_value_like_field(&self.input_schema) {
            return Err(format!(
                "tool `{}` input schema has a `{f}` field",
                self.name
            ));
        }
        let out = self
            .output_schema
            .as_ref()
            .ok_or_else(|| format!("tool `{}` has no output schema", self.name))?;
        let allowed: &[&str] = if layer == Layer::Agent && self.name == SHORT_LIVED_TOOL {
            &[SHORT_LIVED_OUTPUT_FIELD]
        } else {
            &[]
        };
        if let Some(f) = find_in(out, allowed) {
            return Err(format!(
                "tool `{}` output schema has a `{f}` field",
                self.name
            ));
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
            t.check_no_value_field(layer)?;
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

    /// The registry's own (static) name for a requested tool name, if it has such a tool. Lets a
    /// caller record a refused call without ever recording client-supplied text.
    pub fn tool_name(&self, name: &str) -> Option<&'static str> {
        self.tools.iter().find(|t| t.name == name).map(|t| t.name)
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
        input_schema: json!({"type": "object", "additionalProperties": false, "properties": {}}),
        output_schema: None,
        default_enabled: on,
    }
}

fn schemas(mut t: ToolDef, input: Value, output: Value) -> ToolDef {
    t.input_schema = input;
    t.output_schema = Some(output);
    t
}

/// `{"type":"object","required":[...],"additionalProperties":false,"properties":{...}}`.
fn obj(required: &[&str], properties: Value) -> Value {
    json!({"type": "object", "required": required, "additionalProperties": false,
           "properties": properties})
}

/// `{"items": [<item>], "next_cursor": string|null}`, the list shape every list tool returns.
fn page_of(item: Value) -> Value {
    obj(
        &["items"],
        json!({"items": {"type": "array", "items": item},
               "next_cursor": {"type": ["string", "null"]}}),
    )
}

/// Paging input (`limit` 1 to 100 like the REST API) plus tool fields; `required` names the
/// tool fields that must be given.
fn page_input(required: &[&str], extra: Value) -> Value {
    let mut props = json!({"cursor": {"type": "string"},
                           "limit": {"type": "integer", "minimum": 1, "maximum": 100}});
    if let (Some(p), Value::Object(e)) = (props.as_object_mut(), extra) {
        p.extend(e);
    }
    obj(required, props)
}

const UUID: &str = "uuid";

fn id() -> Value {
    json!({"type": "string", "format": UUID})
}

fn time() -> Value {
    json!({"type": "string", "format": "date-time"})
}

fn explain_block_tool() -> ToolDef {
    schemas(
        tool(
            "explain_block",
            "Why a request was blocked and what to do next. Never values.",
            true,
        ),
        obj(
            &["reason"],
            json!({"reason": {"type": "string", "maxLength": 512,
                              "description": "The block message or rule id you received."}}),
        ),
        obj(
            &["explanation", "next_step"],
            json!({"rule": {"type": ["string", "null"]},
                   "explanation": {"type": "string"},
                   "next_step": {"type": "string"}}),
        ),
    )
}

/// Hub tools: the ones this change builds (tasks 2.2 and 2.4). Read tools on, tools that change
/// state off. Hub design section 6 also names list findings, list waiting requests, approve or
/// deny a request and rotate a secret; those join the registry with the changes that build them
/// (decision in design.md "Default tool tables").
pub fn hub_tools() -> Vec<ToolDef> {
    vec![
        schemas(
            tool(
                "list_projects",
                "Projects in your org, with their environments (ids and names).",
                true,
            ),
            page_input(&[], json!({})),
            page_of(obj(
                &["id", "name", "description", "environments"],
                json!({"id": id(), "name": {"type": "string"},
                       "description": {"type": "string"},
                       "environments": {"type": "array", "items": obj(
                           &["id", "name"],
                           json!({"id": id(), "name": {"type": "string"}}))}}),
            )),
        ),
        schemas(
            tool(
                "list_secret_names",
                "Secret names and their versions (numbers and dates) in a project environment. \
                 Never values.",
                true,
            ),
            page_input(
                &["project_id", "environment_id"],
                json!({"project_id": id(), "environment_id": id()}),
            ),
            page_of(obj(
                &["secret_id", "name", "latest_version", "versions"],
                json!({"secret_id": id(), "name": {"type": "string"},
                       "description": {"type": "string"},
                       "latest_version": {"type": ["integer", "null"], "minimum": 1},
                       "versions": {"type": "array", "items": obj(
                           &["version", "created_at"],
                           json!({"version": {"type": "integer", "minimum": 1},
                                  "created_at": time()}))},
                       "updated_at": time()}),
            )),
        ),
        schemas(
            tool(
                "read_activity",
                "Recent audit events in your org, newest first.",
                true,
            ),
            page_input(&[], json!({})),
            page_of(obj(
                &["event_id", "seq", "at", "action", "actor", "outcome"],
                json!({"event_id": id(), "seq": {"type": "integer", "minimum": 1}, "at": time(),
                       "action": {"type": "string"}, "actor": {"type": "string"},
                       "target": {"type": "string"}, "outcome": {"type": "string"}}),
            )),
        ),
        schemas(
            tool("list_agents", "Enrolled agents in your org.", true),
            page_input(&[], json!({})),
            page_of(obj(
                &["agent_id", "name", "description", "created_at"],
                json!({"agent_id": id(), "name": {"type": "string"},
                       "description": {"type": "string"}, "created_at": time()}),
            )),
        ),
        schemas(
            tool(
                "list_grants",
                "An agent's grants: which secret it may use, in which mode, until when. Never \
                 values.",
                true,
            ),
            page_input(&["agent_id"], json!({"agent_id": id()})),
            page_of(obj(
                &[
                    "grant_id",
                    "agent_id",
                    "secret_id",
                    "secret_name",
                    "mode",
                    "created_at",
                ],
                json!({"grant_id": id(), "agent_id": id(), "secret_id": id(),
                       "secret_name": {"type": "string"},
                       "mode": {"type": "string", "enum": ["relay"]},
                       "expires_at": {"type": ["string", "null"], "format": "date-time"},
                       "created_at": time()}),
            )),
        ),
        explain_block_tool(),
        schemas(
            tool("revoke_grant", "Revoke one grant.", false),
            obj(&["grant_id"], json!({"grant_id": id()})),
            obj(
                &["grant_id", "revoked_at"],
                json!({"grant_id": id(), "revoked_at": time()}),
            ),
        ),
        schemas(
            tool(
                "pause_agents",
                "Pause every agent in your org, or the listed ones.",
                false,
            ),
            obj(&[], json!({"agent_ids": {"type": "array", "items": id()}})),
            obj(
                &["paused"],
                json!({"paused": {"type": "integer", "minimum": 0},
                       "not_available": {"type": "boolean"}}),
            ),
        ),
    ]
}

/// Agent tools: the ones this change builds (tasks 3.2 and 3.3). Hub design section 6 also names
/// start session (arrives with `t8-sessions-and-revoke`) and request access (arrives with
/// `t4-access-proposals`); they join the registry, on by default, with those changes. The seven
/// tools of `locksmith-mcp` are the Local MCP column and stay there.
pub fn agent_tools() -> Vec<ToolDef> {
    vec![
        schemas(
            tool(
                "list_my_keys",
                "Secrets this agent holds a grant for: names and ids only. Never values.",
                true,
            ),
            page_input(&[], json!({})),
            page_of(obj(
                &["secret_id", "name", "version"],
                json!({"secret_id": id(), "name": {"type": "string"},
                       "version": {"type": "integer", "minimum": 1},
                       "hosts": {"type": "array", "items": {"type": "string"}},
                       "grant_expires_at": {"type": ["string", "null"], "format": "date-time"}}),
            )),
        ),
        schemas(
            tool(
                "relay_http_request",
                "Send an HTTP request through the gateway; it injects the credential and \
                 returns the redacted response.",
                true,
            ),
            obj(
                &["secret_id", "method", "url"],
                json!({"secret_id": id(), "version": {"type": "integer", "minimum": 1},
                       "method": {"type": "string",
                                  "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]},
                       "url": {"type": "string", "format": "uri"},
                       "headers": {"type": "array", "items": {"type": "array",
                                   "prefixItems": [{"type": "string"}, {"type": "string"}],
                                   "minItems": 2, "maxItems": 2}},
                       "body": {"type": "string"}, "body_base64": {"type": "string"}}),
            ),
            obj(
                &["status", "headers"],
                json!({"status": {"type": "integer", "minimum": 100, "maximum": 599},
                       "headers": {"type": "array", "items": {"type": "array",
                                   "prefixItems": [{"type": "string"}, {"type": "string"}],
                                   "minItems": 2, "maxItems": 2}},
                       "body": {"type": "string"}, "body_base64": {"type": "string"}}),
            ),
        ),
        explain_block_tool(),
        schemas(
            tool(
                SHORT_LIVED_TOOL,
                "A credential valid for minutes, scoped to one job, destroyed after. Off by \
                 default; every issue is audited.",
                false,
            ),
            obj(
                &["secret_id", "job", "ttl_secs"],
                json!({"secret_id": id(), "job": {"type": "string", "maxLength": 128},
                       "ttl_secs": {"type": "integer", "minimum": 60, "maximum": 900}}),
            ),
            obj(
                &[SHORT_LIVED_OUTPUT_FIELD, "expires_at", "scope"],
                json!({SHORT_LIVED_OUTPUT_FIELD: {"type": "string"},
                       "expires_at": time(), "scope": {"type": "string"}}),
            ),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(l: Layer) -> Registry {
        let t = if l == Layer::Hub {
            hub_tools()
        } else {
            agent_tools()
        };
        Registry::new(l, t).unwrap()
    }

    fn with_out(name: &'static str, input: Value, output: Value) -> ToolDef {
        schemas(tool(name, "x", true), input, output)
    }

    #[test]
    fn shipped_registries_carry_no_value_field() {
        reg(Layer::Hub);
        reg(Layer::Agent);
    }

    #[test]
    fn every_shipped_tool_has_real_input_and_output_schemas() {
        for t in hub_tools().into_iter().chain(agent_tools()) {
            let out = t.output_schema.as_ref().expect(t.name);
            assert_eq!(out["type"], "object", "{}", t.name);
            assert!(
                out["properties"].as_object().is_some_and(|p| !p.is_empty()),
                "{} output has no properties",
                t.name
            );
            assert_eq!(t.input_schema["type"], "object", "{}", t.name);
        }
        let r = reg(Layer::Agent);
        let relay = r.authorize("relay_http_request", &HashMap::new()).unwrap();
        for f in ["secret_id", "method", "url", "headers", "body"] {
            assert!(relay.input_schema["properties"][f].is_object(), "{f}");
        }
        assert!(relay.output_schema.as_ref().unwrap()["properties"]["status"].is_object());
    }

    #[test]
    fn missing_output_schema_is_rejected() {
        let e = Registry::new(Layer::Hub, vec![tool("a", "x", true)]).unwrap_err();
        assert!(e.contains("no output schema"), "{e}");
    }

    #[test]
    fn no_value_check_fails_on_nested_input_and_output_fields() {
        let ok = obj(&[], json!({"id": id()}));
        let nested = obj(
            &[],
            json!({"a": {"type": "array",
                         "items": obj(&[], json!({"Password": {"type": "string"}}))}}),
        );
        let e = Registry::new(Layer::Hub, vec![with_out("bad", nested, ok.clone())]).unwrap_err();
        assert!(e.contains("input") && e.contains("Password"), "{e}");
        let out = obj(&[], json!({"value": {"type": "string"}}));
        let e = Registry::new(Layer::Agent, vec![with_out("bad2", ok, out)]).unwrap_err();
        assert!(e.contains("output") && e.contains("value"), "{e}");
    }

    #[test]
    fn value_like_names_are_caught_in_any_spelling() {
        for k in [
            "value",
            "secret",
            "password",
            "api_key",
            "apiKey",
            "APIKey",
            "API_KEY",
            "api-key",
            "api.key",
            "secretValue",
            "secret_value",
            "clientSecret",
            "client-secret",
            "accessToken",
            "access_token",
            "refreshToken",
            "token",
            "credential",
            "awsCredentials",
            "privateKey",
            "private_key",
            "PRIVATE-KEY",
            "dbPassword",
            "passphrase",
            "id_jwt",
            "certPem",
            "values",
            "secrets",
        ] {
            assert!(is_value_like_name(k), "{k} should be value-like");
        }
    }

    #[test]
    fn metadata_names_are_allowed() {
        for k in [
            "secret_id",
            "secretId",
            "secret_name",
            "key_name",
            "keyId",
            "token_expires_at",
            "tokenExpiresAt",
            "latest_version",
            "grant_id",
            "name",
            "hosts",
            "body",
            "url",
            "next_cursor",
        ] {
            assert!(!is_value_like_name(k), "{k} should be allowed");
        }
    }

    #[test]
    fn schema_keywords_are_not_property_names_but_open_maps_are_refused() {
        // `items` and `prefixItems` are keywords, not fields.
        let s = json!({"type":"object","additionalProperties":false,
                       "properties":{"x":{"type":"array","items":{"type":"string"}}}});
        assert_eq!(find_value_like_field(&s), None);
        for open in [
            json!({"type":"object","additionalProperties":{"type":"string"}}),
            json!({"type":"object","additionalProperties":true}),
            json!({"type":"object","patternProperties":{"^x$":{}}}),
            json!({"properties":{"a":{"type":"object","additionalProperties":{}}}}),
        ] {
            let f = find_value_like_field(&open).unwrap_or_default();
            assert!(f.contains("open map"), "{open}");
        }
    }

    #[test]
    fn short_lived_exception_is_only_its_credential_output_field() {
        let r = reg(Layer::Agent);
        assert!(
            r.authorize(
                SHORT_LIVED_TOOL,
                &HashMap::from([(SHORT_LIVED_TOOL.to_string(), true)])
            )
            .is_ok()
        );
        // The same output on any other tool is refused.
        let out = obj(&["credential"], json!({"credential": {"type": "string"}}));
        let other = with_out("other", obj(&[], json!({})), out.clone());
        assert!(Registry::new(Layer::Agent, vec![other]).is_err());
        // The exception never covers its input, nor a nested or second value-like output field.
        let bad_in = with_out(SHORT_LIVED_TOOL, obj(&[], json!({"credential": {}})), out);
        assert!(Registry::new(Layer::Agent, vec![bad_in]).is_err());
        let nested = obj(
            &[],
            json!({"credential": {"type": "object",
                                       "properties": {"credential": {}}}}),
        );
        let bad_nested = with_out(SHORT_LIVED_TOOL, obj(&[], json!({})), nested);
        assert!(Registry::new(Layer::Agent, vec![bad_nested]).is_err());
        let extra = obj(&[], json!({"credential": {}, "refresh_token": {}}));
        let bad_extra = with_out(SHORT_LIVED_TOOL, obj(&[], json!({})), extra);
        assert!(Registry::new(Layer::Agent, vec![bad_extra]).is_err());
    }

    #[test]
    fn hardening_open_objects_layer_and_exact_credential() {
        let ok_in = obj(&[], json!({}));
        let out = |p: Value| obj(&[], p);
        // A nested object with no `additionalProperties: false`, `{}` and `true` are open.
        for open in [
            json!({"meta": {"type": "object"}}),
            json!({"meta": {}}),
            json!({"meta": true}),
            json!({"meta": {"type": "object", "additionalProperties": false,
                            "unevaluatedProperties": true}}),
        ] {
            let t = with_out("t", ok_in.clone(), out(open.clone()));
            assert!(Registry::new(Layer::Agent, vec![t]).is_err(), "{open}");
        }
        // The exception is Agent-only.
        let cred = out(json!({"credential": {"type": "string"}}));
        let t = with_out(SHORT_LIVED_TOOL, ok_in.clone(), cred.clone());
        assert!(Registry::new(Layer::Hub, vec![t]).is_err());
        let t = with_out(SHORT_LIVED_TOOL, ok_in.clone(), cred);
        assert!(Registry::new(Layer::Agent, vec![t]).is_ok());
        // ...and the field must be exactly a string.
        for inner in [
            json!({"type": "object", "additionalProperties": false,
                   "properties": {"stored": {"type": "string"}}}),
            json!({}),
            json!({"type": ["string", "object"]}),
        ] {
            let t = with_out(
                SHORT_LIVED_TOOL,
                ok_in.clone(),
                out(json!({"credential": inner})),
            );
            assert!(Registry::new(Layer::Agent, vec![t]).is_err());
        }
    }

    #[test]
    fn duplicate_names_rejected() {
        let t = || with_out("a", obj(&[], json!({})), obj(&[], json!({"id": id()})));
        assert!(Registry::new(Layer::Hub, vec![t(), t()]).is_err());
    }

    fn on_off(l: Layer) -> (Vec<&'static str>, Vec<&'static str>) {
        let d = reg(l).defaults();
        let mut on: Vec<_> = d.iter().filter(|(_, v)| **v).map(|(n, _)| *n).collect();
        let mut off: Vec<_> = d.iter().filter(|(_, v)| !**v).map(|(n, _)| *n).collect();
        on.sort_unstable();
        off.sort_unstable();
        (on, off)
    }

    #[test]
    fn defaults_hub_reads_on_mutating_off() {
        let (on, off) = on_off(Layer::Hub);
        assert_eq!(
            on,
            [
                "explain_block",
                "list_agents",
                "list_grants",
                "list_projects",
                "list_secret_names",
                "read_activity"
            ]
        );
        assert_eq!(off, ["pause_agents", "revoke_grant"]);
    }

    #[test]
    fn defaults_agent_match_design_section_6_for_tools_built_here() {
        let (on, off) = on_off(Layer::Agent);
        assert_eq!(on, ["explain_block", "list_my_keys", "relay_http_request"]);
        assert_eq!(off, [SHORT_LIVED_TOOL]);
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
        assert!(!r.list(&off).iter().any(|t| t.name == "list_projects"));
    }
}
