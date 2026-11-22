//! OpenAPI contract: the committed `openapi.json` must match the spec generated from the router
//! definitions. No database is needed. Run with `UPDATE_OPENAPI=1` to rewrite the file.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use ls_control_plane::app::{self, AppState};
use ls_control_plane::readiness::ReadyFlag;
use serde_json::{Map, Value};
use similar::{ChangeTag, TextDiff};
use tower::ServiceExt;

fn spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("openapi.json")
}

/// Recursively sort object keys so output never depends on map implementation or insertion order.
fn sorted(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut entries: Vec<_> = m.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k, sorted(v)))
                    .collect::<Map<_, _>>(),
            )
        }
        Value::Array(a) => Value::Array(a.into_iter().map(sorted).collect()),
        other => other,
    }
}

/// Deterministic text form: sorted keys, two-space indent, trailing newline.
fn render(spec: Value) -> String {
    let mut text = serde_json::to_string_pretty(&sorted(spec)).expect("spec serializes");
    text.push('\n');
    text
}

fn generated() -> String {
    render(serde_json::to_value(app::openapi()).expect("spec serializes"))
}

#[test]
fn openapi_snapshot_matches_committed_file() {
    let actual = generated();
    let path = spec_path();
    if std::env::var_os("UPDATE_OPENAPI").is_some_and(|v| v == "1") {
        std::fs::write(&path, &actual).expect("write openapi.json");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    if committed != actual {
        let diff = TextDiff::from_lines(&committed, &actual);
        let mut out = String::new();
        for change in diff.iter_all_changes() {
            let sign = match change.tag() {
                ChangeTag::Delete => "-",
                ChangeTag::Insert => "+",
                ChangeTag::Equal => continue,
            };
            out.push_str(&format!("{sign}{}", change));
            if change.missing_newline() {
                out.push('\n');
            }
        }
        panic!(
            "services/control-plane/openapi.json is out of date ('-' committed, '+' generated):\n{out}\n\
             If the API change is intended, run: UPDATE_OPENAPI=1 cargo test -p ls-control-plane --test openapi"
        );
    }
}

/// Issue #246: every operation has an explicit, unique `<verb>_<resource>` operationId, so
/// generated clients never collide (utoipa otherwise uses the handler fn name, e.g. `list`).
#[test]
fn operation_ids_are_present_and_unique() {
    let spec: Value = serde_json::from_str(&generated()).unwrap();
    let mut seen = std::collections::BTreeMap::new();
    for (path, item) in spec["paths"].as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            let id = op["operationId"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} has no operationId"));
            assert!(
                id.contains('_')
                    && id
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{method} {path}: operationId `{id}` is not snake_case <verb>_<resource>"
            );
            if let Some(prev) = seen.insert(id.to_owned(), format!("{method} {path}")) {
                panic!("operationId `{id}` used by both {prev} and {method} {path}");
            }
        }
    }
    assert!(!seen.is_empty());
}

/// Only the version-write request body may carry `value`, and it must be a write-only string;
/// no other schema (in particular no response) has a value field.
#[test]
fn openapi_is_3_1_and_has_no_secret_value_field() {
    let spec: Value = serde_json::from_str(&generated()).unwrap();
    assert!(spec["openapi"].as_str().unwrap().starts_with("3.1"));
    let schemas = spec["components"]["schemas"].as_object().unwrap();
    for (name, schema) in schemas {
        let value = schema["properties"].get("value");
        if name == "NewSecretVersion" {
            let value = value.expect("NewSecretVersion.value");
            assert_eq!(value["type"], "string");
            assert_eq!(value["writeOnly"], true, "value must be writeOnly");
            assert_eq!(value["format"], "password");
        } else {
            assert!(
                value.is_none(),
                "schema {name} must not carry a `value` property"
            );
        }
    }
    // Responses never reference the request schema.
    for (path, item) in spec["paths"].as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            let responses = op["responses"].to_string();
            assert!(
                !responses.contains("NewSecretVersion"),
                "{method} {path} returns the value schema"
            );
        }
    }
}

/// S3 task 1.2: the internal material response carries ciphertext, the wrapped DEK and ids
/// only (no plaintext field), and the route is tagged `internal` and needs the service token.
#[test]
fn internal_material_schema_has_no_plaintext_field() {
    let spec: Value = serde_json::from_str(&generated()).unwrap();
    let schema = &spec["components"]["schemas"]["SecretVersionMaterial"];
    let mut props: Vec<&str> = schema["properties"]
        .as_object()
        .expect("SecretVersionMaterial.properties")
        .keys()
        .map(String::as_str)
        .collect();
    props.sort_unstable();
    assert_eq!(
        props,
        [
            "ciphertext",
            "key_id",
            "secret_id",
            "version",
            "wrapped_dek"
        ]
    );
    assert_eq!(schema["additionalProperties"], Value::Null);
    // The blobs are base64 strings; nothing is a (write-only) password-style value field.
    for blob in ["ciphertext", "wrapped_dek"] {
        let p = &schema["properties"][blob];
        assert_eq!(p["type"], "string");
        assert_eq!(p["contentEncoding"], "base64");
    }
    for (name, p) in schema["properties"].as_object().unwrap() {
        assert_ne!(p["format"], "password", "{name}");
        assert_ne!(p["writeOnly"], true, "{name}");
    }

    let op = &spec["paths"]["/internal/v1/secrets/{secret_id}/versions/{version}/material"]["get"];
    assert_eq!(op["tags"], serde_json::json!(["internal"]));
    assert_eq!(op["security"], serde_json::json!([{ "service_token": [] }]));
    assert_eq!(
        op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/SecretVersionMaterial"
    );
    for status in ["401", "404"] {
        assert!(op["responses"].get(status).is_some(), "missing {status}");
    }
    assert_eq!(
        spec["components"]["securitySchemes"]["service_token"]["scheme"],
        "bearer"
    );
}

#[tokio::test]
async fn openapi_json_is_served_and_matches_generated_spec() {
    // A lazy pool that never connects: the spec needs no database.
    let state = AppState::new(
        false,
        Arc::new(ReadyFlag::new(false)),
        common::unreachable_db(),
    );
    let response = app::build(state)
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let served: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(render(served), generated());
}

/// Every component schema a response can reach (following `$ref`s transitively).
fn response_schemas(spec: &Value) -> std::collections::BTreeSet<String> {
    fn refs(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                if let Some(Value::String(r)) = m.get("$ref")
                    && let Some(name) = r.strip_prefix("#/components/schemas/")
                {
                    out.push(name.to_owned());
                }
                m.values().for_each(|v| refs(v, out));
            }
            Value::Array(a) => a.iter().for_each(|v| refs(v, out)),
            _ => {}
        }
    }
    let mut todo = Vec::new();
    for item in spec["paths"].as_object().unwrap().values() {
        for op in item.as_object().unwrap().values() {
            refs(&op["responses"], &mut todo);
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    while let Some(name) = todo.pop() {
        if seen.insert(name.clone()) {
            refs(&spec["components"]["schemas"][&name], &mut todo);
        }
    }
    seen
}

/// S4 task 1.3: no response schema carries a secret field. The only credentials any response
/// carries are the enrollment secret (shown once, in `AgentEnrollment`) and the short-lived agent
/// token (`AgentToken`); no response has a value, plaintext, hash, private key or any other
/// password-style field, and no request schema that carries a credential is ever returned.
#[test]
fn no_secret_field_in_any_response_schema() {
    let spec: Value = serde_json::from_str(&generated()).unwrap();
    let reachable = response_schemas(&spec);
    for expected in [
        "Agent",
        "AgentEnrollment",
        "AgentGrant",
        "AgentGrantSet",
        "ActiveGrant",
        "AgentToken",
        "InviteCreated",
        "JwkSet",
        "Jwk",
    ] {
        assert!(reachable.contains(expected), "{expected} is not a response");
    }
    for request_only in [
        "NewSecretVersion",
        "AgentTokenRequest",
        "NewAgent",
        "NewAgentGrant",
    ] {
        assert!(
            !reachable.contains(request_only),
            "{request_only} is returned"
        );
    }

    // `InviteCreated.token` is the T6 invite link token: shown once, only its hash is stored.
    const ALLOWED: [(&str, &str); 3] = [
        ("AgentEnrollment", "enrollment_secret"),
        ("AgentToken", "access_token"),
        ("InviteCreated", "token"),
    ];
    // Names that match the patterns below but carry no credential.
    const BENIGN: [(&str, &str); 1] = [("AgentToken", "token_type")];
    const FORBIDDEN: [&str; 9] = [
        "value",
        "plaintext",
        "secret",
        "secret_value",
        "password",
        "hash",
        "token",
        "key",
        "d",
    ];
    for name in &reachable {
        let props = spec["components"]["schemas"][name]["properties"].as_object();
        for (prop, schema) in props.into_iter().flatten() {
            let allowed = ALLOWED.contains(&(name.as_str(), prop.as_str()))
                || BENIGN.contains(&(name.as_str(), prop.as_str()));
            let lower = prop.to_ascii_lowercase();
            assert!(
                allowed
                    || !(FORBIDDEN.contains(&lower.as_str())
                        || lower.contains("secret")
                            && !lower.ends_with("_id")
                            && lower != "secret_name"
                        || lower.contains("hash")
                        || lower.contains("plain")
                        || lower.contains("private")
                        || lower.contains("token")),
                "response schema {name} has a secret-looking field `{prop}`"
            );
            if !allowed {
                assert_ne!(schema["format"], "password", "{name}.{prop}");
                assert_ne!(schema["writeOnly"], true, "{name}.{prop}");
            }
        }
    }
    // The credential fields are explicitly marked read-only and say they are shown once.
    let enrollment =
        &spec["components"]["schemas"]["AgentEnrollment"]["properties"]["enrollment_secret"];
    assert_eq!(enrollment["readOnly"], true);
    assert!(
        enrollment["description"]
            .as_str()
            .unwrap()
            .contains("Shown only in this response")
    );
    // Only registration and rotation return the enrollment secret.
    let mut returning: Vec<String> = Vec::new();
    for (path, item) in spec["paths"].as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            if op["responses"].to_string().contains("AgentEnrollment") {
                returning.push(format!("{method} {path}"));
            }
        }
    }
    returning.sort();
    assert_eq!(
        returning,
        [
            "post /v1/agents",
            "post /v1/agents/{agent_id}/enrollment-secret"
        ]
    );
}

/// S4 task 1.2: the token, JWKS and internal grants routes are in the document with the right
/// security: the token exchange and JWKS take no org binding; the grants lookup needs the
/// service token.
#[test]
fn agent_routes_are_documented() {
    let spec: Value = serde_json::from_str(&generated()).unwrap();
    let paths = &spec["paths"];
    let token = &paths["/v1/agent-tokens"]["post"];
    assert_eq!(token["security"], Value::Null);
    assert_eq!(
        token["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/AgentToken"
    );
    assert!(token["responses"].get("401").is_some());
    let jwks = &paths["/.well-known/jwks.json"]["get"];
    assert_eq!(
        jwks["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/JwkSet"
    );
    let lookup = &paths["/internal/v1/agents/{agent_id}/grants"]["get"];
    assert_eq!(lookup["tags"], serde_json::json!(["internal"]));
    assert_eq!(
        lookup["security"],
        serde_json::json!([{ "service_token": [] }])
    );
    for (path, method) in [
        ("/v1/agents", "post"),
        ("/v1/agents", "get"),
        ("/v1/agents/{agent_id}", "get"),
        ("/v1/agents/{agent_id}", "delete"),
        ("/v1/agents/{agent_id}/enrollment-secret", "post"),
        ("/v1/agents/{agent_id}/grants", "post"),
        ("/v1/agents/{agent_id}/grants", "get"),
        ("/v1/agents/{agent_id}/grants/{grant_id}", "delete"),
    ] {
        assert_eq!(
            paths[path][method]["security"],
            serde_json::json!([{ "dev_org": [] }]),
            "{method} {path}"
        );
    }
    let mode = &spec["components"]["schemas"]["GrantMode"];
    assert_eq!(mode["enum"], serde_json::json!(["relay"]));
}

/// M1 task 1.4: the MCP switch and client routes are documented, org-scoped, and carry no
/// token or value field.
#[test]
fn mcp_routes_are_documented() {
    let spec: Value = serde_json::from_str(&generated()).unwrap();
    for (path, method, id) in [
        ("/v1/mcp/tools", "get", "list_mcp_tool_settings"),
        (
            "/v1/mcp/tools/{layer}/{tool}",
            "put",
            "update_mcp_tool_setting",
        ),
        ("/v1/mcp/clients", "get", "list_mcp_clients"),
        (
            "/v1/mcp/clients/{client_row_id}/revoke",
            "post",
            "revoke_mcp_client",
        ),
    ] {
        let op = &spec["paths"][path][method];
        assert_eq!(op["operationId"], id, "{method} {path}");
        assert_eq!(op["security"], serde_json::json!([{ "dev_org": [] }]));
    }
    assert_eq!(
        spec["components"]["schemas"]["McpLayer"]["enum"],
        serde_json::json!(["hub", "agent"])
    );
    for name in ["McpClient", "McpToolSetting", "McpToolSettingUpdate"] {
        let props = spec["components"]["schemas"][name]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{name}"));
        for prop in props.keys() {
            assert!(
                !["value", "token", "secret", "key", "password"].contains(&prop.as_str()),
                "{name}.{prop}"
            );
        }
    }
}
