//! Shared contract check: a response must satisfy the schema `services/core/openapi.json`
//! declares for that operation and status (the same schema the TypeScript fixtures are typed by).

use std::sync::OnceLock;

use serde_json::Value;

fn spec() -> &'static Value {
    static SPEC: OnceLock<Value> = OnceLock::new();
    SPEC.get_or_init(|| {
        let raw = include_str!("../../openapi.json");
        serde_json::from_str(raw).expect("openapi.json parses")
    })
}

#[allow(dead_code)] // used by contract.rs only; each test binary compiles this module
/// Every `(path, operationId)` of the POST operations in the contract, in file order.
pub fn operations() -> Vec<(String, String)> {
    spec()["paths"]
        .as_object()
        .expect("paths")
        .iter()
        .filter_map(|(p, v)| {
            let id = v["post"]["operationId"].as_str()?;
            Some((p.clone(), id.to_owned()))
        })
        .collect()
}

/// Panics unless `body` is valid for `POST <path>` answering `status`.
pub fn assert_matches_contract(path: &str, status: u16, body: &Value) {
    assert_method_matches_contract("post", path, status, body);
}

/// Panics unless `body` is valid for `GET <path>` answering `status`.
#[allow(dead_code)] // used by jwks.rs only
pub fn assert_get_matches_contract(path: &str, status: u16, body: &Value) {
    assert_method_matches_contract("get", path, status, body);
}

fn assert_method_matches_contract(method: &str, path: &str, status: u16, body: &Value) {
    let schema_ref = spec()["paths"][path][method]["responses"][status.to_string()]["content"]
        .as_object()
        .and_then(|c| c.values().next())
        .map(|m| m["schema"].clone())
        .unwrap_or_else(|| panic!("{path} declares no body for {status}"));
    let mut root = schema_ref;
    root["components"] = spec()["components"].clone();
    let validator = jsonschema::validator_for(&root).expect("schema compiles");
    let errors: Vec<String> = validator.iter_errors(body).map(|e| e.to_string()).collect();
    assert!(
        errors.is_empty(),
        "{path} {status} breaks the contract: {errors:?}\nbody keys: {:?}",
        body.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
}
