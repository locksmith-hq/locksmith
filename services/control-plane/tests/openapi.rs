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
