use std::collections::HashSet;
use std::path::Path;

use ls_oauth::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

/// Words no wire field may contain.
const FORBIDDEN_WORDS: [&str; 5] = ["token", "secret", "verifier", "password", "credential"];

fn json_keys(v: &Value, out: &mut HashSet<String>) {
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                out.insert(k.clone());
                json_keys(v, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|v| json_keys(v, out)),
        _ => {}
    }
}

fn raw(name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures").join(name);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// Deserialize the fixture, serialize it again and require the same JSON.
fn round_trip<T: Serialize + DeserializeOwned>(name: &str) -> T {
    let v = raw(name);
    let t: T = serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(serde_json::to_value(&t).unwrap(), v, "{name} does not round-trip");
    t
}

#[test]
fn fixtures_round_trip() {
    round_trip::<ProviderSummary>("provider_summary.json");
    let c: ConnectionSummary = round_trip("connection_summary.json");
    assert_eq!(c.status, ConnectionStatus::Connected);
    let c: ConnectionSummary = round_trip("connection_refresh_failed.json");
    assert_eq!(c.status, ConnectionStatus::RefreshFailed);
    let c: ConnectionSummary = round_trip("connection_disconnected.json");
    assert_eq!(c.revoked_at_provider, Some(false));
    round_trip::<ConnectionGrant>("connection_grant.json");
    round_trip::<ConnectionGrantListing>("grant_listing.json");
    round_trip::<ConnectRequest>("connect_request.json");
    round_trip::<ConnectResponse>("connect_response.json");
    let e: ErrorBody = round_trip("error_wrong_person.json");
    assert_eq!(e.error, ErrorSlug::WrongPerson);
    round_trip::<ErrorBody>("error_forbidden_host.json");
    assert!(matches!(round_trip("callback_pending.json"), CallbackResult::Pending(_)));
    assert_eq!(
        round_trip::<CallbackResult>("callback_error.json"),
        CallbackResult::Error(ErrorSlug::ProviderError)
    );
}

#[test]
fn unknown_fields_are_refused() {
    let mut v = raw("connection_summary.json");
    v["access_token"] = "x".into();
    assert!(serde_json::from_value::<ConnectionSummary>(v).is_err());
}

#[test]
fn no_fixture_carries_a_token_shaped_field() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let mut keys = HashSet::new();
        json_keys(&v, &mut keys);
        for k in keys {
            // A field named `code` is an authorization code; `last_error_code` is a slug.
            assert_ne!(k, "code", "{path:?} has field {k}");
            for part in k.split('_') {
                assert!(!FORBIDDEN_WORDS.contains(&part), "{path:?} has field {k}");
            }
        }
    }
}

#[test]
fn error_slugs_are_closed_and_match_their_wire_form() {
    let mut seen = HashSet::new();
    for s in ErrorSlug::ALL {
        assert_eq!(serde_json::to_value(s).unwrap(), Value::String(s.as_str().into()));
        assert!(seen.insert(s.as_str()));
    }
    assert!(serde_json::from_value::<ErrorSlug>("invalid_grant".into()).is_err());
}

#[test]
fn embedded_registry_parses_and_is_empty_for_now() {
    assert!(Registry::embedded().unwrap().provider.is_empty());
}

#[test]
fn registry_is_strict() {
    let ok = r#"
[[provider]]
id = "mock"
name = "Mock"
authorize_url = "http://127.0.0.1:8180/a"
token_url = "http://127.0.0.1:8180/t"
account_url = "http://127.0.0.1:8180/u"
refresh = "rotating"
api_hosts = ["127.0.0.1"]
default_scopes = ["openid"]
"#;
    let r = Registry::parse(ok).unwrap();
    assert_eq!(r.get("mock").unwrap().refresh, RefreshKind::Rotating);
    assert!(r.get("nope").is_none());
    assert!(Registry::parse(&format!("{ok}extra = 1")).is_err());
    assert!(Registry::parse(&ok.replace("rotating", "sometimes")).is_err());
    assert!(Registry::parse("surprise = 1").is_err());
}
