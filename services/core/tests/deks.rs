//! `POST /v1/deks/wrap` and `/v1/deks/unwrap` with a fake KMS (task 3.3; no network).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use ls_core_service::app::{AppState, router};
use ls_core_service::auth::ServiceToken;
use ls_crypto::SecretKey32;
use ls_envelope::{Binding, DataKey, Header, KeyWrapper, WrapError, WrapKeyId, WrappedDek};
use secrecy::SecretString;
use serde_json::{Value, json};
use tower::ServiceExt;

const ORG: &str = "11111111-1111-4111-8111-111111111111";
const SECRET: &str = "22222222-2222-4222-8222-222222222222";

/// Remembers each wrapped blob's binding and key, the way a KMS would authenticate them.
#[derive(Default)]
struct FakeKms {
    wrapped: Mutex<HashMap<Vec<u8>, (Binding, [u8; 32])>>,
    seen_keys: Mutex<Vec<[u8; 32]>>,
    fail: Option<WrapError>,
}

impl KeyWrapper for FakeKms {
    async fn wrap(&self, dek: &DataKey, binding: &Binding) -> Result<WrappedDek, WrapError> {
        if let Some(e) = &self.fail {
            return Err(e.clone());
        }
        // The real wrapper refuses any other purpose.
        if binding.purpose != ls_envelope::Purpose::DekWrap {
            return Err(WrapError::Purpose);
        }
        let key = WrapKeyId::new("gateway", 1)?;
        let mut blob = Header::v1(key.to_key_id()).encode().to_vec();
        let mut rest = vec![0u8; 60];
        getrandom::getrandom(&mut rest).unwrap();
        blob.extend_from_slice(&rest);
        self.wrapped
            .lock()
            .unwrap()
            .insert(blob.clone(), (*binding, *dek.expose()));
        self.seen_keys.lock().unwrap().push(*dek.expose());
        WrappedDek::from_bytes(blob)
    }

    async fn unwrap(
        &self,
        wrapped: &WrappedDek,
        binding: &Binding,
    ) -> Result<SecretKey32, WrapError> {
        if let Some(e) = &self.fail {
            return Err(e.clone());
        }
        match self.wrapped.lock().unwrap().get(wrapped.as_bytes()) {
            Some((b, key)) if b == binding => Ok(SecretKey32::from_bytes(*key)),
            _ => Err(WrapError::Rejected { status: 400 }),
        }
    }
}

fn app(kms: Option<Arc<FakeKms>>) -> axum::Router {
    let mut s = AppState::new(ServiceToken::new(SecretString::from(
        "test-token".to_owned(),
    )));
    if let Some(k) = kms {
        s = s.with_dek_kms(k);
    }
    router(s)
}

struct Reply {
    status: StatusCode,
    cache: Option<String>,
    raw: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.raw).unwrap_or(Value::Null)
    }
}

async fn post(app: &axum::Router, path: &str, auth: Option<&str>, body: Value) -> Reply {
    let mut req = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let cache = res
        .headers()
        .get(header::CACHE_CONTROL)
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        cache,
        raw: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

const AUTH: Option<&str> = Some("Bearer test-token");

fn binding(version: i64) -> Value {
    json!({"org_id": ORG, "secret_id": SECRET, "version": version, "purpose": "dek_wrap"})
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::test]
async fn wrap_then_unwrap_round_trips_without_key_bytes() {
    let kms = Arc::new(FakeKms::default());
    let app = app(Some(kms.clone()));

    let w = post(&app, "/v1/deks/wrap", AUTH, json!({"binding": binding(1)})).await;
    assert_eq!(w.status, StatusCode::OK);
    assert_eq!(w.cache.as_deref(), Some("no-store"));
    let body = w.json();
    let handle = body["dek_handle"].as_str().unwrap();
    assert!(handle.len() >= 22 && handle.len() <= 64);
    assert!(
        handle
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    );
    assert_eq!(body["key_id"], "gateway:v1");
    let blob = B64.decode(body["wrapped_dek"].as_str().unwrap()).unwrap();
    assert_eq!(blob.len(), ls_envelope::WRAPPED_DEK_LEN);

    let key = kms.seen_keys.lock().unwrap()[0];
    for needle in [B64.encode(key), hex(&key)] {
        assert!(!w.raw.contains(&needle), "key bytes in the wrap response");
    }

    let u = post(
        &app,
        "/v1/deks/unwrap",
        AUTH,
        json!({"binding": binding(1), "wrapped_dek": body["wrapped_dek"]}),
    )
    .await;
    assert_eq!(u.status, StatusCode::OK);
    assert_eq!(u.cache.as_deref(), Some("no-store"));
    let ub = u.json();
    assert_eq!(ub["key_id"], "gateway:v1");
    assert_ne!(
        ub["dek_handle"], body["dek_handle"],
        "each call gets its own handle"
    );
    for needle in [B64.encode(key), hex(&key)] {
        assert!(!u.raw.contains(&needle), "key bytes in the unwrap response");
    }
}

#[tokio::test]
async fn wrong_binding_is_a_400() {
    let app = app(Some(Arc::new(FakeKms::default())));
    let w = post(&app, "/v1/deks/wrap", AUTH, json!({"binding": binding(1)})).await;
    let blob = w.json()["wrapped_dek"].clone();
    for b in [
        binding(2),
        json!({"org_id": SECRET, "secret_id": SECRET, "version": 1, "purpose": "dek_wrap"}),
    ] {
        let u = post(
            &app,
            "/v1/deks/unwrap",
            AUTH,
            json!({"binding": b, "wrapped_dek": blob}),
        )
        .await;
        assert_eq!(u.status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn requires_the_service_token() {
    let app = app(Some(Arc::new(FakeKms::default())));
    let body = json!({"binding": binding(1)});
    for auth in [None, Some("Bearer wrong"), Some("test-token")] {
        for path in ["/v1/deks/wrap", "/v1/deks/unwrap"] {
            let r = post(&app, path, auth, body.clone()).await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{path} {auth:?}");
        }
    }
}

#[tokio::test]
async fn bad_input_is_a_400() {
    let app = app(Some(Arc::new(FakeKms::default())));
    let wrap_bad = [
        json!({}),
        json!({"binding": binding(0)}),
        json!({"binding": binding(-1)}),
        json!({"binding": binding(4_294_967_296)}),
        json!({"binding": {"org_id": "nope", "secret_id": SECRET, "version": 1, "purpose": "dek_wrap"}}),
        json!({"binding": {"org_id": ORG, "secret_id": SECRET, "version": 1, "purpose": "other"}}),
        json!({"binding": binding(1), "dek": "AAAA"}),
        // The KMS only wraps `dek_wrap` bindings.
        json!({"binding": {"org_id": ORG, "secret_id": SECRET, "version": 1, "purpose": "secret_payload"}}),
    ];
    for b in wrap_bad {
        let r = post(&app, "/v1/deks/wrap", AUTH, b.clone()).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{b}");
        assert!(r.raw.contains("\"status\":400"));
    }
    for blob in ["not base64!!", "AAAA", ""] {
        let r = post(
            &app,
            "/v1/deks/unwrap",
            AUTH,
            json!({"binding": binding(1), "wrapped_dek": blob}),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{blob:?}");
    }
    let r = post(
        &app,
        "/v1/deks/unwrap",
        AUTH,
        json!({"binding": binding(1)}),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn kms_unavailable_is_a_503_without_detail() {
    let none = app(None);
    let r = post(&none, "/v1/deks/wrap", AUTH, json!({"binding": binding(1)})).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);

    let down = app(Some(Arc::new(FakeKms {
        fail: Some(WrapError::Denied),
        ..FakeKms::default()
    })));
    let r = post(&down, "/v1/deks/wrap", AUTH, json!({"binding": binding(1)})).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!r.raw.to_lowercase().contains("denied"));
}
