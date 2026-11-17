//! S2 tasks 3.2-3.4: write-only secret versions against a throwaway `postgres:18` container
//! (testcontainers; needs a Docker daemon). The KMS is an in-process fake wrapper, except in
//! `live_kms_*`, which uses the dev OpenBao from `just up` (skipped when it is unreachable,
//! unless `LS_REQUIRE_KMS=1`).

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use ls_control_plane::app::{self, AppState};
use ls_control_plane::db::PoolSettings;
use ls_control_plane::kms::DekWrapper;
use ls_control_plane::readiness::ReadyFlag;
use ls_envelope::{
    BaoToken, Binding, DataKey, Header, KeyWrapper, OpenBaoTransit, Purpose, SecretKey32,
    TransportKind, WrapError, WrapKeyId, WrappedDek, open_version,
};
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use sqlx_core::query_as::query_as;
use sqlx_core::query_scalar::query_scalar;
use tower::ServiceExt;
use uuid::Uuid;

const CANARY: &str = "CANARY-5b0e2d77-version-do-not-echo";

/// Fake KMS: returns a well-formed `dek-wrap` blob whose body is a fixed filler (it cannot be
/// unwrapped), and checks the binding it is given. Fails with `fail` when set.
struct FakeKms {
    calls: AtomicU32,
    fail: Option<WrapError>,
}

impl FakeKms {
    fn ok() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicU32::new(0),
            fail: None,
        })
    }
}

impl KeyWrapper for FakeKms {
    fn wrap(
        &self,
        _dek: &DataKey,
        binding: &Binding,
    ) -> impl Future<Output = Result<WrappedDek, WrapError>> + Send {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let result = match &self.fail {
            Some(e) => Err(e.clone()),
            None => {
                assert_eq!(binding.purpose, Purpose::DekWrap);
                assert_eq!(binding.version, n, "versions are numbered 1, 2, ...");
                let key = WrapKeyId::new("gateway", 1).unwrap();
                let mut blob = Header::v1(key.to_key_id()).encode().to_vec();
                blob.extend_from_slice(&[0x5a; 60]);
                WrappedDek::from_bytes(blob)
            }
        };
        async move { result }
    }

    async fn unwrap(
        &self,
        _wrapped: &WrappedDek,
        _binding: &Binding,
    ) -> Result<SecretKey32, WrapError> {
        Err(WrapError::Denied)
    }
}

struct Reply {
    status: StatusCode,
    body: Value,
    raw: String,
}

struct Api {
    app: Router,
    pg: common::Pg,
}

impl Api {
    async fn start(kms: Option<Arc<dyn DekWrapper>>) -> Self {
        let pg = common::Pg::migrated().await;
        let mut state = AppState::new(
            true,
            Arc::new(ReadyFlag::new(true)),
            pg.app_db(PoolSettings::default()),
        );
        if let Some(k) = kms {
            state = state.with_kms(k);
        }
        Self {
            app: app::build(state),
            pg,
        }
    }

    async fn raw(&self, method: &str, uri: &str, org: Uuid, ct: &str, body: String) -> Reply {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("X-Locksmith-Dev-Org", org.to_string())
            .header("content-type", ct)
            .body(Body::from(body))
            .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let raw = String::from_utf8_lossy(&bytes).into_owned();
        Reply {
            status,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            raw,
        }
    }

    async fn post(&self, uri: &str, org: Uuid, body: Value) -> Reply {
        self.raw("POST", uri, org, "application/json", body.to_string())
            .await
    }

    async fn get(&self, uri: &str, org: Uuid) -> Reply {
        let req = Request::builder()
            .uri(uri)
            .header("X-Locksmith-Dev-Org", org.to_string())
            .body(Body::empty())
            .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        Reply {
            status,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            raw: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    async fn org(&self, name: &str) -> Uuid {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/orgs")
            .header("content-type", "application/json")
            .body(Body::from(json!({ "name": name }).to_string()))
            .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        v["id"].as_str().unwrap().parse().unwrap()
    }

    /// Org, project, environment and secret; returns the secret's URL.
    async fn secret(&self, org: Uuid) -> String {
        let name = Uuid::now_v7().to_string();
        let p = self
            .post("/v1/projects", org, json!({ "name": name }))
            .await;
        let p = format!("/v1/projects/{}", p.body["id"].as_str().unwrap());
        let e = self
            .post(&format!("{p}/environments"), org, json!({"name": "dev"}))
            .await;
        let e = format!("{p}/environments/{}", e.body["id"].as_str().unwrap());
        let s = self
            .post(&format!("{e}/secrets"), org, json!({"name": "K"}))
            .await;
        assert_eq!(s.status, StatusCode::CREATED);
        format!("{e}/secrets/{}", s.body["id"].as_str().unwrap())
    }

    /// Every stored version row, read as the bootstrap superuser (bypasses RLS).
    async fn rows(&self) -> Vec<(Uuid, Uuid, i32, Vec<u8>, Vec<u8>, String)> {
        let mut c = self.pg.admin().await;
        let rows = query_as(
            "SELECT org_id, secret_id, version, ciphertext, wrapped_dek, key_id
             FROM secret_versions ORDER BY version",
        )
        .fetch_all(&mut c)
        .await
        .unwrap();
        c.close().await.unwrap();
        rows
    }

    /// The whole database as text, for a canary search (every table, every column).
    async fn dump_text(&self) -> String {
        let mut c = self.pg.admin().await;
        let mut out = String::new();
        for table in [
            "orgs",
            "projects",
            "environments",
            "secrets",
            "secret_versions",
        ] {
            let rows: Vec<String> = query_scalar(sqlx_core::sql_str::AssertSqlSafe(format!(
                "SELECT t::text FROM {table} t"
            )))
            .fetch_all(&mut c)
            .await
            .unwrap();
            out.push_str(&rows.join("\n"));
        }
        c.close().await.unwrap();
        out
    }
}

/// Every encoding of the canary a response or dump could plausibly contain.
fn canary_encodings() -> Vec<String> {
    let b = CANARY.as_bytes();
    vec![
        CANARY.to_owned(),
        hex::encode(b),
        base64::engine::general_purpose::STANDARD.encode(b),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b),
    ]
}

fn assert_no_canary(text: &str, what: &str) {
    for enc in canary_encodings() {
        assert!(!text.contains(&enc), "{what} contains the canary");
    }
}

fn assert_problem(r: &Reply, status: StatusCode, slug: &str) {
    assert_eq!(r.status, status, "{}", r.raw);
    assert_eq!(r.body["type"], format!("urn:locksmith:problem:{slug}"));
    assert_no_canary(&r.raw, "problem body");
}

/// Scenario: create a version. `201` with metadata only, `version_count` increases, the
/// stored row holds only ciphertext and a wrapped DEK, and nothing echoes the value.
#[tokio::test]
async fn create_version_returns_metadata_only_and_counts() {
    let kms = FakeKms::ok();
    let api = Api::start(Some(kms.clone())).await;
    let org = api.org("acme").await;
    let s = api.secret(org).await;
    let versions = format!("{s}/versions");

    let r = api.post(&versions, org, json!({ "value": CANARY })).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    assert_no_canary(&r.raw, "create response");
    let mut keys: Vec<&str> = r
        .body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["created_at", "key_id", "secret_id", "version"]);
    assert_eq!(r.body["version"], 1);
    assert_eq!(r.body["key_id"], "gateway:v1");
    assert!(r.body["created_at"].as_str().unwrap().ends_with('Z'));

    let r2 = api.post(&versions, org, json!({ "value": "second" })).await;
    assert_eq!(r2.status, StatusCode::CREATED);
    assert_eq!(r2.body["version"], 2);
    assert_eq!(kms.calls.load(Ordering::SeqCst), 2);

    // version_count is real on get and list.
    let got = api.get(&s, org).await;
    assert_eq!(got.body["version_count"], 2);
    let listed = api.get(&s[..s.rfind('/').unwrap()], org).await;
    assert_eq!(listed.body["items"][0]["version_count"], 2);

    // GET lists metadata only, oldest first.
    let l = api.get(&versions, org).await;
    assert_eq!(l.status, StatusCode::OK);
    assert_no_canary(&l.raw, "list response");
    let items = l.body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0], r.body);
    assert_eq!(items[1]["version"], 2);

    // The stored rows: bound to the org and secret, ciphertext in the A0-7 format, the DEK
    // wrapped (80-byte dek-wrap blob), and no canary anywhere in the database.
    let rows = api.rows().await;
    assert_eq!(rows.len(), 2);
    let secret_id: Uuid = s.rsplit('/').next().unwrap().parse().unwrap();
    for (i, (o, sid, v, ct, wrapped, key_id)) in rows.iter().enumerate() {
        assert_eq!((*o, *sid, *v), (org, secret_id, i as i32 + 1));
        assert!(ct.starts_with(b"LS"), "A0-7 magic");
        assert_eq!(wrapped.len(), 80);
        assert_eq!(key_id, "gateway:v1");
    }
    assert_eq!(rows[0].3.len(), 48 + CANARY.len());
    assert_ne!(rows[0].3[20..32], rows[1].3[20..32], "nonces differ");
    assert_no_canary(&api.dump_text().await, "database");
}

/// Scenario: cross-org isolation. Org B gets `404` for org A's versions (read and write), the
/// same as for a secret that never existed, and nothing is stored.
#[tokio::test]
async fn other_orgs_versions_are_404() {
    let api = Api::start(Some(FakeKms::ok())).await;
    let a = api.org("a").await;
    let b = api.org("b").await;
    let s = api.secret(a).await;
    let versions = format!("{s}/versions");
    assert_eq!(
        api.post(&versions, a, json!({ "value": CANARY }))
            .await
            .status,
        StatusCode::CREATED
    );

    let never = format!(
        "{}/{}/versions",
        &s[..s.rfind('/').unwrap()],
        Uuid::now_v7()
    );
    let missing = api.get(&never, a).await;
    assert_problem(&missing, StatusCode::NOT_FOUND, "not-found");
    let r = api.get(&versions, b).await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not-found");
    assert_eq!(r.body, missing.body);
    let r = api.post(&versions, b, json!({ "value": "from-b" })).await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not-found");
    // Org A's own secret under another of A's environments is also 404.
    let other_env = api.secret(a).await;
    let crossed = format!(
        "{}/secrets/{}/versions",
        &other_env[..other_env.find("/secrets/").unwrap()],
        s.rsplit('/').next().unwrap()
    );
    let r = api.post(&crossed, a, json!({ "value": "x" })).await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not-found");
    assert_eq!(api.rows().await.len(), 1);
}

/// Value-field misuse: every malformed write is a problem that never echoes the value, and
/// stores nothing. A `value` on any other resource stays an unknown field.
#[tokio::test]
async fn value_field_misuse_is_rejected_without_echo() {
    let kms = FakeKms::ok();
    let api = Api::start(Some(kms.clone())).await;
    let org = api.org("acme").await;
    let s = api.secret(org).await;
    let versions = format!("{s}/versions");

    let r = api.post(&versions, org, json!({})).await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    assert!(r.body["detail"].as_str().unwrap().contains("`value`"));
    let r = api
        .post(&versions, org, json!({ "value": CANARY, "name": CANARY }))
        .await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    assert!(r.body["detail"].as_str().unwrap().contains("`name`"));
    for bad in [
        json!({ "value": "" }),
        json!({ "value": 5 }),
        json!({ "value": [CANARY] }),
        json!({ "value": { "v": CANARY } }),
        json!({ "value": null }),
        json!([CANARY]),
    ] {
        let r = api.post(&versions, org, bad).await;
        assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    }
    // Malformed JSON and the wrong content type.
    let r = api
        .raw(
            "POST",
            &versions,
            org,
            "application/json",
            format!("{{\"value\": \"{CANARY}"),
        )
        .await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    let r = api
        .raw(
            "POST",
            &versions,
            org,
            "text/plain",
            json!({ "value": CANARY }).to_string(),
        )
        .await;
    assert_problem(
        &r,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported-media-type",
    );
    // Over the body limit.
    let big = "x".repeat(app::BODY_LIMIT_BYTES + 1);
    let r = api.post(&versions, org, json!({ "value": big })).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    // Escaped JSON still round-trips into the stored version (and is not echoed).
    let r = api
        .post(
            &versions,
            org,
            json!({ "value": format!("{CANARY}\n\"q\"") }),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert_eq!(r.body["version"], 1);

    // `value` stays an unknown field on secret metadata, create and patch.
    let parent = &s[..s.rfind('/').unwrap()];
    let r = api
        .post(parent, org, json!({ "name": "K2", "value": CANARY }))
        .await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    let r = api
        .raw(
            "PATCH",
            &s,
            org,
            "application/json",
            json!({ "value": CANARY }).to_string(),
        )
        .await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");

    assert_eq!(kms.calls.load(Ordering::SeqCst), 1);
    assert_eq!(api.rows().await.len(), 1);
    assert_no_canary(&api.dump_text().await, "database");
}

/// Without a KMS, or when the KMS fails, nothing is stored and the reply is a problem.
#[tokio::test]
async fn kms_missing_or_failing_stores_nothing() {
    let api = Api::start(None).await;
    let org = api.org("acme").await;
    let s = api.secret(org).await;
    let r = api
        .post(&format!("{s}/versions"), org, json!({ "value": CANARY }))
        .await;
    assert_problem(&r, StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    assert!(api.rows().await.is_empty());
    drop(api);

    for (fail, status, slug) in [
        (
            WrapError::Transport(TransportKind::Connect),
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
        ),
        (
            WrapError::Denied,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
        ),
    ] {
        let kms = Arc::new(FakeKms {
            calls: AtomicU32::new(0),
            fail: Some(fail),
        });
        let api = Api::start(Some(kms)).await;
        let org = api.org("acme").await;
        let s = api.secret(org).await;
        let r = api
            .post(&format!("{s}/versions"), org, json!({ "value": CANARY }))
            .await;
        assert_problem(&r, status, slug);
        assert!(api.rows().await.is_empty());
        assert_eq!(api.get(&s, org).await.body["version_count"], 0);
    }
}

fn openbao_addr() -> String {
    std::env::var("OPENBAO_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_owned())
}

fn openbao(token_env: &str, default: &str) -> OpenBaoTransit {
    OpenBaoTransit::new(
        &openbao_addr(),
        WrapKeyId::new("gateway", 1).unwrap(),
        BaoToken::new(std::env::var(token_env).unwrap_or_else(|_| default.to_owned())),
    )
    .unwrap()
}

/// Full path against the dev OpenBao: the control plane (encrypt-only token) writes a version;
/// its own token cannot unwrap the stored DEK, the gateway test token can, and the stored
/// ciphertext opens to the submitted bytes.
#[tokio::test]
async fn live_kms_write_then_gateway_decrypts_and_control_plane_cannot() {
    let hostport = openbao_addr()
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_owned();
    if tokio::net::TcpStream::connect(&hostport).await.is_err() {
        assert!(
            std::env::var("LS_REQUIRE_KMS").as_deref() != Ok("1"),
            "OpenBao not reachable and LS_REQUIRE_KMS=1"
        );
        eprintln!("skipping: OpenBao not reachable (run `just up`)");
        return;
    }
    // Dev-only token defaults from infra/compose/.env.example.
    let control_plane = openbao("OPENBAO_CONTROL_PLANE_TOKEN", "dev-only-control-plane");
    let api = Api::start(Some(Arc::new(control_plane))).await;
    let org = api.org("acme").await;
    let s = api.secret(org).await;
    let r = api
        .post(&format!("{s}/versions"), org, json!({ "value": CANARY }))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    assert_no_canary(&r.raw, "create response");

    let rows = api.rows().await;
    let (o, sid, v, ct, wrapped, _) = &rows[0];
    let binding = |purpose| Binding {
        org_id: *o.as_bytes(),
        secret_id: *sid.as_bytes(),
        version: *v as u32,
        purpose,
    };
    let wrapped = WrappedDek::from_bytes(wrapped.clone()).unwrap();
    let cp = openbao("OPENBAO_CONTROL_PLANE_TOKEN", "dev-only-control-plane");
    assert_eq!(
        cp.unwrap(&wrapped, &binding(Purpose::DekWrap)).await.err(),
        Some(WrapError::Denied)
    );
    let gw = openbao("OPENBAO_GATEWAY_TOKEN", "dev-only-gateway");
    let key = gw
        .unwrap(&wrapped, &binding(Purpose::DekWrap))
        .await
        .unwrap();
    let dek = DataKey::from_parts(Header::parse(ct).unwrap().key_id, key);
    let pt = open_version(&dek, &binding(Purpose::SecretPayload), ct).unwrap();
    assert!(pt.expose() == CANARY.as_bytes(), "plaintext mismatch");
    assert_no_canary(&api.dump_text().await, "database");
}
