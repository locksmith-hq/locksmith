//! T5 task 2.2: `POST /internal/v1/honey/mint` against a throwaway `postgres:18` container
//! (testcontainers; needs a Docker daemon). The KMS is an in-process fake wrapper.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use ls_control_plane::app::{self, AppState};
use ls_control_plane::auth::ServiceToken;
use ls_control_plane::db::PoolSettings;
use ls_control_plane::kms::DekWrapper;
use ls_control_plane::readiness::ReadyFlag;
use ls_envelope::{
    Binding, DataKey, Header, KeyWrapper, Purpose, SecretKey32, WrapError, WrapKeyId, WrappedDek,
};
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use sqlx_core::query_scalar::query_scalar;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "test-only-gateway-service-token-0123456789";

/// Wraps nothing real: a well-formed `dek-wrap` blob with a filler body.
struct FakeKms;

impl KeyWrapper for FakeKms {
    fn wrap(
        &self,
        _dek: &DataKey,
        binding: &Binding,
    ) -> impl Future<Output = Result<WrappedDek, WrapError>> + Send {
        assert_eq!(binding.purpose, Purpose::DekWrap);
        assert_eq!(binding.version, 1);
        let key = WrapKeyId::new("gateway", 1).unwrap();
        let mut blob = Header::v1(key.to_key_id()).encode().to_vec();
        blob.extend_from_slice(&[0x5a; 60]);
        let r = WrappedDek::from_bytes(blob);
        async move { r }
    }

    async fn unwrap(&self, _w: &WrappedDek, _b: &Binding) -> Result<SecretKey32, WrapError> {
        Err(WrapError::Denied)
    }
}

struct Reply {
    status: StatusCode,
    body: Value,
    raw: String,
}

struct Fixture {
    app: Router,
    pg: common::Pg,
    org: Uuid,
    other_org: Uuid,
    project: String,
    env: String,
}

impl Fixture {
    async fn start() -> Self {
        let pg = common::Pg::migrated().await;
        let state = AppState::new(
            true,
            Arc::new(ReadyFlag::new(true)),
            pg.app_db(PoolSettings::default()),
        )
        .with_service_token(ServiceToken::new(SecretString::from(TOKEN)))
        .with_kms(Arc::new(FakeKms) as Arc<dyn DekWrapper>);
        let app = app::build(state);
        let org = Self::post(&app, "/v1/orgs", None, json!({"name": "a"})).await;
        let other_org = Self::post(&app, "/v1/orgs", None, json!({"name": "b"})).await;
        let project = Self::post(
            &app,
            "/v1/projects",
            Some(org.clone()),
            json!({"name": "p"}),
        )
        .await;
        let env = Self::post(
            &app,
            &format!("/v1/projects/{project}/environments"),
            Some(org.clone()),
            json!({"name": "dev"}),
        )
        .await;
        Self {
            app,
            pg,
            org: org.parse().unwrap(),
            other_org: other_org.parse().unwrap(),
            project,
            env,
        }
    }

    async fn post(app: &Router, uri: &str, org: Option<String>, body: Value) -> String {
        let mut b = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(o) = org {
            b = b.header("x-locksmith-dev-org", o);
        }
        let resp = app
            .clone()
            .oneshot(b.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        v["id"].as_str().unwrap().to_owned()
    }

    /// A secret row; `honey` turns it into a honey token of that template (the NestJS API does
    /// this through its own connection, which is not part of this test).
    async fn secret(&self, name: &str, honey: Option<&str>) -> Uuid {
        let id: Uuid = Self::post(
            &self.app,
            &format!(
                "/v1/projects/{}/environments/{}/secrets",
                self.project, self.env
            ),
            Some(self.org.to_string()),
            json!({"name": name}),
        )
        .await
        .parse()
        .unwrap();
        if let Some(t) = honey {
            let mut c = self.pg.admin().await;
            sqlx_core::query::query(
                "UPDATE secrets SET kind = 'honey', honey_template = $2 WHERE id = $1",
            )
            .bind(id)
            .bind(t)
            .execute(&mut c)
            .await
            .unwrap();
            c.close().await.unwrap();
        }
        id
    }

    async fn mint(&self, org: Uuid, token: Option<&str>, body: Value) -> Reply {
        let mut b = Request::builder()
            .method("POST")
            .uri("/internal/v1/honey/mint")
            .header("content-type", "application/json")
            .header("x-locksmith-org", org.to_string());
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        let resp = self
            .app
            .clone()
            .oneshot(b.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        Reply {
            status,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            raw: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    async fn version_count(&self, id: Uuid) -> i64 {
        let mut c = self.pg.admin().await;
        let n = query_scalar("SELECT count(*) FROM secret_versions WHERE secret_id = $1")
            .bind(id)
            .fetch_one(&mut c)
            .await
            .unwrap();
        c.close().await.unwrap();
        n
    }
}

#[tokio::test]
async fn mints_version_one_and_returns_metadata_only() {
    let f = Fixture::start().await;
    for (i, template) in [
        "aws_access_key",
        "github_pat",
        "slack_token",
        "generic_api_key",
    ]
    .into_iter()
    .enumerate()
    {
        let id = f.secret(&format!("H{i}"), Some(template)).await;
        let r = f
            .mint(
                f.org,
                Some(TOKEN),
                json!({"template": template, "secret_id": id}),
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
        assert_eq!(
            r.body,
            json!({"secret_id": id.to_string(), "version": 1, "template": template})
        );
        for prefix in ["AKIA", "ghp_", "xoxb-", "sk_live_"] {
            assert!(!r.raw.contains(prefix), "response leaks a value: {}", r.raw);
        }
        assert_eq!(f.version_count(id).await, 1);
    }
}

#[tokio::test]
async fn refuses_without_service_token() {
    let f = Fixture::start().await;
    let id = f.secret("H", Some("github_pat")).await;
    let body = json!({"template": "github_pat", "secret_id": id});
    let r = f.mint(f.org, None, body.clone()).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.raw);
    let r = f
        .mint(f.org, Some("wrong-token-wrong-token-wrong-token"), body)
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.raw);
    assert_eq!(f.version_count(id).await, 0);
}

#[tokio::test]
async fn standard_secret_or_template_mismatch_is_409_and_stores_nothing() {
    let f = Fixture::start().await;
    let plain = f.secret("plain", None).await;
    let r = f
        .mint(
            f.org,
            Some(TOKEN),
            json!({"template": "github_pat", "secret_id": plain}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.raw);
    assert_eq!(f.version_count(plain).await, 0);

    let honey = f.secret("honey", Some("aws_access_key")).await;
    let r = f
        .mint(
            f.org,
            Some(TOKEN),
            json!({"template": "slack_token", "secret_id": honey}),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.raw);
    assert_eq!(f.version_count(honey).await, 0);
}

#[tokio::test]
async fn second_mint_is_409_and_keeps_version_one() {
    let f = Fixture::start().await;
    let id = f.secret("H", Some("generic_api_key")).await;
    let body = json!({"template": "generic_api_key", "secret_id": id});
    assert_eq!(
        f.mint(f.org, Some(TOKEN), body.clone()).await.status,
        StatusCode::CREATED
    );
    let r = f.mint(f.org, Some(TOKEN), body).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.raw);
    assert_eq!(f.version_count(id).await, 1);
}

#[tokio::test]
async fn other_orgs_secret_and_unknown_secret_are_404() {
    let f = Fixture::start().await;
    let id = f.secret("H", Some("github_pat")).await;
    let r = f
        .mint(
            f.other_org,
            Some(TOKEN),
            json!({"template": "github_pat", "secret_id": id}),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.raw);
    let r = f
        .mint(
            f.org,
            Some(TOKEN),
            json!({"template": "github_pat", "secret_id": Uuid::now_v7()}),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.raw);
    assert_eq!(f.version_count(id).await, 0);
}
