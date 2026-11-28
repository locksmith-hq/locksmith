//! T10 task 1.3: the entitlement seam and `GET /internal/v1/orgs/{org_id}/entitlements`.
//! No database is needed: the route reads no tenant data.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use ls_control_plane::app::{self, AppState};
use ls_control_plane::auth::ServiceToken;
use ls_control_plane::readiness::ReadyFlag;
use ls_entitlements::{CoreOp, EntitlementSource, Entitlements, Feature, FreeTier, Limits};
use secrecy::SecretString;
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "test-only-gateway-service-token-0123456789";
const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_00000000000a);
const OTHER: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_00000000000b);

struct StubEnterprise;

impl EntitlementSource for StubEnterprise {
    fn entitlements(&self, _org: &str) -> Entitlements {
        Entitlements::enterprise([Feature::AuditStreaming], Limits::default())
    }
}

async fn call(
    source: Option<Arc<dyn EntitlementSource>>,
    path_org: Uuid,
    header_org: Uuid,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut s = AppState::new(
        true,
        Arc::new(ReadyFlag::new(true)),
        common::unreachable_db(),
    )
    .with_service_token(ServiceToken::new(SecretString::from(TOKEN)));
    if let Some(src) = source {
        s = s.with_entitlements(src);
    }
    let app = app::build(s);
    let mut b = Request::builder()
        .uri(format!("/internal/v1/orgs/{path_org}/entitlements"))
        .header("x-locksmith-org", header_org.to_string());
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let resp = app.oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn a_free_org_lacks_audit_streaming() {
    let (status, body) = call(None, ORG, ORG, Some(TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["plan"], "free");
    assert_eq!(body["features"], serde_json::json!([]));
    assert_eq!(body["org_id"], ORG.to_string());
}

#[tokio::test]
async fn a_stub_enterprise_source_has_audit_streaming() {
    let (status, body) = call(Some(Arc::new(StubEnterprise)), ORG, ORG, Some(TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["plan"], "enterprise");
    assert_eq!(body["features"], serde_json::json!(["audit_streaming"]));
}

#[test]
fn export_is_allowed_for_both_plans() {
    for src in [
        Arc::new(FreeTier) as Arc<dyn EntitlementSource>,
        Arc::new(StubEnterprise),
    ] {
        let e = src.entitlements(&ORG.to_string());
        assert!(e.allows(CoreOp::Export));
        assert!(e.allows(CoreOp::Unlock));
    }
}

#[tokio::test]
async fn another_orgs_entitlements_are_a_404() {
    let (status, _) = call(Some(Arc::new(StubEnterprise)), OTHER, ORG, Some(TOKEN)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn no_token_is_a_401() {
    let (status, _) = call(None, ORG, ORG, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(None, ORG, ORG, Some("wrong")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
