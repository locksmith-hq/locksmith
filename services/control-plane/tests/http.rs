use std::sync::Arc;

mod common;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use ls_control_plane::app::{self, AppState, BODY_LIMIT_BYTES};
use ls_control_plane::auth::OrgBinding;
use ls_control_plane::readiness::ReadyFlag;
use tower::ServiceExt;

const ORG: &str = "0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

async fn whoami(org: OrgBinding) -> String {
    org.org_id.to_string()
}

fn app(dev_auth: bool, ready: bool) -> Router {
    // A lazy pool that never connects: these tests touch no tenant data.
    let state = AppState::new(
        dev_auth,
        Arc::new(ReadyFlag::new(ready)),
        common::unreachable_db(),
    );
    app::with_layers(app::routes().route("/whoami", get(whoami)), state)
}

async fn status(app: Router, req: Request<Body>) -> StatusCode {
    app.oneshot(req).await.unwrap().status()
}

fn get_req(uri: &str, org: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().uri(uri);
    if let Some(o) = org {
        b = b.header("X-Locksmith-Dev-Org", o);
    }
    b.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn healthz_ok_even_when_not_ready() {
    assert_eq!(
        status(app(false, false), get_req("/healthz", None)).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn readyz_503_until_ready() {
    assert_eq!(
        status(app(false, false), get_req("/readyz", None)).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        status(app(false, true), get_req("/readyz", None)).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn responses_carry_a_request_id() {
    let resp = app(false, true)
        .oneshot(get_req("/healthz", None))
        .await
        .unwrap();
    assert!(resp.headers().contains_key("x-request-id"));
}

#[tokio::test]
async fn oversized_body_is_rejected() {
    let req = Request::builder()
        .method("POST")
        .uri("/healthz")
        .header("content-length", (BODY_LIMIT_BYTES + 1).to_string())
        .body(Body::from(vec![0u8; BODY_LIMIT_BYTES + 1]))
        .unwrap();
    assert_eq!(
        status(app(false, true), req).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn dev_header_ignored_when_dev_auth_off() {
    assert_eq!(
        status(app(false, true), get_req("/whoami", Some(ORG))).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn dev_header_binds_org_when_dev_auth_on() {
    let resp = app(true, true)
        .oneshot(get_req("/whoami", Some(ORG)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], ORG.as_bytes());
}

#[tokio::test]
async fn dev_auth_on_requires_a_valid_header() {
    assert_eq!(
        status(app(true, true), get_req("/whoami", None)).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(app(true, true), get_req("/whoami", Some("not-a-uuid"))).await,
        StatusCode::UNAUTHORIZED
    );
}
