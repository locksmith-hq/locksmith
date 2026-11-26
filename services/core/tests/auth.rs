use axum::body::Body;
use http::{Request, StatusCode, header};
use ls_core_service::app::{AppState, router};
use ls_core_service::auth::ServiceToken;
use secrecy::SecretString;
use tower::ServiceExt;

fn app() -> axum::Router {
    router(AppState::new(ServiceToken::new(SecretString::from(
        "test-token".to_owned(),
    ))))
}

async fn status(path: &str, auth: Option<&str>) -> StatusCode {
    let mut req = Request::get(path);
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    app()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn probes_are_open() {
    assert_eq!(status("/healthz", None).await, StatusCode::OK);
    assert_eq!(status("/readyz", None).await, StatusCode::OK);
}

#[tokio::test]
async fn unauthenticated_unknown_path_gets_401_not_404() {
    assert_eq!(status("/v1/anything", None).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn internal_routes_require_the_token() {
    // Unknown path under the auth layer: layer runs only for matched routes, so mount a probe.
    let internal = axum::Router::new()
        .route("/x", axum::routing::get(|| async { StatusCode::OK }))
        .route_layer(axum::middleware::from_fn_with_state(
            AppState::new(ServiceToken::new(SecretString::from(
                "test-token".to_owned(),
            ))),
            ls_core_service::auth::require_service_token,
        ));
    for (hdr, want) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some("Bearer wrong"), StatusCode::UNAUTHORIZED),
        (Some("test-token"), StatusCode::UNAUTHORIZED),
        (Some("Bearer test-token"), StatusCode::OK),
    ] {
        let mut req = Request::get("/x");
        if let Some(h) = hdr {
            req = req.header(header::AUTHORIZATION, h);
        }
        let got = internal
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status();
        assert_eq!(got, want, "{hdr:?}");
    }
}
