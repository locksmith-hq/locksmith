//! The gateway `/mcp` route (change m1-remote-mcp, task 3.1): the agent MCP server.
//!
//! The protocol and the Streamable HTTP transport are `rmcp`, mounted with `nest_service` as on
//! the hub (`ls_control_plane::mcp_endpoint`). What is Locksmith's here is the auth in front of
//! it: the bearer token is an agent token (EdDSA, audience `gateway`, 15 minutes), verified by
//! the same [`AgentAuth`] that guards `/v1`, so an expired, forged, wrong-audience or
//! wrong-org token gets the one `401` with a `WWW-Authenticate: Bearer` challenge and nothing
//! runs. A missing or unconfigured endpoint also answers `401` (fail closed).
//!
//! The verified agent is passed to handlers as an [`AgentIdentity`] request extension (read from
//! `RequestContext.extensions` as `http::request::Parts`). The tools arrive in tasks 3.2 and 3.3;
//! until then the server lists none. The `Host` allowlist is loopback plus the configured public
//! hosts and is never disabled. No token text is logged or echoed.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::any;
use rmcp::ServerHandler;
use rmcp::model::{ServerCapabilities, ServerConfig};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::AgentAuth;
use crate::relay::error;

/// The path the MCP service is mounted at.
pub const MCP_PATH: &str = "/mcp";

/// Verifier and `Host` allowlist for `/mcp`.
pub struct McpEndpoint {
    auth: Arc<AgentAuth>,
    allowed_hosts: Vec<String>,
}

impl McpEndpoint {
    /// `auth` is the gateway's agent-token verifier (shared with `/v1`); `public_hosts` are the
    /// `Host` values accepted besides loopback.
    pub fn new(auth: Arc<AgentAuth>, public_hosts: &[String]) -> Self {
        let mut allowed_hosts: Vec<String> = ["localhost", "127.0.0.1", "::1"]
            .map(str::to_owned)
            .to_vec();
        allowed_hosts.extend(public_hosts.iter().cloned());
        Self {
            auth,
            allowed_hosts,
        }
    }
}

/// The gateway MCP server. Tools are added by tasks 3.2 and 3.3.
#[derive(Clone)]
struct GatewayMcp;

impl ServerHandler for GatewayMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Locksmith gateway. Tools return ids, names and relay results, never secret values.",
        )
    }
}

fn unauthorized(token_presented: bool) -> Response {
    let mut response = error(
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        &Uuid::new_v4().to_string(),
    );
    let challenge = if token_presented {
        HeaderValue::from_static(r#"Bearer error="invalid_token""#)
    } else {
        HeaderValue::from_static("Bearer")
    };
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, challenge);
    response
}

async fn require_agent(
    State(endpoint): State<Arc<McpEndpoint>>,
    mut request: Request,
    next: Next,
) -> Response {
    let presented = request.headers().contains_key(header::AUTHORIZATION);
    match endpoint.auth.authenticate(request.headers()).await {
        Ok(identity) => {
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Err(e) => {
            // The reason is a fixed label, never token text.
            tracing::debug!(reason = e.as_str(), "mcp request refused");
            unauthorized(presented)
        }
    }
}

/// The `/mcp` service. Without a configured endpoint `/mcp` answers `401` to everything.
pub fn router(state: &AppState) -> Router<AppState> {
    let Some(endpoint) = state.mcp() else {
        return Router::new()
            .route(MCP_PATH, any(|| async { unauthorized(false) }))
            .route("/mcp/{*rest}", any(|| async { unauthorized(false) }));
    };
    let config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(endpoint.allowed_hosts.clone())
        .with_legacy_session_mode(true);
    let service = StreamableHttpService::new(
        || Ok(GatewayMcp),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    Router::new()
        .nest_service(MCP_PATH, service)
        .layer(middleware::from_fn_with_state(endpoint, require_agent))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{self, AppState};
    use crate::auth::JwksSettings;
    use crate::auth::testkit::StubJwks;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use ls_control_plane::agent_token::{AUDIENCE, AgentClaims, AgentTokenSigner};
    use ls_control_plane::readiness::ReadyFlag;
    use time::OffsetDateTime;
    use tower::ServiceExt;
    use zeroize::Zeroizing;

    const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000b1);
    const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000b2);
    const HOST: &str = "gateway.test";
    const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;

    fn signer() -> AgentTokenSigner {
        AgentTokenSigner::from_seed(Zeroizing::new([5; 32])).unwrap()
    }

    fn token(aud: &str, exp_in: i64, org: Uuid) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        signer()
            .sign(&AgentClaims {
                sub: AGENT,
                org,
                aud: aud.to_owned(),
                iat: now,
                exp: now + exp_in,
            })
            .unwrap()
    }

    fn app(configured: bool) -> Router {
        let mut state = AppState::new(Arc::new(ReadyFlag::new(true)));
        if configured {
            let auth = Arc::new(AgentAuth::new(
                ORG,
                Arc::new(StubJwks::with(vec![signer().jwk().clone()])),
                JwksSettings::default(),
            ));
            state = state.with_mcp(McpEndpoint::new(auth, &[HOST.to_owned()]));
        }
        app::build(state)
    }

    async fn post(app: &Router, authorization: Option<&str>, host: &str) -> (Response, String) {
        let mut b = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, host)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(a) = authorization {
            b = b.header(header::AUTHORIZATION, a);
        }
        let resp = app
            .clone()
            .oneshot(b.body(Body::from(INITIALIZE)).unwrap())
            .await
            .unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        (Response::from_parts(parts, Body::empty()), text)
    }

    fn challenge(resp: &Response) -> &str {
        resp.headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("401 carries WWW-Authenticate")
            .to_str()
            .unwrap()
    }

    #[tokio::test]
    async fn mcp_missing_token_is_401_with_challenge() {
        let (resp, _) = post(&app(true), None, HOST).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(challenge(&resp), "Bearer");
    }

    #[tokio::test]
    async fn mcp_expired_token_is_401() {
        let t = token(AUDIENCE, -600, ORG);
        let (resp, body) = post(&app(true), Some(&format!("Bearer {t}")), HOST).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(challenge(&resp), r#"Bearer error="invalid_token""#);
        assert!(!body.contains(&t), "token echoed back");
    }

    #[tokio::test]
    async fn mcp_wrong_audience_token_is_401() {
        for aud in ["control-plane", "locksmith-api", "https://gateway.test/mcp"] {
            let t = token(aud, 600, ORG);
            let (resp, body) = post(&app(true), Some(&format!("Bearer {t}")), HOST).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "aud {aud}");
            assert!(challenge(&resp).contains("invalid_token"));
            assert!(!body.contains(&t), "token echoed back");
        }
    }

    #[tokio::test]
    async fn mcp_wrong_org_garbage_and_non_bearer_are_401() {
        let other_org = token(AUDIENCE, 600, Uuid::now_v7());
        for auth in [
            format!("Bearer {other_org}"),
            "Bearer not.a.jwt".to_owned(),
            "Basic dXNlcjpwdw==".to_owned(),
        ] {
            let (resp, _) = post(&app(true), Some(&auth), HOST).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{auth}");
        }
    }

    #[tokio::test]
    async fn mcp_valid_agent_token_reaches_the_service() {
        let t = token(AUDIENCE, 600, ORG);
        let (resp, body) = post(&app(true), Some(&format!("Bearer {t}")), HOST).await;
        assert_eq!(resp.status(), StatusCode::OK, "{body}");
        assert!(body.contains("protocolVersion"), "{body}");
        assert!(!body.contains(&t));
    }

    #[tokio::test]
    async fn mcp_host_allowlist_refuses_other_hostnames() {
        let t = token(AUDIENCE, 600, ORG);
        let (resp, _) = post(&app(true), Some(&format!("Bearer {t}")), "evil.test").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn mcp_unconfigured_fails_closed() {
        let t = token(AUDIENCE, 600, ORG);
        let (resp, _) = post(&app(false), Some(&format!("Bearer {t}")), HOST).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(challenge(&resp), "Bearer");
    }
}
