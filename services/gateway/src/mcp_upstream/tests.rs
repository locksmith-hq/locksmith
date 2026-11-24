//! Task 2.2 of m2-mcp-gateway: the `/mcp/upstream/{name}` gate and the tools-only server
//! handler, driven through the gateway router (`tower` oneshot). The production route keeps the
//! forwarding seam closed (task 2.3), so nothing is forwarded and the relay behind the route has
//! no reachable control plane, KMS or upstream. The hop itself is tested in `hop_tests.rs`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use ls_control_plane::agent_token::{AUDIENCE, AgentClaims, AgentTokenSigner};
use ls_control_plane::readiness::ReadyFlag;
use ls_envelope::{BaoToken, OpenBaoTransit};
use ls_mcp_server::upstream::ToolDecision;
use serde_json::Value;
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::app::{self, AppState};
use crate::audit::MemoryAudit;
use crate::auth::testkit::StubJwks;
use crate::auth::{AgentAuth, JwksSettings};
use crate::config::{Bindings, McpUpstream};
use crate::decrypt::testkit::key;
use crate::decrypt::{CacheSettings, ControlPlane, Decryptor, DekCache};
use crate::egress::testkit::StubResolver;
use crate::grants::Grant;
use crate::grants::testkit::StubGrants;
use crate::mcp_endpoint::McpEndpoint;
use crate::relay::{Relay, RelayOptions};

pub(super) const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000c1);
pub(super) const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000c2);
/// The secret behind the `github` upstream.
const SECRET: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000c3);
/// Another secret the agent may hold a grant on.
const OTHER: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000c4);
pub(super) const HOST: &str = "gateway.test";
pub(super) const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;

pub(super) fn signer() -> AgentTokenSigner {
    AgentTokenSigner::from_seed(Zeroizing::new([9; 32])).unwrap()
}

pub(super) fn token(exp_in: i64) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    signer()
        .sign(&AgentClaims {
            sub: AGENT,
            org: ORG,
            aud: AUDIENCE.to_owned(),
            iat: now,
            exp: now + exp_in,
        })
        .unwrap()
}

pub(super) fn grant(secret_id: Uuid, mode: &str, expires_at: Option<OffsetDateTime>) -> Grant {
    Grant {
        grant_id: Uuid::now_v7(),
        secret_id,
        secret_name: "TEST".to_owned(),
        mode: mode.to_owned(),
        scope: None,
        expires_at,
    }
}

fn upstream(name: &str, secret_id: Uuid) -> McpUpstream {
    McpUpstream {
        name: name.to_owned(),
        url: "https://upstream.test/mcp".to_owned(),
        secret_id,
        header: "Authorization".to_owned(),
        template: "Bearer {secret}".to_owned(),
        default: ToolDecision::Hide,
        allow_private_hosts: false,
        version: 1,
        tools: BTreeMap::new(),
    }
}

struct Harness {
    app: Router,
    grants: Arc<StubGrants>,
}

/// The gateway router with `/mcp` configured and one upstream, `github`, bound to [`SECRET`].
/// The agent's grants start empty. The control plane, KMS and upstream are never reached.
fn harness() -> Harness {
    harness_with(StubGrants::default())
}

/// [`harness`] over the given grant source.
fn harness_with(grants: StubGrants) -> Harness {
    let auth = Arc::new(AgentAuth::new(
        ORG,
        Arc::new(StubJwks::with(vec![signer().jwk().clone()])),
        JwksSettings::default(),
    ));
    let grants = Arc::new(grants);
    let bindings = Bindings {
        org_id: ORG,
        bindings: Vec::new(),
        aws_bindings: Vec::new(),
        pg: Vec::new(),
        git_bindings: Vec::new(),
        mcp_upstreams: vec![upstream("github", SECRET)],
    };
    // Port 9 (discard): nothing here may call the control plane or the KMS.
    let control_plane = ControlPlane::new(
        "http://127.0.0.1:9".parse().unwrap(),
        ORG,
        "s".repeat(32).into(),
    )
    .unwrap();
    let transit =
        OpenBaoTransit::new("http://127.0.0.1:9", key(), BaoToken::new("bao".to_owned())).unwrap();
    let decryptor = Decryptor::new(
        ORG,
        Arc::new(control_plane),
        Arc::new(transit),
        Arc::new(DekCache::new(CacheSettings::default())),
    );
    let relay = Relay::new(
        auth.clone(),
        grants.clone(),
        bindings,
        decryptor,
        Arc::new(StubResolver::default()),
        Arc::new(MemoryAudit::default()),
        RelayOptions::default(),
    );
    let state = AppState::new(Arc::new(ReadyFlag::new(true)))
        .with_relay(Arc::new(relay))
        .with_mcp(McpEndpoint::new(auth, &[HOST.to_owned()]));
    Harness {
        app: app::build(state),
        grants,
    }
}

pub(super) struct Answer {
    pub(super) status: StatusCode,
    pub(super) headers: axum::http::HeaderMap,
    pub(super) text: String,
}

impl Answer {
    /// The JSON-RPC message of an MCP answer (JSON or SSE).
    pub(super) fn message(&self) -> Value {
        self.text
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .find_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
            .or_else(|| serde_json::from_str(&self.text).ok())
            .unwrap_or(Value::Null)
    }

    /// The error body without its per-request id, which differs on every answer.
    fn error_without_request_id(&self) -> Value {
        let mut v: Value = serde_json::from_str(&self.text).expect("JSON error body");
        let id = v
            .as_object_mut()
            .and_then(|o| o.remove("request_id"))
            .expect("request_id");
        assert_eq!(
            self.headers
                .get("x-request-id")
                .and_then(|h| h.to_str().ok()),
            id.as_str()
        );
        v
    }

    pub(super) fn session(&self) -> Option<String> {
        self.headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }
}

pub(super) async fn send(
    app: &Router,
    path: &str,
    authorization: Option<&str>,
    host: &str,
    session: Option<&str>,
    body: &str,
) -> Answer {
    let mut b = Request::post(path)
        .header(header::HOST, host)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream");
    if let Some(a) = authorization {
        b = b.header(header::AUTHORIZATION, a);
    }
    if let Some(s) = session {
        b = b
            .header("mcp-session-id", s)
            .header("mcp-protocol-version", "2025-06-18");
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    Answer {
        status: parts.status,
        headers: parts.headers,
        text: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn initialize(app: &Router, path: &str, token: &str) -> Answer {
    send(
        app,
        path,
        Some(&format!("Bearer {token}")),
        HOST,
        None,
        INITIALIZE,
    )
    .await
}

const GITHUB: &str = "/mcp/upstream/github";

#[tokio::test]
async fn mcp_upstream_unknown_name_is_404() {
    let h = harness();
    h.grants.set(AGENT, vec![grant(SECRET, "relay", None)]);
    let t = token(600);
    for path in [
        "/mcp/upstream/nope",
        "/mcp/upstream/GitHub",
        "/mcp/upstream/github%20",
        "/mcp/upstream/%FF",
    ] {
        let a = initialize(&h.app, path, &t).await;
        assert_eq!(a.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            a.error_without_request_id(),
            serde_json::json!({"error": "not_found"}),
            "{path}"
        );
        assert!(!a.text.contains(&t), "token echoed back");
    }
}

#[tokio::test]
async fn mcp_upstream_without_an_unexpired_relay_grant_answers_like_an_unknown_name() {
    let h = harness();
    let t = token(600);
    let unknown = initialize(&h.app, "/mcp/upstream/nope", &t).await;
    let past = OffsetDateTime::now_utc() - time::Duration::minutes(1);
    let cases: [(&str, Vec<Grant>); 5] = [
        ("no grants", Vec::new()),
        ("grant on another secret", vec![grant(OTHER, "relay", None)]),
        (
            "expired relay grant",
            vec![grant(SECRET, "relay", Some(past))],
        ),
        ("inject grant", vec![grant(SECRET, "inject", None)]),
        ("delegate grant", vec![grant(SECRET, "delegate", None)]),
    ];
    for (what, grants) in cases {
        h.grants.set(AGENT, grants);
        let a = initialize(&h.app, GITHUB, &t).await;
        assert_eq!(a.status, unknown.status, "{what}");
        assert_eq!(
            a.error_without_request_id(),
            unknown.error_without_request_id(),
            "{what}"
        );
        let names = |a: &Answer| {
            let mut n: Vec<String> = a.headers.keys().map(|k| k.to_string()).collect();
            n.sort();
            n
        };
        assert_eq!(names(&a), names(&unknown), "{what}: same headers");
        assert_eq!(
            a.headers.get(header::CONTENT_TYPE),
            unknown.headers.get(header::CONTENT_TYPE)
        );
        assert!(a.session().is_none(), "{what}: no session opened");
    }
}

#[tokio::test]
async fn mcp_upstream_grant_is_checked_on_every_request() {
    let h = harness();
    h.grants.set(AGENT, vec![grant(SECRET, "relay", None)]);
    let t = token(600);
    let a = initialize(&h.app, GITHUB, &t).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.text);
    let sid = a.session().expect("session id");
    // The grant is revoked: the open session is refused like an unknown name.
    h.grants.set(AGENT, Vec::new());
    let a = send(
        &h.app,
        GITHUB,
        Some(&format!("Bearer {t}")),
        HOST,
        Some(&sid),
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    )
    .await;
    assert_eq!(a.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mcp_upstream_grants_unavailable_is_the_same_502_for_every_name() {
    let stub = StubGrants {
        fail: true,
        ..StubGrants::default()
    };
    let h = harness_with(stub);
    let t = token(600);
    for path in [GITHUB, "/mcp/upstream/nope"] {
        let a = initialize(&h.app, path, &t).await;
        assert_eq!(a.status, StatusCode::BAD_GATEWAY, "{path}");
        assert_eq!(
            a.error_without_request_id(),
            serde_json::json!({"error": "grants_unavailable"})
        );
    }
}

#[tokio::test]
async fn mcp_upstream_with_grant_initializes_with_only_the_tools_capability() {
    let h = harness();
    h.grants.set(AGENT, vec![grant(SECRET, "relay", None)]);
    let t = token(600);
    let a = initialize(&h.app, GITHUB, &t).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.text);
    assert!(!a.text.contains(&t), "token echoed back");
    let msg = a.message();
    assert_eq!(msg["result"]["protocolVersion"], "2025-06-18", "{msg}");
    let caps = msg["result"]["capabilities"]
        .as_object()
        .expect("capabilities");
    let keys: Vec<&str> = caps.keys().map(String::as_str).collect();
    assert_eq!(keys, ["tools"], "{msg}");
}

#[tokio::test]
async fn mcp_upstream_without_a_catalogue_lists_nothing_and_refuses_other_methods() {
    let h = harness();
    h.grants.set(AGENT, vec![grant(SECRET, "relay", None)]);
    let t = token(600);
    let auth = format!("Bearer {t}");
    let a = initialize(&h.app, GITHUB, &t).await;
    let sid = a.session().expect("session id");
    let a = send(
        &h.app,
        GITHUB,
        Some(&auth),
        HOST,
        Some(&sid),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    )
    .await;
    assert_eq!(a.status, StatusCode::ACCEPTED);
    let rpc = |body: &'static str| send(&h.app, GITHUB, Some(&auth), HOST, Some(&sid), body);

    let msg = rpc(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
        .await
        .message();
    // The catalogue cannot be read here (no control plane or upstream): a fixed error, no tool.
    assert_eq!(msg["error"]["message"], "upstream_unreachable", "{msg}");
    assert!(msg["result"].is_null(), "{msg}");

    let msg = rpc(
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_issues","arguments":{}}}"#,
    )
    .await
    .message();
    assert_eq!(msg["error"]["message"], "upstream_unreachable", "{msg}");

    for (id, method) in [
        (4, "resources/list"),
        (5, "resources/read"),
        (6, "prompts/list"),
    ] {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{{"uri":"file:///x","name":"x"}}}}"#
        );
        let a = send(&h.app, GITHUB, Some(&auth), HOST, Some(&sid), &body).await;
        let msg = a.message();
        assert_eq!(msg["error"]["code"], -32601, "{method}: {msg}");
    }
}

#[tokio::test]
async fn mcp_upstream_refuses_a_bad_token_like_mcp() {
    let h = harness();
    h.grants.set(AGENT, vec![grant(SECRET, "relay", None)]);
    let expired = token(-600);
    for (path, auth) in [
        (GITHUB, None),
        ("/mcp/upstream/nope", None),
        (GITHUB, Some(format!("Bearer {expired}"))),
        (GITHUB, Some("Bearer not.a.jwt".to_owned())),
        (GITHUB, Some("Basic dXNlcjpwdw==".to_owned())),
    ] {
        let a = send(&h.app, path, auth.as_deref(), HOST, None, INITIALIZE).await;
        let on_mcp = send(&h.app, "/mcp", auth.as_deref(), HOST, None, INITIALIZE).await;
        assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{path} {auth:?}");
        assert_eq!(
            a.headers.get(header::WWW_AUTHENTICATE),
            on_mcp.headers.get(header::WWW_AUTHENTICATE),
            "{path} {auth:?}"
        );
        assert!(!a.text.contains(&expired), "token echoed back");
    }
}

#[tokio::test]
async fn mcp_upstream_host_allowlist_refuses_other_hostnames_like_mcp() {
    let h = harness();
    h.grants.set(AGENT, vec![grant(SECRET, "relay", None)]);
    let auth = format!("Bearer {}", token(600));
    let a = send(&h.app, GITHUB, Some(&auth), "evil.test", None, INITIALIZE).await;
    let on_mcp = send(&h.app, "/mcp", Some(&auth), "evil.test", None, INITIALIZE).await;
    assert_eq!(a.status, StatusCode::FORBIDDEN);
    assert_eq!(on_mcp.status, StatusCode::FORBIDDEN);
    assert!(a.session().is_none());
    // Loopback is allowed as on `/mcp`.
    let a = send(&h.app, GITHUB, Some(&auth), "127.0.0.1", None, INITIALIZE).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.text);
}

#[tokio::test]
async fn mcp_upstream_unconfigured_fails_closed() {
    let app = app::build(AppState::new(Arc::new(ReadyFlag::new(true))));
    let auth = format!("Bearer {}", token(600));
    let a = send(&app, GITHUB, Some(&auth), HOST, None, INITIALIZE).await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        a.headers
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok()),
        Some("Bearer")
    );
}

#[tokio::test]
async fn mcp_upstream_does_not_shadow_mcp() {
    let h = harness();
    let a = initialize(&h.app, "/mcp", &token(600)).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.text);
    let caps = &a.message()["result"]["capabilities"];
    assert!(caps.get("tools").is_some(), "{caps}");
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Under the gateway's filter (`RUST_LOG=trace` plus [`crate::mcp_endpoint::cap_rmcp_logs`])
/// rmcp logs nothing below `info` for `/mcp/upstream/{name}`, so no MCP message is logged whole;
/// without the cap the same exchange does log at `debug` (the capture works).
#[tokio::test]
async fn mcp_upstream_rmcp_logs_are_capped_like_mcp() {
    async fn run(capped: bool) -> String {
        let cap = Capture::default();
        let writer = cap.clone();
        let base = tracing_subscriber::EnvFilter::new("trace,rmcp::service=trace");
        let filter = if capped {
            crate::mcp_endpoint::cap_rmcp_logs(base)
        } else {
            base
        };
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let h = harness();
        h.grants.set(AGENT, vec![grant(SECRET, "relay", None)]);
        let t = token(600);
        let auth = format!("Bearer {t}");
        let a = initialize(&h.app, GITHUB, &t).await;
        assert_eq!(a.status, StatusCode::OK);
        let sid = a.session().expect("session id");
        for body in [
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"x","arguments":{}}}"#,
        ] {
            send(&h.app, GITHUB, Some(&auth), HOST, Some(&sid), body).await;
        }
        let logs = cap.0.lock().unwrap().clone();
        let text = String::from_utf8_lossy(&logs).into_owned();
        assert!(!text.contains(&t), "agent token in the logs");
        text
    }
    let below_info = |text: &str| {
        text.lines()
            .any(|l| (l.contains("DEBUG") || l.contains("TRACE")) && l.contains(" rmcp"))
    };
    // Warm-up: the first scoped subscriber of a test binary can miss events while other tests
    // register the same callsites in parallel.
    run(false).await;
    let uncapped = run(false).await;
    assert!(below_info(&uncapped), "capture saw rmcp debug logs");
    let capped = run(true).await;
    assert!(
        capped.contains("create new session"),
        "capture saw rmcp info logs"
    );
    assert!(!below_info(&capped), "rmcp logged below info");
}

async fn get_upstreams(app: &Router, authorization: Option<&str>) -> (StatusCode, String) {
    let mut b = Request::get("/v1/mcp/upstreams");
    if let Some(a) = authorization {
        b = b.header(header::AUTHORIZATION, a);
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Task 6.1: names of the upstreams with an unexpired relay grant, nothing else.
#[tokio::test]
async fn mcp_upstream_list_names_only_the_granted_upstreams() {
    let h = harness();
    let t = format!("Bearer {}", token(600));

    // No grant: an empty list, not an error.
    let (status, body) = get_upstreams(&h.app, Some(&t)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        serde_json::json!({"upstreams": []})
    );

    // A grant on another secret, a delegate grant and an expired relay grant do not count.
    let past = OffsetDateTime::now_utc() - time::Duration::seconds(1);
    h.grants.set(
        AGENT,
        vec![
            grant(OTHER, "relay", None),
            grant(SECRET, "delegate", None),
            grant(SECRET, "relay", Some(past)),
        ],
    );
    let (_, body) = get_upstreams(&h.app, Some(&t)).await;
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        serde_json::json!({"upstreams": []})
    );

    h.grants.set(AGENT, vec![grant(SECRET, "relay", None)]);
    let (status, body) = get_upstreams(&h.app, Some(&t)).await;
    assert_eq!(status, StatusCode::OK);
    // Names only: no URL, header, template or secret id.
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        serde_json::json!({"upstreams": ["github"]})
    );
    assert!(!body.contains("upstream.test") && !body.contains(&SECRET.to_string()));
}

#[tokio::test]
async fn mcp_upstream_list_needs_an_agent_token() {
    let h = harness();
    h.grants.set(AGENT, vec![grant(SECRET, "relay", None)]);
    let (status, body) = get_upstreams(&h.app, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!body.contains("github"));
    let (status, _) = get_upstreams(&h.app, Some("Bearer not-a-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mcp_upstream_list_fails_closed_when_grants_cannot_be_read() {
    let h = harness_with(StubGrants {
        fail: true,
        ..StubGrants::default()
    });
    let t = format!("Bearer {}", token(600));
    let (status, body) = get_upstreams(&h.app, Some(&t)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(!body.contains("github"));
}
