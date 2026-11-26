//! Task 2.3 of m2-mcp-gateway: the upstream hop against a real MCP upstream, an rmcp
//! Streamable HTTP server on a loopback port whose every HTTP request (method, headers, JSON-RPC
//! body) is recorded. The secret is sealed as the control plane stores it and opened through the
//! real `Decryptor` (stand-in material source and KMS from `decrypt::testkit`).

use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use http_body_util::BodyExt as _;
use ls_control_plane::readiness::ReadyFlag;
use ls_mcp_server::upstream::ToolDecision;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, CustomRequest,
    ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig,
    ServerRequest, Tool,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, ServiceError};
use serde_json::Value;
use uuid::Uuid;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::app::AppState;
use crate::audit::MemoryAudit;
use crate::auth::testkit::StubJwks;
use crate::auth::{AgentAuth, JwksSettings};
use crate::config::Bindings;
use crate::decrypt::testkit::{FakeKms, FakeMaterial, seal};
use crate::decrypt::{CacheSettings, DekCache};
use crate::egress::testkit::StubResolver;
use crate::grants::testkit::StubGrants;
use crate::mcp_endpoint::McpEndpoint;
use crate::mcp_upstream::tests::{
    AGENT, HOST, INITIALIZE, ORG, grant, signer, token as agent_token,
};
use crate::relay::{Relay, RelayOptions};

const SECRET: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000d3);
/// The upstream credential (a test value, never a real one).
const VALUE: &str = "up-cred-0123456789abcdef-canary";
/// A header the agent sends that must never reach the upstream.
const AGENT_HEADER: &str = "x-agent-canary";
const AGENT_HEADER_VALUE: &str = "agent-supplied-0123456789";

/// One HTTP request the upstream received.
#[derive(Clone, Debug)]
struct Hit {
    method: Method,
    headers: HeaderMap,
    body: Option<Value>,
}

impl Hit {
    /// The JSON-RPC method of a request body, if any.
    fn rpc(&self) -> Option<&str> {
        self.body.as_ref()?.get("method")?.as_str()
    }
}

#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<Hit>>>);

impl Seen {
    fn hits(&self) -> Vec<Hit> {
        self.0.lock().unwrap().clone()
    }

    fn rpcs(&self) -> Vec<String> {
        self.hits()
            .iter()
            .filter_map(|h| h.rpc().map(str::to_owned))
            .collect()
    }
}

async fn record(State(seen): State<Seen>, req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    seen.0.lock().unwrap().push(Hit {
        method: parts.method.clone(),
        headers: parts.headers.clone(),
        body: serde_json::from_slice(&bytes).ok(),
    });
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

/// The upstream MCP server: one tool, `echo`; `ask` sends the client a sampling, a roots and an
/// elicitation request and reports the JSON-RPC error code each one got.
#[derive(Clone)]
struct FakeUpstream;

impl ServerHandler for FakeUpstream {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
    }

    // Server-to-client requests exist up to 2025-11-25; stay on a revision that has them.
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(ProtocolVersion::known_up_to(&ProtocolVersion::V_2025_06_18))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let schema = serde_json::json!({"type": "object"});
        let schema = schema.as_object().unwrap().clone();
        Ok(ListToolsResult::with_all_items(vec![Tool::new(
            "echo", "echoes", schema,
        )]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        if request.name == "reflect" {
            let auth = context
                .extensions
                .get::<axum::http::request::Parts>()
                .and_then(|p| p.headers.get("authorization"))
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&auth);
            let mut r = CallToolResult::success(vec![ContentBlock::text(format!("raw {auth}"))]);
            r.structured_content = Some(serde_json::json!({"got": auth, "b64": b64}));
            return Ok(r.into());
        }
        if request.name != "ask" {
            return Ok(CallToolResult::success(vec![ContentBlock::text("echoed")]).into());
        }
        let asks = [
            (
                "sampling/createMessage",
                Some(serde_json::json!({
                    "messages": [{"role": "user", "content": {"type": "text", "text": "hi"}}],
                    "maxTokens": 5
                })),
            ),
            ("roots/list", None),
            (
                "elicitation/create",
                Some(serde_json::json!({
                    "message": "give me something",
                    "requestedSchema": {"type": "object", "properties": {}}
                })),
            ),
        ];
        let mut out = Vec::new();
        for (method, params) in asks {
            let r = context
                .peer
                .send_request(ServerRequest::CustomRequest(CustomRequest::new(
                    method, params,
                )))
                .await;
            let got = match r {
                Err(ServiceError::McpError(e)) => e.code.0.to_string(),
                Err(_) => "transport".to_owned(),
                Ok(_) => "answered".to_owned(),
            };
            out.push(format!("{method}={got}"));
        }
        Ok(CallToolResult::success(vec![ContentBlock::text(out.join(" "))]).into())
    }
}

/// A running upstream: its `/mcp` URL and what it saw.
struct Upstream {
    url: String,
    seen: Seen,
}

async fn upstream() -> Upstream {
    let seen = Seen::default();
    let service = StreamableHttpService::new(
        || Ok(FakeUpstream),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let app = Router::new()
        .route_service("/mcp", service)
        .layer(middleware::from_fn_with_state(seen.clone(), record));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Upstream {
        url: format!("http://{addr}/mcp"),
        seen,
    }
}

fn binding(url: &str, header: &str, template: &str, allow_private: bool) -> McpUpstream {
    McpUpstream {
        name: "github".to_owned(),
        url: url.to_owned(),
        secret_id: SECRET,
        header: header.to_owned(),
        template: template.to_owned(),
        default: ToolDecision::Hide,
        allow_private_hosts: allow_private,
        version: 1,
        tools: Default::default(),
    }
}

/// The decrypt path over [`VALUE`] sealed for [`SECRET`] v1, plus its fetch counter.
fn decryptor() -> (Decryptor, Arc<FakeMaterial>) {
    let sealed = seal(ORG, SECRET, 1, VALUE.as_bytes());
    let dek = sealed.dek;
    let material = Arc::new(FakeMaterial {
        sealed,
        secret: SECRET,
        version: 1,
        fetches: AtomicUsize::new(0),
    });
    let kms = Arc::new(FakeKms {
        dek: Some(dek),
        calls: AtomicUsize::new(0),
    });
    let d = Decryptor::new(
        ORG,
        material.clone(),
        kms,
        Arc::new(DekCache::new(CacheSettings::default())),
    );
    (d, material)
}

const ME: AgentIdentity = AgentIdentity {
    agent_id: AGENT,
    org_id: ORG,
};

struct Kit {
    decryptor: Decryptor,
    material: Arc<FakeMaterial>,
    resolver: StubResolver,
}

impl Kit {
    fn new() -> Self {
        Self::with_resolver(StubResolver::default())
    }

    fn with_resolver(resolver: StubResolver) -> Self {
        let (decryptor, material) = decryptor();
        Self {
            decryptor,
            material,
            resolver,
        }
    }

    fn deps(&self) -> HopDeps<'_> {
        HopDeps {
            relay: None,
            decryptor: &self.decryptor,
            resolver: &self.resolver,
            connect_timeout: Duration::from_secs(5),
        }
    }

    fn fetches(&self) -> usize {
        self.material.fetches.load(Ordering::SeqCst)
    }
}

fn text(r: &CallToolResult) -> String {
    serde_json::to_value(&r.content).unwrap().to_string()
}

/// Every request of the exchange carries exactly the templated header.
fn assert_every_hit_has(seen: &Seen, header: &str, expected: &str) {
    let hits = seen.hits();
    assert!(!hits.is_empty(), "the upstream saw nothing");
    for h in &hits {
        let values: Vec<&[u8]> = h
            .headers
            .get_all(header)
            .iter()
            .map(|v| v.as_bytes())
            .collect();
        assert_eq!(
            values,
            [expected.as_bytes()],
            "{} {:?}: {header}",
            h.method,
            h.rpc()
        );
    }
}

#[tokio::test]
async fn hop_lists_and_calls_with_the_bearer_credential_on_every_upstream_request() {
    let up = upstream().await;
    let kit = Kit::new();
    let b = binding(&up.url, "Authorization", "Bearer {secret}", true);

    let tools = list_tools(&kit.deps(), &b, ME, None).await.expect("tools");
    let names: Vec<&str> = tools.tools.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names, ["echo"]);
    let r = call_tool(&kit.deps(), &b, ME, CallToolRequestParams::new("echo"))
        .await
        .expect("call");
    assert!(text(&r).contains("echoed"), "{}", text(&r));

    assert_every_hit_has(&up.seen, "authorization", &format!("Bearer {VALUE}"));
    let rpcs = up.seen.rpcs();
    assert!(rpcs.contains(&"initialize".to_owned()), "{rpcs:?}");
    assert!(rpcs.contains(&"tools/list".to_owned()), "{rpcs:?}");
    assert!(rpcs.contains(&"tools/call".to_owned()), "{rpcs:?}");
    // Per request: fetched and unwrapped for each exchange, nothing kept between them.
    assert_eq!(kit.fetches(), 2);
}

#[tokio::test]
async fn hop_injects_a_non_bearer_authorization_and_custom_headers_as_templated() {
    for (header, template, expected) in [
        ("Authorization", "token {secret}", format!("token {VALUE}")),
        ("X-Api-Key", "{secret}", VALUE.to_owned()),
        ("X-Api-Key", "k={secret};", format!("k={VALUE};")),
    ] {
        let up = upstream().await;
        let kit = Kit::new();
        let b = binding(&up.url, header, template, true);
        list_tools(&kit.deps(), &b, ME, None)
            .await
            .unwrap_or_else(|e| panic!("{header} {template}: {e:?}"));
        assert_every_hit_has(&up.seen, header, &expected);
        if !header.eq_ignore_ascii_case("authorization") {
            assert!(
                up.seen
                    .hits()
                    .iter()
                    .all(|h| h.headers.get("authorization").is_none()),
                "no Authorization besides the binding's header"
            );
        }
    }
}

#[tokio::test]
async fn hop_ping_is_forwarded() {
    let up = upstream().await;
    let kit = Kit::new();
    let b = binding(&up.url, "Authorization", "Bearer {secret}", true);
    let a = forward(&kit.deps(), &b, ME, Forward::Ping)
        .await
        .expect("pong");
    assert!(matches!(a, Answer::Pong));
    assert!(up.seen.rpcs().contains(&"ping".to_owned()));
}

#[tokio::test]
async fn hop_refuses_upstream_sampling_roots_and_elicitation() {
    let up = upstream().await;
    let kit = Kit::new();
    let b = binding(&up.url, "Authorization", "Bearer {secret}", true);
    let r = call_tool(&kit.deps(), &b, ME, CallToolRequestParams::new("ask"))
        .await
        .expect("call");
    // -32601: method not found, answered by the gateway's client, so none was served.
    let t = text(&r);
    for m in ["sampling/createMessage", "roots/list", "elicitation/create"] {
        assert!(t.contains(&format!("{m}=-32601")), "{m}: {t}");
    }
    // The gateway advertised no client capability to the upstream.
    let init = up
        .seen
        .hits()
        .into_iter()
        .find(|h| h.rpc() == Some("initialize"))
        .expect("initialize");
    let caps = &init.body.unwrap()["params"]["capabilities"];
    assert!(
        caps.as_object().is_none_or(|o| o.is_empty()),
        "client capabilities: {caps}"
    );
}

#[tokio::test]
async fn hop_refuses_private_and_metadata_addresses_before_the_secret_is_touched() {
    let up = upstream().await;
    // Loopback without allow_private_hosts: a live server is there, and is not called.
    let kit = Kit::new();
    let b = binding(&up.url, "Authorization", "Bearer {secret}", false);
    let e = list_tools(&kit.deps(), &b, ME, None).await.unwrap_err();
    assert_eq!(e, HopError::DeniedAddress);
    assert_eq!(e.slug(), "denied_address");
    assert_eq!(kit.fetches(), 0, "no material fetched");
    assert!(up.seen.hits().is_empty(), "upstream not called");

    // A name resolving to private or metadata addresses (metadata even with allow_private_hosts).
    for (ip, allow_private) in [
        ("10.0.0.7", false),
        ("169.254.169.254", true),
        ("fd00:ec2::254", true),
    ] {
        let ip: IpAddr = ip.parse().unwrap();
        let kit = Kit::with_resolver(StubResolver::with(&[("upstream.test", ip)]));
        let b = binding(
            "https://upstream.test/mcp",
            "Authorization",
            "Bearer {secret}",
            allow_private,
        );
        let e = list_tools(&kit.deps(), &b, ME, None).await.unwrap_err();
        assert_eq!(e, HopError::DeniedAddress, "{ip}");
        assert_eq!(kit.fetches(), 0, "{ip}: no material fetched");
    }
}

#[tokio::test]
async fn hop_does_not_follow_a_redirect() {
    let target = upstream().await;
    let redirector = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(307).insert_header("location", target.url.as_str()))
        .mount(&redirector)
        .await;
    let kit = Kit::new();
    let b = binding(
        &format!("{}/mcp", redirector.uri()),
        "Authorization",
        "Bearer {secret}",
        true,
    );
    let e = list_tools(&kit.deps(), &b, ME, None).await.unwrap_err();
    assert_eq!(e, HopError::Upstream);
    assert!(target.seen.hits().is_empty(), "redirect followed");
    assert!(!redirector.received_requests().await.unwrap().is_empty());
}

/// Through the router with `echo` allowed: the agent's `Authorization` and its other
/// headers never reach the upstream; only the four methods cross.
#[tokio::test]
async fn hop_through_the_route_forwards_no_agent_header_and_no_other_method() {
    let up = upstream().await;
    let (decryptor, _material) = decryptor();
    let auth = Arc::new(AgentAuth::new(
        ORG,
        Arc::new(StubJwks::with(vec![signer().jwk().clone()])),
        JwksSettings::default(),
    ));
    let grants = Arc::new(StubGrants::default());
    grants.set(AGENT, vec![grant(SECRET, "relay", None)]);
    let bindings = Bindings {
        org_id: ORG,
        bindings: Vec::new(),
        aws_bindings: Vec::new(),
        pg: Vec::new(),
        git_bindings: Vec::new(),
        mcp_upstreams: vec![{
            let mut b = binding(&up.url, "Authorization", "Bearer {secret}", true);
            b.tools.insert("echo".to_owned(), ToolDecision::Allow);
            b
        }],
    };
    let policy = Arc::new(crate::mcp_upstream::policy::StaticToolPolicy::new(
        &bindings.mcp_upstreams,
    ));
    let relay = Relay::new(
        auth.clone(),
        grants,
        bindings,
        decryptor,
        Arc::new(StubResolver::default()),
        Arc::new(MemoryAudit::default()),
        RelayOptions::default(),
    );
    let state = AppState::new(Arc::new(ReadyFlag::new(true)))
        .with_relay(Arc::new(relay))
        .with_mcp(McpEndpoint::new(auth, &[HOST.to_owned()]))
        .with_tool_policy(policy);
    let app = Router::new()
        .route(
            crate::mcp_upstream::PATH,
            crate::mcp_upstream::route(&state),
        )
        .with_state(state);

    let t = agent_token(600);
    let bearer = format!("Bearer {t}");
    let call = |session: Option<String>, body: String| {
        let app = app.clone();
        let bearer = bearer.clone();
        async move {
            let mut b = axum::http::Request::post("/mcp/upstream/github")
                .header("host", HOST)
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("authorization", bearer)
                .header(AGENT_HEADER, AGENT_HEADER_VALUE)
                .header("cookie", format!("c={AGENT_HEADER_VALUE}"));
            if let Some(s) = session {
                b = b
                    .header("mcp-session-id", s)
                    .header("mcp-protocol-version", "2025-06-18");
            }
            use tower::ServiceExt as _;
            let resp = app
                .oneshot(b.body(Body::from(body)).unwrap())
                .await
                .unwrap();
            let (parts, body) = resp.into_parts();
            let bytes = body.collect().await.unwrap().to_bytes();
            (parts, String::from_utf8_lossy(&bytes).into_owned())
        }
    };
    let message = |text: &str| -> Value {
        text.lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .find_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
            .or_else(|| serde_json::from_str(text).ok())
            .unwrap_or(Value::Null)
    };

    let (parts, _) = call(None, INITIALIZE.to_owned()).await;
    assert_eq!(parts.status, StatusCode::OK);
    let sid = parts
        .headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .expect("session");
    let (parts, _) = call(
        Some(sid.clone()),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_owned(),
    )
    .await;
    assert_eq!(parts.status, StatusCode::ACCEPTED);
    // Answered by the gateway's own server, never forwarded.
    assert!(up.seen.hits().is_empty(), "initialize is answered locally");

    let (_, body) = call(
        Some(sid.clone()),
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#.to_owned(),
    )
    .await;
    let msg = message(&body);
    assert_eq!(msg["result"]["tools"][0]["name"], "echo", "{msg}");
    let (_, body) = call(
        Some(sid.clone()),
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#
            .to_owned(),
    )
    .await;
    let msg = message(&body);
    assert!(msg["result"].to_string().contains("echoed"), "{msg}");
    let forwarded = up.seen.hits().len();

    for (id, method) in [
        (4, "resources/list"),
        (5, "resources/read"),
        (6, "prompts/list"),
        (7, "completion/complete"),
        (8, "logging/setLevel"),
    ] {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{{"uri":"file:///x","level":"debug"}}}}"#
        );
        let (_, text) = call(Some(sid.clone()), body).await;
        let msg = message(&text);
        assert_eq!(msg["error"]["code"], -32601, "{method}: {msg}");
    }
    assert_eq!(
        up.seen.hits().len(),
        forwarded,
        "an unknown method reached the upstream"
    );

    let rpcs = up.seen.rpcs();
    for m in &rpcs {
        assert!(
            [
                "initialize",
                "notifications/initialized",
                "tools/list",
                "tools/call"
            ]
            .contains(&m.as_str()),
            "{m} forwarded"
        );
    }
    assert_every_hit_has(&up.seen, "authorization", &format!("Bearer {VALUE}"));
    let hits = up.seen.hits();
    assert!(hits.len() >= 4, "{rpcs:?}");
    for h in &hits {
        assert!(
            h.headers.get(AGENT_HEADER).is_none(),
            "agent header forwarded"
        );
        assert!(h.headers.get("cookie").is_none(), "agent cookie forwarded");
        for (name, v) in &h.headers {
            let v = String::from_utf8_lossy(v.as_bytes());
            assert!(!v.contains(&t), "agent token in upstream header {name}");
            assert!(
                !v.contains(AGENT_HEADER_VALUE),
                "agent header value in upstream header {name}"
            );
        }
        let body = h.body.as_ref().map(Value::to_string).unwrap_or_default();
        assert!(!body.contains(&t), "agent token in the upstream body");
    }
}

/// A forwarded answer built around `VALUE` in several places and encodings.
fn reflected() -> CallToolResult {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(VALUE);
    let mut r = CallToolResult::success(vec![ContentBlock::text(format!("raw {VALUE} end"))]);
    r.structured_content =
        Some(serde_json::json!({"got": VALUE, "b64": b64, "esc": VALUE.replace('-', "\\u002d")}));
    r
}

fn redactor() -> Redactor {
    Redactor::new(&[Secret::new(crate::relay::REDACTION_LABEL, VALUE.as_bytes())])
}

#[test]
fn redact_scrubs_results_descriptions_and_schemas() {
    let r = redactor();
    let Answer::Call(c) = redact(&r, Answer::Call(reflected())).unwrap() else {
        panic!()
    };
    let out = serde_json::to_string(&c).unwrap();
    assert!(r.find(out.as_bytes()).is_empty(), "{out}");
    assert!(!out.contains(VALUE), "{out}");
    assert!(out.contains("[REDACTED:SECRET]"), "{out}");

    let schema = serde_json::json!({"type": "object", "description": VALUE});
    let tool = Tool::new(
        format!("t-{VALUE}"),
        format!("see {VALUE}"),
        schema.as_object().unwrap().clone(),
    );
    let Answer::Tools(t) = redact(
        &r,
        Answer::Tools(ListToolsResult::with_all_items(vec![tool])),
    )
    .unwrap() else {
        panic!()
    };
    let out = serde_json::to_string(&t).unwrap();
    assert!(r.find(out.as_bytes()).is_empty(), "{out}");
    assert!(!out.contains(VALUE), "{out}");
}

#[test]
fn redact_withholds_an_oversized_message() {
    let big = "x".repeat(MAX_MESSAGE + 1);
    let c = CallToolResult::success(vec![ContentBlock::text(big)]);
    assert_eq!(
        redact(&redactor(), Answer::Call(c)).unwrap_err(),
        HopError::RedactionFailed
    );
    assert_eq!(HopError::RedactionFailed.slug(), "redaction_failed");
}

#[tokio::test]
async fn hop_redacts_what_the_upstream_reflects() {
    let up = upstream().await;
    let kit = Kit::new();
    let b = binding(&up.url, "Authorization", "Bearer {secret}", true);
    let r = call_tool(&kit.deps(), &b, ME, CallToolRequestParams::new("reflect"))
        .await
        .expect("call");
    let out = serde_json::to_string(&r).unwrap();
    assert!(!out.contains(VALUE), "{out}");
    assert!(redactor().find(out.as_bytes()).is_empty(), "{out}");
    assert!(out.contains("[REDACTED:SECRET]"), "{out}");
    // The upstream really received it: the reflection above is not vacuous.
    assert_every_hit_has(&up.seen, "authorization", &format!("Bearer {VALUE}"));
}

#[tokio::test]
async fn hop_refuses_a_credential_too_short_to_scan_for() {
    let up = upstream().await;
    let sealed = seal(ORG, SECRET, 1, b"short");
    let dek = sealed.dek;
    let material = Arc::new(FakeMaterial {
        sealed,
        secret: SECRET,
        version: 1,
        fetches: AtomicUsize::new(0),
    });
    let kms = Arc::new(FakeKms {
        dek: Some(dek),
        calls: AtomicUsize::new(0),
    });
    let d = Decryptor::new(
        ORG,
        material,
        kms,
        Arc::new(DekCache::new(CacheSettings::default())),
    );
    let resolver = StubResolver::default();
    let deps = HopDeps {
        relay: None,
        decryptor: &d,
        resolver: &resolver,
        connect_timeout: Duration::from_secs(5),
    };
    let b = binding(&up.url, "Authorization", "Bearer {secret}", true);
    let e = list_tools(&deps, &b, ME, None).await.unwrap_err();
    assert_eq!(e, HopError::RedactionFailed);
    assert!(up.seen.hits().is_empty(), "nothing was sent upstream");
}
