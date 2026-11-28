//! Tasks 3.1-3.4 of m2-mcp-gateway: the static policy as a table, then the catalogue and the four
//! decisions through the router against a real rmcp upstream on a loopback port (the secret is
//! sealed as the control plane stores it and opened through the real `Decryptor`).

use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use ls_control_plane::readiness::ReadyFlag;
use ls_mcp_server::upstream::{
    CatalogueEntry, PolicyError, ToolDecision, ToolQuery, valid_tool_name,
};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use serde_json::{Value, json};
use uuid::Uuid;

use super::*;
use crate::app::AppState;
use crate::audit::{AuditSink, MemoryAudit};
use crate::auth::testkit::StubJwks;
use crate::auth::{AgentAuth, JwksSettings};
use crate::config::{Bindings, McpUpstream};
use crate::decrypt::testkit::{FakeKms, FakeMaterial, seal};
use crate::decrypt::{CacheSettings, Decryptor, DekCache};
use crate::egress::testkit::StubResolver;
use crate::grants::testkit::StubGrants;
use crate::mcp_endpoint::McpEndpoint;
use crate::mcp_upstream::tests::{AGENT, HOST, INITIALIZE, ORG, grant, send, signer, token};
use crate::mcp_upstream::{PATH, route_with_ttl_for_tests};
use crate::relay::{Relay, RelayOptions};
use crate::ttl::MAX_CACHE_TTL;

// ---------------------------------------------------------------------------------------------
// The policy as a table (no network).

fn upstream_binding(
    name: &str,
    default: ToolDecision,
    rules: &[(&str, ToolDecision)],
) -> McpUpstream {
    McpUpstream {
        name: name.to_owned(),
        url: "https://upstream.test/mcp".to_owned(),
        secret_id: Uuid::nil(),
        header: "Authorization".to_owned(),
        template: "Bearer {secret}".to_owned(),
        default,
        allow_private_hosts: false,
        version: 1,
        tools: rules.iter().map(|(n, d)| ((*n).to_owned(), *d)).collect(),
    }
}

fn query(upstream: &str, names: &[&str]) -> ToolQuery {
    ToolQuery {
        org: ORG.to_string(),
        agent: AGENT.to_string(),
        upstream: upstream.to_owned(),
        catalogue: names
            .iter()
            .map(|n| CatalogueEntry {
                name: (*n).to_owned(),
                read_only_hint: None,
                destructive_hint: None,
            })
            .collect(),
    }
}

async fn decide(
    p: &StaticToolPolicy,
    q: &ToolQuery,
) -> Result<Vec<(String, ToolDecision)>, PolicyError> {
    let mut v: Vec<_> = p.decide(q).await?.into_iter().collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(v)
}

#[tokio::test]
async fn policy_decides_the_four_decisions_from_the_table() {
    use ToolDecision::{Allow, Deny, Hide, Hold};
    let p = StaticToolPolicy::new(&[upstream_binding(
        "github",
        Hide,
        &[
            ("list_issues", Allow),
            ("create_issue", Hold),
            ("delete_repository", Deny),
            ("secret_admin", Hide),
        ],
    )]);
    let q = query(
        "github",
        &[
            "list_issues",
            "create_issue",
            "delete_repository",
            "secret_admin",
        ],
    );
    let got = decide(&p, &q).await.unwrap();
    assert_eq!(
        got,
        [
            ("create_issue".to_owned(), Hold),
            ("delete_repository".to_owned(), Deny),
            ("list_issues".to_owned(), Allow),
            ("secret_admin".to_owned(), Hide),
        ]
    );
}

#[tokio::test]
async fn policy_default_applies_to_unnamed_tools() {
    use ToolDecision::{Allow, Deny, Hide, Hold};
    for (default, expected) in [(Hide, Hide), (Deny, Deny), (Hold, Hold), (Allow, Allow)] {
        let p = StaticToolPolicy::new(&[upstream_binding("a", default, &[("named", Allow)])]);
        let got = decide(&p, &query("a", &["named", "other"])).await.unwrap();
        assert_eq!(
            got,
            [("named".to_owned(), Allow), ("other".to_owned(), expected)],
            "default {default:?}"
        );
    }
}

#[tokio::test]
async fn policy_matches_names_exactly() {
    use ToolDecision::{Allow, Hide};
    let p = StaticToolPolicy::new(&[upstream_binding("a", Hide, &[("list_issues", Allow)])]);
    // Case variants, a Cyrillic look-alike, a zero-width suffix, whitespace and a prefix are
    // other names: they take the default, never the rule of the name they resemble.
    let names = [
        "list_issues",
        "List_Issues",
        "LIST_ISSUES",
        "list_\u{456}ssues",
        "list_issues\u{200b}",
        " list_issues",
        "list_issues ",
        "list_issue",
        "list-issues",
    ];
    let got = decide(&p, &query("a", &names)).await.unwrap();
    for (name, d) in got {
        let want = if name == "list_issues" { Allow } else { Hide };
        assert_eq!(d, want, "{name:?}");
    }
}

#[tokio::test]
async fn policy_ignores_a_rule_for_a_tool_the_upstream_does_not_offer() {
    use ToolDecision::{Allow, Hide};
    let p = StaticToolPolicy::new(&[upstream_binding(
        "a",
        Hide,
        &[("list_issues", Allow), ("ghost_tool", Allow)],
    )]);
    let got = decide(&p, &query("a", &["list_issues"])).await.unwrap();
    assert_eq!(got, [("list_issues".to_owned(), Allow)]);
    let got = decide(&p, &query("a", &[])).await.unwrap();
    assert!(got.is_empty());
}

#[tokio::test]
async fn policy_is_per_upstream_and_fails_closed_for_an_unknown_one() {
    use ToolDecision::{Allow, Deny};
    let p = StaticToolPolicy::new(&[
        upstream_binding("a", Deny, &[("t", Allow)]),
        upstream_binding("b", Allow, &[("t", Deny)]),
    ]);
    assert_eq!(
        decide(&p, &query("a", &["t"])).await.unwrap(),
        [("t".to_owned(), Allow)]
    );
    assert_eq!(
        decide(&p, &query("b", &["t"])).await.unwrap(),
        [("t".to_owned(), Deny)]
    );
    let e = decide(&p, &query("c", &["t"])).await.unwrap_err();
    assert_eq!(e.code, "unknown_upstream");
    let e = decide(&StaticToolPolicy::default(), &query("a", &["t"]))
        .await
        .unwrap_err();
    assert_eq!(e.code, "unknown_upstream");
}

#[test]
fn catalogue_drops_invalid_and_repeated_names() {
    let schema = json!({"type": "object"}).as_object().unwrap().clone();
    let tool = |n: &'static str| Tool::new(n, "d", schema.clone());
    let c = crate::mcp_upstream::catalogue::Catalogue::from_tools(vec![
        tool("ok"),
        tool("has space"),
        tool(""),
        tool("caf\u{e9}"),
        tool("ok"),
        tool("also.ok-1"),
    ]);
    let names: Vec<&str> = c.tools().iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names, ["ok", "also.ok-1"]);
    assert!(names.iter().all(|n| valid_tool_name(n)));
    assert!(c.contains("ok") && !c.contains("OK") && !c.contains("has space"));
}

// ---------------------------------------------------------------------------------------------
// Through the router.

pub(in crate::mcp_upstream) const SECRET: Uuid =
    Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000e1);
/// The upstream credential (a test value, never a real one).
pub(in crate::mcp_upstream) const VALUE: &str = "up-cred-0123456789abcdef-canary";

/// Text in every call result, for tests that look for it elsewhere.
pub(in crate::mcp_upstream) const RESULT_CANARY: &str = "result-canary-5b1d7e";

/// What the upstream saw and how it behaves.
#[derive(Default)]
pub(in crate::mcp_upstream) struct Probe {
    pub(in crate::mcp_upstream) lists: AtomicUsize,
    calls: Mutex<Vec<String>>,
    pub(in crate::mcp_upstream) fail_list: AtomicBool,
    /// Every `tools/call` is answered with a JSON-RPC error.
    pub(in crate::mcp_upstream) fail_call: AtomicBool,
}

impl Probe {
    pub(in crate::mcp_upstream) fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

/// The upstream MCP server: the catalogue below, with the credential in one description.
#[derive(Clone)]
struct FakeUpstream(Arc<Probe>);

fn catalogue_tools() -> Vec<Tool> {
    let schema = json!({"type": "object"}).as_object().unwrap().clone();
    let t = |n: &str, d: String| Tool::new(n.to_owned(), d, schema.clone());
    vec![
        t("list_issues", format!("lists issues; token {VALUE}")),
        t("create_issue", "creates one".to_owned()),
        t("delete_repository", "deletes".to_owned()),
        t("secret_admin", "hidden by the table".to_owned()),
        t("unlisted_tool", "takes the default".to_owned()),
        t("bad name", "invalid name".to_owned()),
    ]
}

impl ServerHandler for FakeUpstream {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(ProtocolVersion::known_up_to(&ProtocolVersion::V_2025_06_18))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        self.0.lists.fetch_add(1, Ordering::SeqCst);
        if self.0.fail_list.load(Ordering::SeqCst) {
            return Err(McpError::internal_error("boom", None));
        }
        Ok(ListToolsResult::with_all_items(catalogue_tools()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        self.0.calls.lock().unwrap().push(request.name.to_string());
        if self.0.fail_call.load(Ordering::SeqCst) {
            return Err(McpError::internal_error("boom", None));
        }
        Ok(
            CallToolResult::success(vec![ContentBlock::text(format!("called {RESULT_CANARY}"))])
                .into(),
        )
    }
}

fn decryptor() -> Decryptor {
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
    Decryptor::new(
        ORG,
        material,
        kms,
        Arc::new(DekCache::new(CacheSettings::default())),
    )
}

/// The gateway router over a live upstream, with an agent session already initialized.
pub(in crate::mcp_upstream) struct Rig {
    app: Router,
    pub(in crate::mcp_upstream) probe: Arc<Probe>,
    auth: String,
    sid: String,
}

impl Rig {
    async fn new(ttl: Duration) -> Self {
        Self::build(
            ttl,
            Arc::new(MemoryAudit::default()),
            RelayOptions::default(),
        )
        .await
    }

    /// [`Rig::new`] with the relay's audit sink and options chosen by the test.
    pub(in crate::mcp_upstream) async fn build(
        ttl: Duration,
        audit: Arc<dyn AuditSink>,
        options: RelayOptions,
    ) -> Self {
        Self::build_budgeted(ttl, audit, options, None).await
    }

    /// [`Rig::build`] with a budget on the agent's grant for the upstream's secret.
    pub(in crate::mcp_upstream) async fn build_budgeted(
        ttl: Duration,
        audit: Arc<dyn AuditSink>,
        options: RelayOptions,
        budget: Option<crate::grants::Budget>,
    ) -> Self {
        use ToolDecision::{Allow, Deny, Hide, Hold};
        let probe = Arc::new(Probe::default());
        let fake = FakeUpstream(probe.clone());
        let service = StreamableHttpService::new(
            move || Ok(fake.clone()),
            Arc::new(LocalSessionManager::default()),
            StreamableHttpServerConfig::default().with_legacy_session_mode(true),
        );
        let up_app = Router::new().route_service("/mcp", service);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, up_app).await.unwrap() });

        let mut binding = upstream_binding(
            "github",
            Hide,
            &[
                ("list_issues", Allow),
                ("create_issue", Hold),
                ("delete_repository", Deny),
                ("secret_admin", Hide),
                ("ghost_tool", Allow),
            ],
        );
        binding.url = format!("http://{addr}/mcp");
        binding.secret_id = SECRET;
        binding.allow_private_hosts = true;
        let auth = Arc::new(AgentAuth::new(
            ORG,
            Arc::new(StubJwks::with(vec![signer().jwk().clone()])),
            JwksSettings::default(),
        ));
        let grants = Arc::new(StubGrants::default());
        let mut g = grant(SECRET, "relay", None);
        g.budget = budget;
        grants.set(AGENT, vec![g]);
        let bindings = Bindings {
            org_id: ORG,
            bindings: Vec::new(),
            aws_bindings: Vec::new(),
            pg: Vec::new(),
            git_bindings: Vec::new(),
            mcp_upstreams: vec![binding],
        };
        let policy = Arc::new(StaticToolPolicy::new(&bindings.mcp_upstreams));
        let relay = Relay::new(
            auth.clone(),
            grants,
            bindings,
            decryptor(),
            Arc::new(StubResolver::default()),
            audit,
            options,
        );
        let state = AppState::new(Arc::new(ReadyFlag::new(true)))
            .with_relay(Arc::new(relay))
            .with_mcp(McpEndpoint::new(auth, &[HOST.to_owned()]))
            .with_tool_policy(policy);
        let app = Router::new()
            .route(PATH, route_with_ttl_for_tests(&state, ttl))
            .with_state(state);
        let auth = format!("Bearer {}", token(600));
        let a = send(
            &app,
            "/mcp/upstream/github",
            Some(&auth),
            HOST,
            None,
            INITIALIZE,
        )
        .await;
        let sid = a.session().expect("session");
        let a = send(
            &app,
            "/mcp/upstream/github",
            Some(&auth),
            HOST,
            Some(&sid),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        )
        .await;
        assert_eq!(a.status, StatusCode::ACCEPTED);
        Self {
            app,
            probe,
            auth,
            sid,
        }
    }

    pub(in crate::mcp_upstream) async fn rpc(
        &self,
        body: &str,
    ) -> crate::mcp_upstream::tests::Answer {
        send(
            &self.app,
            "/mcp/upstream/github",
            Some(&self.auth),
            HOST,
            Some(&self.sid),
            body,
        )
        .await
    }

    pub(in crate::mcp_upstream) async fn list(&self) -> Value {
        self.rpc(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
            .await
            .message()
    }

    pub(in crate::mcp_upstream) async fn call(&self, name: &str) -> Value {
        self.call_with(name, json!({})).await.message()
    }

    /// A `tools/call` with these arguments; the whole answer.
    pub(in crate::mcp_upstream) async fn call_with(
        &self,
        name: &str,
        arguments: Value,
    ) -> crate::mcp_upstream::tests::Answer {
        let body = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}});
        self.rpc(&body.to_string()).await
    }
}

fn listed(msg: &Value) -> Vec<&str> {
    msg["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("no tools in {msg}"))
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn catalogue_lists_everything_but_hide_and_invalid_names() {
    let rig = Rig::new(MAX_CACHE_TTL).await;
    let msg = rig.list().await;
    // `secret_admin` (hide), `unlisted_tool` (the default, hide) and `bad name` are absent;
    // allow, hold and deny are listed. The rule for `ghost_tool` adds nothing.
    assert_eq!(
        listed(&msg),
        ["list_issues", "create_issue", "delete_repository"],
        "{msg}"
    );
    assert!(rig.probe.calls().is_empty());
}

#[tokio::test]
async fn call_decisions_allow_deny_hold_and_hide() {
    let rig = Rig::new(MAX_CACHE_TTL).await;

    let msg = rig.call("list_issues").await;
    assert!(msg["result"].to_string().contains("called"), "{msg}");
    assert_eq!(rig.probe.calls(), ["list_issues"]);

    let msg = rig.call("delete_repository").await;
    assert_eq!(msg["error"]["message"], "tool_denied", "{msg}");
    let msg = rig.call("create_issue").await;
    assert_eq!(msg["error"]["message"], "approval_required", "{msg}");

    // Hidden by the table, hidden by the default, a rule without a tool, an invalid upstream
    // name and a name nobody offers: one and the same answer, byte for byte.
    let unknown = rig.call("does_not_exist").await;
    assert_eq!(unknown["error"]["message"], "unknown_tool", "{unknown}");
    for name in [
        "secret_admin",
        "unlisted_tool",
        "ghost_tool",
        "bad name",
        "",
    ] {
        let msg = rig.call(name).await;
        assert_eq!(msg["error"], unknown["error"], "{name:?}");
    }

    // Only the allowed call reached the upstream.
    assert_eq!(rig.probe.calls(), ["list_issues"]);
}

#[tokio::test]
async fn case_variants_and_look_alikes_are_unknown_tools() {
    let rig = Rig::new(MAX_CACHE_TTL).await;
    let unknown = rig.call("does_not_exist").await["error"].clone();
    for name in [
        "LIST_ISSUES",
        "List_Issues",
        "Secret_Admin",
        "secret_admin ",
        "secret_admin\u{200b}",
        "s\u{435}cret_admin",
        "list_\u{456}ssues",
        "delete_repositor\u{443}",
    ] {
        let msg = rig.call(name).await;
        assert_eq!(msg["error"], unknown, "{name:?}");
    }
    assert!(rig.probe.calls().is_empty(), "{:?}", rig.probe.calls());
}

#[tokio::test]
async fn a_batch_request_reaches_nothing() {
    let rig = Rig::new(MAX_CACHE_TTL).await;
    let batch = json!([
        {"jsonrpc": "2.0", "id": 10, "method": "tools/call",
         "params": {"name": "secret_admin", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 11, "method": "tools/call",
         "params": {"name": "delete_repository", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 12, "method": "tools/call",
         "params": {"name": "list_issues", "arguments": {}}},
    ]);
    let a = rig.rpc(&batch.to_string()).await;
    assert!(
        !a.text.contains("called"),
        "a batched call ran: {} {}",
        a.status,
        a.text
    );
    assert!(rig.probe.calls().is_empty(), "{:?}", rig.probe.calls());
}

#[tokio::test]
async fn catalogue_is_cached_and_a_failed_fetch_is_not_served_stale() {
    let rig = Rig::new(Duration::from_millis(150)).await;
    rig.list().await;
    rig.list().await;
    rig.call("list_issues").await;
    assert_eq!(
        rig.probe.lists.load(Ordering::SeqCst),
        1,
        "one fetch within the TTL"
    );

    // After the TTL the upstream fails: the agent gets the fixed error and no tool, not the
    // old list, for a list and for a call alike.
    rig.probe.fail_list.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(250)).await;
    let msg = rig.list().await;
    assert_eq!(msg["error"]["message"], "upstream_error", "{msg}");
    assert!(msg["result"].is_null());
    let msg = rig.call("list_issues").await;
    assert_eq!(msg["error"]["message"], "upstream_error", "{msg}");
    assert_eq!(
        rig.probe.calls(),
        ["list_issues"],
        "no call after the failure"
    );

    // Recovery: the next fetch works and is cached again.
    rig.probe.fail_list.store(false, Ordering::SeqCst);
    let msg = rig.list().await;
    assert_eq!(listed(&msg).len(), 3, "{msg}");
}

/// End to end: the upstream puts its credential in a tool description; the agent's list shows a
/// redaction marker, never the value or an encoding of it, and the cached catalogue behind the
/// call path holds only the redacted text.
#[tokio::test]
async fn a_canary_in_a_tool_description_is_redacted_in_the_listing() {
    use base64::Engine as _;
    let rig = Rig::new(MAX_CACHE_TTL).await;
    let a = rig
        .rpc(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
        .await;
    let msg = a.message();
    let desc = msg["result"]["tools"][0]["description"].as_str().unwrap();
    assert!(desc.starts_with("lists issues; token "), "{desc}");
    let b64 = base64::engine::general_purpose::STANDARD.encode(VALUE);
    for needle in [VALUE, b64.as_str()] {
        assert!(!a.text.contains(needle), "canary in the list answer");
    }
    assert!(!desc.contains("canary"), "{desc}");
    assert_ne!(desc, format!("lists issues; token {VALUE}"));
}
