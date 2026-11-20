//! M1 task 2.2: the hub MCP read tools, over the real `/mcp` route (Streamable HTTP, rmcp) with a
//! mock OIDC issuer and a throwaway `postgres:18` (needs Docker). Covers every read tool, org
//! isolation between two people, typed errors, and that a sentinel secret value never appears in
//! any tool result. Switches (2.3) and audit (2.5) are not tested here.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header as JwtHeader};
use ls_control_plane::app::{self, AppState};
use ls_control_plane::auth::human::{HumanAuth, HumanAuthConfig};
use ls_control_plane::db::PoolSettings;
use ls_control_plane::issuer_admin::{IssuerAdmin, IssuerAdminConfig};
use ls_control_plane::mcp_endpoint::McpEndpoint;
use ls_control_plane::readiness::ReadyFlag;
use ls_envelope::{
    Binding, DataKey, Header, KeyWrapper, SecretKey32, WrapError, WrapKeyId, WrappedDek,
};
use p256::pkcs8::EncodePrivateKey as _;
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use sqlx_core::query_scalar::query_scalar;
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ISSUER: &str = "https://idp.test/realms/locksmith";
const RESOURCE: &str = "https://hub.test/mcp";
const HOST: &str = "hub.test";
/// The stored secret value of every seeded version. No tool result may contain it.
const SENTINEL: &str = "SENTINEL-7c1f0e9a-secret-value-do-not-echo";
const READ_TOOLS: [&str; 6] = [
    "explain_block",
    "list_agents",
    "list_grants",
    "list_projects",
    "list_secret_names",
    "read_activity",
];

struct FakeKms(AtomicU32);

impl KeyWrapper for FakeKms {
    fn wrap(
        &self,
        _dek: &DataKey,
        _binding: &Binding,
    ) -> impl Future<Output = Result<WrappedDek, WrapError>> + Send {
        self.0.fetch_add(1, Ordering::SeqCst);
        let key = WrapKeyId::new("gateway", 1).unwrap();
        let mut blob = Header::v1(key.to_key_id()).encode().to_vec();
        blob.extend_from_slice(&[0x5a; 60]);
        let r = WrappedDek::from_bytes(blob);
        async move { r }
    }

    async fn unwrap(
        &self,
        _wrapped: &WrappedDek,
        _binding: &Binding,
    ) -> Result<SecretKey32, WrapError> {
        Err(WrapError::Denied)
    }
}

struct TestKey(p256::ecdsa::SigningKey);

impl TestKey {
    fn jwk(&self) -> Value {
        let point = self.0.verifying_key().to_sec1_point(false);
        json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        })
    }

    /// A token for the person `sub` (verified email unless `verified` is false).
    fn token(&self, sub: &str, verified: bool) -> String {
        self.token_for(sub, verified, None)
    }

    /// As [`Self::token`], issued to the OAuth client `client` (the `azp` claim).
    fn token_for(&self, sub: &str, verified: bool, client: Option<&str>) -> String {
        self.token_at(sub, verified, client, None)
    }

    /// As [`Self::token_for`], with the issuer's `auth_time` (unix seconds) when given.
    fn token_at(
        &self,
        sub: &str,
        verified: bool,
        client: Option<&str>,
        auth_time: Option<u64>,
    ) -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let mut claims = json!({
            "iss": ISSUER, "aud": RESOURCE, "sub": sub, "exp": exp,
            "email": format!("{sub}@example.com"), "email_verified": verified,
        });
        if let Some(c) = client {
            claims["azp"] = json!(c);
        }
        if let Some(t) = auth_time {
            claims["auth_time"] = json!(t);
        }
        let mut header = JwtHeader::new(Algorithm::ES256);
        header.kid = Some("k1".to_owned());
        let der = self.0.to_pkcs8_der().unwrap();
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ec_der(der.as_bytes())).unwrap()
    }
}

struct Fixture {
    issuer: MockServer,
    key: TestKey,
    app: Router,
    pg: common::Pg,
}

async fn start() -> Fixture {
    start_with(false).await
}

/// The admin client's secret in the tests that configure one: it must never be logged, audited
/// or returned.
const ADMIN_SECRET: &str = "ADMIN-SECRET-CANARY-3b7d";
const ADMIN_TOKEN: &str = "ADMIN-TOKEN-CANARY-91ac";

/// As [`start`], with the issuer admin client pointed at the mock issuer when `admin` is set.
async fn start_with(admin: bool) -> Fixture {
    let server = MockServer::start().await;
    let key = TestKey(p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap());
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [key.jwk()] })))
        .mount(&server)
        .await;
    let cfg = HumanAuthConfig {
        issuer: ISSUER.to_owned(),
        audience: "locksmith-api".to_owned(),
        jwks_url: format!("{}/jwks", server.uri()),
    };
    let pg = common::Pg::migrated().await;
    // Dev auth is on only so the test can seed data through the REST API; `/mcp` never uses it.
    let mut state = AppState::new(
        true,
        Arc::new(ReadyFlag::new(true)),
        pg.app_db(PoolSettings::default()),
    )
    .with_kms(Arc::new(FakeKms(AtomicU32::new(0))))
    .with_human_auth(HumanAuth::new(&cfg).unwrap())
    .with_mcp(McpEndpoint::new(&cfg, RESOURCE).unwrap());
    if admin {
        let admin_cfg = IssuerAdminConfig {
            url: server.uri(),
            realm: "locksmith".to_owned(),
            client_id: "locksmith-control-plane".to_owned(),
            client_secret: ADMIN_SECRET.to_owned().into(),
        };
        state = state.with_issuer_admin(IssuerAdmin::new(&admin_cfg, ISSUER).unwrap());
    }
    Fixture {
        issuer: server,
        key,
        app: app::build(state),
        pg,
    }
}

/// The JSON-RPC message in a Streamable HTTP response (plain JSON or an SSE stream).
fn rpc_message(body: &str) -> Value {
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        return v;
    }
    body.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
        .find(|v| {
            v.get("jsonrpc").is_some() && (v.get("result").is_some() || v.get("error").is_some())
        })
        .unwrap_or_else(|| panic!("no JSON-RPC message in {body}"))
}

/// A person's MCP session: an initialized client with its bearer token.
struct Person {
    app: Router,
    token: String,
    session: Option<String>,
    next_id: u64,
    /// Every response body this person received, for the sentinel scan.
    transcript: Vec<String>,
}

impl Person {
    async fn connect(f: &Fixture, sub: &str) -> Self {
        Self::connect_as(f, sub, None).await
    }

    /// Initialize as the OAuth client `client` (token `azp`), when given.
    async fn connect_as(f: &Fixture, sub: &str, client: Option<&str>) -> Self {
        let mut p = Self {
            app: f.app.clone(),
            token: f.key.token_for(sub, true, client),
            session: None,
            next_id: 1,
            transcript: Vec::new(),
        };
        let init = p
            .send(
                json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}}}),
            )
            .await;
        assert_eq!(init.0, StatusCode::OK, "{}", init.1);
        p.session = init.2;
        let (s, _, _) = p
            .send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        assert!(s.is_success(), "initialized notification: {s}");
        p
    }

    /// A client holding `token`, not yet initialized.
    fn raw(f: &Fixture, token: String) -> Self {
        Self {
            app: f.app.clone(),
            token,
            session: None,
            next_id: 1,
            transcript: Vec::new(),
        }
    }

    /// As [`Self::init_status`], keeping the client (and its session) for further calls.
    async fn init_status_keep(&mut self) -> StatusCode {
        let (s, _, session) = self
            .send(
                json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}}}),
            )
            .await;
        self.session = session;
        s
    }

    /// The status of an `initialize` with this token.
    async fn init_status(mut self) -> StatusCode {
        self.send(
            json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}}}),
        )
        .await
        .0
    }

    /// A person whose token has an unverified email (no session needed: `initialize` only).
    async fn connect_unverified(f: &Fixture, sub: &str) -> Self {
        let mut p = Self::connect(f, "placeholder-verified").await;
        p.token = f.key.token(sub, false);
        p
    }

    async fn send(&mut self, body: Value) -> (StatusCode, String, Option<String>) {
        let mut b = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, HOST)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token));
        if let Some(s) = &self.session {
            b = b.header("mcp-session-id", s);
        }
        let resp = self
            .app
            .clone()
            .oneshot(b.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let (parts, body) = resp.into_parts();
        let text = String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes()).into_owned();
        self.transcript.push(text.clone());
        let session = parts
            .headers
            .get("mcp-session-id")
            .map(|v| v.to_str().unwrap().to_owned());
        (parts.status, text, session)
    }

    /// A JSON-RPC request; returns the whole response message.
    async fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let (s, text, _) = self
            .send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        assert_eq!(s, StatusCode::OK, "{text}");
        rpc_message(&text)
    }

    async fn list_tools(&mut self) -> Vec<Value> {
        let r = self.rpc("tools/list", json!({})).await;
        r["result"]["tools"].as_array().expect("tools").clone()
    }

    /// Call a tool; returns `(is_error, structuredContent)`. Panics on a protocol error.
    async fn call(&mut self, tool: &str, args: Value) -> (bool, Value) {
        let r = self
            .rpc("tools/call", json!({"name": tool, "arguments": args}))
            .await;
        let result = &r["result"];
        assert!(result.is_object(), "protocol error calling {tool}: {r}");
        (
            result["isError"].as_bool().unwrap_or(false),
            result["structuredContent"].clone(),
        )
    }
}

/// Minimal output-schema conformance: object schemas are closed, required keys are present, and
/// arrays recurse into their item schema. (No JSON-schema crate is in the tree.)
fn conforms(schema: &Value, v: &Value, at: &str) {
    match schema["type"].clone() {
        Value::String(t) if t == "object" => {
            let obj = v
                .as_object()
                .unwrap_or_else(|| panic!("{at}: not an object: {v}"));
            let props = schema["properties"].as_object().unwrap();
            for k in schema["required"].as_array().into_iter().flatten() {
                assert!(
                    obj.contains_key(k.as_str().unwrap()),
                    "{at}: missing {k} in {v}"
                );
            }
            for (k, val) in obj {
                let sub = props
                    .get(k)
                    .unwrap_or_else(|| panic!("{at}: field `{k}` is not in the output schema"));
                conforms(sub, val, &format!("{at}.{k}"));
            }
        }
        Value::String(t) if t == "array" => {
            for (i, item) in v
                .as_array()
                .unwrap_or_else(|| panic!("{at}: not an array"))
                .iter()
                .enumerate()
            {
                conforms(&schema["items"], item, &format!("{at}[{i}]"));
            }
        }
        Value::String(t) => {
            let ok = match t.as_str() {
                "string" => v.is_string(),
                "integer" => v.is_i64() || v.is_u64(),
                _ => true,
            };
            assert!(ok, "{at}: {v} is not a {t}");
        }
        Value::Array(types) => {
            let ok = types.iter().any(|t| match t.as_str().unwrap() {
                "null" => v.is_null(),
                "string" => v.is_string(),
                "integer" => v.is_i64() || v.is_u64(),
                _ => true,
            });
            assert!(ok, "{at}: {v} matches none of {types:?}");
        }
        _ => {}
    }
}

/// REST seeding as an org (dev header), for data the tools then read.
struct Seed {
    org: Uuid,
    project: Uuid,
    env: Uuid,
    secret: Uuid,
    agent: Uuid,
    grant: Uuid,
}

async fn rest(f: &Fixture, method: &str, uri: &str, org: Uuid, body: Value) -> Value {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-locksmith-dev-org", org.to_string())
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = f.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(
        status.is_success(),
        "{method} {uri}: {status} {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn id_of(v: &Value) -> Uuid {
    v["id"].as_str().unwrap().parse().unwrap()
}

/// The org a person's first tool call created for them (their personal org).
async fn personal_org(f: &Fixture, sub: &str) -> Uuid {
    let mut c = f.pg.admin().await;
    let org: Uuid = query_scalar("SELECT personal_org_id FROM users WHERE subject = $1")
        .bind(sub)
        .fetch_one(&mut c)
        .await
        .unwrap();
    c.close().await.unwrap();
    org
}

/// Project, environment, a secret with two versions (value = [`SENTINEL`]), an agent and a grant.
async fn seed(f: &Fixture, org: Uuid, tag: &str) -> Seed {
    let p = rest(
        f,
        "POST",
        "/v1/projects",
        org,
        json!({"name": format!("proj-{tag}")}),
    )
    .await;
    let project = id_of(&p);
    let e = rest(
        f,
        "POST",
        &format!("/v1/projects/{project}/environments"),
        org,
        json!({"name": "prod"}),
    )
    .await;
    let env = id_of(&e);
    let base = format!("/v1/projects/{project}/environments/{env}/secrets");
    let s = rest(
        f,
        "POST",
        &base,
        org,
        json!({"name": format!("API_KEY_{tag}")}),
    )
    .await;
    let secret = id_of(&s);
    for _ in 0..2 {
        rest(
            f,
            "POST",
            &format!("{base}/{secret}/versions"),
            org,
            json!({"value": SENTINEL}),
        )
        .await;
    }
    let a = rest(
        f,
        "POST",
        "/v1/agents",
        org,
        json!({"name": format!("agent-{tag}")}),
    )
    .await;
    let agent = id_of(&a["agent"]);
    let g = rest(
        f,
        "POST",
        &format!("/v1/agents/{agent}/grants"),
        org,
        json!({"secret_id": secret}),
    )
    .await;
    Seed {
        org,
        project,
        env,
        secret,
        agent,
        grant: id_of(&g),
    }
}

/// Two people, each with their own seeded org.
async fn two_people() -> (Fixture, Person, Person, Seed, Seed) {
    let f = start().await;
    let mut alice = Person::connect(&f, "alice").await;
    let mut bob = Person::connect(&f, "bob").await;
    // A first call signs the person in and creates their personal org.
    alice.call("list_projects", json!({})).await;
    bob.call("list_projects", json!({})).await;
    let a = seed(&f, personal_org(&f, "alice").await, "a").await;
    let b = seed(&f, personal_org(&f, "bob").await, "b").await;
    (f, alice, bob, a, b)
}

#[tokio::test]
async fn mcp_tools_list_has_the_six_read_tools_with_real_schemas() {
    let f = start().await;
    let mut p = Person::connect(&f, "alice").await;
    let tools = p.list_tools().await;
    let mut names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    names.sort_unstable();
    // The tools that change state ship off and are not listed (the switch itself is task 2.3).
    assert_eq!(names, READ_TOOLS);
    for t in &tools {
        assert_eq!(t["inputSchema"]["type"], "object", "{t}");
        assert!(t["inputSchema"]["properties"].is_object(), "{t}");
        assert_eq!(t["outputSchema"]["type"], "object", "{t}");
        assert!(
            t["outputSchema"]["properties"]
                .as_object()
                .is_some_and(|p| !p.is_empty())
        );
        assert_eq!(t["annotations"]["readOnlyHint"], true, "{t}");
    }
}

#[tokio::test]
async fn mcp_each_read_tool_returns_the_persons_metadata_and_conforms_to_its_schema() {
    let (_f, mut alice, _bob, a, _b) = two_people().await;
    let tools = alice.list_tools().await;
    let schema = |name: &str| -> Value {
        tools.iter().find(|t| t["name"] == name).unwrap()["outputSchema"].clone()
    };

    let (err, out) = alice.call("list_projects", json!({})).await;
    assert!(!err, "{out}");
    conforms(&schema("list_projects"), &out, "list_projects");
    assert_eq!(out["items"].as_array().unwrap().len(), 1);
    let project = &out["items"][0];
    assert_eq!(project["id"], a.project.to_string());
    assert_eq!(project["name"], "proj-a");
    assert_eq!(
        project["environments"],
        json!([{"id": a.env.to_string(), "name": "prod"}])
    );

    let args = json!({"project_id": a.project, "environment_id": a.env});
    let (err, out) = alice.call("list_secret_names", args).await;
    assert!(!err, "{out}");
    conforms(&schema("list_secret_names"), &out, "list_secret_names");
    let s = &out["items"][0];
    assert_eq!(s["secret_id"], a.secret.to_string());
    assert_eq!(s["name"], "API_KEY_a");
    assert_eq!(s["latest_version"], 2);
    let versions: Vec<i64> = s["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].as_i64().unwrap())
        .collect();
    assert_eq!(versions, [1, 2]);

    let (err, out) = alice.call("list_agents", json!({})).await;
    assert!(!err, "{out}");
    conforms(&schema("list_agents"), &out, "list_agents");
    assert_eq!(out["items"][0]["agent_id"], a.agent.to_string());
    assert_eq!(out["items"][0]["name"], "agent-a");

    let (err, out) = alice
        .call("list_grants", json!({"agent_id": a.agent}))
        .await;
    assert!(!err, "{out}");
    conforms(&schema("list_grants"), &out, "list_grants");
    let g = &out["items"][0];
    assert_eq!(g["grant_id"], a.grant.to_string());
    assert_eq!(g["secret_id"], a.secret.to_string());
    assert_eq!(g["secret_name"], "API_KEY_a");
    assert_eq!(g["mode"], "relay");

    let (err, out) = alice.call("read_activity", json!({})).await;
    assert!(!err, "{out}");
    conforms(&schema("read_activity"), &out, "read_activity");
    let actions: Vec<&str> = out["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"agent.created"), "{actions:?}");
    // Newest first.
    let seqs: Vec<i64> = out["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_i64().unwrap())
        .collect();
    assert!(seqs.windows(2).all(|w| w[0] > w[1]), "{seqs:?}");
}

#[tokio::test]
async fn mcp_paging_uses_the_rest_cursor() {
    let (f, mut alice, _bob, a, _b) = two_people().await;
    rest(&f, "POST", "/v1/projects", a.org, json!({"name": "second"})).await;
    let (_, p1) = alice.call("list_projects", json!({"limit": 1})).await;
    assert_eq!(p1["items"].as_array().unwrap().len(), 1);
    let cursor = p1["next_cursor"]
        .as_str()
        .expect("a second page")
        .to_owned();
    let (_, p2) = alice
        .call("list_projects", json!({"limit": 1, "cursor": cursor}))
        .await;
    assert_eq!(p2["items"].as_array().unwrap().len(), 1);
    assert_ne!(p1["items"][0]["id"], p2["items"][0]["id"]);
    assert!(p2["next_cursor"].is_null());
    // The REST bounds apply: limit 0 and a garbage cursor are validation errors, as in the console.
    let (err, out) = alice.call("list_projects", json!({"limit": 0})).await;
    assert!(err);
    assert_eq!(out["error"]["code"], "validation");
    let (err, out) = alice
        .call("list_projects", json!({"cursor": "not-a-cursor"}))
        .await;
    assert!(err);
    assert_eq!(out["error"]["code"], "validation");
}

#[tokio::test]
async fn mcp_a_person_in_org_a_cannot_see_org_b() {
    let (_f, mut alice, mut bob, a, b) = two_people().await;
    assert_ne!(a.org, b.org);

    // Lists show only the caller's own org.
    let (_, out) = bob.call("list_projects", json!({})).await;
    assert_eq!(out["items"].as_array().unwrap().len(), 1);
    assert_eq!(out["items"][0]["id"], b.project.to_string());
    let (_, out) = bob.call("list_agents", json!({})).await;
    assert_eq!(out["items"].as_array().unwrap().len(), 1);
    assert_eq!(out["items"][0]["agent_id"], b.agent.to_string());

    // A's ids are not found for B (the same 404 the console gives), never a leak or a hint.
    let (err, out) = bob
        .call(
            "list_secret_names",
            json!({"project_id": a.project, "environment_id": a.env}),
        )
        .await;
    assert!(err);
    assert_eq!(out["error"]["code"], "not-found");
    let (err, out) = bob.call("list_grants", json!({"agent_id": a.agent})).await;
    assert!(err);
    assert_eq!(out["error"]["code"], "not-found");
    // B's own ids work for B and fail for A.
    let (err, _) = alice
        .call(
            "list_secret_names",
            json!({"project_id": b.project, "environment_id": b.env}),
        )
        .await;
    assert!(err);

    // Activity is each org's own chain: nothing of A's mentions B's ids and the reverse.
    let (_, act_b) = bob.call("read_activity", json!({})).await;
    let (_, act_a) = alice.call("read_activity", json!({})).await;
    let (act_a, act_b) = (act_a.to_string(), act_b.to_string());
    for needle in [
        b.agent.to_string(),
        b.secret.to_string(),
        b.grant.to_string(),
    ] {
        assert!(!act_a.contains(&needle), "A saw B's {needle}");
    }
    for needle in [
        a.agent.to_string(),
        a.secret.to_string(),
        a.grant.to_string(),
    ] {
        assert!(!act_b.contains(&needle), "B saw A's {needle}");
    }
    assert!(act_b.contains(&b.agent.to_string()));
}

#[tokio::test]
async fn mcp_no_tool_result_or_response_contains_a_stored_secret_value() {
    let (_f, mut alice, mut bob, a, b) = two_people().await;
    for p in [&mut alice, &mut bob] {
        p.call("list_projects", json!({})).await;
        p.call("list_agents", json!({})).await;
        p.call("read_activity", json!({"limit": 100})).await;
        p.call("explain_block", json!({"reason": "blocked"})).await;
        // Refused calls do not echo what was sent, even a value passed in a bogus field.
        for (tool, args) in [
            ("no_such_tool", json!({})),
            ("list_projects", json!({"value": SENTINEL})),
        ] {
            let r = p
                .rpc("tools/call", json!({"name": tool, "arguments": args}))
                .await;
            assert!(r["error"].is_object(), "{r}");
        }
    }
    for s in [&a, &b] {
        let p = if s.org == a.org { &mut alice } else { &mut bob };
        p.call(
            "list_secret_names",
            json!({"project_id": s.project, "environment_id": s.env}),
        )
        .await;
        p.call("list_grants", json!({"agent_id": s.agent})).await;
    }
    for (who, p) in [("alice", &alice), ("bob", &bob)] {
        assert!(!p.transcript.is_empty());
        for body in &p.transcript {
            assert!(
                !body.contains(SENTINEL),
                "{who} received the sentinel value: {body}"
            );
            // Not even a prefix, or its base64 form.
            assert!(!body.contains(&SENTINEL[..16]), "{who}");
            assert!(!body.contains(&base64::engine::general_purpose::STANDARD.encode(SENTINEL)));
        }
    }
}

#[tokio::test]
async fn mcp_explain_block_explains_a_code_and_never_echoes_input() {
    let f = start().await;
    let mut p = Person::connect(&f, "alice").await;
    let (err, out) = p.call("explain_block", json!({"reason": "no_grant"})).await;
    assert!(!err, "{out}");
    assert_eq!(out["rule"], "no_grant");
    assert!(out["next_step"].as_str().unwrap().contains("human"));
    let (err, out) = p
        .call("explain_block", json!({"reason": "zz SENTINEL-echo"}))
        .await;
    assert!(!err);
    assert!(out["rule"].is_null());
    assert!(!out.to_string().contains("SENTINEL-echo"));
}

#[tokio::test]
async fn mcp_bad_arguments_unknown_and_off_tools_are_protocol_errors() {
    let f = start().await;
    let mut p = Person::connect(&f, "alice").await;
    let calls = [
        ("list_projects", json!({"unexpected": 1})),
        ("list_secret_names", json!({})),
        (
            "list_secret_names",
            json!({"project_id": "not-a-uuid", "environment_id": Uuid::nil()}),
        ),
        ("list_grants", json!({"agent_id": 5})),
        // Off by default (state-changing): not listed, and not callable.
        ("revoke_grant", json!({"grant_id": Uuid::nil()})),
        ("pause_agents", json!({})),
        ("no_such_tool", json!({})),
    ];
    for (tool, args) in calls {
        let r = p
            .rpc("tools/call", json!({"name": tool, "arguments": args}))
            .await;
        assert!(r["error"].is_object(), "{tool} {args}: {r}");
        assert!(r["result"].is_null(), "{tool}: {r}");
    }
}

#[tokio::test]
async fn mcp_unverified_email_is_refused_like_the_console() {
    let f = start().await;
    let mut p = Person::connect_unverified(&f, "mallory").await;
    let (err, out) = p.call("list_projects", json!({})).await;
    assert!(err);
    assert_eq!(out["error"]["code"], "email-verification-required");
    // No user or org was created for the unverified identity.
    let mut c = f.pg.admin().await;
    let n: i64 = query_scalar("SELECT count(*) FROM users WHERE subject = 'mallory'")
        .fetch_one(&mut c)
        .await
        .unwrap();
    c.close().await.unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn mcp_an_off_tool_is_hidden_and_refused_and_switches_are_per_org() {
    let (f, mut alice, mut bob, _a, _b) = two_people().await;
    let org_a = personal_org(&f, "alice").await;
    let put = |org, tool: &'static str, enabled: bool| {
        let f = &f;
        async move {
            rest(
                f,
                "PUT",
                &format!("/v1/mcp/tools/hub/{tool}"),
                org,
                json!({ "enabled": enabled }),
            )
            .await
        }
    };
    put(org_a, "list_projects", false).await;
    let names: Vec<String> = alice
        .list_tools()
        .await
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect();
    assert!(!names.iter().any(|n| n == "list_projects"), "{names:?}");
    let r = alice
        .rpc(
            "tools/call",
            json!({"name": "list_projects", "arguments": {}}),
        )
        .await;
    assert!(r["error"].is_object(), "off tool must be refused: {r}");
    // Another org keeps the default.
    let (err, _) = bob.call("list_projects", json!({})).await;
    assert!(!err);
    assert!(
        bob.list_tools()
            .await
            .iter()
            .any(|t| t["name"] == "list_projects")
    );
    // Turning it back on lists and runs it again.
    put(org_a, "list_projects", true).await;
    let (err, _) = alice.call("list_projects", json!({})).await;
    assert!(!err);
    // An off-by-default tool the org turns on is listed.
    put(org_a, "revoke_grant", true).await;
    assert!(
        alice
            .list_tools()
            .await
            .iter()
            .any(|t| t["name"] == "revoke_grant")
    );
}

#[tokio::test]
async fn mcp_initialize_records_the_client_and_never_unrevokes_it() {
    let f = start().await;
    let _first = Person::connect_as(&f, "alice", Some("client-abc")).await;
    let org = personal_org(&f, "alice").await;
    let rows = rest(&f, "GET", "/v1/mcp/clients", org, Value::Null).await;
    let items = rows["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{rows}");
    assert_eq!(items[0]["client_id"], "client-abc");
    assert_eq!(items[0]["client_name"], "test");
    assert_eq!(items[0]["layer"], "hub");
    assert!(items[0]["revoked_at"].is_null());
    // A second initialize (a new session) is the same row.
    let _second = Person::connect_as(&f, "alice", Some("client-abc")).await;
    let rows = rest(&f, "GET", "/v1/mcp/clients", org, Value::Null).await;
    assert_eq!(rows["items"].as_array().unwrap().len(), 1, "{rows}");
    // After a revoke, initializing again keeps the first revoke time.
    let row_id = rows["items"][0]["id"].as_str().unwrap().to_owned();
    let revoked = rest(
        &f,
        "POST",
        &format!("/v1/mcp/clients/{row_id}/revoke"),
        org,
        json!({}),
    )
    .await;
    let third = Person::raw(&f, f.key.token_for("alice", true, Some("client-abc")));
    assert_eq!(third.init_status().await, StatusCode::UNAUTHORIZED);
    let rows = rest(&f, "GET", "/v1/mcp/clients", org, Value::Null).await;
    assert_eq!(rows["items"].as_array().unwrap().len(), 1, "{rows}");
    assert_eq!(rows["items"][0]["revoked_at"], revoked["revoked_at"]);
    // A different client is a different row; a token without a client id records none.
    let _other = Person::connect_as(&f, "alice", Some("client-xyz")).await;
    let _none = Person::connect(&f, "alice").await;
    let rows = rest(&f, "GET", "/v1/mcp/clients", org, Value::Null).await;
    assert_eq!(rows["items"].as_array().unwrap().len(), 2, "{rows}");
}

#[tokio::test]
async fn mcp_mutating_tools_work_only_when_switched_on_and_stay_in_the_callers_org() {
    let (f, mut alice, mut bob, a, _b) = two_people().await;
    for (who, org) in [
        ("alice", personal_org(&f, "alice").await),
        ("bob", personal_org(&f, "bob").await),
    ] {
        let _ = who;
        for tool in ["revoke_grant", "pause_agents"] {
            rest(
                &f,
                "PUT",
                &format!("/v1/mcp/tools/hub/{tool}"),
                org,
                json!({"enabled": true}),
            )
            .await;
        }
    }
    // Another org's grant is the same 404 the console gives, and it survives the attempt.
    let (err, out) = bob.call("revoke_grant", json!({"grant_id": a.grant})).await;
    assert!(err);
    assert_eq!(out["error"]["code"], "not-found");
    let (_, out) = alice
        .call("list_grants", json!({"agent_id": a.agent}))
        .await;
    assert_eq!(out["items"].as_array().unwrap().len(), 1);

    // The owner revokes it; the result matches the registered output schema.
    let (err, out) = alice
        .call("revoke_grant", json!({"grant_id": a.grant}))
        .await;
    assert!(!err, "{out}");
    let tools = alice.list_tools().await;
    let schema =
        tools.iter().find(|t| t["name"] == "revoke_grant").unwrap()["outputSchema"].clone();
    conforms(&schema, &out, "revoke_grant");
    assert_eq!(out["grant_id"], a.grant.to_string());
    let (_, out) = alice
        .call("list_grants", json!({"agent_id": a.agent}))
        .await;
    assert!(out["items"].as_array().unwrap().is_empty());
    let (err, out) = alice
        .call("revoke_grant", json!({"grant_id": a.grant}))
        .await;
    assert!(err);
    assert_eq!(out["error"]["code"], "not-found");

    // Pause waits for the session and revoke change: a typed error, the argument not echoed.
    let (err, out) = alice
        .call("pause_agents", json!({"agent_ids": [a.agent]}))
        .await;
    assert!(err);
    assert_eq!(out["error"]["code"], "not_available");
    assert!(!out.to_string().contains(&a.agent.to_string()));
}

/// `(kind, actor, target, outcome, attrs)` of every ledger row of `kind`, oldest first.
async fn ledger(f: &Fixture, kind: &str) -> Vec<(String, String, String, String)> {
    let mut c = f.pg.admin().await;
    let rows: Vec<(String, String, String, String)> = sqlx_core::query_as::query_as(
        "SELECT actor, COALESCE(target, ''), outcome, attrs::text FROM audit_events \
         WHERE kind = $1 ORDER BY seq",
    )
    .bind(kind)
    .fetch_all(&mut c)
    .await
    .unwrap();
    c.close().await.unwrap();
    rows
}

#[tokio::test]
async fn mcp_every_call_is_audited_denied_ones_too_and_arguments_are_never_recorded() {
    let f = start().await;
    let mut alice = Person::connect(&f, "alice").await;
    let canary = "ARG-CANARY-5e1d-do-not-record";

    // Allowed, off (revoke_grant ships off), unknown, bad arguments, and a failed read.
    let (err, _) = alice.call("list_projects", json!({})).await;
    assert!(!err);
    // The first call created the person and the org.
    let org = personal_org(&f, "alice").await;
    for (tool, args) in [
        (
            "revoke_grant",
            json!({"grant_id": Uuid::nil(), "note": canary}),
        ),
        ("no_such_tool", json!({"password": canary})),
        ("list_grants", json!({"agent_id": canary})),
    ] {
        let r = alice
            .rpc("tools/call", json!({"name": tool, "arguments": args}))
            .await;
        assert!(r["error"].is_object(), "{tool}: {r}");
    }
    let (err, _) = alice
        .call("list_grants", json!({"agent_id": Uuid::new_v4()}))
        .await;
    // An unknown agent lists nothing or 404s; either way it is a recorded call.
    let _ = err;

    let rows = ledger(&f, "mcp.call").await;
    let user = {
        let mut c = f.pg.admin().await;
        let id: Uuid = query_scalar("SELECT id FROM users WHERE subject = 'alice'")
            .fetch_one(&mut c)
            .await
            .unwrap();
        c.close().await.unwrap();
        format!("user:{id}")
    };
    assert_eq!(rows.len(), 5, "{rows:?}");
    for (actor, target, _, attrs) in &rows {
        assert_eq!(actor, &user);
        assert_eq!(target, &format!("org:{org}"));
        assert!(attrs.contains("hub"), "layer missing: {attrs}");
    }
    let has = |i: usize, outcome: &str, tool: &str, reason: Option<&str>| {
        let (_, _, o, attrs) = &rows[i];
        assert_eq!(o, outcome, "row {i}: {rows:?}");
        assert!(attrs.contains(tool), "row {i} tool {tool}: {attrs}");
        if let Some(r) = reason {
            assert!(attrs.contains(r), "row {i} reason {r}: {attrs}");
        }
    };
    has(0, "ok", "list_projects", None);
    // A denied call is recorded, with the typed reason.
    has(1, "denied", "revoke_grant", Some("tool_off"));
    has(2, "denied", "unknown", Some("unknown_tool"));
    has(3, "error", "list_grants", Some("invalid_arguments"));

    // Nothing the client sent (tool name of an unknown tool, argument names or values) is stored.
    let mut c = f.pg.admin().await;
    let all: String = query_scalar("SELECT string_agg(t::text, E'\n') FROM audit_events t")
        .fetch_one(&mut c)
        .await
        .unwrap();
    c.close().await.unwrap();
    for leaked in [canary, "no_such_tool", "password"] {
        assert!(!all.contains(leaked), "ledger contains {leaked}");
    }
}

#[tokio::test]
async fn mcp_revoke_grant_is_attributed_to_the_person_and_the_call_is_audited() {
    let (f, mut alice, _bob, a, _b) = two_people().await;
    let org = personal_org(&f, "alice").await;
    rest(
        &f,
        "PUT",
        "/v1/mcp/tools/hub/revoke_grant",
        org,
        json!({"enabled": true}),
    )
    .await;
    let (err, out) = alice
        .call("revoke_grant", json!({"grant_id": a.grant}))
        .await;
    assert!(!err, "{out}");
    let revoked = ledger(&f, "grant.revoked").await;
    assert_eq!(revoked.len(), 1, "{revoked:?}");
    assert!(revoked[0].0.starts_with("user:"), "{revoked:?}");
    assert_ne!(revoked[0].0, "service:dev_auth");
    let calls = ledger(&f, "mcp.call").await;
    let row = calls
        .iter()
        .find(|r| r.3.contains("revoke_grant"))
        .expect("revoke_grant call recorded");
    assert_eq!(row.2, "ok");
    assert_eq!(row.0, revoked[0].0);
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn mcp_revoking_again_after_a_new_sign_in_cuts_that_sign_in_off() {
    let f = start().await;
    let token = |at: u64| f.key.token_at("alice", true, Some("client-again"), Some(at));
    let mut first = Person::raw(&f, token(now_secs() - 60));
    assert_eq!(first.init_status_keep().await, StatusCode::OK);
    let org = personal_org(&f, "alice").await;
    let rows = rest(&f, "GET", "/v1/mcp/clients", org, Value::Null).await;
    let row_id = rows["items"][0]["id"].as_str().unwrap().to_owned();
    let path = format!("/v1/mcp/clients/{row_id}/revoke");
    rest(&f, "POST", &path, org, json!({})).await;
    // A sign-in after the first revoke is let through.
    let signed_in_again = now_secs() + 1;
    tokio::time::sleep(std::time::Duration::from_millis(2200)).await;
    assert_eq!(Person::raw(&f, token(signed_in_again)).init_status().await, StatusCode::OK);
    // Revoking again moves the cut-off forward: that sign-in is now refused too.
    rest(&f, "POST", &path, org, json!({})).await;
    assert_eq!(
        Person::raw(&f, token(signed_in_again)).init_status().await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn mcp_a_revoked_client_is_refused_on_the_next_call_and_on_a_fresh_initialize() {
    let f = start().await;
    let signed_in = now_secs() - 60;
    let token = |client: &str, at: Option<u64>| f.key.token_at("alice", true, Some(client), at);
    // Connect with an issued-before-revoke token.
    let mut client = Person::raw(&f, token("client-abc", Some(signed_in)));
    assert_eq!(client.init_status_keep().await, StatusCode::OK);
    let (s, _, _) = client
        .send(json!({"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}}))
        .await;
    assert_eq!(s, StatusCode::OK);
    let org = personal_org(&f, "alice").await;
    let rows = rest(&f, "GET", "/v1/mcp/clients", org, Value::Null).await;
    let row_id = rows["items"][0]["id"].as_str().unwrap().to_owned();
    // Another client of the same person, to prove the revoke is per client.
    let other = Person::connect_as(&f, "alice", Some("client-other")).await;
    let revoked = rest(
        &f,
        "POST",
        &format!("/v1/mcp/clients/{row_id}/revoke"),
        org,
        json!({}),
    )
    .await;
    let revoked_secs = time::OffsetDateTime::parse(
        revoked["revoked_at"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .unix_timestamp() as u64;
    // The next call on the live session is refused with 401 and a challenge.
    let (s, _, _) = client
        .send(json!({"jsonrpc": "2.0", "id": 6, "method": "tools/list", "params": {}}))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // So is a fresh initialize with the same (older) token, and with a token that has no auth_time.
    let same = Person::raw(&f, token("client-abc", Some(signed_in)));
    assert_eq!(same.init_status().await, StatusCode::UNAUTHORIZED);
    let none = Person::raw(&f, token("client-abc", None));
    assert_eq!(none.init_status().await, StatusCode::UNAUTHORIZED);
    // The person's other client and another person with the same client id are unaffected.
    let mut other = other;
    assert!(!other.list_tools().await.is_empty());
    let bob = Person::raw(&f, f.key.token_at("bob", true, Some("client-abc"), None));
    assert_eq!(bob.init_status().await, StatusCode::OK);
    // A sign-in in the same second as the revoke but before it (revoked_at has microseconds) is
    // still old; only a sign-in after the revoke is let through. The row stays revoked.
    let same_second = Person::raw(&f, token("client-abc", Some(revoked_secs)));
    assert_eq!(same_second.init_status().await, StatusCode::UNAUTHORIZED);
    let fresh = Person::raw(&f, token("client-abc", Some(now_secs() + 5)));
    assert_eq!(fresh.init_status().await, StatusCode::OK);
    let rows = rest(&f, "GET", "/v1/mcp/clients", org, Value::Null).await;
    let row = rows["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["client_id"] == "client-abc")
        .unwrap();
    assert!(!row["revoked_at"].is_null(), "{rows}");
}

/// Mount the issuer's token endpoint (answering `token_status`) and the consent delete
/// (answering `delete_status`).
async fn mount_issuer_admin(f: &Fixture, token_status: u16, delete_status: u16) {
    let token = if token_status == 200 {
        ResponseTemplate::new(200)
            .set_body_json(json!({"access_token": ADMIN_TOKEN, "token_type": "Bearer"}))
    } else {
        ResponseTemplate::new(token_status).set_body_string(ADMIN_TOKEN)
    };
    Mock::given(method("POST"))
        .and(path("/realms/locksmith/protocol/openid-connect/token"))
        .respond_with(token)
        .mount(&f.issuer)
        .await;
    Mock::given(method("DELETE"))
        .and(path(
            "/admin/realms/locksmith/users/alice/consents/client-abc",
        ))
        .respond_with(ResponseTemplate::new(delete_status).set_body_string(ADMIN_TOKEN))
        .mount(&f.issuer)
        .await;
}

/// Requests the mock issuer received on its admin and token endpoints.
async fn admin_requests(f: &Fixture) -> Vec<wiremock::Request> {
    f.issuer
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path().starts_with("/admin/") || r.url.path().starts_with("/realms/"))
        .collect()
}

/// Connect `alice` as `client-abc` and revoke that client; returns `(org, revoked_client)`.
async fn revoke_alices_client(f: &Fixture) -> (Uuid, Value) {
    let _alice = Person::connect_as(f, "alice", Some("client-abc")).await;
    let org = personal_org(f, "alice").await;
    let rows = rest(f, "GET", "/v1/mcp/clients", org, Value::Null).await;
    let row_id = rows["items"][0]["id"].as_str().unwrap().to_owned();
    let revoked = rest(
        f,
        "POST",
        &format!("/v1/mcp/clients/{row_id}/revoke"),
        org,
        json!({}),
    )
    .await;
    (org, revoked)
}

#[tokio::test]
async fn mcp_revoke_deletes_the_persons_consent_at_the_issuer_and_audits_it() {
    let f = start_with(true).await;
    mount_issuer_admin(&f, 200, 204).await;
    let (_, revoked) = revoke_alices_client(&f).await;
    assert!(revoked["revoked_at"].is_string(), "{revoked}");
    let reqs = admin_requests(&f).await;
    assert_eq!(reqs.len(), 2, "{reqs:?}");
    // The admin client signs in with its own credentials, then deletes with the access token.
    assert_eq!(reqs[0].method.as_str(), "POST");
    let basic = reqs[0]
        .headers
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(basic.starts_with("Basic "), "client authentication");
    assert_eq!(reqs[1].method.as_str(), "DELETE");
    assert_eq!(
        reqs[1]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("Bearer {ADMIN_TOKEN}")
    );
    // One event, outcome ok, no reason, nothing from the issuer.
    let events = ledger(&f, "mcp.issuer_revoke").await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].2, "ok");
    assert!(!events[0].3.contains(ADMIN_TOKEN) && !events[0].3.contains(ADMIN_SECRET));
    // The revoke is enforced by the database rule whatever the issuer does.
    let again = Person::raw(&f, f.key.token_at("alice", true, Some("client-abc"), None));
    assert_eq!(again.init_status().await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mcp_revoke_still_succeeds_and_holds_when_the_issuer_call_fails() {
    for (token_status, delete_status, reason) in [
        (200, 500, "issuer_admin_delete"),
        (200, 403, "issuer_admin_delete"),
        (401, 204, "issuer_admin_token"),
    ] {
        let f = start_with(true).await;
        mount_issuer_admin(&f, token_status, delete_status).await;
        let (org, revoked) = revoke_alices_client(&f).await;
        // The API answered success with the revoked row, and the row is revoked.
        assert!(revoked["revoked_at"].is_string(), "{revoked}");
        let rows = rest(&f, "GET", "/v1/mcp/clients", org, Value::Null).await;
        assert_eq!(rows["items"][0]["revoked_at"], revoked["revoked_at"]);
        // The next call and a fresh initialize are refused (the issuer step is not the control).
        let again = Person::raw(&f, f.key.token_at("alice", true, Some("client-abc"), None));
        assert_eq!(again.init_status().await, StatusCode::UNAUTHORIZED);
        // The failure is an audit event with outcome error and a static reason only.
        let events = ledger(&f, "mcp.issuer_revoke").await;
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0].2, "error");
        assert!(events[0].3.contains(reason), "{events:?}");
        for banned in [ADMIN_TOKEN, ADMIN_SECRET, "alice"] {
            assert!(!events[0].3.contains(banned), "{banned} in {events:?}");
        }
    }
}

#[tokio::test]
async fn mcp_revoke_of_an_unreachable_issuer_still_succeeds() {
    let f = start_with(true).await;
    // Nothing mounted: the mock answers 404 to the token request.
    let (_, revoked) = revoke_alices_client(&f).await;
    assert!(revoked["revoked_at"].is_string(), "{revoked}");
    let events = ledger(&f, "mcp.issuer_revoke").await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].2, "error");
}

#[tokio::test]
async fn mcp_revoke_skips_the_issuer_when_no_admin_client_is_configured() {
    let f = start().await;
    mount_issuer_admin(&f, 200, 204).await;
    let (_, revoked) = revoke_alices_client(&f).await;
    assert!(revoked["revoked_at"].is_string(), "{revoked}");
    assert!(admin_requests(&f).await.is_empty(), "no issuer call");
    assert!(ledger(&f, "mcp.issuer_revoke").await.is_empty());
}
