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
        let mut header = JwtHeader::new(Algorithm::ES256);
        header.kid = Some("k1".to_owned());
        let der = self.0.to_pkcs8_der().unwrap();
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ec_der(der.as_bytes())).unwrap()
    }
}

struct Fixture {
    _issuer: MockServer,
    key: TestKey,
    app: Router,
    pg: common::Pg,
}

async fn start() -> Fixture {
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
    let state = AppState::new(
        true,
        Arc::new(ReadyFlag::new(true)),
        pg.app_db(PoolSettings::default()),
    )
    .with_kms(Arc::new(FakeKms(AtomicU32::new(0))))
    .with_human_auth(HumanAuth::new(&cfg).unwrap())
    .with_mcp(McpEndpoint::new(&cfg, RESOURCE).unwrap());
    Fixture {
        _issuer: server,
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
async fn mcp_explain_block_is_a_typed_not_available_error() {
    let f = start().await;
    let mut p = Person::connect(&f, "alice").await;
    let (err, out) = p
        .call("explain_block", json!({"reason": "policy.denied"}))
        .await;
    assert!(err);
    assert_eq!(out["error"]["code"], "not_available");
    assert!(
        out["error"]["message"]
            .as_str()
            .unwrap()
            .contains("explain_block")
    );
    // The reason is checked against the schema but never echoed.
    assert!(!out.to_string().contains("policy.denied"));
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
    let _third = Person::connect_as(&f, "alice", Some("client-abc")).await;
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
