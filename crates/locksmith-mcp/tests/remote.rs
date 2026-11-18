//! `locksmith-mcp` remote mode (S4 task 3.2): `list_grants` and `relay_request` against a mock
//! gateway, driven over stdio JSON-RPC through the real binary. Local-vault tools unchanged.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "eyJhbGciOiJFZERTQSJ9.TOKEN_CANARY_PAYLOAD_0123456789.SIGNATURE_CANARY_abcdef";
const SECRET_ID: &str = "0191a3b2-7c1e-7a3f-8b2d-5e6f7a8b9c0d";

/// Throwaway LOCKSMITH_HOME (and runtime dir, so no real daemon is reached).
struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "lsmcp-e2e-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Home(p)
    }

    /// The state file `smith login --agent` writes (same shape, mode 0600).
    fn login(&self, gw: &MockServer, expires_in: i64) {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + expires_in;
        let body = json!({
            "access_token": TOKEN, "expires_at_unix": exp,
            "control_plane_url": "http://127.0.0.1:1", "gateway_url": gw.uri(),
        })
        .to_string();
        let p = self.0.join("agent.json");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&p).unwrap().write_all(body.as_bytes()).unwrap();
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Send `msgs` (one JSON-RPC message per line) and return (raw stdout+stderr, parsed replies).
async fn mcp(home: &Home, msgs: Vec<Value>) -> (String, Vec<Value>) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_locksmith-mcp"));
    c.env("LOCKSMITH_HOME", &home.0)
        .env("LOCKSMITH_RUNTIME_DIR", home.0.join("run"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let input: String = msgs.iter().map(|m| format!("{m}\n")).collect();
    let o = tokio::task::spawn_blocking(move || {
        let mut child = c.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    let raw = format!("{out}{}", String::from_utf8_lossy(&o.stderr));
    let replies = out
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    (raw, replies)
}

fn call(id: u64, name: &str, args: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": args}})
}

/// (isError, text) of a tools/call reply.
fn result(r: &Value) -> (bool, String) {
    (
        r["result"]["isError"].as_bool().unwrap(),
        r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
}

fn assert_no_token(s: &str) {
    assert!(
        !s.contains(TOKEN)
            && !s.contains("TOKEN_CANARY_PAYLOAD")
            && !s.contains("SIGNATURE_CANARY"),
        "token leaked: {s}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tools_list_has_remote_and_local_tools() {
    let home = Home::new();
    let (_, r) = mcp(
        &home,
        vec![json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})],
    )
    .await;
    let names: Vec<&str> = r[0]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    for n in [
        "locksmith_list_keys",
        "locksmith_status",
        "locksmith_issue_token",
        "locksmith_start_session",
        "locksmith_explain_block",
        "list_grants",
        "relay_request",
    ] {
        assert!(names.contains(&n), "{n} missing from {names:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn list_grants_returns_names_and_hosts_only() {
    let (home, gw) = (Home::new(), MockServer::start().await);
    Mock::given(method("GET"))
        .and(path("/v1/grants"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "agent_id": "0191a3b2-0000-7000-8000-000000000001",
            "grants": [{
                "secret_id": SECRET_ID, "secret_name": "langfuse", "mode": "relay",
                "expires_at": null, "allowed_origin": "https://api.example.com",
                "value": "sk_live_SHOULD_NOT_APPEAR", "note": TOKEN
            }]
        })))
        .expect(1)
        .mount(&gw)
        .await;
    home.login(&gw, 900);
    let (raw, r) = mcp(&home, vec![call(1, "list_grants", json!({}))]).await;
    let (err, t) = result(&r[0]);
    assert!(!err, "{t}");
    let v: Value = serde_json::from_str(&t).unwrap();
    assert_eq!(v["grants"][0]["secret_name"], "langfuse");
    assert_eq!(v["grants"][0]["allowed_origin"], "https://api.example.com");
    let mut keys: Vec<_> = v["grants"][0]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "allowed_origin",
            "expires_at",
            "mode",
            "secret_id",
            "secret_name"
        ]
    );
    assert!(!raw.contains("SHOULD_NOT_APPEAR"), "{raw}");
    assert_no_token(&raw);
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_request_sends_gateway_shape_and_returns_redacted_response() {
    let (home, gw) = (Home::new(), MockServer::start().await);
    Mock::given(method("POST"))
        .and(path("/v1/relay"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .and(body_json(json!({
            "secret_id": SECRET_ID, "version": 2, "method": "POST",
            "url": "https://api.example.com/v1/x",
            "headers": [["x-a", "b"]], "body": "{\"k\":1}"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": 201,
            "headers": [["x-echo", TOKEN]],
            "body": format!("ok [REDACTED:SECRET] token={TOKEN}")
        })))
        .expect(1)
        .mount(&gw)
        .await;
    home.login(&gw, 900);
    let (raw, r) = mcp(
        &home,
        vec![call(
            1,
            "relay_request",
            json!({"secret_id": SECRET_ID, "version": 2, "method": "POST",
                   "url": "https://api.example.com/v1/x",
                   "headers": {"x-a": "b"}, "body": "{\"k\":1}"}),
        )],
    )
    .await;
    let (err, t) = result(&r[0]);
    assert!(!err, "{t}");
    let v: Value = serde_json::from_str(&t).unwrap();
    assert_eq!(v["status"], 201);
    let body = v["body"].as_str().unwrap();
    assert!(
        body.starts_with("ok [REDACTED:SECRET] token=") && body.contains("REDACTED"),
        "{body}"
    );
    assert_eq!(v["headers"][0][0], "x-echo");
    assert_no_token(&raw);
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_request_refuses_caller_credentials_without_calling_the_gateway() {
    let (home, gw) = (Home::new(), MockServer::start().await);
    home.login(&gw, 900);
    let msgs = ["Authorization", "cookie", "Proxy-Authorization"]
        .iter()
        .enumerate()
        .map(|(i, h)| {
            call(
                i as u64,
                "relay_request",
                json!({"secret_id": SECRET_ID, "url": "https://api.example.com/",
                       "headers": {*h: "Bearer sk_live_CALLER_CANARY"}}),
            )
        })
        .collect();
    let (raw, r) = mcp(&home, msgs).await;
    assert_eq!(r.len(), 3);
    for x in &r {
        let (err, t) = result(x);
        assert!(err && t.contains("not allowed"), "{t}");
    }
    assert!(!raw.contains("CALLER_CANARY"), "{raw}");
    assert!(gw.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_denied_shows_slug_only() {
    let (home, gw) = (Home::new(), MockServer::start().await);
    Mock::given(method("POST"))
        .and(path("/v1/relay"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"error": "no_grant", "request_id": "r1", "detail": TOKEN})),
        )
        .mount(&gw)
        .await;
    home.login(&gw, 900);
    let (raw, r) = mcp(
        &home,
        vec![call(
            1,
            "relay_request",
            json!({"secret_id": SECRET_ID, "url": "https://api.example.com/"}),
        )],
    )
    .await;
    let (err, t) = result(&r[0]);
    assert!(err && t.contains("403") && t.contains("no_grant"), "{t}");
    assert_no_token(&raw);
}

#[tokio::test(flavor = "multi_thread")]
async fn not_logged_in_expired_and_loose_state_are_refused() {
    let (home, gw) = (Home::new(), MockServer::start().await);
    let (_, r) = mcp(&home, vec![call(1, "list_grants", json!({}))]).await;
    let (err, t) = result(&r[0]);
    assert!(err && t.contains("smith login --agent"), "{t}");

    home.login(&gw, 5);
    let (raw, r) = mcp(&home, vec![call(1, "list_grants", json!({}))]).await;
    let (err, t) = result(&r[0]);
    assert!(err && t.contains("expired"), "{t}");
    assert_no_token(&raw);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        home.login(&gw, 900);
        let p = home.0.join("agent.json");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (raw, r) = mcp(&home, vec![call(1, "list_grants", json!({}))]).await;
        let (err, t) = result(&r[0]);
        assert!(err && t.contains("0600"), "{t}");
        assert_no_token(&raw);
    }
    assert!(gw.received_requests().await.unwrap().is_empty());
}

/// The local-vault tools behave as before whether or not a remote login exists: they go to the
/// daemon (unreachable here) and never to the gateway.
#[tokio::test(flavor = "multi_thread")]
async fn local_vault_tools_unchanged_by_remote_mode() {
    let (home, gw) = (Home::new(), MockServer::start().await);
    let msgs = || {
        vec![
            call(1, "locksmith_list_keys", json!({})),
            call(2, "locksmith_status", json!({})),
            call(3, "locksmith_issue_token", json!({})),
            call(
                4,
                "locksmith_explain_block",
                json!({"reason": "relay_only"}),
            ),
        ]
    };
    let (_, before) = mcp(&home, msgs()).await;
    home.login(&gw, 900);
    let (raw, after) = mcp(&home, msgs()).await;
    assert_eq!(before, after);
    let (err, t) = result(&after[0]);
    assert!(err && t.contains("daemon not reachable"), "{t}");
    assert_eq!(result(&after[2]), (true, "`key` is required".to_owned()));
    let (err, t) = result(&after[3]);
    assert!(!err && t.contains("locksmith_issue_token"), "{t}");
    assert_no_token(&raw);
    assert!(gw.received_requests().await.unwrap().is_empty());
}
