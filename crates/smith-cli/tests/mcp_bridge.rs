//! `smith mcp bridge <name>` (m2-mcp-gateway task 6.2) against a mock control plane and gateway.
mod common;

use std::io::Write;
use std::process::Output;

use common::Home;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ENROLLMENT: &str = "lse_ENROLLMENT_CANARY_0123456789abcdef";
const TOKEN: &str = "eyJhbGciOiJFZERTQSJ9.TOKEN_CANARY_PAYLOAD_0123456789.SIGNATURE_CANARY_abcdef";
const ENROLL_ENV: &str = "LOCKSMITH_ENROLLMENT_SECRET";

async fn run(home: &Home, args: &[&str], stdin: &str, env: &[(&str, &str)]) -> Output {
    let mut c = home.cmd(args);
    c.env_remove(ENROLL_ENV);
    for (k, v) in env {
        c.env(k, v);
    }
    let stdin = stdin.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut child = c.spawn().unwrap();
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// Log in against a mock control plane; the token lives `expires_in` seconds.
async fn login(home: &Home, gw: &MockServer, expires_in: u64) {
    let cp = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent-tokens"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": TOKEN, "token_type": "Bearer", "expires_in": expires_in,
            "expires_at": "2099-01-01T00:00:00Z"
        })))
        .mount(&cp)
        .await;
    let (cpu, gwu) = (cp.uri(), gw.uri());
    let o = run(
        home,
        &[
            "login",
            "--agent",
            "--control-plane-url",
            cpu.as_str(),
            "--gateway-url",
            gwu.as_str(),
        ],
        "",
        &[(ENROLL_ENV, ENROLLMENT)],
    )
    .await;
    assert!(o.status.success(), "{}", text(&o));
}

fn lines(o: &Output) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|_| panic!("not JSON: {l}")))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn bridge_forwards_a_call_with_the_token_and_prints_the_answer() {
    let (home, gw) = (Home::new(), MockServer::start().await);
    login(&home, &gw, 900).await;
    // The gateway answers a tools/list as SSE and echoes the agent token in a description, which
    // the bridge must still redact.
    let answer = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"tools\":[{{\"name\":\"echo\",\"description\":\"{TOKEN}\"}}]}}}}"
    );
    Mock::given(method("POST"))
        .and(path("/mcp/upstream/github"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .insert_header("mcp-session-id", "sess-1")
                .set_body_string(format!("event: message\ndata: {answer}\n\n")),
        )
        .expect(1)
        .mount(&gw)
        .await;
    let input = concat!(
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        "\n",
    );
    let o = run(&home, &["mcp", "bridge", "github"], input, &[]).await;
    assert!(o.status.success(), "{}", text(&o));
    let out = lines(&o);
    // The notification is not answered or forwarded; the request gets its answer.
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(out[0]["id"], 2);
    assert_eq!(out[0]["result"]["tools"][0]["name"], "echo");
    assert!(!text(&o).contains("TOKEN_CANARY"), "token reached output");
}

#[tokio::test(flavor = "multi_thread")]
async fn bridge_refuses_other_methods_and_never_sends_them() {
    let (home, gw) = (Home::new(), MockServer::start().await);
    login(&home, &gw, 900).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&gw)
        .await;
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"resources/list"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"sampling/createMessage"}"#,
        "\n",
        r#"[{"jsonrpc":"2.0","id":3,"method":"tools/list"}]"#,
        "\n",
        "not json\n",
    );
    let o = run(&home, &["mcp", "bridge", "github"], input, &[]).await;
    assert!(o.status.success(), "{}", text(&o));
    let out = lines(&o);
    assert_eq!(out.len(), 4);
    assert!(out.iter().all(|m| m["error"]["code"].is_i64()), "{out:?}");
    assert_eq!(out[0]["id"], 1);
    assert_eq!(out[1]["id"], 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_token_is_an_error_that_says_to_log_in_again() {
    let (home, gw) = (Home::new(), MockServer::start().await);
    // Inside the 30 s freshness margin: already unusable.
    login(&home, &gw, 10).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&gw)
        .await;
    let input = "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/list\"}\n";
    let o = run(&home, &["mcp", "bridge", "github"], input, &[]).await;
    assert!(o.status.success(), "{}", text(&o));
    let out = lines(&o);
    assert_eq!(out[0]["id"], 9);
    let msg = out[0]["error"]["message"].as_str().unwrap();
    assert!(msg.contains("smith login --agent"), "{msg}");
    assert!(!text(&o).contains("TOKEN_CANARY"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_upstream_name_is_a_usage_error() {
    let home = Home::new();
    for name in ["Bad", "a/b", "../x", ""] {
        let o = run(&home, &["mcp", "bridge", name], "", &[]).await;
        assert_eq!(o.status.code(), Some(2), "{name}: {}", text(&o));
    }
}

async fn run_in(home: &Home, dir: &std::path::Path, args: &[&str]) -> Output {
    let mut c = home.cmd(args);
    c.env_remove(ENROLL_ENV).current_dir(dir);
    tokio::task::spawn_blocking(move || {
        let mut child = c.spawn().unwrap();
        drop(child.stdin.take());
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap()
}

/// Task 6.3: `smith init --mcp-gateway` swaps the entry of a granted upstream for the bridge,
/// leaves other entries alone, masks the old values in the preview, and is idempotent.
#[tokio::test(flavor = "multi_thread")]
async fn init_mcp_gateway_rewrites_granted_entries_only() {
    const OLD: &str = "ghp_OLD_ENTRY_CANARY_0123456789";
    const OTHER: &str = "lin_OTHER_ENTRY_0123456789";
    let (home, gw) = (Home::new(), MockServer::start().await);
    login(&home, &gw, 900).await;
    Mock::given(method("GET"))
        .and(path("/v1/mcp/upstreams"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"upstreams": ["github"]})),
        )
        .mount(&gw)
        .await;
    let repo = common::Repo::new();
    std::fs::create_dir_all(repo.0.join(".claude")).unwrap();
    let mcp = format!(
        r#"{{"mcpServers":{{"github":{{"url":"https://api.example/mcp","headers":{{"Authorization":"Bearer {OLD}"}}}},"linear":{{"command":"npx","env":{{"LINEAR_API_KEY":"{OTHER}"}}}}}}}}"#
    );
    repo.write(".mcp.json", &mcp);

    // Dry run: the preview names the entry, masks its values and writes nothing.
    let o = run_in(&home, &repo.0, &["init", "--mcp-gateway", "--dry-run"]).await;
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    assert!(
        out.contains("smith mcp bridge") && out.contains("is not saved"),
        "{out}"
    );
    assert!(
        !out.contains("api.example/mcp"),
        "preview shows the old URL: {out}"
    );
    assert!(!out.contains(TOKEN), "{out}");
    assert!(
        !out.contains(OLD),
        "the replaced entry's token is shown: {out}"
    );
    assert_eq!(
        std::fs::read_to_string(repo.0.join(".mcp.json")).unwrap(),
        mcp
    );

    let o = run_in(&home, &repo.0, &["init", "--mcp-gateway", "--yes"]).await;
    assert!(o.status.success(), "{}", text(&o));
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(repo.0.join(".mcp.json")).unwrap()).unwrap();
    assert_eq!(
        v["mcpServers"]["github"],
        serde_json::json!({"command":"smith","args":["mcp","bridge","github"]})
    );
    assert_eq!(v["mcpServers"]["linear"]["env"]["LINEAR_API_KEY"], OTHER);
    assert!(
        v["mcpServers"]["locksmith"].is_object(),
        "the locksmith entry is still added"
    );
    let raw = std::fs::read_to_string(repo.0.join(".mcp.json")).unwrap();
    assert!(!raw.contains("api.example") && !raw.contains("Bearer"));

    let o = run_in(&home, &repo.0, &["init", "--mcp-gateway", "--yes"]).await;
    assert!(text(&o).contains("already set up"), "{}", text(&o));
    assert_eq!(
        std::fs::read_to_string(repo.0.join(".mcp.json")).unwrap(),
        raw
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn init_mcp_gateway_needs_a_login() {
    let home = Home::new();
    let repo = common::Repo::new();
    let o = run_in(&home, &repo.0, &["init", "--mcp-gateway", "--yes"]).await;
    assert!(!o.status.success());
    assert!(text(&o).contains("smith login --agent"), "{}", text(&o));
}
