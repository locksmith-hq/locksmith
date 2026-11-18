//! `smith login --agent`, `smith grants`, `smith relay` against a mock control plane and gateway.
mod common;

use std::io::Write;
use std::process::Output;

use common::Home;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ENROLLMENT: &str = "lse_ENROLLMENT_CANARY_0123456789abcdef";
const TOKEN: &str = "eyJhbGciOiJFZERTQSJ9.TOKEN_CANARY_PAYLOAD_0123456789.SIGNATURE_CANARY_abcdef";
const SECRET_ID: &str = "0191a3b2-7c1e-7a3f-8b2d-5e6f7a8b9c0d";

/// Run `smith` with `args`, optional stdin and extra env, off the async worker.
async fn smith(home: &Home, args: &[&str], stdin: &str, env: &[(&str, &str)]) -> Output {
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

const ENROLL_ENV: &str = "LOCKSMITH_ENROLLMENT_SECRET";

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

async fn token_server(expires_in: u64) -> MockServer {
    let cp = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent-tokens"))
        .and(body_json(
            serde_json::json!({ "enrollment_secret": ENROLLMENT }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": TOKEN, "token_type": "Bearer", "expires_in": expires_in,
            "expires_at": "2099-01-01T00:00:00Z"
        })))
        .mount(&cp)
        .await;
    cp
}

async fn login(home: &Home, cp: &MockServer, gw: &MockServer, via_env: bool) -> Output {
    let (cpu, gwu) = (cp.uri(), gw.uri());
    let args = [
        "login",
        "--agent",
        "--control-plane-url",
        cpu.as_str(),
        "--gateway-url",
        gwu.as_str(),
    ];
    if via_env {
        smith(home, &args, "", &[(ENROLL_ENV, ENROLLMENT)]).await
    } else {
        smith(home, &args, &format!("{ENROLLMENT}\n"), &[]).await
    }
}

fn state_path(home: &Home) -> std::path::PathBuf {
    home.0.join("agent.json")
}

#[tokio::test(flavor = "multi_thread")]
async fn login_stdin_writes_0600_state_without_enrollment_secret() {
    let (home, cp, gw) = (
        Home::new(),
        token_server(900).await,
        MockServer::start().await,
    );
    let o = login(&home, &cp, &gw, false).await;
    assert!(o.status.success(), "{}", text(&o));
    let out = text(&o);
    assert!(!out.contains(ENROLLMENT) && !out.contains(TOKEN), "{out}");
    let raw = std::fs::read_to_string(state_path(&home)).unwrap();
    assert!(raw.contains(TOKEN));
    assert!(
        !raw.contains(ENROLLMENT),
        "enrollment secret must not be stored"
    );
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "access_token",
            "control_plane_url",
            "expires_at_unix",
            "gateway_url"
        ]
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(state_path(&home))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn login_env_works_and_json_output_is_clean() {
    let (home, cp, gw) = (
        Home::new(),
        token_server(900).await,
        MockServer::start().await,
    );
    let (cpu, gwu) = (cp.uri(), gw.uri());
    let o = smith(
        &home,
        &[
            "--json",
            "login",
            "--agent",
            "--control-plane-url",
            &cpu,
            "--gateway-url",
            &gwu,
        ],
        "",
        &[(ENROLL_ENV, ENROLLMENT)],
    )
    .await;
    assert!(o.status.success(), "{}", text(&o));
    let out = text(&o);
    assert!(!out.contains(ENROLLMENT) && !out.contains(TOKEN));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["status"], "logged_in");
}

#[tokio::test(flavor = "multi_thread")]
async fn login_rejected_prints_no_secret() {
    let (home, gw) = (Home::new(), MockServer::start().await);
    let cp = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent-tokens"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string(format!("{{\"error\":\"echo {ENROLLMENT}\"}}")),
        )
        .mount(&cp)
        .await;
    let o = login(&home, &cp, &gw, false).await;
    assert!(!o.status.success());
    let out = text(&o);
    assert!(out.contains("401"), "{out}");
    assert!(!out.contains(ENROLLMENT), "{out}");
    assert!(!state_path(&home).exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn login_refuses_plain_http_to_remote_host() {
    let home = Home::new();
    let o = smith(
        &home,
        &[
            "login",
            "--agent",
            "--control-plane-url",
            "http://cp.example.com",
            "--gateway-url",
            "https://gw.example.com",
        ],
        &format!("{ENROLLMENT}\n"),
        &[],
    )
    .await;
    assert!(!o.status.success());
    assert!(!text(&o).contains(ENROLLMENT));
}

#[tokio::test(flavor = "multi_thread")]
async fn grants_lists_names_and_hosts_only() {
    let (home, cp, gw) = (
        Home::new(),
        token_server(900).await,
        MockServer::start().await,
    );
    Mock::given(method("GET"))
        .and(path("/v1/grants"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "agent_id": "0191a3b2-0000-7000-8000-000000000001",
            "grants": [{
                "secret_id": SECRET_ID, "secret_name": "langfuse", "mode": "relay",
                "expires_at": null, "allowed_origin": "https://api.example.com",
                "value": "sk_live_SHOULD_NOT_APPEAR"
            }]
        })))
        .mount(&gw)
        .await;
    assert!(login(&home, &cp, &gw, false).await.status.success());
    let o = smith(&home, &["grants"], "", &[]).await;
    assert!(o.status.success(), "{}", text(&o));
    let out = text(&o);
    assert!(
        out.contains("langfuse") && out.contains("https://api.example.com"),
        "{out}"
    );
    assert!(
        !out.contains("SHOULD_NOT_APPEAR") && !out.contains(TOKEN),
        "{out}"
    );
    let j = smith(&home, &["--json", "grants"], "", &[]).await;
    let v: serde_json::Value = serde_json::from_slice(&j.stdout).unwrap();
    assert_eq!(v["grants"][0]["secret_name"], "langfuse");
    assert!(!text(&j).contains("SHOULD_NOT_APPEAR"));
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_sends_request_and_redacts_output() {
    let (home, cp, gw) = (
        Home::new(),
        token_server(900).await,
        MockServer::start().await,
    );
    Mock::given(method("POST"))
        .and(path("/v1/relay"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .and(body_json(serde_json::json!({
            "secret_id": SECRET_ID, "version": 2, "method": "POST",
            "url": "https://api.example.com/v1/x",
            "headers": [["x-a", "b"]], "body": "{\"k\":1}"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": 201,
            "headers": [["x-echo", TOKEN]],
            "body": format!("ok [REDACTED:SECRET] token={TOKEN}")
        })))
        .mount(&gw)
        .await;
    assert!(login(&home, &cp, &gw, true).await.status.success());
    let args = [
        "relay",
        "--secret-id",
        SECRET_ID,
        "--version",
        "2",
        "-X",
        "POST",
        "-H",
        "x-a: b",
        "--data",
        "{\"k\":1}",
        "--show",
        "all",
        "https://api.example.com/v1/x",
    ];
    let o = smith(&home, &args, "", &[]).await;
    assert!(o.status.success(), "{}", text(&o));
    let out = text(&o);
    assert!(
        out.contains("HTTP 201") && out.contains("[REDACTED:SECRET]"),
        "{out}"
    );
    assert!(
        !out.contains(TOKEN) && !out.contains("TOKEN_CANARY_PAYLOAD"),
        "{out}"
    );
    let mut j = vec!["--json"];
    j.extend_from_slice(&args);
    let o = smith(&home, &j, "", &[]).await;
    assert!(!text(&o).contains("TOKEN_CANARY_PAYLOAD"));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["status"], 201);
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_denied_shows_slug_only() {
    let (home, cp, gw) = (
        Home::new(),
        token_server(900).await,
        MockServer::start().await,
    );
    Mock::given(method("POST"))
        .and(path("/v1/relay"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(serde_json::json!({"error": "no_grant", "request_id": "r1"})),
        )
        .mount(&gw)
        .await;
    assert!(login(&home, &cp, &gw, false).await.status.success());
    let o = smith(
        &home,
        &[
            "relay",
            "--secret-id",
            SECRET_ID,
            "https://api.example.com/",
        ],
        "",
        &[],
    )
    .await;
    assert!(!o.status.success());
    let out = text(&o);
    assert!(out.contains("403") && out.contains("no_grant"), "{out}");
    assert!(!out.contains(TOKEN));
}

#[tokio::test(flavor = "multi_thread")]
async fn not_logged_in_and_expired_token_are_refused() {
    let home = Home::new();
    let o = smith(&home, &["grants"], "", &[]).await;
    assert!(!o.status.success());
    assert!(text(&o).contains("smith login --agent"));

    let (cp, gw) = (token_server(5).await, MockServer::start().await);
    assert!(login(&home, &cp, &gw, false).await.status.success());
    let o = smith(&home, &["grants"], "", &[]).await;
    assert!(!o.status.success());
    let out = text(&o);
    assert!(out.contains("expired") && !out.contains(TOKEN), "{out}");
    assert!(gw.received_requests().await.unwrap().is_empty());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn state_file_with_loose_permissions_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let (home, cp, gw) = (
        Home::new(),
        token_server(900).await,
        MockServer::start().await,
    );
    assert!(login(&home, &cp, &gw, false).await.status.success());
    std::fs::set_permissions(state_path(&home), std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = smith(&home, &["grants"], "", &[]).await;
    assert!(!o.status.success());
    assert!(text(&o).contains("0600"));
    assert!(gw.received_requests().await.unwrap().is_empty());
}
