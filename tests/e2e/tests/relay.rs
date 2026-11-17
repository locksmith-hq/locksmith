//! E2E for the S3 gateway relay. Requires `just up` and `just api` (dev auth, :8080, with the
//! gateway service token and OpenBao wired from infra/compose/.env.example) and a built gateway
//! (`just relay-smoke` builds it). The test starts its own gateway on a free port.
//!
//! A canary secret is written through the control plane, relayed to the WireMock upstream (which
//! echoes it back), and the test asserts: the upstream saw it in the injected header, the relay
//! response the caller gets does not contain it in any encoding the test checks, and a response
//! to a disallowed host is refused. `just leak-scan` then covers Postgres, Loki and Tempo.

use std::env;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use reqwest::{Client, StatusCode};
use serde_json::{Value, json};

const CALLER_TOKEN: &str = "dev-only-gateway-caller-token-0123456789ab";
const SERVICE_TOKEN: &str = "dev-only-gateway-service-token-0123456789";

fn root() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../..")
}

fn api() -> String {
    env::var("E2E_API_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into())
}

fn wiremock() -> String {
    env::var("E2E_WIREMOCK_URL").unwrap_or_else(|_| "http://127.0.0.1:8089".into())
}

fn uniq(prefix: &str) -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{t}")
}

/// A fresh canary from the leak oracle (the gitignored canary file); never printed.
fn mint_canary() -> String {
    let file = env::var("LOCKSMITH_CANARIES")
        .unwrap_or_else(|_| format!("{}/infra/compose/.canaries", root()));
    let out = Command::new("python3")
        .args([
            "-I",
            &format!("{}/tests/kit/oracle.py", root()),
            "canary-new",
            "--file",
            &file,
        ])
        .output()
        .expect("run oracle");
    assert!(out.status.success(), "oracle canary-new failed");
    std::fs::read_to_string(&file)
        .unwrap()
        .lines()
        .last()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned()
}

async fn cp(c: &Client, path: &str, org: Option<&str>, body: Value) -> Value {
    let mut req = c.post(format!("{}{path}", api())).json(&body);
    if let Some(o) = org {
        req = req.header("X-Locksmith-Dev-Org", o);
    }
    let r = req
        .send()
        .await
        .expect("reach locksmith-api (is `just api` running?)");
    let status = r.status();
    let v: Value = r.json().await.unwrap_or(Value::Null);
    assert_eq!(status, StatusCode::CREATED, "POST {path}: {v}");
    v
}

struct Gateway {
    child: Child,
    base: String,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start the built gateway binary with a bindings file, wait for `/readyz`.
async fn start_gateway(c: &Client, bindings: &str) -> Gateway {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = std::env::temp_dir().join(uniq("relay-e2e"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bindings.toml");
    std::fs::write(&path, bindings).unwrap();

    let bin = env::var("LOCKSMITH_GATEWAY_BIN")
        .unwrap_or_else(|_| format!("{}/target/debug/locksmith-gateway", root()));
    let child = Command::new(bin)
        .env("LOCKSMITH_GATEWAY_BIND", format!("127.0.0.1:{port}"))
        .env(
            "DATABASE_URL",
            "postgres://locksmith_app:locksmith-app-dev-only@127.0.0.1:5432/locksmith",
        )
        .env("LOCKSMITH_GATEWAY_CALLER_TOKEN", CALLER_TOKEN)
        .env("LOCKSMITH_GATEWAY_SERVICE_TOKEN", SERVICE_TOKEN)
        .env("LOCKSMITH_CONTROL_PLANE_URL", api())
        .env("OPENBAO_ADDR", "http://127.0.0.1:8200")
        .env("OPENBAO_GATEWAY_TOKEN", "dev-only-gateway")
        .env("LOCKSMITH_GATEWAY_BINDINGS", &path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start locksmith-gateway (run `just relay-smoke` to build it)");
    let gw = Gateway {
        child,
        base: format!("http://127.0.0.1:{port}"),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(r) = c.get(format!("{}/readyz", gw.base)).send().await
            && r.status().is_success()
        {
            return gw;
        }
        assert!(Instant::now() < deadline, "gateway did not become ready");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test]
async fn relay_injects_secret_upstream_and_never_returns_it() {
    let c = Client::new();
    let canary = mint_canary();

    // Control plane: org, project, environment, secret, version holding the canary.
    let org = cp(&c, "/v1/orgs", None, json!({ "name": uniq("relay") })).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let o = Some(org.as_str());
    let pid = cp(&c, "/v1/projects", o, json!({ "name": "p" })).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let eid = cp(
        &c,
        &format!("/v1/projects/{pid}/environments"),
        o,
        json!({ "name": "e" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let base = format!("/v1/projects/{pid}/environments/{eid}/secrets");
    let sid = cp(&c, &base, o, json!({ "name": "UPSTREAM_KEY" })).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    cp(
        &c,
        &format!("{base}/{sid}/versions"),
        o,
        json!({ "value": canary }),
    )
    .await;

    // Upstream stub: echoes the secret in the body (the gateway must redact it).
    let path = format!("/{}", uniq("relay-echo"));
    let stub = json!({
        "request": { "method": "GET", "url": path },
        "response": { "status": 200, "jsonBody": { "echo": canary, "ok": true } }
    });
    let r = c
        .post(format!("{}/__admin/mappings", wiremock()))
        .json(&stub)
        .send()
        .await
        .expect("reach WireMock (is `just up` running?)");
    assert!(r.status().is_success(), "stub: {}", r.status());

    let bindings = format!(
        "org_id = \"{org}\"\n[[binding]]\nsecret_id = \"{sid}\"\norigin = \"{origin}\"\nheader = \"Authorization\"\ntemplate = \"Bearer {{secret}}\"\nallow_private_hosts = true\n",
        origin = wiremock()
    );
    let gw = start_gateway(&c, &bindings).await;

    let resp = c
        .post(format!("{}/v1/relay", gw.base))
        .bearer_auth(CALLER_TOKEN)
        .json(&json!({
            "secret_id": sid, "version": 1, "method": "GET",
            "url": format!("{}{path}", wiremock())
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let text = resp.text().await.unwrap();
    assert!(!text.contains(&canary), "relay response leaked the secret");
    assert!(text.contains("REDACTED"), "echoed secret was not redacted");

    // The upstream saw the secret in the injected header.
    let journal: Value = c
        .get(format!("{}/__admin/requests", wiremock()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let seen = journal["requests"].as_array().unwrap().iter().any(|r| {
        r["request"]["url"] == path.as_str()
            && r["request"]["headers"]["Authorization"]
                .as_str()
                .is_some_and(|h| h == format!("Bearer {canary}"))
    });
    assert!(seen, "upstream did not receive the injected header");

    // A host that is not bound is refused and makes no upstream call.
    let denied = c
        .post(format!("{}/v1/relay", gw.base))
        .bearer_auth(CALLER_TOKEN)
        .json(&json!({
            "secret_id": sid, "version": 1, "method": "GET",
            "url": "http://127.0.0.1:9/never"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(!denied.text().await.unwrap().contains(&canary));

    // No caller token: 401.
    let anon = c
        .post(format!("{}/v1/relay", gw.base))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);
}
