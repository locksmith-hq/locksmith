//! E2E for the agent connector (S4 task 5.1). Requires `just up`, `just api` and a built gateway,
//! `smith` and `locksmith-mcp` (`just connector-smoke` builds them).
//!
//! An org, a canary secret, an agent and a grant are created through the control plane. The test
//! then acts as the agent only through the shipped binaries: `smith login --agent`, `smith grants`,
//! `smith relay` and the `locksmith-mcp` tools `list_grants` and `relay_request`. It asserts the
//! WireMock upstream saw the injected canary, and that nothing the agent sees (stdout, stderr, the
//! 0600 state file, MCP replies) contains it. `just leak-scan` then covers Postgres, Loki, Tempo.

use std::env;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ls_e2e::{api, mint_canary, root, uniq, wiremock};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};

const SERVICE_TOKEN: &str = "dev-only-gateway-service-token-0123456789";

async fn cp(c: &Client, path: &str, org: Option<&str>, body: Value) -> Value {
    cp_status(c, path, org, body, StatusCode::CREATED).await
}

async fn cp_status(
    c: &Client,
    path: &str,
    org: Option<&str>,
    body: Value,
    expected: StatusCode,
) -> Value {
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
    assert_eq!(status, expected, "POST {path}");
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
    let dir = std::env::temp_dir().join(uniq("connector-e2e"));
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

fn bin(name: &str, var: &str) -> String {
    env::var(var).unwrap_or_else(|_| format!("{}/target/debug/{name}", root()))
}

/// Run a binary as the agent: isolated config dir, no ambient credentials.
fn agent_cmd(program: &str, home: &std::path::Path, gw: &str) -> Command {
    let mut c = Command::new(program);
    c.env_clear()
        .env("PATH", env::var("PATH").unwrap_or_default())
        .env("LOCKSMITH_HOME", home)
        .env("LOCKSMITH_CONTROL_PLANE_URL", api())
        .env("LOCKSMITH_GATEWAY_URL", gw);
    c
}

fn id_of(v: &Value) -> String {
    v["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn agent_uses_a_credential_it_never_holds() {
    let c = Client::new();
    let canary = mint_canary();

    let org = id_of(&cp(&c, "/v1/orgs", None, json!({ "name": uniq("conn") })).await);
    let o = Some(org.as_str());
    let pid = id_of(&cp(&c, "/v1/projects", o, json!({ "name": "p" })).await);
    let eid = id_of(
        &cp(
            &c,
            &format!("/v1/projects/{pid}/environments"),
            o,
            json!({ "name": "e" }),
        )
        .await,
    );
    let base = format!("/v1/projects/{pid}/environments/{eid}/secrets");
    let sid = id_of(&cp(&c, &base, o, json!({ "name": "UPSTREAM_KEY" })).await);
    cp(&c, &format!("{base}/{sid}/versions"), o, json!({ "value": canary })).await;

    let enrolled = cp(&c, "/v1/agents", o, json!({ "name": uniq("conn-agent") })).await;
    let agent_id = id_of(&enrolled["agent"]);
    let enrollment = enrolled["enrollment_secret"].as_str().unwrap().to_owned();
    cp(
        &c,
        &format!("/v1/agents/{agent_id}/grants"),
        o,
        json!({ "secret_id": sid }),
    )
    .await;

    // Upstream stub that echoes the secret (the gateway must redact it).
    let path = format!("/{}", uniq("conn-echo"));
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
    let home = std::env::temp_dir().join(uniq("connector-home"));
    std::fs::create_dir_all(&home).unwrap();
    let smith = bin("smith", "LOCKSMITH_SMITH_BIN");
    let mcp = bin("locksmith-mcp", "LOCKSMITH_MCP_BIN");
    let url = format!("{}{path}", wiremock());

    // Everything the agent can observe is collected here and checked for the canary and the
    // enrollment secret at the end.
    let mut observed = String::new();
    let mut seen = |o: &std::process::Output| {
        observed.push_str(&String::from_utf8_lossy(&o.stdout));
        observed.push_str(&String::from_utf8_lossy(&o.stderr));
    };

    // smith login --agent (enrollment secret on the env, as a launcher would supply it).
    let out = agent_cmd(&smith, &home, &gw.base)
        .env("LOCKSMITH_ENROLLMENT_SECRET", &enrollment)
        .args(["login", "--agent"])
        .output()
        .unwrap();
    seen(&out);
    assert!(out.status.success(), "smith login --agent failed");

    // State file: 0600, token present, enrollment secret not stored.
    let state_path = home.join("agent.json");
    let state = std::fs::read_to_string(&state_path).expect("agent.json written");
    assert!(!state.contains(&enrollment), "enrollment secret was stored");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&state_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "state file must be 0600");
    }

    // smith grants: shows the name and origin, never a value.
    let out = agent_cmd(&smith, &home, &gw.base)
        .args(["--json", "grants"])
        .output()
        .unwrap();
    seen(&out);
    assert!(out.status.success(), "smith grants failed");
    let g: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(g["grants"][0]["secret_name"], "UPSTREAM_KEY");

    // smith relay: the upstream response comes back redacted.
    let out = agent_cmd(&smith, &home, &gw.base)
        .args(["relay", "--secret-id", &sid, &url])
        .output()
        .unwrap();
    seen(&out);
    assert!(out.status.success(), "smith relay failed");
    assert!(String::from_utf8_lossy(&out.stdout).contains("REDACTED"));

    // MCP tools over stdio: list_grants and relay_request.
    let mut child = agent_cmd(&mcp, &home, &gw.base)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start locksmith-mcp (run `just connector-smoke`)");
    let mut stdin = child.stdin.take().unwrap();
    let msgs = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_grants","arguments":{}}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"relay_request","arguments":{"secret_id": sid, "method":"GET", "url": url}}}),
    ];
    for m in &msgs {
        writeln!(stdin, "{m}").unwrap();
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    seen(&out);
    let replies = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(replies.contains("UPSTREAM_KEY"), "list_grants missing the grant");
    assert!(replies.contains("REDACTED"), "relay_request not redacted");

    // The upstream saw the injected secret at least twice (smith and MCP); the agent never did.
    let journal: Value = c
        .get(format!("{}/__admin/requests", wiremock()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hits = journal["requests"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| {
            r["request"]["url"] == path.as_str()
                && r["request"]["headers"]["Authorization"]
                    .as_str()
                    .is_some_and(|h| h == format!("Bearer {canary}"))
        })
        .count();
    assert!(hits >= 2, "upstream saw the injected header {hits} times, expected 2");

    observed.push_str(&state);
    assert!(!observed.contains(&canary), "the agent observed the secret");
    assert!(!observed.contains(&enrollment), "the enrollment secret leaked");
    let _ = std::fs::remove_dir_all(&home);
}
