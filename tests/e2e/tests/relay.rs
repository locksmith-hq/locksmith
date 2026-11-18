//! E2E for the gateway relay (S3) with agent tokens (S4 task 2.1). Requires `just up` and `just api` (dev auth, :8080, with the
//! gateway service token and OpenBao wired from infra/compose/.env.example) and a built gateway
//! (`just relay-smoke` builds it). The test starts its own gateway on a free port.
//!
//! A canary secret is written through the control plane, an agent is registered, granted the
//! secret and given a token (`POST /v1/agent-tokens`, verified by the gateway through the JWKS).
//! The secret is relayed to the WireMock upstream (which echoes it back), and the test asserts: the upstream saw it in the injected header, the relay
//! response the caller gets does not contain it in any encoding the test checks, and a response
//! to a disallowed host is refused. `just leak-scan` then covers Postgres, Loki and Tempo.

use std::env;
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

    // Agent: register, grant the secret, exchange the enrollment secret for a token.
    let enrolled = cp(&c, "/v1/agents", o, json!({ "name": uniq("relay-agent") })).await;
    let agent_id = enrolled["agent"]["id"].as_str().unwrap().to_owned();
    let enrollment = enrolled["enrollment_secret"].as_str().unwrap().to_owned();
    cp(
        &c,
        &format!("/v1/agents/{agent_id}/grants"),
        o,
        json!({ "secret_id": sid }),
    )
    .await;
    let token = cp_status(
        &c,
        "/v1/agent-tokens",
        None,
        json!({ "enrollment_secret": enrollment }),
        StatusCode::OK,
    )
    .await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();

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
        .bearer_auth(&token)
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
        .bearer_auth(&token)
        .json(&json!({
            "secret_id": sid, "version": 1, "method": "GET",
            "url": "http://127.0.0.1:9/never"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(!denied.text().await.unwrap().contains(&canary));

    // The agent sees its grant (name and origin, no value).
    let grants = c
        .get(format!("{}/v1/grants", gw.base))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(grants.status(), StatusCode::OK);
    let grants: Value = grants.json().await.unwrap();
    assert_eq!(grants["agent_id"], agent_id.as_str());
    assert_eq!(grants["grants"][0]["secret_name"], "UPSTREAM_KEY");
    assert_eq!(grants["grants"][0]["allowed_origin"], wiremock().as_str());
    assert!(!grants.to_string().contains(&canary));

    // No agent token, or a forged one: 401.
    let forged = format!("{}x", token);
    let refused = c
        .post(format!("{}/v1/relay", gw.base))
        .bearer_auth(&forged)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let anon = c
        .post(format!("{}/v1/relay", gw.base))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);
}
