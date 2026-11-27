//! m2-mcp-gateway task 8.1: an agent reaches an upstream MCP server through the gateway with
//! `smith mcp bridge`, never holding the upstream credential. Requires `just up`, `just api` and
//! built `locksmith-gateway` and `smith` (`just mcp-gateway-smoke` builds them).
//!
//! The upstream is `tests/adversarial/fixtures/mcp_upstream.py` in `echo-credential` mode (it
//! reflects the credential it receives into results). An org, a secret holding a fake upstream key,
//! an agent with a `relay` grant and a gateway with an `[[mcp_upstream]]` (`list_issues` allow,
//! `create_issue` hold, `delete_repository` deny, `echo` hide) are created; the test then acts as
//! the agent only through `smith login --agent` and `smith mcp bridge github`, driven by a scripted
//! MCP client on its stdin. It asserts the tool list (allow, hold and deny shown; hide absent), an
//! allowed call's redacted result, `deny` and `hold` refused with their slugs and no upstream call,
//! the ledger events, the Bindings inventory row and that the agent HOME holds no upstream key.
//!
//! Skips (passes with a note) without the stack or `python3`; `E2E_REQUIRE_MCP_GATEWAY=1` makes
//! that a failure. The key is a fake and is never printed.

use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ls_e2e::{api, root, uniq};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};

const SERVICE_TOKEN: &str = "dev-only-gateway-service-token-0123456789";
/// Fake upstream key; it must reach the upstream only.
const UPSTREAM_KEY: &str = "ls-mcp-smoke-fake-upstream-key-Qw7Zr2LmN8";

fn id_of(v: &Value) -> String {
    v["id"].as_str().unwrap().to_owned()
}

fn bin(name: &str, var: &str) -> String {
    env::var(var).unwrap_or_else(|_| format!("{}/target/debug/{name}", root()))
}

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn cp(
    c: &Client,
    method: &str,
    path: &str,
    org: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let url = format!("{}{path}", api());
    let mut req = if method == "GET" {
        c.get(url)
    } else {
        c.post(url)
    };
    if let Some(b) = body {
        req = req.json(&b);
    }
    if let Some(o) = org {
        req = req.header("X-Locksmith-Dev-Org", o);
    }
    let r = req
        .send()
        .await
        .expect("reach locksmith-api (is `just api` running?)");
    let status = r.status();
    (status, r.json().await.unwrap_or(Value::Null))
}

async fn create(c: &Client, path: &str, org: Option<&str>, body: Value) -> Value {
    let (st, v) = cp(c, "POST", path, org, Some(body)).await;
    assert_eq!(st, StatusCode::CREATED, "POST {path}");
    v
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                files(&p, out);
            } else {
                out.push(p);
            }
        }
    }
}

fn agent_cmd(program: &str, home: &Path, gw: &str) -> Command {
    let mut c = Command::new(program);
    c.env_clear()
        .env("PATH", env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("LOCKSMITH_HOME", home.join(".locksmith"))
        .env("LOCKSMITH_CONTROL_PLANE_URL", api())
        .env("LOCKSMITH_GATEWAY_URL", gw);
    c
}

/// The upstream fixture; its port file is read once it is up.
fn start_upstream(dir: &Path) -> Option<(Proc, u16, PathBuf)> {
    let port_file = dir.join("up.port");
    let log = dir.join("up-headers.log");
    let child = Command::new("python3")
        .arg("-I")
        .arg(format!(
            "{}/tests/adversarial/fixtures/mcp_upstream.py",
            root()
        ))
        .args(["echo-credential"])
        .arg(&port_file)
        .arg(&log)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let p = Proc(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(s) = std::fs::read_to_string(&port_file)
            && let Ok(port) = s.trim().parse::<u16>()
        {
            return Some((p, port, log));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

async fn start_gateway(c: &Client, dir: &Path, bindings: &str) -> (Proc, String) {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let path = dir.join("bindings.toml");
    std::fs::write(&path, bindings).unwrap();
    let child = Command::new(bin("locksmith-gateway", "LOCKSMITH_GATEWAY_BIN"))
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
        .expect("start locksmith-gateway (run `just mcp-gateway-smoke` to build it)");
    let gw = Proc(child);
    let base = format!("http://127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(r) = c.get(format!("{base}/readyz")).send().await
            && r.status().is_success()
        {
            return (gw, base);
        }
        assert!(Instant::now() < deadline, "gateway did not become ready");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Run `smith mcp bridge github` with `lines` on stdin; the JSON-RPC replies by id.
fn run_bridge(smith: &str, home: &Path, gw: &str, lines: &[Value]) -> (Vec<Value>, String) {
    let mut child = agent_cmd(smith, home, gw)
        .args(["mcp", "bridge", "github"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run smith mcp bridge");
    {
        let mut stdin = child.stdin.take().unwrap();
        for l in lines {
            writeln!(stdin, "{l}").unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let replies = stdout
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    (replies, format!("{stdout}{stderr}"))
}

fn reply<'a>(replies: &'a [Value], id: &str) -> &'a Value {
    replies
        .iter()
        .find(|r| r["id"] == json!(id))
        .unwrap_or_else(|| panic!("no reply for {id}"))
}

#[tokio::test]
async fn agent_uses_an_upstream_mcp_server_without_holding_its_key() {
    let required = env::var("E2E_REQUIRE_MCP_GATEWAY").is_ok();
    let c = Client::new();
    let dir = env::temp_dir().join(uniq("mcp-gw-smoke"));
    std::fs::create_dir_all(&dir).unwrap();
    let Some((_up, up_port, up_log)) = start_upstream(&dir) else {
        assert!(
            !required,
            "python3 or the upstream fixture is unavailable and E2E_REQUIRE_MCP_GATEWAY is set"
        );
        eprintln!("skipped: the upstream MCP fixture did not start (python3 missing?)");
        return;
    };
    if c.get(format!("{}/readyz", api())).send().await.is_err() {
        assert!(
            !required,
            "the control plane is down and E2E_REQUIRE_MCP_GATEWAY is set"
        );
        eprintln!(
            "skipped: no control plane at {} (run `just up` and `just api`)",
            api()
        );
        return;
    }

    let org = id_of(&create(&c, "/v1/orgs", None, json!({ "name": uniq("mcpgw") })).await);
    let o = Some(org.as_str());
    let pid = id_of(&create(&c, "/v1/projects", o, json!({ "name": "p" })).await);
    let eid = id_of(
        &create(
            &c,
            &format!("/v1/projects/{pid}/environments"),
            o,
            json!({ "name": "e" }),
        )
        .await,
    );
    let base = format!("/v1/projects/{pid}/environments/{eid}/secrets");
    let sid = id_of(&create(&c, &base, o, json!({ "name": "UPSTREAM_MCP_KEY" })).await);
    create(
        &c,
        &format!("{base}/{sid}/versions"),
        o,
        json!({ "value": UPSTREAM_KEY }),
    )
    .await;
    let enrolled = create(&c, "/v1/agents", o, json!({ "name": uniq("mcp-agent") })).await;
    let agent_id = id_of(&enrolled["agent"]);
    let enrollment = enrolled["enrollment_secret"].as_str().unwrap().to_owned();
    create(
        &c,
        &format!("/v1/agents/{agent_id}/grants"),
        o,
        json!({ "secret_id": sid }),
    )
    .await;

    let bindings = format!(
        "org_id = \"{org}\"\n[[mcp_upstream]]\nname = \"github\"\nurl = \"http://127.0.0.1:{up_port}/mcp\"\nsecret_id = \"{sid}\"\nheader = \"Authorization\"\ntemplate = \"Bearer {{secret}}\"\nallow_private_hosts = true\ndefault = \"hide\"\n[mcp_upstream.tools]\nlist_issues = \"allow\"\ncreate_issue = \"hold\"\ndelete_repository = \"deny\"\necho = \"hide\"\n"
    );
    let (_gw, gw_url) = start_gateway(&c, &dir, &bindings).await;

    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let smith = bin("smith", "LOCKSMITH_SMITH_BIN");
    let out = agent_cmd(&smith, &home, &gw_url)
        .env("LOCKSMITH_ENROLLMENT_SECRET", &enrollment)
        .args(["login", "--agent"])
        .output()
        .unwrap();
    assert!(out.status.success(), "smith login --agent failed");

    // The scripted MCP client: initialize, list, an allowed call, a held one, a denied one, a hidden one.
    let call = |id: &str, name: &str| json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":{}}});
    let lines = vec![
        json!({"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":"list","method":"tools/list"}),
        call("allow", "list_issues"),
        call("hold", "create_issue"),
        call("deny", "delete_repository"),
        call("hide", "echo"),
    ];
    let (replies, observed) = run_bridge(&smith, &home, &gw_url, &lines);

    let names: Vec<String> = reply(&replies, "list")["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect();
    for shown in ["list_issues", "create_issue", "delete_repository"] {
        assert!(
            names.iter().any(|n| n == shown),
            "tools/list lacks {shown}: {names:?}"
        );
    }
    assert!(
        !names.iter().any(|n| n == "echo"),
        "the hidden tool is listed"
    );
    assert!(
        reply(&replies, "allow")["result"].is_object(),
        "the allowed call did not return a result"
    );
    assert_eq!(
        reply(&replies, "hold")["error"]["message"],
        "approval_required"
    );
    assert_eq!(reply(&replies, "deny")["error"]["message"], "tool_denied");
    assert_eq!(reply(&replies, "hide")["error"]["message"], "unknown_tool");

    // The upstream got the key and the allowed call only.
    let log = std::fs::read_to_string(&up_log).unwrap();
    assert!(
        log.contains(UPSTREAM_KEY),
        "the upstream never received the key"
    );
    for refused in ["create_issue", "delete_repository", "echo"] {
        assert!(
            !log.lines()
                .any(|l| l.contains(&format!("\"tool\": \"{refused}\""))),
            "{refused} reached the upstream"
        );
    }

    // Nothing the agent saw or holds contains the key, even though the upstream reflected it.
    assert!(
        !observed.contains(UPSTREAM_KEY),
        "the bridge output holds the upstream key"
    );
    let mut held = Vec::new();
    files(&home, &mut held);
    for f in held {
        let bytes = std::fs::read(&f).unwrap_or_default();
        assert!(
            !String::from_utf8_lossy(&bytes).contains(UPSTREAM_KEY),
            "the agent HOME holds the upstream key ({})",
            f.display()
        );
    }

    // Ledger: a pending call and an ok outcome for the allowed call, denied events for the others.
    let (st, events) = cp(&c, "GET", "/v1/audit/events?limit=100", o, None).await;
    assert_eq!(st, StatusCode::OK);
    let items = events["items"].as_array().expect("audit items");
    let count = |kind: &str, outcome: &str| {
        items
            .iter()
            .filter(|e| e["kind"] == kind && e["outcome"] == outcome)
            .count()
    };
    assert_eq!(count("mcp.upstream_call", "pending"), 1, "one pending call");
    assert_eq!(count("mcp.upstream_outcome", "ok"), 1, "one ok outcome");
    assert_eq!(
        count("mcp.upstream_call", "denied"),
        3,
        "hold, deny and hide are denied events"
    );
    assert!(
        !serde_json::to_string(items).unwrap().contains(UPSTREAM_KEY),
        "the ledger holds the upstream key"
    );

    // Bindings inventory: the MCP row with its tool rules, never the template or secret id.
    let deadline = Instant::now() + Duration::from_secs(20);
    let row = loop {
        let (st, inv) = cp(&c, "GET", "/v1/bindings", o, None).await;
        if st == StatusCode::OK
            && let Some(r) = inv["items"]
                .as_array()
                .and_then(|a| a.iter().find(|b| b["kind"] == "mcp"))
        {
            break r.clone();
        }
        assert!(
            Instant::now() < deadline,
            "no MCP row in the bindings inventory"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    let text = row.to_string();
    assert!(text.contains("github"), "the row lacks the upstream name");
    assert!(
        !text.contains(&sid) && !text.contains("{secret}"),
        "the row exposes the secret id or template"
    );
    assert!(
        row["tools"].as_array().is_some_and(|t| t
            .iter()
            .any(|x| x["name"] == "list_issues" && x["decision"] == "allow")),
        "the row lacks the tool rules"
    );
}
