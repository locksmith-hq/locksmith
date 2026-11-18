//! E2E for the S5 audit ledger (task 7.1, run by `just audit-smoke`). Requires `just up`, `just api`
//! and a built gateway and `smith` (the recipe builds them).
//!
//! An org, a canary secret, an agent and a grant are created through the control plane; the agent
//! logs in and relays once through `smith`. The test asserts the ledger holds `agent.created`,
//! `grant.created`, `relay.attempt` and `relay.outcome`, with no canary in any event.
//!
//! Load (with `AUDIT_SMOKE_LOAD=1`, which `just audit-smoke` sets): when `oha` is found
//! (`LOCKSMITH_OHA_BIN`, else `PATH`), it drives `POST /v1/relay` at `AUDIT_SMOKE_RATE` relays/s
//! (default 200) for `AUDIT_SMOKE_LOAD_SECS` (default 20) and prints the relay p99 (oha) and the
//! append server spans Tempo holds for this org; then it drives `POST /internal/v1/audit/events`
//! at twice that rate (two appends per relay) and prints the append p99 (oha). Without oha the
//! load step is skipped with a message. Release builds give figures worth recording
//! (`LOCKSMITH_GATEWAY_BIN`, and `locksmith-api` built with `--release`).
//!
//! Finally it waits until a signed checkpoint covers the org's head (`GET /v1/audit/status`). The
//! recipe then exports, verifies (`--db` and `--dir`) and runs `just leak-scan`. Nothing printed
//! here contains the canary or a token.

use std::env;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ls_e2e::{api, mint_canary, root, uniq, wiremock};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};

const SERVICE_TOKEN: &str = "dev-only-gateway-service-token-0123456789";
/// The checkpoint job signs at most 60 s after an org's oldest unsigned event, plus a 5 s tick.
const CHECKPOINT_WAIT: Duration = Duration::from_secs(150);

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
    assert_eq!(status, StatusCode::CREATED, "POST {path}");
    v
}

async fn cp_get(c: &Client, path: &str, org: &str) -> Value {
    let r = c
        .get(format!("{}{path}", api()))
        .header("X-Locksmith-Dev-Org", org)
        .send()
        .await
        .expect("reach locksmith-api");
    assert_eq!(r.status(), StatusCode::OK, "GET {path}");
    r.json().await.unwrap()
}

fn id_of(v: &Value) -> String {
    v["id"].as_str().unwrap().to_owned()
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
    let dir = std::env::temp_dir().join(uniq("audit-e2e"));
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
        .expect("start locksmith-gateway (run `just audit-smoke` to build it)");
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

/// Run `smith` as the agent: isolated config dir, no ambient credentials.
fn smith(home: &std::path::Path, gw: &str) -> Command {
    let bin = env::var("LOCKSMITH_SMITH_BIN")
        .unwrap_or_else(|_| format!("{}/target/debug/smith", root()));
    let mut c = Command::new(bin);
    c.env_clear()
        .env("PATH", env::var("PATH").unwrap_or_default())
        .env("LOCKSMITH_HOME", home)
        .env("LOCKSMITH_CONTROL_PLANE_URL", api())
        .env("LOCKSMITH_GATEWAY_URL", gw);
    c
}

/// `oha` from `LOCKSMITH_OHA_BIN` or `PATH`.
fn find_oha() -> Option<std::path::PathBuf> {
    if let Ok(p) = env::var("LOCKSMITH_OHA_BIN") {
        return Some(p.into());
    }
    env::split_paths(&env::var_os("PATH")?)
        .map(|d| d.join("oha"))
        .find(|p| p.is_file())
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Percent-encode a query value (RFC 3986 unreserved characters kept).
fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Nearest-rank percentile of sorted `v`.
fn pct(v: &[f64], p: f64) -> f64 {
    let rank = ((p / 100.0) * v.len() as f64).ceil() as usize;
    v[rank.clamp(1, v.len()) - 1]
}

/// Durations (ms) of the control plane's append request spans for `org` in `[start, end]`, from
/// Tempo through the Grafana proxy (`LEAK_SCAN_TEMPO` overrides the base, as for `leak-scan`).
async fn append_spans_ms(c: &Client, org: &str, start: u64, end: u64) -> Result<Vec<f64>, String> {
    let base = env::var("LEAK_SCAN_TEMPO").unwrap_or_else(|_| {
        let g = env::var("LEAK_SCAN_GRAFANA").unwrap_or_else(|_| "http://127.0.0.1:3000".into());
        format!(
            "{}/api/datasources/proxy/uid/tempo",
            g.trim_end_matches('/')
        )
    });
    let q =
        format!("{{ span.http.route = \"/internal/v1/audit/events\" && span.org.id = \"{org}\" }}");
    let mut out = Vec::new();
    // One search over the load window (the limit is above 2 appends x 200/s x the default 20 s).
    let url = format!(
        "{base}/api/search?q={}&start={}&end={}&limit=50000&spss=10",
        enc(&q),
        start,
        end + 1
    );
    let r = c.get(&url).send().await.map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        let status = r.status();
        let why = r.text().await.unwrap_or_default();
        return Err(format!(
            "tempo search: HTTP {status}: {}",
            why.chars().take(200).collect::<String>()
        ));
    }
    let v: Value = r.json().await.map_err(|e| e.to_string())?;
    for t in v["traces"].as_array().into_iter().flatten() {
        for set in t["spanSets"].as_array().into_iter().flatten() {
            for sp in set["spans"].as_array().into_iter().flatten() {
                if let Some(ns) = sp["durationNanos"]
                    .as_str()
                    .and_then(|d| d.parse::<f64>().ok())
                {
                    out.push(ns / 1e6);
                }
            }
        }
    }
    Ok(out)
}

/// One oha run's figures.
struct Run {
    total: u64,
    errors: u64,
    achieved: f64,
    p50_ms: f64,
    p99_ms: f64,
}

/// Run oha at `rate` requests/s for `secs` and assert every response was `expect`. `headers` may
/// hold dev-stack tokens: they are on oha's command line for the run and never printed.
fn oha_run(
    oha: &std::path::Path,
    rate: u64,
    secs: u64,
    url: &str,
    body: &str,
    headers: &[String],
    expect: &str,
) -> Run {
    let mut cmd = Command::new(oha);
    cmd.args(["--no-tui", "--output-format", "json", "-c", "50"])
        // Count queueing delay from the scheduled send time (no coordinated omission), and let
        // requests in flight at the deadline finish so none is cut off after its attempt append.
        .args([
            "--latency-correction",
            "--wait-ongoing-requests-after-deadline",
        ])
        .args(["-q", &rate.to_string(), "-z", &format!("{secs}s")])
        .args(["-m", "POST", "-T", "application/json", "-d", body]);
    for h in headers {
        cmd.args(["-H", h]);
    }
    let out = cmd.arg(url).stdin(Stdio::null()).output().expect("run oha");
    assert!(out.status.success(), "oha failed (exit {:?})", out.status);
    let r: Value = serde_json::from_slice(&out.stdout).expect("oha JSON output");
    let codes = &r["statusCodeDistribution"];
    let total: u64 = codes
        .as_object()
        .map(|m| m.values().filter_map(Value::as_u64).sum())
        .unwrap_or(0);
    assert!(total > 0, "oha got no responses");
    assert_eq!(
        codes[expect].as_u64().unwrap_or(0),
        total,
        "responses under load were not all {expect}: {codes}"
    );
    let errors = r["errorDistribution"]
        .as_object()
        .map(|m| m.values().filter_map(Value::as_u64).sum())
        .unwrap_or(0);
    Run {
        total,
        errors,
        achieved: r["summary"]["requestsPerSec"].as_f64().unwrap_or(f64::NAN),
        p50_ms: r["latencyPercentiles"]["p50"].as_f64().unwrap_or(f64::NAN) * 1e3,
        p99_ms: r["latencyPercentiles"]["p99"].as_f64().unwrap_or(f64::NAN) * 1e3,
    }
}

/// The load step: relays at `rate`/s through the gateway (relay p99, plus the append spans Tempo
/// kept), then appends at `2 * rate`/s straight to the ledger endpoint (each relay appends twice,
/// so this is the append rate 200 relays/s produce). Skipped with a message when oha is missing.
async fn load(c: &Client, org: &str, gw: &str, token: &str, agent_id: &str, sid: &str, url: &str) {
    if env::var("AUDIT_SMOKE_LOAD").ok().as_deref() != Some("1") {
        eprintln!(
            "audit-smoke: load step SKIPPED (set AUDIT_SMOKE_LOAD=1; `just audit-smoke` does)"
        );
        return;
    }
    let Some(oha) = find_oha() else {
        eprintln!(
            "audit-smoke: load step SKIPPED: oha not found (cargo install oha, or set LOCKSMITH_OHA_BIN); no append p99 recorded"
        );
        return;
    };
    let rate = env_u64("AUDIT_SMOKE_RATE", 200);
    let secs = env_u64("AUDIT_SMOKE_LOAD_SECS", 20);

    // 1. Relays through the gateway.
    let body = json!({ "secret_id": sid, "version": 1, "method": "GET", "url": url }).to_string();
    let start = now_s();
    let relay = oha_run(
        &oha,
        rate,
        secs,
        &format!("{gw}/v1/relay"),
        &body,
        &[format!("Authorization: Bearer {token}")],
        "200",
    );
    let end = now_s() + 1;
    eprintln!(
        "audit-smoke: relay load: target {rate}/s, achieved {:.1}/s for {secs} s, {} relays all 200, {} client errors; relay p50 {:.2} ms, p99 {:.2} ms (oha)",
        relay.achieved, relay.total, relay.errors, relay.p50_ms, relay.p99_ms
    );
    // Spans reach Tempo after the exporter's batch delay. The exporter drops spans when its queue
    // is full, so the count can fall short of the appends made.
    // Poll until Tempo has (nearly) every append span, or 90 s pass.
    let want = 2 * relay.total;
    let deadline = Instant::now() + Duration::from_secs(90);
    let spans = loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let got = append_spans_ms(c, org, start, end).await;
        let enough = matches!(&got, Ok(v) if v.len() as u64 * 100 >= want * 99);
        if enough || Instant::now() >= deadline {
            break got;
        }
    };
    match spans {
        Ok(mut v) if !v.is_empty() => {
            v.sort_by(f64::total_cmp);
            eprintln!(
                "audit-smoke: append during relay load (server spans in Tempo: {} of {want} appends): p50 {:.2} ms, p99 {:.2} ms",
                v.len(),
                pct(&v, 50.0),
                pct(&v, 99.0)
            );
        }
        Ok(_) => eprintln!("audit-smoke: append spans unavailable: Tempo returned none"),
        Err(e) => eprintln!("audit-smoke: append spans unavailable: {e}"),
    }

    // 2. Appends straight to the ledger endpoint. `relay.denied` costs one append like an attempt
    // but leaves no open attempt in verify output.
    let host = url
        .split("://")
        .nth(1)
        .and_then(|r| r.split([':', '/']).next())
        .unwrap_or("127.0.0.1");
    let body = json!({
        "kind": "relay.denied", "outcome": "denied", "agent_id": agent_id, "secret_id": sid,
        "version": 1, "method": "GET", "host": host
    })
    .to_string();
    let append = oha_run(
        &oha,
        2 * rate,
        secs,
        &format!("{}/internal/v1/audit/events", api()),
        &body,
        &[
            format!("Authorization: Bearer {SERVICE_TOKEN}"),
            format!("X-Locksmith-Org: {org}"),
        ],
        "201",
    );
    eprintln!(
        "audit-smoke: append load: target {}/s (= {rate} relays/s), achieved {:.1}/s for {secs} s, {} appends all 201, {} client errors; append p50 {:.2} ms, p99 {:.2} ms (oha)",
        2 * rate,
        append.achieved,
        append.total,
        append.errors,
        append.p50_ms,
        append.p99_ms
    );
}

#[tokio::test]
async fn relay_is_audited_checkpointed_and_never_leaks() {
    let c = Client::new();
    let canary = mint_canary();

    let org = id_of(&cp(&c, "/v1/orgs", None, json!({ "name": uniq("audit") })).await);
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
    cp(
        &c,
        &format!("{base}/{sid}/versions"),
        o,
        json!({ "value": canary }),
    )
    .await;

    // Register an agent and grant it the canary secret.
    let enrolled = cp(&c, "/v1/agents", o, json!({ "name": uniq("audit-agent") })).await;
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
    let path = format!("/{}", uniq("audit-echo"));
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
    let home = std::env::temp_dir().join(uniq("audit-home"));
    std::fs::create_dir_all(&home).unwrap();
    let url = format!("{}{path}", wiremock());

    // Relay through smith, as the agent.
    let mut observed = String::new();
    let out = smith(&home, &gw.base)
        .env("LOCKSMITH_ENROLLMENT_SECRET", &enrollment)
        .args(["login", "--agent"])
        .output()
        .unwrap();
    observed.push_str(&String::from_utf8_lossy(&out.stdout));
    observed.push_str(&String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "smith login --agent failed");
    let out = smith(&home, &gw.base)
        .args(["relay", "--secret-id", &sid, &url])
        .output()
        .unwrap();
    observed.push_str(&String::from_utf8_lossy(&out.stdout));
    observed.push_str(&String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "smith relay failed");
    assert!(String::from_utf8_lossy(&out.stdout).contains("REDACTED"));
    assert!(!observed.contains(&canary), "the agent observed the secret");

    // The ledger holds the admin events and the relay attempt and outcome, and no canary.
    let page = cp_get(&c, "/v1/audit/events?limit=50", &org).await;
    assert!(
        !page.to_string().contains(&canary),
        "an audit event holds the canary"
    );
    let events = page["items"].as_array().unwrap();
    let has = |kind: &str, outcome: &str| {
        events
            .iter()
            .any(|e| e["kind"] == kind && e["outcome"] == outcome)
    };
    assert!(has("agent.created", "ok"), "no agent.created event");
    assert!(has("grant.created", "ok"), "no grant.created event");
    assert!(has("relay.attempt", "pending"), "no relay.attempt event");
    assert!(has("relay.outcome", "ok"), "no ok relay.outcome event");
    let head_after_relay = events[0]["seq"].as_i64().unwrap();
    eprintln!("audit-smoke: org {org}: relay audited, head seq {head_after_relay}");

    // Optional load at 200 relays/s with oha (the agent's token from its 0600 state file).
    let state: Value =
        serde_json::from_str(&std::fs::read_to_string(home.join("agent.json")).unwrap()).unwrap();
    let token = state["access_token"].as_str().unwrap().to_owned();
    load(&c, &org, &gw.base, &token, &agent_id, &sid, &url).await;
    drop(gw);
    let _ = std::fs::remove_dir_all(&home);

    // Wait for a signed checkpoint that covers the head.
    let deadline = Instant::now() + CHECKPOINT_WAIT;
    loop {
        let st = cp_get(&c, "/v1/audit/status", &org).await;
        let head = st["head_seq"].as_i64().unwrap();
        if let Some(cp_seq) = st["latest_checkpoint"]["seq"].as_i64()
            && cp_seq == head
            && head >= head_after_relay
        {
            eprintln!(
                "audit-smoke: checkpoint at seq {cp_seq} ({}) covers the head",
                st["latest_checkpoint"]["key_id"].as_str().unwrap_or("?")
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no checkpoint covered head seq {head} within {CHECKPOINT_WAIT:?} (is OPENBAO_AUDIT_CHECKPOINT_TOKEN set for `just api`?)"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
