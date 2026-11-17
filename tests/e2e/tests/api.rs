//! E2E for the control-plane API (S1). Requires `just up` and `just api` (dev auth, :8080).
//! Tempo makes a trace searchable ~30 s after export, so the trace poll waits up to 60 s.
//! Overrides: E2E_API_URL, E2E_GRAFANA_URL. Dev-only Grafana credentials (admin:admin).

use std::env;
use std::time::{Duration, Instant};

use reqwest::{Client, StatusCode};
use serde_json::{Value, json};

fn api() -> String {
    env::var("E2E_API_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into())
}

fn grafana() -> String {
    env::var("E2E_GRAFANA_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".into())
}

struct Reply {
    status: StatusCode,
    location: Option<String>,
    body: Value,
}

async fn call(
    c: &Client,
    method: &str,
    path: &str,
    org: Option<&str>,
    body: Option<Value>,
) -> Reply {
    let mut req = c.request(method.parse().unwrap(), format!("{}{path}", api()));
    if let Some(o) = org {
        req = req.header("X-Locksmith-Dev-Org", o);
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req
        .send()
        .await
        .expect("reach locksmith-api (is `just api` running?)");
    let status = resp.status();
    let location = resp
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap().to_owned());
    let text = resp.text().await.unwrap();
    Reply {
        status,
        location,
        body: serde_json::from_str(&text).unwrap_or(Value::Null),
    }
}

async fn new_org(c: &Client, name: &str) -> String {
    let r = call(c, "POST", "/v1/orgs", None, Some(json!({ "name": name }))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    r.body["id"].as_str().unwrap().to_owned()
}

fn uniq(prefix: &str) -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{t}")
}

/// A fresh canary value, minted by the leak oracle into the gitignored canary file. The test never
/// prints it; it is sent to the API once, as secret metadata, and must only land in the database.
fn mint_canary() -> String {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let file = env::var("LOCKSMITH_CANARIES")
        .unwrap_or_else(|_| format!("{root}/infra/compose/.canaries"));
    let out = std::process::Command::new("python3")
        .args([
            "-I",
            &format!("{root}/tests/kit/oracle.py"),
            "canary-new",
            "--file",
            &file,
        ])
        .output()
        .expect("run oracle");
    assert!(out.status.success(), "oracle canary-new failed");
    let text = std::fs::read_to_string(&file).unwrap();
    text.lines()
        .last()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn readyz_is_ok() {
    let c = Client::new();
    let r = call(&c, "GET", "/readyz", None, None).await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn project_tree_isolation_and_pagination() {
    let c = Client::new();
    let a = new_org(&c, &uniq("e2e-a")).await;
    let b = new_org(&c, &uniq("e2e-b")).await;

    let p = call(
        &c,
        "POST",
        "/v1/projects",
        Some(&a),
        Some(json!({ "name": "web" })),
    )
    .await;
    assert_eq!(p.status, StatusCode::CREATED, "{:?}", p.body);
    let ploc = p.location.clone().expect("Location header");
    let pid = p.body["id"].as_str().unwrap().to_owned();

    let e = call(
        &c,
        "POST",
        &format!("/v1/projects/{pid}/environments"),
        Some(&a),
        Some(json!({ "name": "prod" })),
    )
    .await;
    assert_eq!(e.status, StatusCode::CREATED, "{:?}", e.body);
    let eid = e.body["id"].as_str().unwrap().to_owned();

    let s = call(
        &c,
        "POST",
        &format!("/v1/projects/{pid}/environments/{eid}/secrets"),
        Some(&a),
        Some(json!({ "name": "API_KEY", "description": "metadata only" })),
    )
    .await;
    assert_eq!(s.status, StatusCode::CREATED, "{:?}", s.body);
    assert_eq!(s.body["version_count"], 0);

    // Reads round-trip for the owner and are invisible to another org.
    assert_eq!(call(&c, "GET", &ploc, Some(&a), None).await.body, p.body);
    assert_eq!(
        call(&c, "GET", &ploc, Some(&b), None).await.status,
        StatusCode::NOT_FOUND
    );
    let lb = call(&c, "GET", "/v1/projects", Some(&b), None).await;
    assert_eq!(lb.status, StatusCode::OK);
    assert!(
        lb.body["items"].as_array().unwrap().is_empty(),
        "{:?}",
        lb.body
    );

    // Pagination: 120 projects, limit 50 => 50 + 50 + 20, no overlap.
    let pg = new_org(&c, &uniq("e2e-pg")).await;
    for i in 0..120 {
        let r = call(
            &c,
            "POST",
            "/v1/projects",
            Some(&pg),
            Some(json!({ "name": format!("p{i:03}") })),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED);
    }
    let mut seen = std::collections::HashSet::new();
    let mut next: Option<String> = None;
    let mut pages = 0;
    loop {
        let mut uri = "/v1/projects?limit=50".to_owned();
        if let Some(n) = &next {
            uri.push_str(&format!("&cursor={n}"));
        }
        let r = call(&c, "GET", &uri, Some(&pg), None).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        for it in r.body["items"].as_array().unwrap() {
            assert!(
                seen.insert(it["id"].as_str().unwrap().to_owned()),
                "duplicate id across pages"
            );
        }
        pages += 1;
        next = r.body["next"].as_str().map(str::to_owned);
        if next.is_none() {
            break;
        }
    }
    assert_eq!((seen.len(), pages), (120, 3));
}

#[tokio::test]
async fn post_projects_trace_has_db_child_span() {
    let c = Client::new();
    let org = new_org(&c, &uniq("e2e-trace")).await;
    let r = call(
        &c,
        "POST",
        "/v1/projects",
        Some(&org),
        Some(json!({ "name": uniq("t") })),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let started = Instant::now();
    let search = format!(
        "{}/api/datasources/proxy/uid/tempo/api/search?tags=service.name%3Dlocksmith-api%20org.id%3D{org}&limit=5",
        grafana()
    );
    let mut last = String::from("no attempt");
    while started.elapsed() < Duration::from_secs(60) {
        let resp = c
            .get(&search)
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .unwrap();
        let st = resp.status();
        let text = resp.text().await.unwrap();
        let found: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        last = format!("search status {st}, {} bytes", text.len());
        for t in found["traces"].as_array().into_iter().flatten() {
            if t["rootTraceName"] != "POST /v1/projects" {
                continue;
            }
            let id = t["traceID"].as_str().unwrap();
            let tr: Value = c
                .get(format!(
                    "{}/api/datasources/proxy/uid/tempo/api/traces/{id}",
                    grafana()
                ))
                .basic_auth("admin", Some("admin"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap_or(Value::Null);
            let names: Vec<String> = tr["batches"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|b| b["scopeSpans"].as_array().into_iter().flatten())
                .flat_map(|s| s["spans"].as_array().into_iter().flatten())
                .map(|sp| sp["name"].as_str().unwrap_or("").to_owned())
                .collect();
            last = format!("{names:?}");
            if names.iter().any(|n| n == "db.transaction") {
                return;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!(
        "no POST /v1/projects trace with a db.transaction child span within 60 s; last spans: {last}"
    );
}

#[tokio::test]
async fn canary_in_secret_description_only_reaches_the_database() {
    let c = Client::new();
    let canary = mint_canary();
    let org = new_org(&c, &uniq("e2e-canary")).await;
    let p = call(
        &c,
        "POST",
        "/v1/projects",
        Some(&org),
        Some(json!({ "name": "p" })),
    )
    .await;
    let pid = p.body["id"].as_str().unwrap().to_owned();
    let e = call(
        &c,
        "POST",
        &format!("/v1/projects/{pid}/environments"),
        Some(&org),
        Some(json!({ "name": "e" })),
    )
    .await;
    let eid = e.body["id"].as_str().unwrap().to_owned();
    let s = call(
        &c,
        "POST",
        &format!("/v1/projects/{pid}/environments/{eid}/secrets"),
        Some(&org),
        Some(json!({ "name": "S", "description": canary })),
    )
    .await;
    assert_eq!(s.status, StatusCode::CREATED);
    // `just leak-scan` (the verify step) asserts logs and traces are clean. Delete the row so the
    // canary does not linger in the database and later scans stay green.
    let sid = s.body["id"].as_str().unwrap();
    let del = call(
        &c,
        "DELETE",
        &format!("/v1/projects/{pid}/environments/{eid}/secrets/{sid}"),
        Some(&org),
        None,
    )
    .await;
    assert_eq!(del.status, StatusCode::NO_CONTENT);
}
