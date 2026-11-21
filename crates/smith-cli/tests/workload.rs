//! `smith login --workload github|kubernetes` (D4 task 5.4) against a stub runner token endpoint,
//! a projected token file and a mock control plane. Asserts that nothing but `agent.json` is
//! written and that the external token appears in no output and no file.
mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::Home;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const EXTERNAL: &str =
    "eyJhbGciOiJSUzI1NiJ9.EXTERNAL_CANARY_PAYLOAD_0123456789.EXTSIG_CANARY_abcdef";
const REQUEST_TOKEN: &str = "RUNNER_REQUEST_TOKEN_CANARY_0123456789";
const AGENT_TOKEN: &str =
    "eyJhbGciOiJFZERTQSJ9.AGENT_CANARY_PAYLOAD_0123456789.AGENTSIG_CANARY_abcdef";
const POLICY: &str = "lsw_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// Run `smith` off the async worker, in `cwd`, with a clean workload environment plus `env`.
async fn smith(home: &Home, cwd: &Path, args: Vec<String>, env: Vec<(String, String)>) -> Output {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut c = home.cmd(&refs);
    c.current_dir(cwd);
    for k in [
        "LOCKSMITH_WORKLOAD_POLICY",
        "LOCKSMITH_WORKLOAD_AUDIENCE",
        "LOCKSMITH_WORKLOAD_TOKEN_FILE",
        "LOCKSMITH_ENROLLMENT_SECRET",
        "LOCKSMITH_CONTROL_PLANE_URL",
        "LOCKSMITH_GATEWAY_URL",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    ] {
        c.env_remove(k);
    }
    for (k, v) in env {
        c.env(k, v);
    }
    tokio::task::spawn_blocking(move || {
        let mut child = c.spawn().unwrap();
        drop(child.stdin.take());
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap()
}

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("smith-workload-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Every file under `dir` (recursive) must not contain `needle`.
fn assert_no_file_contains(dir: &Path, needle: &str) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            assert_no_file_contains(&p, needle);
        } else if let Ok(raw) = std::fs::read(&p) {
            assert!(
                !String::from_utf8_lossy(&raw).contains(needle),
                "{} contains the external token",
                p.display()
            );
        }
    }
}

async fn control_plane(status: u16) -> MockServer {
    let cp = MockServer::start().await;
    let resp = if status == 200 {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": AGENT_TOKEN, "token_type": "Bearer", "expires_in": 900,
            "expires_at": "2099-01-01T00:00:00Z"
        }))
    } else {
        ResponseTemplate::new(status).set_body_string(format!("{{\"error\":\"echo {EXTERNAL}\"}}"))
    };
    Mock::given(method("POST"))
        .and(path("/v1/workload-tokens"))
        .and(body_json(
            serde_json::json!({ "policy": POLICY, "token": EXTERNAL }),
        ))
        .respond_with(resp)
        .mount(&cp)
        .await;
    cp
}

async fn runner(audience: &str) -> MockServer {
    let r = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/idtoken"))
        .and(query_param("audience", audience))
        .and(header(
            "authorization",
            format!("Bearer {REQUEST_TOKEN}").as_str(),
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": EXTERNAL })),
        )
        .mount(&r)
        .await;
    r
}

fn assert_only_agent_json(home: &Home, cwd: &Path) {
    assert_eq!(
        names(&home.0),
        ["agent.json"],
        "files written under LOCKSMITH_HOME"
    );
    assert!(
        names(cwd).is_empty(),
        "files written in the working directory"
    );
    let raw = std::fs::read_to_string(home.0.join("agent.json")).unwrap();
    assert!(raw.contains(AGENT_TOKEN));
    assert!(!raw.contains(EXTERNAL));
    assert_no_file_contains(&home.0, EXTERNAL);
    assert_no_file_contains(&home.0, REQUEST_TOKEN);
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
        let mode = std::fs::metadata(home.0.join("agent.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

fn assert_clean(o: &Output) {
    let out = text(o);
    for s in [EXTERNAL, REQUEST_TOKEN, AGENT_TOKEN] {
        assert!(!out.contains(s), "output leaks a token: {out}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn workload_github_login_writes_only_agent_json() {
    let home = Home::new();
    let cwd = scratch("gh");
    let cp = control_plane(200).await;
    let audience = cp.uri();
    let rn = runner(&audience).await;
    let gw = MockServer::start().await;
    let o = smith(
        &home,
        &cwd,
        args(&[
            "login",
            "--workload",
            "github",
            "--policy",
            POLICY,
            "--control-plane-url",
            &cp.uri(),
            "--gateway-url",
            &gw.uri(),
        ]),
        vec![
            (
                "ACTIONS_ID_TOKEN_REQUEST_URL".into(),
                format!("{}/idtoken?api-version=2.0", rn.uri()),
            ),
            (
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN".into(),
                REQUEST_TOKEN.into(),
            ),
        ],
    )
    .await;
    assert!(o.status.success(), "{}", text(&o));
    assert_clean(&o);
    assert_only_agent_json(&home, &cwd);
}

#[tokio::test(flavor = "multi_thread")]
async fn workload_github_login_uses_policy_and_audience_from_env() {
    let home = Home::new();
    let cwd = scratch("gh-env");
    let cp = control_plane(200).await;
    let rn = runner("locksmith-audience").await;
    let gw = MockServer::start().await;
    let o = smith(
        &home,
        &cwd,
        args(&["--json", "login", "--workload", "github"]),
        vec![
            ("LOCKSMITH_WORKLOAD_POLICY".into(), POLICY.into()),
            (
                "LOCKSMITH_WORKLOAD_AUDIENCE".into(),
                "locksmith-audience".into(),
            ),
            ("LOCKSMITH_CONTROL_PLANE_URL".into(), cp.uri()),
            ("LOCKSMITH_GATEWAY_URL".into(), gw.uri()),
            (
                "ACTIONS_ID_TOKEN_REQUEST_URL".into(),
                format!("{}/idtoken?api-version=2.0", rn.uri()),
            ),
            (
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN".into(),
                REQUEST_TOKEN.into(),
            ),
        ],
    )
    .await;
    assert!(o.status.success(), "{}", text(&o));
    assert_clean(&o);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["status"], "logged_in");
    assert_only_agent_json(&home, &cwd);
}

#[tokio::test(flavor = "multi_thread")]
async fn workload_kubernetes_login_reads_token_file_and_writes_only_agent_json() {
    let home = Home::new();
    let cwd = scratch("k8s");
    let tokdir = scratch("k8s-token");
    let file = tokdir.join("token");
    std::fs::write(&file, format!("{EXTERNAL}\n")).unwrap();
    let cp = control_plane(200).await;
    let gw = MockServer::start().await;
    let o = smith(
        &home,
        &cwd,
        args(&[
            "login",
            "--workload",
            "kubernetes",
            "--policy",
            POLICY,
            "--token-file",
            file.to_str().unwrap(),
            "--control-plane-url",
            &cp.uri(),
            "--gateway-url",
            &gw.uri(),
        ]),
        vec![],
    )
    .await;
    assert!(o.status.success(), "{}", text(&o));
    assert_clean(&o);
    assert_only_agent_json(&home, &cwd);
    // The token file is only read, never modified.
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!("{EXTERNAL}\n")
    );
    assert_eq!(names(&tokdir), ["token"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn workload_login_rejected_prints_no_token_and_writes_nothing() {
    let home = Home::new();
    let cwd = scratch("denied");
    let tokdir = scratch("denied-token");
    let file = tokdir.join("token");
    std::fs::write(&file, EXTERNAL).unwrap();
    let cp = control_plane(401).await;
    let gw = MockServer::start().await;
    let o = smith(
        &home,
        &cwd,
        args(&[
            "login",
            "--workload",
            "kubernetes",
            "--policy",
            POLICY,
            "--token-file",
            file.to_str().unwrap(),
            "--control-plane-url",
            &cp.uri(),
            "--gateway-url",
            &gw.uri(),
        ]),
        vec![],
    )
    .await;
    assert!(!o.status.success());
    let out = text(&o);
    assert!(out.contains("401"), "{out}");
    assert_clean(&o);
    assert!(
        names(&home.0).is_empty(),
        "nothing may be written on refusal"
    );
    assert!(names(&cwd).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn workload_login_runner_failure_prints_no_token() {
    let home = Home::new();
    let cwd = scratch("runner-fail");
    let rn = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/idtoken"))
        .respond_with(ResponseTemplate::new(403).set_body_string(REQUEST_TOKEN))
        .mount(&rn)
        .await;
    let o = smith(
        &home,
        &cwd,
        args(&[
            "login",
            "--workload",
            "github",
            "--policy",
            POLICY,
            "--control-plane-url",
            "http://127.0.0.1:9",
            "--gateway-url",
            "http://127.0.0.1:9",
        ]),
        vec![
            (
                "ACTIONS_ID_TOKEN_REQUEST_URL".into(),
                format!("{}/idtoken?api-version=2.0", rn.uri()),
            ),
            (
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN".into(),
                REQUEST_TOKEN.into(),
            ),
        ],
    )
    .await;
    assert!(!o.status.success());
    assert_clean(&o);
    assert!(names(&home.0).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn workload_login_requires_a_wellformed_policy_before_any_request() {
    let home = Home::new();
    let cwd = scratch("usage");
    let base = [
        "login",
        "--workload",
        "github",
        "--control-plane-url",
        "http://127.0.0.1:9",
        "--gateway-url",
        "http://127.0.0.1:9",
    ];
    let o = smith(&home, &cwd, args(&base), vec![]).await;
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    let mut bad = args(&base);
    bad.extend(args(&["--policy", "not-a-handle"]));
    let o = smith(&home, &cwd, bad, vec![]).await;
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(names(&home.0).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn workload_login_conflicts_with_agent_and_user() {
    let home = Home::new();
    let cwd = scratch("conflict");
    for other in ["--agent", "--user"] {
        let o = smith(
            &home,
            &cwd,
            args(&["login", "--workload", "github", other]),
            vec![],
        )
        .await;
        assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn workload_doctor_reports_policy_and_token_source() {
    let home = Home::new();
    let cwd = scratch("doctor");
    let tokdir = scratch("doctor-token");
    let file = tokdir.join("token");
    std::fs::write(&file, EXTERNAL).unwrap();
    let o = smith(
        &home,
        &cwd,
        args(&["doctor", "--json"]),
        vec![
            ("LOCKSMITH_UPDATE_URL".into(), "http://127.0.0.1:9".into()),
            ("LOCKSMITH_WORKLOAD_POLICY".into(), POLICY.into()),
            (
                "LOCKSMITH_WORKLOAD_TOKEN_FILE".into(),
                file.to_str().unwrap().into(),
            ),
        ],
    )
    .await;
    assert_clean(&o);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let c = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "workload.login")
        .expect("workload check present");
    assert_eq!(c["status"], "ok", "{c}");
}
