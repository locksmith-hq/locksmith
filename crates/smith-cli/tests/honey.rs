//! t5-honey-tokens task 2.4: `smith honey plant <name> --into <path>` against a mock gateway
//! (the gateway side is tested against the real control plane in services/gateway). The decoy
//! and the person's token are canaries: neither may appear on stdout or stderr.
#![cfg(unix)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Output;

use common::Home;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const USER_TOKEN: &str = "eyJhbGciOiJFUzI1NiJ9.USER_TOKEN_CANARY_0123.SIGNATURE_CANARY_xyz";
const VALUE: &[u8] = b"AKIAHONEYPLANTCANARY7";
const ID: &str = "0197c1f0-0000-7000-8000-0000000000d1";
const ID2: &str = "0197c1f0-0000-7000-8000-0000000000d2";

async fn smith(home: &Home, args: &[&str], gateway: &str, token: Option<&str>) -> Output {
    let mut c = home.cmd(args);
    c.env("LOCKSMITH_GATEWAY_URL", gateway)
        .env_remove("LOCKSMITH_USER_ACCESS_TOKEN");
    if let Some(t) = token {
        c.env("LOCKSMITH_USER_ACCESS_TOKEN", t);
    }
    tokio::task::spawn_blocking(move || {
        let mut child = c.spawn().unwrap();
        drop(child.stdin.take());
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap()
}

fn assert_clean(o: &Output) {
    for (what, bytes) in [("stdout", &o.stdout), ("stderr", &o.stderr)] {
        for canary in [VALUE, USER_TOKEN.as_bytes()] {
            assert!(
                !bytes.windows(canary.len()).any(|w| w == canary),
                "{what} leaks a canary: {}",
                String::from_utf8_lossy(bytes)
            );
        }
    }
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// A gateway that knows one honey token `prod-aws-decoy` and serves its value to `USER_TOKEN`.
async fn gateway() -> MockServer {
    let s = MockServer::start().await;
    let bearer = format!("Bearer {USER_TOKEN}");
    Mock::given(method("GET"))
        .and(path("/v1/honey-tokens"))
        .and(query_param("name", "prod-aws-decoy"))
        .and(header("authorization", bearer.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [{"id": ID, "name": "prod-aws-decoy", "template": "aws_access_key", "disabled": false}]
        })))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/honey-tokens"))
        .and(query_param("name", "twice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [
                {"id": ID, "name": "twice", "template": "github_pat", "disabled": false},
                {"id": ID2, "name": "twice", "template": "github_pat", "disabled": false}
            ]
        })))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/honey-tokens/{ID}/value")))
        .and(header("authorization", bearer.as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/octet-stream")
                .set_body_bytes(VALUE),
        )
        .mount(&s)
        .await;
    s
}

async fn value_calls(s: &MockServer) -> usize {
    s.received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("/value"))
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn plant_writes_the_decoy_with_mode_0600_and_never_prints_it() {
    let home = Home::new();
    let gw = gateway().await;
    let into = home.0.join(".env");
    let into_s = into.to_str().unwrap();

    let o = smith(
        &home,
        &["honey", "plant", "prod-aws-decoy", "--into", into_s],
        &gw.uri(),
        Some(USER_TOKEN),
    )
    .await;
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_clean(&o);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("prod-aws-decoy") && out.contains(ID), "{out}");
    let mut want = VALUE.to_vec();
    want.push(b'\n');
    assert_eq!(std::fs::read(&into).unwrap(), want);
    assert_eq!(mode(&into), 0o600);
    assert_eq!(value_calls(&gw).await, 1);

    // An existing file is refused before the value is fetched, and left as it was.
    std::fs::write(&into, b"KEEP=1\n").unwrap();
    std::fs::set_permissions(&into, std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = smith(
        &home,
        &[
            "--json",
            "honey",
            "plant",
            "prod-aws-decoy",
            "--into",
            into_s,
        ],
        &gw.uri(),
        Some(USER_TOKEN),
    )
    .await;
    assert!(!o.status.success());
    assert_clean(&o);
    assert!(String::from_utf8_lossy(&o.stdout).contains("--force"));
    assert_eq!(std::fs::read(&into).unwrap(), b"KEEP=1\n");
    assert_eq!(value_calls(&gw).await, 1, "no reveal for a refused write");

    // `--force` replaces it, with mode 0600 even though the old file was 0644; by id this time.
    let o = smith(
        &home,
        &["--json", "honey", "plant", ID, "--into", into_s, "--force"],
        &gw.uri(),
        Some(USER_TOKEN),
    )
    .await;
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
    assert_clean(&o);
    let doc: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(doc["status"], "planted");
    assert_eq!(doc["id"], ID);
    assert_eq!(std::fs::read(&into).unwrap(), want);
    assert_eq!(mode(&into), 0o600);
    // No temporary file is left behind.
    let leftovers: Vec<_> = std::fs::read_dir(&home.0)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".smith-"))
        .collect();
    assert!(leftovers.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn refusals_write_nothing_and_leak_nothing() {
    let home = Home::new();
    let gw = gateway().await;
    let into = home.0.join("decoy.env");
    let into_s = into.to_str().unwrap();

    // The gateway refuses an agent token (or anyone but the owner) with 403.
    let refusing = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "agent_token_refused", "request_id": "r1"
        })))
        .mount(&refusing)
        .await;
    let o = smith(
        &home,
        &["honey", "plant", "prod-aws-decoy", "--into", into_s],
        &refusing.uri(),
        Some(USER_TOKEN),
    )
    .await;
    assert!(!o.status.success());
    assert_clean(&o);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("403") && err.contains("owner"), "{err}");
    assert!(!into.exists());

    // Unknown and ambiguous names.
    let o = smith(
        &home,
        &["honey", "plant", "nope", "--into", into_s],
        &gw.uri(),
        Some(USER_TOKEN),
    )
    .await;
    assert!(!o.status.success());
    let o2 = smith(
        &home,
        &["honey", "plant", "twice", "--into", into_s],
        &gw.uri(),
        Some(USER_TOKEN),
    )
    .await;
    assert!(!o2.status.success());
    let err = String::from_utf8_lossy(&o2.stderr);
    assert!(err.contains(ID) && err.contains(ID2), "{err}");
    assert!(!into.exists());
    assert_eq!(value_calls(&gw).await, 0);

    // A plain-http gateway that is not loopback is refused before any request.
    let o = smith(
        &home,
        &["honey", "plant", "prod-aws-decoy", "--into", into_s],
        "http://gateway.example.com",
        Some(USER_TOKEN),
    )
    .await;
    assert!(!o.status.success());
    assert!(!into.exists());
}
