//! End-to-end tests live in `tests/`. They need the dev stack (`just up`).
//! Shared helpers for those tests (dev-only endpoints; overridable by env).

use std::env;
use std::process::Command;

/// Repository root.
pub fn root() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../..")
}

/// Control-plane API base URL (`E2E_API_URL`).
pub fn api() -> String {
    env::var("E2E_API_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into())
}

/// WireMock base URL (`E2E_WIREMOCK_URL`).
pub fn wiremock() -> String {
    env::var("E2E_WIREMOCK_URL").unwrap_or_else(|_| "http://127.0.0.1:8089".into())
}

/// Floci (local AWS stand-in, `floci` in compose) base URL (`FLOCI_URL`).
pub fn floci() -> String {
    env::var("FLOCI_URL").unwrap_or_else(|_| "http://127.0.0.1:4566".into())
}

/// `prefix` plus a nanosecond timestamp, for names that must not collide between runs.
pub fn uniq(prefix: &str) -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{t}")
}

/// A fresh canary value, minted by the leak oracle into the gitignored canary file. Never print it.
pub fn mint_canary() -> String {
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
