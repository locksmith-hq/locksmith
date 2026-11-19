//! cli-core spec: version formats, JSON purity, exit codes, completions, doctor.

use std::process::Command;

fn smith(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_smith"))
        .args(args)
        .env(
            "LOCKSMITH_HOME",
            std::env::temp_dir().join("smith-cli-test-home"),
        )
        .env("LOCKSMITH_UPDATE_URL", "http://127.0.0.1:9") // keep doctor offline and fast
        .output()
        .unwrap()
}

#[test]
fn human_version() {
    let o = smith(&["--version"]);
    assert!(o.status.success());
    let s = String::from_utf8(o.stdout).unwrap();
    assert!(
        s.starts_with(&format!("smith {} (", env!("CARGO_PKG_VERSION"))),
        "{s}"
    );
}

#[test]
fn json_version_has_keys() {
    let o = smith(&["--version", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    for k in ["version", "commit", "target", "channel"] {
        assert!(v.get(k).is_some(), "missing {k}");
    }
}

#[test]
fn unknown_flag_is_usage_error() {
    let o = smith(&["--definitely-not-a-flag"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(!o.stderr.is_empty());
}

#[test]
fn zsh_completions() {
    let o = smith(&["completions", "zsh"]);
    assert!(o.status.success());
    assert!(
        String::from_utf8(o.stdout)
            .unwrap()
            .contains("#compdef smith")
    );
}

#[test]
fn doctor_json_is_single_document() {
    let o = smith(&["doctor", "--json"]);
    let v: serde_json::Value =
        serde_json::from_slice(&o.stdout).expect("stdout is one JSON document");
    assert_eq!(v["schema"], "doctor.v1");
    let ids: Vec<&str> = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    for id in [
        "platform.supported",
        "fs.config_dir_perms",
        "binary.signature",
        "update.reachable",
        "vault.present",
        "vault.perms",
        "vault.kdf_params",
        "vault.wraps",
        "redact.selftest",
        "run.pty_available",
    ] {
        assert!(ids.contains(&id), "missing check {id}");
    }
}

#[test]
fn update_error_in_json_mode_is_one_document() {
    let o = smith(&["self", "update", "--check", "--json"]);
    assert_eq!(o.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["code"], 1);
}

#[test]
fn login_user_refuses_plain_http_issuer_before_any_request() {
    let o = smith(&[
        "login",
        "--user",
        "--issuer",
        "http://issuer.example.com/realms/x",
    ]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("https"));
}

#[test]
fn login_requires_agent_or_user_and_they_conflict() {
    assert_eq!(smith(&["login"]).status.code(), Some(2));
    let o = smith(&["login", "--user", "--agent"]);
    assert_eq!(o.status.code(), Some(2));
}
