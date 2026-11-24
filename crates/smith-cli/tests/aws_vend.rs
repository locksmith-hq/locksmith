//! D2 task 4: `smith aws credential-process|setup|teardown` and the `aws.vend` doctor check, against
//! a mock gateway. The credential canaries must appear only on the one stdout line that is the
//! `credential_process` document.
#![cfg(unix)]

mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::Home;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "eyJhbGciOiJFZERTQSJ9.TOKEN_CANARY_PAYLOAD_0123456789.SIGNATURE_CANARY_abcdef";
const AKID: &str = "ASIACANARYKEYID0000";
const SECRET: &str = "SECRET_ACCESS_KEY_CANARY_0123456789";
const SESSION: &str = "SESSION_TOKEN_CANARY_abcdefghijklmnop";

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn login_state(home: &Home, gateway: &str) {
    let p = home.0.join("agent.json");
    let doc = serde_json::json!({
        "access_token": TOKEN,
        "expires_at_unix": 4_102_444_800_u64,
        "control_plane_url": "http://127.0.0.1:1",
        "gateway_url": gateway,
    });
    std::fs::write(&p, doc.to_string()).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn smith(home: &Home, args: &[&str], env: &[(&str, &Path)]) -> Output {
    let mut c = home.cmd(args);
    for (k, v) in env {
        c.env(k, v);
    }
    let mut child = c.spawn().unwrap();
    drop(child.stdin.take());
    child.wait_with_output().unwrap()
}

fn gateway_ok() -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("cache-control", "no-store")
        .set_body_json(serde_json::json!({
            "Version": 1,
            "AccessKeyId": AKID,
            "SecretAccessKey": SECRET,
            "SessionToken": SESSION,
            "Expiration": "2030-01-01T00:15:00Z",
            "Extra": "dropped"
        }))
}

async fn run(home: &Home, args: Vec<String>) -> Output {
    let c = {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut c = home.cmd(&args);
        c.env("AWS_CONFIG_FILE", home.0.join("aws-config"));
        c
    };
    tokio::task::spawn_blocking(move || {
        let mut c = c;
        let mut child = c.spawn().unwrap();
        drop(child.stdin.take());
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn aws_credential_process_prints_the_documented_json_and_caches_nothing() {
    let gw = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/aws/credentials"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(gateway_ok())
        .expect(1)
        .mount(&gw)
        .await;
    let home = Home::new();
    login_state(&home, &gw.uri());
    let before = std::fs::read_dir(&home.0).unwrap().count();
    let o = run(&home, vec!["aws".into(), "credential-process".into()]).await;
    assert!(o.status.success(), "{}", text(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["Version"], 1);
    assert_eq!(v["AccessKeyId"], AKID);
    assert_eq!(v["SecretAccessKey"], SECRET);
    assert_eq!(v["SessionToken"], SESSION);
    assert_eq!(v["Expiration"], "2030-01-01T00:15:00Z");
    assert_eq!(
        v.as_object().unwrap().len(),
        5,
        "only the documented fields"
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        !err.contains(SECRET) && !err.contains(SESSION) && !err.contains(TOKEN),
        "{err}"
    );
    // Nothing written to disk: the home holds the same entries as before, and no file has a key.
    assert_eq!(before, std::fs::read_dir(&home.0).unwrap().count());
    for e in std::fs::read_dir(&home.0).unwrap().flatten() {
        if e.path().is_file() {
            let c = std::fs::read_to_string(e.path()).unwrap_or_default();
            assert!(
                !c.contains(SECRET) && !c.contains(SESSION),
                "{:?}",
                e.path()
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn aws_denial_is_one_fixed_message_without_server_text() {
    let gw = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/aws/credentials"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "vend_disabled",
            "detail": format!("{SECRET} {SESSION} {AKID}")
        })))
        .mount(&gw)
        .await;
    let home = Home::new();
    login_state(&home, &gw.uri());
    let o = run(&home, vec!["aws".into(), "credential-process".into()]).await;
    assert!(!o.status.success());
    assert!(o.stdout.is_empty(), "no stdout on denial");
    let err = text(&o);
    assert!(err.contains("AWS credentials were not issued"), "{err}");
    for canary in [SECRET, SESSION, AKID, TOKEN, "vend_disabled"] {
        assert!(!err.contains(canary), "{err}");
    }
    // A 500 and a malformed 200 give the same message.
    gw.reset().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("{{\"x\":\"{SECRET}\"}}")))
        .mount(&gw)
        .await;
    let o = run(&home, vec!["aws".into(), "credential-process".into()]).await;
    assert!(!o.status.success() && o.stdout.is_empty());
    assert!(text(&o).contains("AWS credentials were not issued"));
    assert!(!text(&o).contains(SECRET));
}

#[tokio::test(flavor = "multi_thread")]
async fn aws_credential_process_needs_login_and_the_right_gateway() {
    let home = Home::new();
    let o = run(&home, vec!["aws".into(), "credential-process".into()]).await;
    assert!(!o.status.success() && o.stdout.is_empty());
    assert!(text(&o).contains("not logged in"), "{}", text(&o));

    let gw = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(gateway_ok())
        .expect(0)
        .mount(&gw)
        .await;
    login_state(&home, &gw.uri());
    let o = run(
        &home,
        vec![
            "aws".into(),
            "credential-process".into(),
            "--gateway".into(),
            "http://127.0.0.1:9".into(),
        ],
    )
    .await;
    assert!(!o.status.success() && o.stdout.is_empty());
    assert!(!text(&o).contains(TOKEN));
}

fn aws_home() -> (Home, PathBuf) {
    let home = Home::new();
    let cfg = home.0.join("aws-config");
    (home, cfg)
}

#[test]
fn aws_setup_then_teardown_restores_the_config_and_writes_no_key() {
    let (home, cfg) = aws_home();
    let env = [("AWS_CONFIG_FILE", cfg.as_path())];
    let orig = "[default]\nregion = us-east-1\n\n[profile dev]\nsso_session = corp\n";
    std::fs::write(&cfg, orig).unwrap();

    let o = smith(&home, &["aws", "setup", "--region", "eu-west-1"], &env);
    assert!(o.status.success(), "{}", text(&o));
    let after = std::fs::read_to_string(&cfg).unwrap();
    assert!(after.starts_with(orig));
    assert!(after.contains("[profile locksmith]"));
    assert!(after.contains("region = eu-west-1"));
    assert!(after.contains("aws credential-process"));
    let lower = after.to_ascii_lowercase();
    assert!(!lower.contains("aws_access_key_id") && !lower.contains("aws_secret_access_key"));
    assert!(!lower.contains("aws_session_token"));

    // Idempotent.
    let o = smith(&home, &["aws", "setup", "--region", "eu-west-1"], &env);
    assert!(o.status.success());
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), after);

    let o = smith(&home, &["aws", "teardown"], &env);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), orig);
    // Teardown again is a no-op.
    let o = smith(&home, &["aws", "teardown"], &env);
    assert!(o.status.success());
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), orig);
}

#[test]
fn aws_setup_creates_a_missing_config_and_teardown_empties_it() {
    let (home, cfg) = aws_home();
    let cfg = cfg.parent().unwrap().join("nested").join("config");
    let env = [("AWS_CONFIG_FILE", cfg.as_path())];
    let o = smith(
        &home,
        &["aws", "setup", "--gateway", "http://127.0.0.1:8080"],
        &env,
    );
    assert!(o.status.success(), "{}", text(&o));
    let c = std::fs::read_to_string(&cfg).unwrap();
    assert!(c.contains("--gateway http://127.0.0.1:8080"), "{c}");
    let o = smith(&home, &["aws", "teardown"], &env);
    assert!(o.status.success());
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), "");
}

#[test]
fn aws_setup_refuses_to_clobber_and_bad_input() {
    let (home, cfg) = aws_home();
    let env = [("AWS_CONFIG_FILE", cfg.as_path())];
    let orig = "[profile locksmith]\nregion = us-west-2\n";
    std::fs::write(&cfg, orig).unwrap();
    let o = smith(&home, &["aws", "setup"], &env);
    assert!(!o.status.success());
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), orig);
    // Teardown leaves an unmanaged profile alone.
    let o = smith(&home, &["aws", "teardown"], &env);
    assert!(o.status.success());
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), orig);
    for args in [
        vec!["aws", "setup", "--profile", "a]\n[b"],
        vec!["aws", "setup", "--gateway", "http://example.com"],
        vec!["aws", "setup", "--region", "x y"],
    ] {
        let o = smith(&home, &args, &env);
        assert!(!o.status.success(), "{args:?}");
        assert_eq!(std::fs::read_to_string(&cfg).unwrap(), orig);
    }
}

fn doctor_check(home: &Home, cfg: &Path, creds: &Path) -> serde_json::Value {
    let o = smith(
        home,
        &["--json", "doctor"],
        &[
            ("AWS_CONFIG_FILE", cfg),
            ("AWS_SHARED_CREDENTIALS_FILE", creds),
        ],
    );
    let v: serde_json::Value =
        serde_json::from_slice(&o.stdout).unwrap_or_else(|_| panic!("{}", text(&o)));
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "aws.vend")
        .unwrap_or_else(|| panic!("no aws.vend check"))
        .clone()
}

#[test]
fn doctor_aws_vend_off_warn_and_fail() {
    let (home, cfg) = aws_home();
    let creds = home.0.join("aws-credentials");
    assert_eq!(doctor_check(&home, &cfg, &creds)["status"], "skip");

    let o = smith(
        &home,
        &["aws", "setup"],
        &[("AWS_CONFIG_FILE", cfg.as_path())],
    );
    assert!(o.status.success());
    let c = doctor_check(&home, &cfg, &creds);
    assert_eq!(c["status"], "warn", "{c}");
    assert!(
        c["summary"]
            .as_str()
            .unwrap()
            .contains("visible to the agent")
    );

    let mut f = std::fs::File::create(&creds).unwrap();
    writeln!(
        f,
        "[default]\naws_access_key_id = {AKID}\naws_secret_access_key = {SECRET}"
    )
    .unwrap();
    let c = doctor_check(&home, &cfg, &creds);
    assert_eq!(c["status"], "fail", "{c}");
    assert!(!c.to_string().contains(SECRET) && !c.to_string().contains(AKID));
}

#[test]
fn aws_help_mentions_vending_and_agent_visibility() {
    let home = Home::new();
    let o = smith(&home, &["aws", "--help"], &[]);
    let h = text(&o);
    for w in ["credential-process", "setup", "teardown"] {
        assert!(h.contains(w), "{h}");
    }
    let o = smith(&home, &["aws", "credential-process", "--help"], &[]);
    assert!(text(&o).contains("visible"), "{}", text(&o));
}
