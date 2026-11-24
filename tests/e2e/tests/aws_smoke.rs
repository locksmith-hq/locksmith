//! d2-aws-sts task 7.1: the real `aws` CLI through `smith aws setup` / `credential_process`.
//! Requires `just up` (Floci), `just api` and built `locksmith-gateway` and `smith`
//! (`just aws-vend-smoke` builds them).
//!
//! An org, an AWS base-credential secret (a Floci fake), an agent and a `delegate` grant with a
//! scope are created through the control plane. A gateway is started with an `[[aws_binding]]`
//! (`vend = true`) whose STS endpoint is Floci. The test then acts as the agent only through the
//! shipped binaries and the real `aws` CLI in an isolated HOME: `smith login --agent`,
//! `smith aws setup`, `aws sts get-caller-identity --endpoint-url <floci>`. It asserts the assumed
//! role identity, the credential expiry, and that nothing in the agent's HOME or in any output
//! holds the base credential or any long-lived key.
//!
//! Skips (passes with a note) when `aws` or Floci is missing; `E2E_REQUIRE_AWS=1` makes either a
//! failure. All credentials are Floci fakes and are never printed.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ls_e2e::{api, floci, root, uniq};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use time::OffsetDateTime;

const SERVICE_TOKEN: &str = "dev-only-gateway-service-token-0123456789";
/// Floci's fixed account id.
const ACCOUNT: &str = "000000000000";
const REGION: &str = "us-east-1";
/// Fake base key (Floci accepts any key without IAM enforcement). Never in any agent-visible place.
const BASE_KEY_ID: &str = "AKIALOCKSMITHSMOKE01";
const BASE_SECRET: &str = "locksmith-smoke-fake-base-secret-not-real-9Zq";

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

fn bin(name: &str, var: &str) -> String {
    env::var(var).unwrap_or_else(|_| format!("{}/target/debug/{name}", root()))
}

async fn start_gateway(c: &Client, bindings: &str, sts: &str) -> Gateway {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = env::temp_dir().join(uniq("aws-smoke-gw"));
    std::fs::create_dir_all(&dir).unwrap();
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
        .env("LOCKSMITH_GATEWAY_AWS_STS_ENDPOINT", sts)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start locksmith-gateway (run `just aws-vend-smoke` to build it)");
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

/// A command run as the agent: isolated HOME, no ambient AWS credentials or config.
fn agent_cmd(program: &str, home: &Path, gw: &str) -> Command {
    let mut c = Command::new(program);
    c.env_clear()
        .env("PATH", env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("LOCKSMITH_HOME", home.join(".locksmith"))
        .env("LOCKSMITH_CONTROL_PLANE_URL", api())
        .env("LOCKSMITH_GATEWAY_URL", gw)
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("AWS_PAGER", "");
    // A pip `--user` awscli lives under the real HOME; keep Python's user site reachable.
    if let Some(h) = env::var_os("HOME") {
        let base = PathBuf::from(h).join(".local");
        if base.is_dir() {
            c.env("PYTHONUSERBASE", base);
        }
    }
    c
}

/// Every file under `dir`, recursively.
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

async fn floci_up(c: &Client) -> bool {
    c.get(format!("{}/_floci/health", floci()))
        .send()
        .await
        .is_ok_and(|r| r.status().is_success())
}

fn have_aws() -> bool {
    Command::new("aws")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[tokio::test]
async fn real_aws_cli_gets_scoped_keyless_credentials() {
    let required = env::var("E2E_REQUIRE_AWS").is_ok();
    let c = Client::new();
    if !have_aws() {
        assert!(
            !required,
            "the `aws` CLI is missing and E2E_REQUIRE_AWS is set"
        );
        eprintln!("skipped: the `aws` CLI is not installed (pip install awscli)");
        return;
    }
    if !floci_up(&c).await {
        assert!(
            !required,
            "Floci is not reachable and E2E_REQUIRE_AWS is set"
        );
        eprintln!(
            "skipped: Floci is not reachable at {} (run `just up`)",
            floci()
        );
        return;
    }

    // Control plane: org, project, environment, the AWS base-credential secret, agent, grant.
    let org = id_of(&cp(&c, "/v1/orgs", None, json!({ "name": uniq("awssmoke") })).await);
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
    let sid = id_of(&cp(&c, &base, o, json!({ "name": "AWS_BASE" })).await);
    let base_json = json!({ "access_key_id": BASE_KEY_ID, "secret_access_key": BASE_SECRET });
    cp(
        &c,
        &format!("{base}/{sid}/versions"),
        o,
        json!({ "value": base_json.to_string() }),
    )
    .await;
    let enrolled = cp(&c, "/v1/agents", o, json!({ "name": uniq("aws-agent") })).await;
    let agent_id = id_of(&enrolled["agent"]);
    let enrollment = enrolled["enrollment_secret"].as_str().unwrap().to_owned();
    cp(
        &c,
        &format!("/v1/agents/{agent_id}/grants"),
        o,
        json!({
            "secret_id": sid,
            "mode": "delegate",
            "scope": {
                "actions": ["s3:GetObject"],
                "resources": ["arn:aws:s3:::ls-smoke-bucket/*"],
                "max_duration_secs": 900
            }
        }),
    )
    .await;

    let role = format!("ls-smoke-{}", uniq("r").replace('-', ""));
    let bindings = format!(
        "org_id = \"{org}\"\n[[aws_binding]]\nsecret_id = \"{sid}\"\nrole_arn = \"arn:aws:iam::{ACCOUNT}:role/{role}\"\nregion = \"{REGION}\"\nexternal_id = \"ext-smoke-1\"\nvend = true\nmax_duration_secs = 900\n"
    );
    // Floci refuses AssumeRole on an unknown role: create it with the base key.
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}"#;
    let made = Command::new("aws")
        .args(["iam", "create-role", "--role-name", &role])
        .args(["--assume-role-policy-document", trust])
        .args([
            "--endpoint-url",
            &floci(),
            "--region",
            REGION,
            "--output",
            "json",
        ])
        .env("AWS_ACCESS_KEY_ID", BASE_KEY_ID)
        .env("AWS_SECRET_ACCESS_KEY", BASE_SECRET)
        .env("AWS_CONFIG_FILE", "/dev/null")
        .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run aws iam create-role");
    assert!(made.success(), "aws iam create-role on Floci failed");
    let gw = start_gateway(&c, &bindings, &floci()).await;

    let home = env::temp_dir().join(uniq("aws-smoke-home"));
    std::fs::create_dir_all(&home).unwrap();
    let smith = bin("smith", "LOCKSMITH_SMITH_BIN");
    let mut observed = String::new();
    let mut seen = |o: &std::process::Output| {
        observed.push_str(&String::from_utf8_lossy(&o.stdout));
        observed.push_str(&String::from_utf8_lossy(&o.stderr));
    };

    let out = agent_cmd(&smith, &home, &gw.base)
        .env("LOCKSMITH_ENROLLMENT_SECRET", &enrollment)
        .args(["login", "--agent"])
        .output()
        .unwrap();
    seen(&out);
    assert!(out.status.success(), "smith login --agent failed");

    let out = agent_cmd(&smith, &home, &gw.base)
        .args(["aws", "setup", "--region", REGION])
        .output()
        .unwrap();
    seen(&out);
    assert!(out.status.success(), "smith aws setup failed");
    let config = std::fs::read_to_string(home.join(".aws/config")).expect("aws config written");
    assert!(
        config.contains("credential_process"),
        "no credential_process"
    );
    assert!(
        !config.contains("aws_access_key_id") && !config.contains("aws_secret_access_key"),
        "profile holds a key"
    );
    assert!(
        !home.join(".aws/credentials").exists(),
        "a shared credentials file exists"
    );

    // The real AWS CLI, default profile `locksmith`, STS on Floci.
    let out = agent_cmd("aws", &home, &gw.base)
        .env("AWS_PROFILE", "locksmith")
        .args([
            "sts",
            "get-caller-identity",
            "--endpoint-url",
            &floci(),
            "--output",
            "json",
        ])
        .output()
        .unwrap();
    seen(&out);
    assert!(
        out.status.success(),
        "aws sts get-caller-identity failed: {}",
        String::from_utf8_lossy(&out.stderr)
            .lines()
            .last()
            .unwrap_or("")
    );
    let who: Value = serde_json::from_slice(&out.stdout).expect("aws JSON");
    let arn = who["Arn"].as_str().unwrap();
    assert_eq!(
        arn.split('/').take(2).collect::<Vec<_>>().join("/"),
        format!("arn:aws:sts::{ACCOUNT}:assumed-role/{role}"),
        "identity is not the bound role"
    );
    assert!(
        arn.contains("/locksmith-"),
        "session name is not the agent's"
    );

    // Expiry: the document `credential_process` prints is the documented shape and short-lived
    // (900 s grant cap, whatever the agent asks for).
    let out = agent_cmd(&smith, &home, &gw.base)
        .args(["aws", "credential-process", "--duration-secs", "3600"])
        .output()
        .unwrap();
    assert!(out.status.success(), "credential-process failed");
    let doc: Value = serde_json::from_slice(&out.stdout).expect("credential_process JSON");
    assert_eq!(doc["Version"], 1);
    let key = doc["AccessKeyId"].as_str().unwrap();
    assert!(key.starts_with("ASIA"), "temporary key id expected");
    let exp = OffsetDateTime::parse(
        doc["Expiration"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let left = (exp - OffsetDateTime::now_utc()).whole_seconds();
    assert!((600..=960).contains(&left), "expiry out of range: {left}s");
    let temp_secret = doc["SecretAccessKey"].as_str().unwrap().to_owned();
    let temp_token = doc["SessionToken"].as_str().unwrap().to_owned();
    // The base credential is not in the vended document or any output.
    let doc_text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(!doc_text.contains(BASE_SECRET) && !doc_text.contains(BASE_KEY_ID));

    // The agent's HOME holds no key: no long-lived key id, no base credential, no vended secret
    // cached by smith or the CLI.
    let mut all = Vec::new();
    files(&home, &mut all);
    assert!(!all.is_empty());
    for f in &all {
        let Ok(bytes) = std::fs::read(f) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        let name = f.strip_prefix(&home).unwrap().display().to_string();
        for (what, needle) in [
            ("base key id", BASE_KEY_ID),
            ("base secret", BASE_SECRET),
            ("long-lived key prefix", "AKIA"),
            ("vended secret", temp_secret.as_str()),
            ("vended session token", temp_token.as_str()),
            ("enrollment secret", enrollment.as_str()),
        ] {
            assert!(!text.contains(needle), "{what} found in HOME file {name}");
        }
    }
    for needle in [
        BASE_KEY_ID,
        BASE_SECRET,
        temp_secret.as_str(),
        temp_token.as_str(),
    ] {
        assert!(!observed.contains(needle), "a secret reached agent output");
    }
    let _ = std::fs::remove_dir_all(&home);
}
