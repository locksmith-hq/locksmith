//! E2E for the hosted Postgres relay (D3 task 7.1). Requires `just up`, `just api`, a built
//! gateway and `smith` (`just db-smoke` builds them) and `psql` on PATH; skips with a message when
//! the stack or `psql` is unreachable.
//!
//! A SCRAM role is created on the compose Postgres, its password stored as a secret, and an agent
//! granted relay mode. The test starts its own gateway with a pg listener (rcgen certificate) and
//! runs real `psql` through `smith db connect --gateway`. It asserts the query result, that
//! `db connect` created or modified no file (the existing `agent.json` excepted, home snapshotted
//! before and after), and that no file or output holds the database password or the agent token.
//! `just leak-scan` then covers Postgres, Loki and Tempo.

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ls_e2e::{api, mint_canary, root, uniq};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};

const SERVICE_TOKEN: &str = "dev-only-gateway-service-token-0123456789";
const PG_ADDR: &str = "127.0.0.1:5432";
const PG_SUPERUSER: &str = "host=127.0.0.1 user=locksmith password=locksmith-dev-only dbname=locksmith";

async fn cp(c: &Client, path: &str, org: Option<&str>, body: Value) -> Value {
    let mut req = c.post(format!("{}{path}", api())).json(&body);
    if let Some(o) = org {
        req = req.header("X-Locksmith-Dev-Org", o);
    }
    let r = req.send().await.expect("reach locksmith-api");
    let status = r.status();
    let v: Value = r.json().await.unwrap_or(Value::Null);
    assert_eq!(status, StatusCode::CREATED, "POST {path}");
    v
}

fn id_of(v: &Value) -> String {
    v["id"].as_str().unwrap().to_owned()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Gateway {
    child: Child,
    pg_port: u16,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start the built gateway with a pg listener and wait for `/readyz`.
async fn start_gateway(c: &Client, dir: &Path, bindings: &str, cert: &Path, key: &Path) -> Gateway {
    let http_port = free_port();
    let pg_port = free_port();
    let path = dir.join("bindings.toml");
    std::fs::write(&path, bindings).unwrap();
    let bin = env::var("LOCKSMITH_GATEWAY_BIN")
        .unwrap_or_else(|_| format!("{}/target/debug/locksmith-gateway", root()));
    let child = Command::new(bin)
        .env("LOCKSMITH_GATEWAY_BIND", format!("127.0.0.1:{http_port}"))
        .env(
            "DATABASE_URL",
            "postgres://locksmith_app:locksmith-app-dev-only@127.0.0.1:5432/locksmith",
        )
        .env("LOCKSMITH_GATEWAY_SERVICE_TOKEN", SERVICE_TOKEN)
        .env("LOCKSMITH_CONTROL_PLANE_URL", api())
        .env("OPENBAO_ADDR", "http://127.0.0.1:8200")
        .env("OPENBAO_GATEWAY_TOKEN", "dev-only-gateway")
        .env("LOCKSMITH_GATEWAY_BINDINGS", &path)
        .env("LOCKSMITH_GATEWAY_PG_LISTEN", format!("127.0.0.1:{pg_port}"))
        .env("LOCKSMITH_GATEWAY_PG_TLS_CERT", cert)
        .env("LOCKSMITH_GATEWAY_PG_TLS_KEY", key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start locksmith-gateway (run `just db-smoke` to build it)");
    let gw = Gateway { child, pg_port };
    let base = format!("http://127.0.0.1:{http_port}");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(r) = c.get(format!("{base}/readyz")).send().await
            && r.status().is_success()
        {
            return gw;
        }
        assert!(Instant::now() < deadline, "gateway did not become ready");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Every regular file under `dir`, relative path to contents.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(base, &p, out);
            } else if let Ok(b) = std::fs::read(&p) {
                out.insert(p.strip_prefix(base).unwrap().to_path_buf(), b);
            }
        }
    }
    let mut m = BTreeMap::new();
    walk(dir, dir, &mut m);
    m
}

fn contains(hay: &[u8], needle: &str) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// Why the test cannot run here, if so.
async fn unavailable(c: &Client) -> Option<String> {
    if Command::new("psql")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        return Some("psql is not on PATH".into());
    }
    if tokio::net::TcpStream::connect(PG_ADDR).await.is_err() {
        return Some(format!("Postgres is not reachable at {PG_ADDR} (run `just up`)"));
    }
    if c.get(format!("{}/healthz", api())).send().await.is_err() {
        return Some(format!("locksmith-api is not reachable at {} (run `just api`)", api()));
    }
    None
}

#[tokio::test]
async fn psql_through_smith_db_connect_holds_no_password_or_token() {
    let c = Client::new();
    if let Some(why) = unavailable(&c).await {
        eprintln!("skipped: {why}");
        return;
    }

    // A SCRAM role on the compose Postgres, its password minted as a canary for `just leak-scan`.
    let password = mint_canary();
    let role = uniq("ls_e2e_db").replace('-', "_");
    let (pg, conn) = tokio_postgres::connect(PG_SUPERUSER, tokio_postgres::NoTls)
        .await
        .expect("connect to the compose Postgres as its superuser");
    tokio::spawn(conn);
    pg.batch_execute("SET password_encryption = 'scram-sha-256'")
        .await
        .unwrap();
    pg.batch_execute(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD '{}'",
        password.replace('\'', "''")
    ))
    .await
    .unwrap();

    // Control plane: org, the password as a secret, an agent granted relay mode.
    let org = id_of(&cp(&c, "/v1/orgs", None, json!({ "name": uniq("db") })).await);
    let o = Some(org.as_str());
    let pid = id_of(&cp(&c, "/v1/projects", o, json!({ "name": "p" })).await);
    let eid = id_of(
        &cp(&c, &format!("/v1/projects/{pid}/environments"), o, json!({ "name": "e" })).await,
    );
    let base = format!("/v1/projects/{pid}/environments/{eid}/secrets");
    let sid = id_of(&cp(&c, &base, o, json!({ "name": "DB_PASSWORD" })).await);
    cp(&c, &format!("{base}/{sid}/versions"), o, json!({ "value": password })).await;
    let enrolled = cp(&c, "/v1/agents", o, json!({ "name": uniq("db-agent") })).await;
    let agent_id = id_of(&enrolled["agent"]);
    let enrollment = enrolled["enrollment_secret"].as_str().unwrap().to_owned();
    cp(
        &c,
        &format!("/v1/agents/{agent_id}/grants"),
        o,
        json!({ "secret_id": sid, "mode": "relay" }),
    )
    .await;

    // Gateway with a pg listener. The compose Postgres has no TLS, so the upstream leg is
    // `disable`, allowed only with allow_private_hosts (loopback).
    let dir = env::temp_dir().join(uniq("db-relay-e2e"));
    std::fs::create_dir_all(&dir).unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let (cert_path, key_path) = (dir.join("gw.crt"), dir.join("gw.key"));
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    let bindings = format!(
        "org_id = \"{org}\"\n[[pg]]\nname = \"app\"\nsecret_id = \"{sid}\"\nhost = \"127.0.0.1\"\nport = 5432\nuser = \"{role}\"\ndatabase = \"locksmith\"\ntls = \"disable\"\nallow_private_hosts = true\n"
    );
    let gw = start_gateway(&c, &dir, &bindings, &cert_path, &key_path).await;

    // The agent: an isolated home (also HOME and TMPDIR, so any stray file is seen), own cwd.
    let home = dir.join("home");
    let cwd = dir.join("cwd");
    std::fs::create_dir_all(home.join("tmp")).unwrap();
    std::fs::create_dir_all(&cwd).unwrap();
    let smith = env::var("LOCKSMITH_SMITH_BIN")
        .unwrap_or_else(|_| format!("{}/target/debug/smith", root()));
    let agent_cmd = |first: &str| {
        let mut cmd = Command::new(&smith);
        cmd.env_clear()
            .current_dir(&cwd)
            .env("PATH", env::var("PATH").unwrap_or_default())
            .env("HOME", &home)
            .env("TMPDIR", home.join("tmp"))
            .env("LOCKSMITH_HOME", &home)
            .env("LOCKSMITH_CONTROL_PLANE_URL", api())
            .env("LOCKSMITH_GATEWAY_URL", "http://127.0.0.1:1")
            .arg(first);
        cmd
    };
    let out = agent_cmd("login")
        .arg("--agent")
        .env("LOCKSMITH_ENROLLMENT_SECRET", &enrollment)
        .output()
        .unwrap();
    assert!(out.status.success(), "smith login --agent failed");

    let state = std::fs::read_to_string(home.join("agent.json")).expect("agent.json written");
    let token = serde_json::from_str::<Value>(&state).unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let before = (snapshot(&home), snapshot(&cwd));
    let out = agent_cmd("db")
        .args(["connect", "app", "--gateway"])
        .arg(format!("localhost:{}", gw.pg_port))
        .arg("--ca-cert")
        .arg(&cert_path)
        .args(["--", "psql", "-X", "-w", "-tA", "-F", "|", "-c", "SELECT current_user, 6 * 7"])
        .output()
        .unwrap();
    let after = (snapshot(&home), snapshot(&cwd));

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut observed = stdout.clone();
    observed.push_str(&String::from_utf8_lossy(&out.stderr));
    let ok = out.status.success();
    let expected = format!("{role}|42");

    // Drop the role before asserting, so a failure leaves nothing behind.
    let _ = pg.batch_execute(&format!("DROP ROLE IF EXISTS {role}")).await;

    assert!(ok, "psql through smith db connect failed");
    assert_eq!(stdout.trim(), expected, "query ran as the bound role");

    // `db connect` wrote nothing: every file except agent.json is identical, none is new.
    for (name, (b, a)) in [("home", (&before.0, &after.0)), ("cwd", (&before.1, &after.1))] {
        let strip = |m: &BTreeMap<PathBuf, Vec<u8>>| {
            m.iter()
                .filter(|(p, _)| p.as_os_str() != "agent.json")
                .map(|(p, v)| (p.clone(), v.clone()))
                .collect::<BTreeMap<_, _>>()
        };
        assert!(strip(b) == strip(a), "db connect created or changed a file in the {name}");
    }
    assert!(after.0.contains_key(Path::new("agent.json")), "agent.json is kept");

    // No file holds the database password; no file but agent.json holds the token; neither shows
    // in anything the agent saw.
    for (p, bytes) in after.0.iter().chain(after.1.iter()) {
        assert!(!contains(bytes, &password), "{} holds the database password", p.display());
        if p.as_os_str() != "agent.json" {
            assert!(!contains(bytes, &token), "{} holds the agent token", p.display());
        }
    }
    assert!(!contains(observed.as_bytes(), &password), "output shows the database password");
    assert!(!contains(observed.as_bytes(), &token), "output shows the agent token");
    assert!(!contains(observed.as_bytes(), &enrollment), "output shows the enrollment secret");
    let _ = std::fs::remove_dir_all(&dir);
}
