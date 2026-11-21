//! E2E for workload identity (D4 task 7.1). Requires `just up`, a built gateway and `smith`, and a
//! control plane started by `just workload-smoke-api` (it trusts the stub issuer's certificate and
//! allows a loopback issuer; `just workload-smoke` builds the binaries and creates the certificate).
//!
//! An org, a canary secret, an agent, a grant and a workload policy (issuer: an in-process
//! GitHub-shaped OIDC stub over TLS on loopback) are created through the API. The test then acts as
//! the CI job only through the shipped binary: `smith login --workload github` against an
//! in-process stub of the runner token endpoint, then `smith relay` through the gateway. It asserts
//! the WireMock upstream saw the canary, and that nothing the workload sees (smith output, the
//! files in its home) contains the canary or the external token. A token whose `ref` does not match
//! the policy is refused at exchange, and after the grant is revoked a relay is refused and the
//! upstream sees nothing more. `just leak-scan` then covers Postgres, Loki and Tempo.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ls_e2e::{api, mint_canary, root, uniq, wiremock};
use p256::pkcs8::EncodePrivateKey as _;
use reqwest::{Client, StatusCode};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;

const SERVICE_TOKEN: &str = "dev-only-gateway-service-token-0123456789";
const AUDIENCE: &str = "locksmith-workload-smoke";
const REPO: &str = "acme/api";
const RUNNER_BEARER: &str = "stub-runner-request-token";

// ---------------------------------------------------------------------------------------------
// Control plane helpers (as in connector.rs)

async fn cp_status(
    c: &Client,
    method: &str,
    path: &str,
    org: Option<&str>,
    body: Option<Value>,
    expected: StatusCode,
) -> Value {
    let url = format!("{}{path}", api());
    let mut req = match method {
        "POST" => c.post(url),
        "DELETE" => c.delete(url),
        _ => c.get(url),
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
        .expect("reach locksmith-api (is `just workload-smoke-api` running?)");
    let status = r.status();
    let v: Value = r.json().await.unwrap_or(Value::Null);
    assert_eq!(status, expected, "{method} {path}");
    v
}

async fn cp(c: &Client, path: &str, org: Option<&str>, body: Value) -> Value {
    cp_status(c, "POST", path, org, Some(body), StatusCode::CREATED).await
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

async fn start_gateway(c: &Client, bindings: &str) -> Gateway {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = env::temp_dir().join(uniq("workload-e2e"));
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
        .expect("start locksmith-gateway (run `just workload-smoke` to build it)");
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

/// Run `smith` as the workload: isolated home, no ambient credentials.
fn smith_cmd(smith: &str, home: &Path, gw: &str) -> Command {
    let mut c = Command::new(smith);
    c.env_clear()
        .env("PATH", env::var("PATH").unwrap_or_default())
        .env("LOCKSMITH_HOME", home)
        .env("LOCKSMITH_CONTROL_PLANE_URL", api())
        .env("LOCKSMITH_GATEWAY_URL", gw);
    c
}

// ---------------------------------------------------------------------------------------------
// Stubs: a GitHub-shaped OIDC issuer (TLS, loopback) and the runner's token endpoint (http).

struct Key {
    signing: p256::ecdsa::SigningKey,
}

impl Key {
    const KID: &'static str = "workload-smoke-k1";

    fn new() -> Self {
        Self {
            signing: p256::ecdsa::SigningKey::from_slice(&[0x37; 32]).unwrap(),
        }
    }

    fn jwk(&self) -> Value {
        let point = self.signing.verifying_key().to_sec1_point(false);
        json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": Self::KID,
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        })
    }

    fn mint(&self, claims: &Value) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(Self::KID.to_owned());
        let der = self.signing.to_pkcs8_der().unwrap();
        jsonwebtoken::encode(
            &header,
            claims,
            &jsonwebtoken::EncodingKey::from_ec_der(der.as_bytes()),
        )
        .unwrap()
    }
}

type Route = Arc<dyn Fn(&str) -> (u16, String) + Send + Sync>;

/// Answer one HTTP/1.1 request on `stream`: `route(request head)` returns `(status, body)`.
async fn answer<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, route: Route) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let (status, body) = route(&head);
    let reply = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(reply.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn request_target(head: &str) -> &str {
    head.split_whitespace().nth(1).unwrap_or("")
}

/// The stub issuer: discovery and JWKS over TLS with the smoke certificate. Returns its URL.
async fn start_issuer(key: &Key) -> String {
    let dir = env::var("E2E_WORKLOAD_CERT_DIR")
        .unwrap_or_else(|_| format!("{}/infra/compose/.workload-smoke", root()));
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(format!("{dir}/cert.pem"))
            .expect("read the stub issuer certificate (run `just workload-smoke`)")
            .map(|c| c.unwrap())
            .collect();
    let private = PrivateKeyDer::from_pem_file(format!("{dir}/key.pem")).expect("read key");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, private)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let discovery = json!({ "issuer": url, "jwks_uri": format!("{url}/jwks") }).to_string();
    let jwks = json!({ "keys": [key.jwk()] }).to_string();
    let route: Route = Arc::new(move |head| match request_target(head) {
        "/.well-known/openid-configuration" => (200, discovery.clone()),
        "/jwks" => (200, jwks.clone()),
        _ => (404, "{}".into()),
    });
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let (acceptor, route) = (acceptor.clone(), route.clone());
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    answer(tls, route).await;
                }
            });
        }
    });
    url
}

/// What the stub runner hands out and saw.
#[derive(Default)]
struct Runner {
    token: Mutex<String>,
    audiences: Mutex<Vec<String>>,
}

/// The runner's `ACTIONS_ID_TOKEN_REQUEST_URL` endpoint. Returns the URL to put in the env.
async fn start_runner(state: Arc<Runner>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://127.0.0.1:{}/idtoken",
        listener.local_addr().unwrap().port()
    );
    let route: Route = Arc::new(move |head| {
        let authed = head
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {RUNNER_BEARER}"));
        if !authed {
            return (401, "{}".into());
        }
        let target = request_target(head);
        if let Some(a) = target.split("audience=").nth(1) {
            let a = a.split('&').next().unwrap_or("").to_owned();
            state.audiences.lock().unwrap().push(a);
        }
        let token = state.token.lock().unwrap().clone();
        (200, json!({ "count": 1, "value": token }).to_string())
    });
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(answer(tcp, route.clone()));
        }
    });
    url
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn claims(issuer: &str, git_ref: &str) -> Value {
    let t = now();
    json!({
        "iss": issuer, "aud": AUDIENCE, "sub": format!("repo:{REPO}:ref:{git_ref}"),
        "repository": REPO, "ref": git_ref, "actor": "workload-smoke",
        "jti": uniq("jti"), "iat": t, "nbf": t, "exp": t + 600,
    })
}

async fn upstream_hits(c: &Client, path: &str, canary: &str) -> usize {
    let journal: Value = c
        .get(format!("{}/__admin/requests", wiremock()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    journal["requests"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| {
            r["request"]["url"] == path
                && r["request"]["headers"]["Authorization"]
                    .as_str()
                    .is_some_and(|h| h == format!("Bearer {canary}"))
        })
        .count()
}

fn seen(observed: &mut String, o: &std::process::Output) {
    observed.push_str(&String::from_utf8_lossy(&o.stdout));
    observed.push_str(&String::from_utf8_lossy(&o.stderr));
}

fn home_files(home: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(home)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn workload_logs_in_with_oidc_and_never_holds_a_secret() {
    let c = Client::new();
    let canary = mint_canary();

    // Org, canary secret, agent, grant (all through the API).
    let org = id_of(&cp(&c, "/v1/orgs", None, json!({ "name": uniq("wl") })).await);
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
    let enrolled = cp(&c, "/v1/agents", o, json!({ "name": uniq("wl-agent") })).await;
    let agent_id = id_of(&enrolled["agent"]);
    let grant = id_of(
        &cp(
            &c,
            &format!("/v1/agents/{agent_id}/grants"),
            o,
            json!({ "secret_id": sid }),
        )
        .await,
    );

    // Stub issuer and the workload policy (repository and ref pinned).
    let key = Key::new();
    let issuer = start_issuer(&key).await;
    let policy = cp(
        &c,
        "/v1/workload-identities",
        o,
        json!({
            "name": uniq("ci"), "issuer_kind": "oidc", "issuer": issuer, "audience": AUDIENCE,
            "agent_id": agent_id,
            "conditions": [
                {"claim": "sub", "pattern": format!("repo:{REPO}:*")},
                {"claim": "repository", "pattern": REPO},
                {"claim": "ref", "pattern": "refs/heads/main"},
            ],
        }),
    )
    .await;
    let handle = policy["handle"].as_str().unwrap().to_owned();
    assert!(handle.starts_with("lsw_"));

    // Upstream stub that echoes the secret (the gateway must redact it), and the gateway.
    let path = format!("/{}", uniq("wl-echo"));
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
    let url = format!("{}{path}", wiremock());

    // The runner hands out a token for the matching ref.
    let runner = Arc::new(Runner::default());
    let runner_url = start_runner(runner.clone()).await;
    let good = key.mint(&claims(&issuer, "refs/heads/main"));
    *runner.token.lock().unwrap() = good.clone();

    let smith = env::var("LOCKSMITH_SMITH_BIN")
        .unwrap_or_else(|_| format!("{}/target/debug/smith", root()));
    let home = env::temp_dir().join(uniq("workload-home"));
    std::fs::create_dir_all(&home).unwrap();
    let mut observed = String::new();
    let login = |smith: &str, home: &Path| {
        smith_cmd(smith, home, &gw.base)
            .env("ACTIONS_ID_TOKEN_REQUEST_URL", &runner_url)
            .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", RUNNER_BEARER)
            .env("LOCKSMITH_WORKLOAD_AUDIENCE", AUDIENCE)
            .env("LOCKSMITH_WORKLOAD_POLICY", &handle)
            .args(["login", "--workload", "github"])
            .output()
            .unwrap()
    };

    // 1. Matching token: login succeeds and writes only agent.json.
    let out = login(&smith, &home);
    seen(&mut observed, &out);
    assert!(out.status.success(), "smith login --workload github failed");
    assert_eq!(
        *runner.audiences.lock().unwrap(),
        vec![AUDIENCE.to_owned()],
        "smith asked the runner for the policy audience"
    );
    let files = home_files(&home);
    assert_eq!(
        files
            .iter()
            .map(|p| p.file_name().unwrap().to_owned())
            .collect::<Vec<_>>(),
        vec![std::ffi::OsString::from("agent.json")],
        "only agent.json may be written"
    );
    let state = std::fs::read_to_string(home.join("agent.json")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(home.join("agent.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "state file must be 0600");
    }

    // 2. Relay through the gateway: the upstream sees the secret, the workload does not.
    let out = smith_cmd(&smith, &home, &gw.base)
        .args(["relay", "--secret-id", &sid, &url])
        .output()
        .unwrap();
    seen(&mut observed, &out);
    assert!(out.status.success(), "smith relay failed");
    assert!(String::from_utf8_lossy(&out.stdout).contains("REDACTED"));
    assert_eq!(
        upstream_hits(&c, &path, &canary).await,
        1,
        "upstream saw the injected header"
    );

    observed.push_str(&state);
    assert!(
        !observed.contains(&canary),
        "the workload observed the secret"
    );
    assert!(!observed.contains(&good), "the external token leaked");
    let external_sig = good.rsplit('.').next().unwrap();
    assert!(
        !observed.contains(external_sig),
        "the external token signature leaked"
    );

    // 3. A token whose ref does not match the policy is refused; no new state is written.
    let other = tempdir_home();
    *runner.token.lock().unwrap() = key.mint(&claims(&issuer, "refs/heads/attacker"));
    let out = login(&smith, &other);
    assert!(!out.status.success(), "a non-matching ref must be refused");
    assert!(
        !other.join("agent.json").exists(),
        "no state after a refused exchange"
    );
    let refused = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !refused.contains("attacker"),
        "refusal must not echo claims"
    );

    // 4. Revoke the grant: the still-valid agent token gets nothing from the gateway.
    cp_status(
        &c,
        "DELETE",
        &format!("/v1/agents/{agent_id}/grants/{grant}"),
        o,
        None,
        StatusCode::NO_CONTENT,
    )
    .await;
    // The gateway serves a grant set from memory for at most 10 s (grants.rs `MAX_GRANT_TTL`).
    tokio::time::sleep(Duration::from_secs(11)).await;
    let out = smith_cmd(&smith, &home, &gw.base)
        .args(["relay", "--secret-id", &sid, &url])
        .output()
        .unwrap();
    seen(&mut observed, &out);
    // `smith relay` prints the gateway's status; a refusal is a non-2xx (or a non-zero exit).
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success() || !stdout.starts_with("HTTP 2"),
        "a revoked grant must be refused, got: {}",
        stdout.lines().next().unwrap_or("")
    );
    assert!(
        !stdout.contains("REDACTED"),
        "no upstream body after the revoke"
    );
    assert_eq!(
        upstream_hits(&c, &path, &canary).await,
        1,
        "the upstream saw nothing after the revoke"
    );
    assert!(
        !observed.contains(&canary),
        "the workload observed the secret"
    );

    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&other);
}

fn tempdir_home() -> PathBuf {
    let d = env::temp_dir().join(uniq("workload-home"));
    std::fs::create_dir_all(&d).unwrap();
    d
}
