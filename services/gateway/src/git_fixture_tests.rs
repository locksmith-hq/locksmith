//! D1 task 2.4: the Git route against a real `git http-backend` fixture (a tiny axum server that
//! runs the CGI and requires the injected credential), with the real `git` client on the agent
//! side. Every test skips cleanly when `git http-backend` is not installed.

use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ls_control_plane::agent_token::{AUDIENCE, AgentClaims, AgentTokenSigner};
use ls_control_plane::readiness::ReadyFlag;
use ls_envelope::{BaoToken, OpenBaoTransit};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::app::{self, AppState};
use crate::audit::{EventKind, MemoryAudit, Method as AuditMethod, Outcome};
use crate::auth::testkit::StubJwks;
use crate::auth::{AgentAuth, JwksSettings};
use crate::config::Bindings;
use crate::decrypt::testkit::{key, seal};
use crate::decrypt::{CacheSettings, ControlPlane, Decryptor, DekCache};
use crate::egress::testkit::StubResolver;
use crate::git::{GitBinding, GitOptions, GitService, GitState, MAX_SCANNED_BODY};
use crate::grants::testkit::StubGrants;
use crate::grants::{Grant, GrantCache, GrantCacheSettings};
use crate::relay::{Relay, RelayOptions};

const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_000000000001);
const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a1);
/// acme/widgets: fetch and push, a PAT.
const RW: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000b1);
/// acme/ro: fetch only.
const RO: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000b2);
/// acme/redir: bound to a mock upstream that redirects.
const REDIR: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000b3);
/// acme/app: a GitHub App credential.
const APP: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000b4);
const PAT: &str = "ghp_canary-git-test-7Hk2Zx9WqP";
const INSTALL_TOKEN: &str = "ghs_canary-installation-token-4Rt8";

fn have_http_backend() -> bool {
    Command::new("git")
        .arg("http-backend")
        .env_remove("REQUEST_METHOD")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stderr).contains("REQUEST_METHOD"))
        .unwrap_or(false)
}

macro_rules! require_backend {
    () => {
        if !have_http_backend() {
            eprintln!("git http-backend not available; skipping");
            return;
        }
    };
}

/// A scratch directory removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "ls-git-{tag}-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.test")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.test")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("https_proxy")
        .env_remove("http_proxy")
        .output()
        .expect("run git")
}

fn git_ok(dir: &Path, args: &[&str]) -> String {
    let o = git(dir, args);
    assert!(
        o.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// A bare repository `root/acme/<name>.git` with one commit on `main`, receive-pack enabled.
fn seed_repo(root: &Path, name: &str) {
    let bare = root.join("acme").join(format!("{name}.git"));
    std::fs::create_dir_all(&bare).unwrap();
    git_ok(&bare, &["init", "--bare", "-b", "main", "."]);
    git_ok(&bare, &["config", "http.receivepack", "true"]);
    let work = Dir::new("seed");
    git_ok(&work.0, &["init", "-b", "main", "."]);
    std::fs::write(work.0.join("README"), format!("hello {name}\n")).unwrap();
    git_ok(&work.0, &["add", "."]);
    git_ok(&work.0, &["commit", "-m", "seed"]);
    git_ok(&work.0, &["push", bare.to_str().unwrap(), "main"]);
}

/// What the fixture saw.
#[derive(Default)]
struct Seen {
    authorized: AtomicUsize,
    unauthorized: AtomicUsize,
}

struct Fixture {
    port: u16,
    root: Dir,
    seen: Arc<Seen>,
}

struct FixtureState {
    root: PathBuf,
    /// Accepted `Authorization` header values.
    accepted: HashSet<String>,
    seen: Arc<Seen>,
}

fn basic(token: &str) -> String {
    format!("Basic {}", B64.encode(format!("x-access-token:{token}")))
}

async fn cgi(State(fx): State<Arc<FixtureState>>, req: Request<Body>) -> Response {
    let (parts, body) = req.into_parts();
    let ok = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| fx.accepted.contains(v));
    if !ok {
        fx.seen.unauthorized.fetch_add(1, Ordering::SeqCst);
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("www-authenticate", "Basic realm=\"fixture\"")
            .body(Body::empty())
            .unwrap();
    }
    fx.seen.authorized.fetch_add(1, Ordering::SeqCst);
    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let header = |n: &str| {
        parts
            .headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let (root, uri_path, query, ctype, enc, proto, len) = (
        fx.root.clone(),
        parts.uri.path().to_owned(),
        parts.uri.query().unwrap_or("").to_owned(),
        header("content-type"),
        header("content-encoding"),
        header("git-protocol"),
        body.len(),
    );
    let method = parts.method.to_string();
    let out = tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new("git");
        cmd.arg("http-backend")
            .env("GIT_PROJECT_ROOT", &root)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("REQUEST_METHOD", method)
            .env("PATH_INFO", uri_path)
            .env("QUERY_STRING", query)
            .env("CONTENT_TYPE", ctype)
            .env("CONTENT_LENGTH", len.to_string())
            .env("REMOTE_USER", "fixture")
            .env("REMOTE_ADDR", "127.0.0.1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if !enc.is_empty() {
            cmd.env("HTTP_CONTENT_ENCODING", enc);
        }
        if !proto.is_empty() {
            cmd.env("GIT_PROTOCOL", proto);
        }
        let mut child = cmd.spawn().expect("spawn git http-backend");
        let mut stdin = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(&body);
        });
        let out = child.wait_with_output().unwrap();
        let _ = writer.join();
        out.stdout
    })
    .await
    .unwrap();
    // CGI output: headers, a blank line, the body.
    let split = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| (p, 4))
        .or_else(|| out.windows(2).position(|w| w == b"\n\n").map(|p| (p, 2)))
        .expect("CGI headers");
    let head = String::from_utf8_lossy(&out[..split.0]).into_owned();
    let mut resp = Response::builder();
    let mut status = StatusCode::OK;
    for line in head.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let v = v.trim();
            if k.eq_ignore_ascii_case("status") {
                status = v
                    .split(' ')
                    .next()
                    .and_then(|c| c.parse::<u16>().ok())
                    .and_then(|c| StatusCode::from_u16(c).ok())
                    .unwrap_or(StatusCode::OK);
            } else {
                resp = resp.header(k, v);
            }
        }
    }
    resp.status(status)
        .body(Body::from(out[split.0 + split.1..].to_vec()))
        .unwrap()
}

async fn start_fixture(accepted: &[String]) -> Fixture {
    let root = Dir::new("root");
    seed_repo(&root.0, "widgets");
    seed_repo(&root.0, "ro");
    seed_repo(&root.0, "app");
    let seen = Arc::new(Seen::default());
    let state = Arc::new(FixtureState {
        root: root.0.clone(),
        accepted: accepted.iter().cloned().collect(),
        seen: seen.clone(),
    });
    let app = Router::new().fallback(cgi).with_state(state);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    Fixture { port, root, seen }
}

fn git_binding(secret: Uuid, repo: &str, services: Vec<GitService>, port: u16) -> GitBinding {
    GitBinding {
        secret_id: secret,
        host: "127.0.0.1".to_owned(),
        repo_prefix: repo.to_owned(),
        services,
        allow_private_hosts: true,
        version: 1,
        port: Some(port),
        plain_http: true,
    }
}

struct Gateway {
    base: String,
    token: String,
    cp: MockServer,
    audit: Arc<MemoryAudit>,
}

impl Gateway {
    /// `https`-free base the agent's Git talks to: `http://127.0.0.1:<port>/git/127.0.0.1`.
    fn remote(&self, repo: &str) -> String {
        format!("{}/git/127.0.0.1/acme/{repo}.git", self.base)
    }

    fn bearer(&self) -> String {
        format!("Authorization: Bearer {}", self.token)
    }

    /// Material fetches the control plane saw (a decrypt always starts with one).
    async fn material_fetches(&self) -> usize {
        self.cp
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().contains("/material"))
            .count()
    }
}

fn grant(secret_id: Uuid) -> Grant {
    Grant {
        grant_id: Uuid::now_v7(),
        secret_id,
        secret_name: "GIT".to_owned(),
        mode: "relay".to_owned(),
        expires_at: None,
    }
}

/// A gateway on a real port with the given Git bindings and credentials (secret id, value).
async fn start_gateway(
    git_bindings: Vec<GitBinding>,
    secrets: &[(Uuid, Vec<u8>)],
    github_api: Option<String>,
) -> Gateway {
    start_gateway_with(
        git_bindings,
        secrets,
        github_api,
        Arc::new(MemoryAudit::default()),
    )
    .await
}

async fn start_gateway_with(
    git_bindings: Vec<GitBinding>,
    secrets: &[(Uuid, Vec<u8>)],
    github_api: Option<String>,
    audit: Arc<MemoryAudit>,
) -> Gateway {
    let cp = MockServer::start().await;
    let bao = MockServer::start().await;
    for (id, value) in secrets {
        let sealed = seal(ORG, *id, 1, value);
        Mock::given(method("GET"))
            .and(path(format!(
                "/internal/v1/secrets/{id}/versions/1/material"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(sealed.json(*id, 1)))
            .mount(&cp)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/gateway"))
            .and(wiremock::matchers::body_string_contains(
                sealed.transit_ciphertext(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "plaintext": B64.encode(sealed.dek) }
            })))
            .mount(&bao)
            .await;
    }
    let control_plane =
        ControlPlane::new(cp.uri().parse().unwrap(), ORG, "s".repeat(32).into()).unwrap();
    let transit = OpenBaoTransit::new(&bao.uri(), key(), BaoToken::new("bao".to_owned())).unwrap();
    let decryptor = Decryptor::new(
        ORG,
        Arc::new(control_plane),
        Arc::new(transit),
        Arc::new(DekCache::new(CacheSettings::default())),
    );
    let signer = AgentTokenSigner::from_seed(zeroize::Zeroizing::new([7u8; 32])).unwrap();
    let auth = Arc::new(AgentAuth::new(
        ORG,
        Arc::new(StubJwks::with(vec![signer.jwk().clone()])),
        JwksSettings::default(),
    ));
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let token = signer
        .sign(&AgentClaims {
            sub: AGENT,
            org: ORG,
            aud: AUDIENCE.to_owned(),
            iat: now,
            exp: now + 600,
        })
        .unwrap();
    let grants = Arc::new(StubGrants::default());
    grants.set(
        AGENT,
        git_bindings.iter().map(|b| grant(b.secret_id)).collect(),
    );
    let mut state = GitState::default().with_options(GitOptions {
        connect_timeout: Duration::from_secs(2),
        total_timeout: Duration::from_secs(60),
        idle_timeout: Duration::from_secs(20),
    });
    if let Some(api) = github_api {
        state = state.with_api_base(&api);
    }
    let relay = Relay::new(
        auth,
        Arc::new(GrantCache::new(grants, GrantCacheSettings::default())),
        Bindings {
            org_id: ORG,
            bindings: Vec::new(),
            aws_bindings: Vec::new(),
            git_bindings,
        },
        decryptor,
        Arc::new(StubResolver::default()),
        audit.clone(),
        RelayOptions::default(),
    )
    .with_git(state);
    let router =
        app::build(AppState::new(Arc::new(ReadyFlag::new(true))).with_relay(Arc::new(relay)));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    Gateway {
        base,
        token,
        cp,
        audit,
    }
}

async fn run_git(dir: PathBuf, args: Vec<String>) -> std::process::Output {
    tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        git(&dir, &refs)
    })
    .await
    .unwrap()
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

fn http() -> reqwest::Client {
    crate::http_client::build(Duration::from_secs(5), Duration::from_secs(30), None).unwrap()
}

fn all_bindings(port: u16) -> Vec<GitBinding> {
    vec![
        git_binding(
            RW,
            "acme/widgets",
            vec![GitService::Fetch, GitService::Push],
            port,
        ),
        git_binding(RO, "acme/ro", vec![GitService::Fetch], port),
    ]
}

fn secrets() -> Vec<(Uuid, Vec<u8>)> {
    vec![(RW, PAT.as_bytes().to_vec()), (RO, PAT.as_bytes().to_vec())]
}

#[tokio::test(flavor = "multi_thread")]
async fn git_clone_and_push_through_gateway() {
    require_backend!();
    let fx = start_fixture(&[basic(PAT)]).await;
    let gw = start_gateway(all_bindings(fx.port), &secrets(), None).await;
    let work = Dir::new("agent");
    let bearer = gw.bearer();

    // Clone with the agent token as the Basic password (what the credential helper returns):
    // exercises the 401 challenge, then the retry.
    let basic_url = format!(
        "http://agent:{}@{}/git/127.0.0.1/acme/widgets.git",
        gw.token,
        gw.base.trim_start_matches("http://")
    );
    let o = run_git(work.0.clone(), s(&["clone", &basic_url, "w"])).await;
    assert!(
        o.status.success(),
        "clone: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let w = work.0.join("w");
    assert_eq!(
        std::fs::read_to_string(w.join("README")).unwrap(),
        "hello widgets\n"
    );

    std::fs::write(w.join("new.txt"), "pushed\n").unwrap();
    git_ok(&w, &["add", "."]);
    git_ok(&w, &["commit", "-m", "add new.txt"]);
    let head = git_ok(&w, &["rev-parse", "HEAD"]);
    let o = run_git(
        w.clone(),
        vec![
            "-c".into(),
            format!("http.extraHeader={bearer}"),
            "push".into(),
            gw.remote("widgets"),
            "main".into(),
        ],
    )
    .await;
    assert!(
        o.status.success(),
        "push: {}",
        String::from_utf8_lossy(&o.stderr)
    );

    let bare = fx.root.0.join("acme/widgets.git");
    assert_eq!(git_ok(&bare, &["rev-parse", "main"]), head);

    // The fixture saw the credential on every request and never one without it.
    assert!(fx.seen.authorized.load(Ordering::SeqCst) >= 4);
    assert_eq!(fx.seen.unauthorized.load(Ordering::SeqCst), 0);
    // The ledger has the fetches and the push, and neither credential nor pack data.
    let kinds: Vec<EventKind> = gw.audit.events().into_iter().map(|e| e.kind).collect();
    assert!(
        kinds.contains(&EventKind::GitFetch(Outcome::Ok)),
        "{kinds:?}"
    );
    assert!(
        kinds.contains(&EventKind::GitPush(Outcome::Ok)),
        "{kinds:?}"
    );
    assert!(
        kinds
            .iter()
            .all(|k| matches!(k, EventKind::GitFetch(_) | EventKind::GitPush(_)))
    );
    assert_no_secret(
        "audit events",
        format!("{:?}", gw.audit.stored()).as_bytes(),
    );
    // The agent side never holds the GitHub credential.
    let text = std::fs::read_to_string(w.join(".git/config")).unwrap();
    assert!(!text.contains(PAT) && !text.contains(&B64.encode(format!("x-access-token:{PAT}"))));
    for out in [&o.stdout, &o.stderr] {
        assert!(!String::from_utf8_lossy(out).contains(PAT));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn git_unauthenticated_gets_a_basic_challenge() {
    require_backend!();
    let fx = start_fixture(&[basic(PAT)]).await;
    let gw = start_gateway(all_bindings(fx.port), &secrets(), None).await;
    let url = format!("{}/info/refs?service=git-upload-pack", gw.remote("widgets"));
    let r = http().get(&url).send().await.unwrap();
    assert_eq!(r.status(), 401);
    assert!(
        r.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .starts_with("Basic")
    );
    assert_eq!(gw.material_fetches().await, 0);
    assert_eq!(fx.seen.authorized.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn git_unbound_repo_is_403_with_no_decrypt_and_no_upstream_call() {
    require_backend!();
    let fx = start_fixture(&[basic(PAT)]).await;
    let gw = start_gateway(all_bindings(fx.port), &secrets(), None).await;
    let h = http();
    for url in [
        // Outside the binding.
        format!(
            "{}/git/127.0.0.1/acme/other.git/info/refs?service=git-upload-pack",
            gw.base
        ),
        // Another host.
        format!(
            "{}/git/github.com/acme/widgets.git/info/refs?service=git-upload-pack",
            gw.base
        ),
        // Not one of the three paths.
        format!(
            "{}/git/127.0.0.1/acme/widgets.git/objects/info/packs",
            gw.base
        ),
        format!("{}/git/127.0.0.1/acme/widgets.git/info/refs", gw.base),
        format!(
            "{}/git/127.0.0.1/acme/%2e%2e/info/refs?service=git-upload-pack",
            gw.base
        ),
    ] {
        let r = h
            .get(&url)
            .header("authorization", format!("Bearer {}", gw.token))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "{url}");
    }
    let o = run_git(
        Dir::new("agent").0.clone(),
        s(&[
            "-c",
            &gw.bearer()
                .replace("Authorization: ", "http.extraHeader=Authorization: "),
            "ls-remote",
            &gw.remote("other"),
        ]),
    )
    .await;
    assert!(!o.status.success());
    assert_eq!(
        gw.material_fetches().await,
        0,
        "no decrypt for an unbound repository"
    );
    let events = gw.audit.events();
    assert!(!events.is_empty());
    assert!(
        events
            .iter()
            .all(|e| e.kind == EventKind::GitDenied(Outcome::Denied) && e.status.is_none()),
        "{events:?}"
    );
    assert_eq!(fx.seen.authorized.load(Ordering::SeqCst), 0);
    assert_eq!(
        fx.seen.unauthorized.load(Ordering::SeqCst),
        0,
        "no upstream call"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn git_fetch_only_grant_cannot_push() {
    require_backend!();
    let fx = start_fixture(&[basic(PAT)]).await;
    let gw = start_gateway(all_bindings(fx.port), &secrets(), None).await;
    let work = Dir::new("agent");
    let hdr = format!("http.extraHeader={}", gw.bearer());

    let o = run_git(
        work.0.clone(),
        s(&["-c", &hdr, "clone", &gw.remote("ro"), "r"]),
    )
    .await;
    assert!(
        o.status.success(),
        "fetch is allowed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let r = work.0.join("r");
    std::fs::write(r.join("x"), "x").unwrap();
    git_ok(&r, &["add", "."]);
    git_ok(&r, &["commit", "-m", "x"]);
    let before = fx.seen.authorized.load(Ordering::SeqCst);
    let o = run_git(
        r.clone(),
        s(&["-c", &hdr, "push", &gw.remote("ro"), "main"]),
    )
    .await;
    assert!(!o.status.success(), "push must fail");
    assert!(String::from_utf8_lossy(&o.stderr).contains("403"));
    assert_eq!(
        fx.seen.authorized.load(Ordering::SeqCst),
        before,
        "no upstream call for the push"
    );
    let bare = fx.root.0.join("acme/ro.git");
    assert_ne!(
        git_ok(&bare, &["rev-parse", "main"]),
        git_ok(&r, &["rev-parse", "HEAD"])
    );

    // Directly: the receive-pack advertisement and the POST are both refused.
    let h = http();
    let adv = h
        .get(format!(
            "{}/info/refs?service=git-receive-pack",
            gw.remote("ro")
        ))
        .header("authorization", format!("Bearer {}", gw.token))
        .send()
        .await
        .unwrap();
    assert_eq!(adv.status(), 403);
    let post = h
        .post(format!("{}/git-receive-pack", gw.remote("ro")))
        .header("authorization", format!("Bearer {}", gw.token))
        .body("0000")
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn git_redirect_is_not_followed() {
    require_backend!();
    let elsewhere = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&elsewhere)
        .await;
    let up = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/stolen", elsewhere.uri())),
        )
        .expect(1)
        .mount(&up)
        .await;
    let binding = git_binding(
        REDIR,
        "acme/redir",
        vec![GitService::Fetch],
        up.address().port(),
    );
    let gw = start_gateway(vec![binding], &[(REDIR, PAT.as_bytes().to_vec())], None).await;
    let r = http()
        .get(format!(
            "{}/info/refs?service=git-upload-pack",
            gw.remote("redir")
        ))
        .header("authorization", format!("Bearer {}", gw.token))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 502);
    assert!(r.headers().get("location").is_none());
    let body = r.text().await.unwrap();
    assert!(body.contains("upstream_redirect") && !body.contains(PAT));
    let seen = up.received_requests().await.unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        basic(PAT),
        "the credential went to the bound host only"
    );
    assert!(elsewhere.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn git_app_installation_token_is_minted_and_injected() {
    require_backend!();
    let Some(key) = rsa_pem() else {
        eprintln!("openssl not available; skipping");
        return;
    };
    let api = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/app/installations/456/access_tokens"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token": INSTALL_TOKEN,
            "expires_at": "2099-01-01T00:00:00Z"
        })))
        .expect(1..)
        .mount(&api)
        .await;
    let fx = start_fixture(&[basic(INSTALL_TOKEN)]).await;
    let cred = serde_json::json!({"app_id": 123, "installation_id": 456, "private_key": key});
    let gw = start_gateway(
        vec![git_binding(
            APP,
            "acme/app",
            vec![GitService::Fetch, GitService::Push],
            fx.port,
        )],
        &[(APP, cred.to_string().into_bytes())],
        Some(api.uri()),
    )
    .await;
    let work = Dir::new("agent");
    let hdr = format!("http.extraHeader={}", gw.bearer());
    let o = run_git(
        work.0.clone(),
        s(&["-c", &hdr, "clone", &gw.remote("app"), "a"]),
    )
    .await;
    assert!(
        o.status.success(),
        "clone: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(fx.seen.unauthorized.load(Ordering::SeqCst), 0);
    assert!(fx.seen.authorized.load(Ordering::SeqCst) >= 2);
    // The minted token is cached: one mint serves every request of the clone.
    assert_eq!(api.received_requests().await.unwrap().len(), 1);
    let text = std::fs::read_to_string(work.0.join("a/.git/config")).unwrap();
    assert!(!text.contains(INSTALL_TOKEN));
}

/// A PKCS#1 RSA private key PEM, or `None` when `openssl` is unavailable.
fn rsa_pem() -> Option<String> {
    let dir = Dir::new("rsa");
    let raw = dir.0.join("raw.pem");
    let k1 = dir.0.join("k1.pem");
    let run = |args: &[&str]| {
        Command::new("openssl")
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    (run(&["genrsa", "-out", raw.to_str()?, "2048"])
        && run(&[
            "rsa",
            "-traditional",
            "-in",
            raw.to_str()?,
            "-out",
            k1.to_str()?,
        ]))
    .then(|| std::fs::read_to_string(&k1).ok())
    .flatten()
}

// ---------------------------------------------------------------------------------------------
// D1 task 3: redaction (headers, text error bodies) and the ledger events.
// ---------------------------------------------------------------------------------------------

/// The oracle: every form `ls-redact` knows of the PAT and of its `Basic` header.
fn assert_no_secret(what: &str, bytes: &[u8]) {
    let mut secret = ls_redact::Secret::new("C", PAT.as_bytes());
    secret.basic_auth_user = Some("x-access-token".to_owned());
    let oracle = ls_redact::Redactor::new(&[secret]);
    assert!(
        oracle.find(bytes).is_empty(),
        "{what}: the credential is still there"
    );
}

/// A gateway bound to a mock upstream that answers every request with `reply`.
async fn hostile(reply: ResponseTemplate, services: Vec<GitService>) -> (Gateway, MockServer) {
    hostile_with(reply, services, Arc::new(MemoryAudit::default())).await
}

async fn hostile_with(
    reply: ResponseTemplate,
    services: Vec<GitService>,
    audit: Arc<MemoryAudit>,
) -> (Gateway, MockServer) {
    let up = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(reply)
        .mount(&up)
        .await;
    let binding = git_binding(RW, "acme/widgets", services, up.address().port());
    let gw = start_gateway_with(vec![binding], &[(RW, PAT.as_bytes().to_vec())], None, audit).await;
    (gw, up)
}

fn refs_url(gw: &Gateway) -> String {
    format!("{}/info/refs?service=git-upload-pack", gw.remote("widgets"))
}

#[tokio::test(flavor = "multi_thread")]
async fn git_redact_error_body_and_headers_echoing_the_credential() {
    let basic_b64 = B64.encode(format!("x-access-token:{PAT}"));
    let echo = format!(
        "denied for token {PAT}; header Authorization: Basic {basic_b64}; json {{\"t\":\"{PAT}\"}}"
    );
    let reply = ResponseTemplate::new(403)
        .insert_header("content-type", "text/plain")
        .insert_header("cache-control", format!("no-cache, echo={PAT}"))
        .insert_header("pragma", format!("Basic {basic_b64}"))
        // Not on the allow-list: dropped whole.
        .insert_header("x-echo", PAT)
        .insert_header("www-authenticate", format!("Basic realm=\"{PAT}\""))
        .set_body_string(echo);
    let (gw, up) = hostile(reply, vec![GitService::Fetch]).await;
    let r = http()
        .get(refs_url(&gw))
        .header("authorization", format!("Bearer {}", gw.token))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "the upstream status passes through");
    let mut head = String::new();
    for (n, v) in r.headers() {
        head.push_str(&format!("{n}: {}\n", String::from_utf8_lossy(v.as_bytes())));
    }
    assert!(r.headers().get("x-echo").is_none());
    assert!(r.headers().get("www-authenticate").is_none());
    assert_no_secret("response headers", head.as_bytes());
    assert!(
        r.headers()["cache-control"]
            .to_str()
            .unwrap()
            .contains("[REDACTED:SECRET]")
    );
    let body = r.text().await.unwrap();
    assert_no_secret("response body", body.as_bytes());
    assert!(body.contains("[REDACTED:SECRET]") && body.contains("denied for token"));
    // The injected credential did reach the upstream, in the one header.
    let seen = up.received_requests().await.unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        basic(PAT)
    );
    // The ledger: one `git.fetch` carrying the upstream status.
    let events = gw.audit.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].kind, EventKind::GitFetch(Outcome::Ok));
    assert_eq!(events[0].status, Some(403));
    assert_no_secret("audit events", format!("{events:?}").as_bytes());
}

#[tokio::test(flavor = "multi_thread")]
async fn git_redact_withholds_what_it_cannot_scan() {
    let big = vec![b'a'; MAX_SCANNED_BODY + 1];
    for reply in [
        // A text body past the scan bound.
        ResponseTemplate::new(500)
            .insert_header("content-type", "text/plain")
            .set_body_bytes(big.clone()),
        // A compressed body: the redactor could not read it.
        ResponseTemplate::new(500)
            .insert_header("content-type", "text/plain")
            .insert_header("content-encoding", "gzip")
            .set_body_bytes(b"\x1f\x8b not really gzip".to_vec()),
        // A "success" that is not a Git stream is scanned like an error page.
        ResponseTemplate::new(200)
            .insert_header("content-type", "text/html")
            .set_body_bytes(big.clone()),
    ] {
        let (gw, _up) = hostile(reply, vec![GitService::Fetch]).await;
        let r = http()
            .get(refs_url(&gw))
            .header("authorization", format!("Bearer {}", gw.token))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 502);
        assert!(r.text().await.unwrap().contains("redaction_failed"));
        let events = gw.audit.events();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(
            events[0].kind,
            EventKind::GitFetch(Outcome::RedactionFailed)
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn git_redact_git_streams_pass_through_raw() {
    // Binary pack-like data past the scan bound, a pkt-line length that a rewrite would break.
    let mut pack = b"001e# service=git-upload-pack\n0000PACK".to_vec();
    pack.extend((0..MAX_SCANNED_BODY * 2).map(|i| (i % 251) as u8));
    let reply = ResponseTemplate::new(200)
        .insert_header(
            "content-type",
            "application/x-git-upload-pack-advertisement",
        )
        .insert_header("cache-control", "no-cache")
        .set_body_bytes(pack.clone());
    let (gw, _up) = hostile(reply, vec![GitService::Fetch]).await;
    let r = http()
        .get(refs_url(&gw))
        .header("authorization", format!("Bearer {}", gw.token))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap().as_ref(), pack.as_slice());
    let events = gw.audit.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::GitFetch(Outcome::Ok));
}

#[tokio::test(flavor = "multi_thread")]
async fn git_redact_allowed_header_values_are_replaced() {
    // A header the gateway passes back is scanned: the credential in it is replaced.
    let reply = ResponseTemplate::new(200)
        .insert_header(
            "content-type",
            "application/x-git-upload-pack-advertisement",
        )
        .insert_header("expires", format!("{PAT}{PAT}"))
        .set_body_bytes(b"0000".to_vec());
    let (gw, _up) = hostile(reply, vec![GitService::Fetch]).await;
    let r = http()
        .get(refs_url(&gw))
        .header("authorization", format!("Bearer {}", gw.token))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["expires"], "[REDACTED:SECRET][REDACTED:SECRET]");
}

#[tokio::test(flavor = "multi_thread")]
async fn git_redact_events_hold_ids_and_codes_only() {
    let pack = "PACKDATA-MARKER-9f3a";
    let reply = ResponseTemplate::new(200)
        .insert_header("content-type", "application/x-git-receive-pack-result")
        .set_body_bytes(b"000eunpack ok\n0000".to_vec());
    let (gw, up) = hostile(reply, vec![GitService::Fetch, GitService::Push]).await;
    let h = http();
    let auth = format!("Bearer {}", gw.token);
    let push = h
        .post(format!("{}/git-receive-pack", gw.remote("widgets")))
        .header("authorization", &auth)
        .header("content-type", "application/x-git-receive-pack-request")
        .body(pack.to_owned())
        .send()
        .await
        .unwrap();
    assert_eq!(push.status(), 200);
    let fetch = h
        .get(refs_url(&gw))
        .header("authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(fetch.status(), 200);
    assert_eq!(up.received_requests().await.unwrap().len(), 2);

    let events = gw.audit.events();
    let shape: Vec<_> = events
        .iter()
        .map(|e| (e.kind, e.method, e.status))
        .collect();
    assert_eq!(
        shape,
        [
            (
                EventKind::GitPush(Outcome::Ok),
                Some(AuditMethod::Post),
                Some(200)
            ),
            (
                EventKind::GitFetch(Outcome::Ok),
                Some(AuditMethod::Get),
                Some(200)
            ),
        ]
    );
    for e in &events {
        assert_eq!((e.agent_id, e.secret_id), (AGENT, RW));
        assert_eq!(e.host.as_deref(), Some("127.0.0.1"));
        assert!(e.attempt_id.is_none());
    }
    let text = format!("{:?}", gw.audit.stored());
    assert_no_secret("audit events", text.as_bytes());
    assert!(
        !text.contains(pack) && !text.contains("widgets"),
        "no pack data, no repository path"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn git_redact_denials_are_recorded_without_request_data() {
    let (gw, up) = hostile(ResponseTemplate::new(200), vec![GitService::Fetch]).await;
    let auth = format!("Bearer {}", gw.token);
    // A push with a fetch-only binding, then an unbound repository.
    let push = http()
        .post(format!("{}/git-receive-pack", gw.remote("widgets")))
        .header("authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(push.status(), 403);
    let other = http()
        .get(format!(
            "{}/git/127.0.0.1/acme/secret-repo-name.git/info/refs?service=git-upload-pack",
            gw.base
        ))
        .header("authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), 403);
    assert!(up.received_requests().await.unwrap().is_empty());
    let events = gw.audit.events();
    assert_eq!(events.len(), 2);
    for e in &events {
        assert_eq!(e.kind, EventKind::GitDenied(Outcome::Denied));
        assert_eq!((e.agent_id, e.secret_id, e.status), (AGENT, RW, None));
    }
    let text = format!("{events:?}");
    assert!(
        !text.contains("secret-repo-name"),
        "the caller's path never reaches the ledger"
    );
    // An unauthenticated caller is not audited at all.
    let anon = http().get(refs_url(&gw)).send().await.unwrap();
    assert_eq!(anon.status(), 401);
    assert_eq!(gw.audit.events().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn git_redact_unaudited_response_is_withheld() {
    let audit = Arc::new(MemoryAudit {
        fail: true,
        ..MemoryAudit::default()
    });
    let reply = ResponseTemplate::new(200)
        .insert_header(
            "content-type",
            "application/x-git-upload-pack-advertisement",
        )
        .set_body_bytes(b"0000".to_vec());
    let (gw, _up) = hostile_with(reply, vec![GitService::Fetch], audit).await;
    let r = http()
        .get(refs_url(&gw))
        .header("authorization", format!("Bearer {}", gw.token))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 500);
    assert!(r.text().await.unwrap().contains("audit_failed"));
}

// ---- D1 task 5: a large push is streamed, not buffered ----

/// Resident set size of this process in bytes (Linux; `None` elsewhere).
fn rss_bytes() -> Option<usize> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: usize = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4096)
}

/// A 50 MB `git-receive-pack` body goes through the gateway to an upstream that drains it
/// slowly. The gateway must stream it: the upstream sees every byte with the injected
/// credential, and the process (gateway, upstream and client share it) never holds anything
/// near the body size. The gateway never reads the agent token's request body into memory.
#[tokio::test(flavor = "multi_thread")]
async fn git_large_push_is_streamed_with_bounded_memory() {
    use http_body_util::BodyExt as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const TOTAL: usize = 50 * 1024 * 1024;
    const CHUNK: usize = 64 * 1024;
    // Generous for buffers and allocator slack, but far below the 50 MB body.
    const BOUND: usize = 20 * 1024 * 1024;

    let received = Arc::new(AtomicUsize::new(0));
    let authorized = Arc::new(AtomicUsize::new(0));
    let (rx, auth_seen) = (received.clone(), authorized.clone());
    let expected = basic(PAT);
    let app = Router::new().fallback(move |req: Request<Body>| {
        let (rx, auth_seen, expected) = (rx.clone(), auth_seen.clone(), expected.clone());
        async move {
            let ok = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v == expected);
            if ok {
                auth_seen.fetch_add(1, Ordering::SeqCst);
            }
            let mut body = req.into_body();
            while let Some(frame) = body.frame().await {
                if let Ok(data) = frame
                    .map(|f| f.into_data())
                    .unwrap_or(Ok(Default::default()))
                {
                    rx.fetch_add(data.len(), Ordering::SeqCst);
                }
                // A slow consumer: a buffering gateway would pile the body up here.
                tokio::time::sleep(Duration::from_micros(500)).await;
            }
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/x-git-receive-pack-result")
                .body(Body::from("000eunpack ok\n0000"))
                .unwrap()
        }
    });
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });

    let binding = git_binding(
        RW,
        "acme/widgets",
        vec![GitService::Fetch, GitService::Push],
        up_port,
    );
    let gw = start_gateway(vec![binding], &[(RW, PAT.as_bytes().to_vec())], None).await;

    // Sample the resident set while the push runs.
    let base_rss = rss_bytes();
    let peak = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sampler = {
        let (peak, stop) = (peak.clone(), stop.clone());
        tokio::spawn(async move {
            while !stop.load(Ordering::SeqCst) {
                if let Some(r) = rss_bytes() {
                    peak.fetch_max(r, Ordering::SeqCst);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    };

    // The agent side: a raw HTTP/1.1 request, the body written in chunks (no buffering).
    let addr = gw.base.trim_start_matches("http://").to_owned();
    let mut sock = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let head = format!(
        "POST /git/127.0.0.1/acme/widgets.git/git-receive-pack HTTP/1.1\r\nHost: {addr}\r\n\
         Authorization: Bearer {}\r\nContent-Type: application/x-git-receive-pack-request\r\n\
         Content-Length: {TOTAL}\r\nConnection: close\r\n\r\n",
        gw.token
    );
    sock.write_all(head.as_bytes()).await.unwrap();
    let chunk = vec![0xA5u8; CHUNK];
    for _ in 0..TOTAL / CHUNK {
        sock.write_all(&chunk).await.unwrap();
    }
    let mut reply = Vec::new();
    sock.read_to_end(&mut reply).await.unwrap();
    stop.store(true, Ordering::SeqCst);
    let _ = sampler.await;

    let reply = String::from_utf8_lossy(&reply);
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert!(reply.contains("unpack ok"), "{reply}");
    // Every byte reached the upstream, with the injected credential and no other.
    assert_eq!(received.load(Ordering::SeqCst), TOTAL);
    assert_eq!(authorized.load(Ordering::SeqCst), 1);
    assert!(!reply.contains(PAT));
    // The ledger records the push and nothing about the pack.
    let kinds: Vec<EventKind> = gw.audit.events().into_iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![EventKind::GitPush(Outcome::Ok)], "{kinds:?}");

    if let Some(base) = base_rss {
        let grew = peak.load(Ordering::SeqCst).saturating_sub(base);
        assert!(
            grew < BOUND,
            "resident set grew {grew} bytes during a {TOTAL} byte push (bound {BOUND})"
        );
    }
}
