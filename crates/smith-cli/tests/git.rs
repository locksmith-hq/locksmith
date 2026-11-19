//! M5 Git delegation e2e: real `git`, `locksmithd` and `smith`, with a `git http-backend` CGI
//! fixture standing in for the upstream host (`LOCKSMITH_TEST_GIT_UPSTREAM`). One throwaway
//! home, runtime dir and fixture per test. Fake secrets are built at runtime.

mod common;
use common::*;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

const HOST: &str = "example.test";

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                o.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                o.push('=');
            }
        }
    }
    o
}

fn have_http_backend() -> bool {
    Command::new("git")
        .arg("http-backend")
        .env_remove("REQUEST_METHOD")
        .output()
        .is_ok_and(|o| s(&o.stderr).contains("REQUEST_METHOD") || s(&o.stdout).contains("Status"))
}

macro_rules! need_backend {
    () => {
        if !have_http_backend() {
            eprintln!("SKIP: `git http-backend` is unavailable");
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
            "timed out waiting for {}",
            p.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Upstream fixture counters.
#[derive(Default)]
struct Seen {
    requests: AtomicUsize,
    /// Requests whose Authorization was not the PAT header, or that carried a forwarder-token
    /// (`locksmith:` basic auth) anywhere.
    bad: AtomicUsize,
    paths: Mutex<Vec<String>>,
}

fn start_upstream(root: &Path, pat: &str, seen: Arc<Seen>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let root = root.to_path_buf();
    let want = format!("Basic {}", b64(format!("x-access-token:{pat}").as_bytes()));
    std::thread::spawn(move || {
        for st in l.incoming().flatten() {
            let (root, seen, want) = (root.clone(), seen.clone(), want.clone());
            std::thread::spawn(move || upstream_conn(st, &root, &want, &seen));
        }
    });
    addr
}

fn upstream_conn(mut st: TcpStream, root: &Path, want: &str, seen: &Seen) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let hl = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        let k = st.read(&mut tmp).unwrap();
        assert!(k > 0);
        buf.extend_from_slice(&tmp[..k]);
    };
    let head = s(&buf[..hl]);
    let mut lines = head.lines();
    let mut rl = lines.next().unwrap().split(' ');
    let (method, path) = (
        rl.next().unwrap().to_string(),
        rl.next().unwrap().to_string(),
    );
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let get = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    seen.requests.fetch_add(1, SeqCst);
    seen.paths.lock().unwrap().push(path.clone());
    let fwd_marker = b64(b"locksmith:");
    if get("authorization").as_deref() != Some(want)
        || headers
            .iter()
            .any(|(_, v)| v.contains(&fwd_marker[..fwd_marker.len() - 2]))
    {
        seen.bad.fetch_add(1, SeqCst);
    }
    let mut body = buf[hl + 4..].to_vec();
    if get("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        body = dechunk(&mut st, body);
    } else {
        let cl: usize = get("content-length").map_or(0, |v| v.parse().unwrap());
        while body.len() < cl {
            let k = st.read(&mut tmp).unwrap();
            assert!(k > 0);
            body.extend_from_slice(&tmp[..k]);
        }
    }
    let (p, q) = path.split_once('?').unwrap_or((&path, ""));
    let mut cmd = Command::new("git");
    cmd.arg("http-backend")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("GIT_PROJECT_ROOT", root)
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("REQUEST_METHOD", &method)
        .env("PATH_INFO", p)
        .env("QUERY_STRING", q)
        .env("CONTENT_TYPE", get("content-type").unwrap_or_default())
        .env("CONTENT_LENGTH", body.len().to_string())
        .env("REMOTE_USER", "x-access-token")
        .env("REMOTE_ADDR", "127.0.0.1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(v) = get("git-protocol") {
        cmd.env("GIT_PROTOCOL", v);
    }
    let mut child = cmd.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&body);
    });
    let out = child.wait_with_output().unwrap().stdout;
    writer.join().unwrap();
    let (i, sep) = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| out.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2)))
        .expect("cgi headers");
    let mut status = "200 OK".to_string();
    let mut resp = String::new();
    for line in s(&out[..i]).lines() {
        match line.strip_prefix("Status: ") {
            Some(x) => status = x.to_string(),
            None => resp.push_str(&format!("{line}\r\n")),
        }
    }
    let payload = &out[i + sep..];
    let h = format!(
        "HTTP/1.1 {status}\r\n{resp}Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    st.write_all(h.as_bytes()).unwrap();
    st.write_all(payload).unwrap();
}

fn dechunk(st: &mut TcpStream, mut raw: Vec<u8>) -> Vec<u8> {
    let (mut out, mut tmp) = (Vec::new(), [0u8; 8192]);
    loop {
        let Some(nl) = raw.windows(2).position(|w| w == b"\r\n") else {
            let k = st.read(&mut tmp).unwrap();
            assert!(k > 0);
            raw.extend_from_slice(&tmp[..k]);
            continue;
        };
        let size = usize::from_str_radix(
            std::str::from_utf8(&raw[..nl])
                .unwrap()
                .split(';')
                .next()
                .unwrap(),
            16,
        )
        .unwrap();
        if raw.len() < nl + 2 + size + 2 {
            let k = st.read(&mut tmp).unwrap();
            assert!(k > 0);
            raw.extend_from_slice(&tmp[..k]);
            continue;
        }
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&raw[nl + 2..nl + 2 + size]);
        raw.drain(..nl + 2 + size + 2);
    }
}

fn git_in(dir: &Path, args: &[&str]) -> Output {
    let o = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args([
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(o.status.success(), "git {args:?}: {}", s(&o.stderr));
    o
}

/// Home + runtime dir + daemon (with the upstream switch) + fixture + a work repo.
struct Env {
    h: Home,
    run: PathBuf,
    work: PathBuf,
    user_home: PathBuf,
    extra_path: Option<PathBuf>,
    daemon: Option<std::process::Child>,
    pat: String,
    seen: Arc<Seen>,
}

impl Env {
    /// `fixture`: serve a bare `acme/app.git` upstream and start the daemon pointed at it.
    fn new(fixture: bool) -> Env {
        locksmithd();
        let h = Home::new();
        let id =
            h.0.file_name()
                .unwrap()
                .to_string_lossy()
                .replace("smith-e2e-", "");
        let run = PathBuf::from(format!("/tmp/lsr-{id}"));
        let work = h.0.join("work");
        let user_home = h.0.join("uhome");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&user_home).unwrap();
        let pat = format!("pat_{}_{}", std::process::id(), id);
        let mut e = Env {
            h,
            run,
            work,
            user_home,
            extra_path: None,
            daemon: None,
            pat,
            seen: Arc::new(Seen::default()),
        };
        e.h.ready();
        assert!(e.h.add("GIT_TOKEN", &e.pat).status.success());
        assert!(e.h.add("GITHUB_TOKEN", &e.pat).status.success());
        let mut up = String::new();
        if fixture {
            let srv = e.h.0.join("srv");
            let bare = srv.join("acme/app.git");
            std::fs::create_dir_all(&bare).unwrap();
            git_in(&bare, &["init", "--bare", "-b", "main", "."]);
            git_in(&bare, &["config", "http.receivepack", "true"]);
            let seed = e.h.0.join("seed");
            std::fs::create_dir_all(&seed).unwrap();
            git_in(&seed, &["init", "-b", "main", "."]);
            std::fs::write(seed.join("a.txt"), "hello").unwrap();
            git_in(&seed, &["add", "."]);
            git_in(&seed, &["commit", "-m", "seed"]);
            git_in(&seed, &["push", bare.to_str().unwrap(), "main"]);
            let addr = start_upstream(&srv, &e.pat, e.seen.clone());
            up = format!("{HOST}={addr}");
        }
        let mut d = Command::new(locksmithd());
        d.env("LOCKSMITH_HOME", &e.h.0)
            .env("LOCKSMITH_RUNTIME_DIR", &e.run)
            .env("LOCKSMITH_INSECURE_TEST_KDF", "1")
            .env("HOME", &e.user_home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if fixture {
            d.env("LOCKSMITH_TEST_GIT_UPSTREAM", up);
        }
        e.daemon = Some(d.spawn().unwrap());
        wait_for(&e.run.join("locksmithd.sock"));
        e
    }

    /// The work repo: remote `origin` is `https://example.test/<repo>.git`, plus a binding.
    fn repo(&self, repo: &str, toml: &str) {
        git_in(&self.work, &["init", "-q", "-b", "main", "."]);
        git_in(
            &self.work,
            &[
                "remote",
                "add",
                "origin",
                &format!("https://{HOST}/{repo}.git"),
            ],
        );
        std::fs::write(
            self.work.join(".locksmith.toml"),
            format!("[git.credentials]\n\"{HOST}\" = \"GIT_TOKEN\"\n{toml}"),
        )
        .unwrap();
    }

    fn smith(&self, args: &[&str]) -> Command {
        let mut c = self.h.cmd(&[]);
        let path = std::env::var("PATH").unwrap();
        let path = match &self.extra_path {
            Some(x) => format!("{}:{}:{path}", x.display(), bin_dir().display()),
            None => format!("{}:{path}", bin_dir().display()),
        };
        c.args(args)
            .current_dir(&self.work)
            .env("LOCKSMITH_RUNTIME_DIR", &self.run)
            .env("HOME", &self.user_home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .env("PATH", path);
        c
    }

    fn out(&self, args: &[&str]) -> Output {
        let mut c = self.smith(args);
        c.stdin(Stdio::null());
        c.output().unwrap()
    }

    fn setup(&self, args: &[&str]) -> Output {
        let mut a = vec!["git", "setup"];
        a.extend_from_slice(args);
        let o = self.out(&a);
        assert!(o.status.success(), "setup: {}", s(&o.stderr));
        o
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
        let o = self.out(&["git", "status", "--json"]);
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        v["port"].as_u64().unwrap() as u16
    }

    fn audit(&self) -> Vec<serde_json::Value> {
        let o = self.out(&["audit", "ls", "--json", "--limit", "200"]);
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        v["events"].as_array().unwrap().clone()
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

fn find<'a>(
    ev: &'a [serde_json::Value],
    action: &str,
    needle: &str,
) -> Option<&'a serde_json::Value> {
    ev.iter().find(|e| {
        e["action"] == action
            && (e["target"].as_str().unwrap_or("").contains(needle)
                || e["policy_rule"].as_str().unwrap_or("").contains(needle))
    })
}

/// Script prefix for the in-session git work: wait files in `work`.
fn gate(e: &Env, name: &str) -> String {
    format!(
        "touch {w}/{name}.ready; while [ ! -e {w}/{name}.go ]; do sleep 0.1; done",
        w = e.work.display()
    )
}

#[test]
fn push_branch_protected_delete_and_allowlist() {
    need_backend!();
    let e = Env::new(true);
    e.repo("acme/app", "[git]\nrepos = [\"example.test/acme/app\"]\n");
    e.setup(&["--repo", "--host", HOST]);
    git_in(
        &e.work,
        &[
            "remote",
            "add",
            "other",
            &format!("https://{HOST}/acme/other.git"),
        ],
    );

    let script = r#"set -u
git fetch -q origin main && git checkout -q -b feature FETCH_HEAD || echo FETCH_FAILED
echo b > b.txt; git add b.txt; git commit -q -m b
git push -q origin feature; echo "push_rc=$?"
git ls-remote origin refs/heads/feature
git push origin :main 2>del.err; echo "del_rc=$?"
cat del.err
"#;
    let o = e.session(script).wait_with_output().unwrap();
    let out = s(&o.stdout);
    assert!(!out.contains("FETCH_FAILED"), "{out} {}", s(&o.stderr));
    assert!(out.contains("push_rc=0"), "{out} {}", s(&o.stderr));
    assert!(out.contains("refs/heads/feature"), "{out}");
    assert!(
        out.contains("del_rc=1") || out.contains("del_rc=128"),
        "{out}"
    );
    assert!(out.contains("protected ref refs/heads/main"), "{out}");

    // The upstream saw only the PAT header, never the forwarder token, and main survives.
    assert!(e.seen.requests.load(SeqCst) >= 3);
    assert_eq!(
        e.seen.bad.load(SeqCst),
        0,
        "upstream saw a non-PAT Authorization"
    );
    let ev = e.audit();
    let a = find(&ev, "ACCESS", "git:example.test/acme/app");
    assert!(
        a.is_some(),
        "no ACCESS for git:example.test/acme/app in {ev:?}"
    );
    let b = find(&ev, "BLOCKED", "git_policy");
    assert!(b.is_some(), "no BLOCKED git_policy in {ev:?}");
    assert!(!s(&e.out(&["audit", "ls", "--json"]).stdout).contains(&e.pat));

    // Not in the allowlist: refused before the fixture is contacted.
    let before = e.seen.requests.load(SeqCst);
    let script = "git push other HEAD:refs/heads/x 2>other.err; echo \"rc=$?\"; cat other.err";
    let o = e.session(script).wait_with_output().unwrap();
    let out = s(&o.stdout);
    assert!(!out.contains("rc=0"), "{out}");
    assert_eq!(
        e.seen.requests.load(SeqCst),
        before,
        "fixture was contacted: {out}"
    );
    let ev = e.audit();
    assert!(
        find(&ev, "BLOCKED", "git_repo_not_allowed").is_some(),
        "{ev:?}"
    );
}

#[test]
fn replay_from_outside_session_tree_is_403() {
    need_backend!();
    let e = Env::new(true);
    e.repo("acme/app", "");
    e.setup(&["--repo", "--host", HOST]);
    let port = e.port();
    let tok = e.work.join("tok");
    let script = format!(
        "printf 'protocol=http\\nhost=127.0.0.1:{port}\\npath=git/{HOST}/acme/app.git\\n\\n' | smith git credential get > {t}; {g}",
        t = tok.display(),
        g = gate(&e, "a")
    );
    let agent = e.session(&script);
    wait_for(&e.work.join("a.ready"));
    let creds = std::fs::read_to_string(&tok).unwrap();
    let token = creds
        .lines()
        .find_map(|l| l.strip_prefix("password="))
        .unwrap_or_else(|| panic!("no token in helper output {creds:?}"))
        .to_string();

    let before = e.seen.requests.load(SeqCst);
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let auth = b64(format!("locksmith:{token}").as_bytes());
    write!(
        c,
        "GET /git/{HOST}/acme/app.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Basic {auth}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut resp = String::new();
    let _ = c.read_to_string(&mut resp);
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert_eq!(
        e.seen.requests.load(SeqCst),
        before,
        "replay reached the upstream"
    );
    let ev = e.audit();
    assert!(
        ev.iter()
            .any(|v| v["action"] == "BLOCKED"
                && v["target"].as_str().unwrap_or("").contains("acme/app")),
        "{ev:?}"
    );
    std::fs::write(e.work.join("a.go"), "").unwrap();
    agent.wait_with_output().unwrap();
}

#[test]
fn revoke_all_stops_git_fetch() {
    need_backend!();
    let e = Env::new(true);
    e.repo("acme/app", "");
    e.setup(&["--repo", "--host", HOST]);
    let script = format!(
        "git fetch -q origin; echo \"before=$?\"; {g}; git fetch -q origin 2>f.err; echo \"after=$?\"; cat f.err",
        g = gate(&e, "r")
    );
    let agent = e.session(&script);
    wait_for(&e.work.join("r.ready"));
    let o = e.out(&["revoke", "--all"]);
    assert!(o.status.success(), "{}", s(&o.stderr));
    std::fs::write(e.work.join("r.go"), "").unwrap();
    let o = agent.wait_with_output().unwrap();
    let out = s(&o.stdout);
    assert!(out.contains("before=0"), "{out} {}", s(&o.stderr));
    assert!(
        !out.contains("after=0"),
        "fetch succeeded after revoke: {out}"
    );
}

#[test]
fn setup_and_teardown_leave_no_residue() {
    let e = Env::new(false);
    git_in(&e.work, &["init", "-q", "-b", "main", "."]);
    let cfg = e.work.join(".git/config");
    let before = std::fs::read(&cfg).unwrap();
    e.setup(&["--repo"]);
    let o = git_in(
        &e.work,
        &["config", "--show-origin", "--get-all", "include.path"],
    );
    let shown = s(&o.stdout);
    assert!(
        shown.contains(".git/config") && shown.contains("forwarder.gitconfig"),
        "{shown}"
    );
    let inc = shown.split_whitespace().last().unwrap();
    let body = std::fs::read_to_string(inc).unwrap();
    for h in ["github.com", "gitlab.com", "bitbucket.org"] {
        for form in [
            format!("https://{h}/"),
            format!("git@{h}:"),
            format!("ssh://git@{h}/"),
        ] {
            assert!(
                body.contains(&format!("insteadOf = {form}")),
                "{form} in {body}"
            );
        }
    }
    assert!(e.out(&["git", "teardown", "--repo"]).status.success());
    assert_eq!(std::fs::read(&cfg).unwrap(), before, ".git/config changed");

    // Global scope with HOME in a temp dir (a pre-existing ~/.gitconfig survives untouched).
    let gc = e.user_home.join(".gitconfig");
    std::fs::write(&gc, "[user]\n\tname = someone\n").unwrap();
    let before = std::fs::read(&gc).unwrap();
    let outside = e.h.0.join("norepo");
    std::fs::create_dir_all(&outside).unwrap();
    let run_in = |args: &[&str]| {
        let mut c = e.smith(args);
        c.current_dir(&outside).stdin(Stdio::null());
        c.output().unwrap()
    };
    assert!(run_in(&["git", "setup", "--global"]).status.success());
    let g = s(&Command::new("git")
        .args(["config", "--global", "--get-all", "include.path"])
        .env("HOME", &e.user_home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
        .stdout);
    assert!(g.contains("forwarder.gitconfig"), "{g}");
    assert!(run_in(&["git", "teardown", "--global"]).status.success());
    assert_eq!(std::fs::read(&gc).unwrap(), before, "~/.gitconfig changed");
}

#[cfg(unix)] // the fake `gh` is a /bin/sh script
#[test]
fn gh_output_is_redacted_and_audited() {
    let e = Env::new(false);
    git_in(&e.work, &["init", "-q", "-b", "main", "."]);
    let bin = e.h.0.join("fakebin");
    std::fs::create_dir_all(&bin).unwrap();
    let gh = bin.join("gh");
    std::fs::write(
        &gh,
        "#!/bin/sh\necho \"$GH_TOKEN\"\necho \"token=$GH_TOKEN\"\nexit 0\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut e = e;
    e.extra_path = Some(bin);
    let o = e
        .session("smith gh -- api user; echo \"rc=$?\"")
        .wait_with_output()
        .unwrap();
    let out = s(&o.stdout);
    assert!(out.contains("rc=0"), "{out} {}", s(&o.stderr));
    assert!(out.contains("token="), "fake gh did not run: {out}");
    assert!(!out.contains(&e.pat), "PAT leaked: {out}");
    assert!(!s(&o.stderr).contains(&e.pat));
    let ev = e.audit();
    assert!(find(&ev, "ACCESS", "gh").is_some(), "{ev:?}");
}
