//! End to end: real `git` -> forwarder -> `git http-backend` fixture.

use base64::Engine;
use ls_proxy::forward::{Upstream, serve};
use ls_proxy::{Authority, Deny, Grant, Route};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

fn expected_auth() -> String {
    // Built at runtime so no token-shaped literal sits in the source.
    format!(
        "Basic {}",
        b64(&format!("x-access-token:{}", "fake_pat_for_tests"))
    )
}

struct Fake {
    pushes_denied: Mutex<Vec<String>>,
    forwarded: AtomicUsize,
}

impl Authority for Fake {
    fn authorize(
        &self,
        token: Option<&str>,
        _: SocketAddr,
        _: SocketAddr,
        _: &Route,
    ) -> Result<Grant, Deny> {
        match token {
            None => Err(Deny {
                status: 401,
                message: "credentials required".into(),
            }),
            Some("fwd-token") => Ok(Grant {
                upstream_auth: Zeroizing::new(expected_auth()),
                protected: vec!["main".into()],
                lease: "lease-1".into(),
            }),
            Some(_) => Err(Deny {
                status: 403,
                message: "invalid forwarder token".into(),
            }),
        }
    }
    fn push_denied(&self, _: &Route, g: &Grant, why: &str) {
        assert_eq!(g.lease, "lease-1");
        self.pushes_denied.lock().unwrap().push(why.to_string());
    }
    fn forwarded(&self, _: &Route, _: &Grant, _: &str) {
        self.forwarded.fetch_add(1, SeqCst);
    }
}

/// Upstream fixture: `git http-backend` as CGI. Counts requests with a wrong Authorization.
fn start_upstream(root: &Path, bad: Arc<AtomicUsize>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let root = root.to_path_buf();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let (root, bad) = (root.clone(), bad.clone());
            std::thread::spawn(move || upstream_conn(s, &root, &bad));
        }
    });
    addr
}

fn upstream_conn(mut s: TcpStream, root: &Path, bad: &AtomicUsize) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let (n, method, path, headers) = loop {
        let mut hs = [httparse::EMPTY_HEADER; 64];
        let mut r = httparse::Request::new(&mut hs);
        if let Ok(httparse::Status::Complete(n)) = r.parse(&buf) {
            let h: Vec<(String, String)> = r
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_ascii_lowercase(),
                        String::from_utf8_lossy(h.value).into_owned(),
                    )
                })
                .collect();
            break (
                n,
                r.method.unwrap().to_string(),
                r.path.unwrap().to_string(),
                h,
            );
        }
        let k = s.read(&mut tmp).unwrap();
        assert!(k > 0);
        buf.extend_from_slice(&tmp[..k]);
    };
    let get = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    // The forwarder token must never arrive upstream, only the PAT header.
    if get("authorization").as_deref() != Some(&expected_auth())
        || headers
            .iter()
            .any(|(_, v)| v.contains("fwd-token") || v.contains(&b64("x:fwd-token")))
    {
        bad.fetch_add(1, SeqCst);
    }
    let mut body = buf[n..].to_vec();
    if get("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        body = dechunk(&mut s, body);
    } else {
        let cl: usize = get("content-length").map_or(0, |v| v.parse().unwrap());
        while body.len() < cl {
            let k = s.read(&mut tmp).unwrap();
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
    let split = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| out.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2)));
    let (hl, sep) = split.expect("cgi headers");
    let mut status = "200 OK".to_string();
    let mut resp = String::new();
    for line in String::from_utf8_lossy(&out[..hl]).lines() {
        match line.strip_prefix("Status: ") {
            Some(st) => status = st.to_string(),
            None => resp.push_str(&format!("{line}\r\n")),
        }
    }
    let payload = &out[hl + sep..];
    let head = format!(
        "HTTP/1.1 {status}\r\n{resp}Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(payload).unwrap();
}

fn dechunk(s: &mut TcpStream, mut raw: Vec<u8>) -> Vec<u8> {
    let (mut out, mut tmp) = (Vec::new(), [0u8; 8192]);
    loop {
        // Need a full "<hex>\r\n<data>\r\n" unit.
        let Some(nl) = raw.windows(2).position(|w| w == b"\r\n") else {
            let k = s.read(&mut tmp).unwrap();
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
            let k = s.read(&mut tmp).unwrap();
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

fn git(dir: &Path, token: &str, args: &[&str]) -> (bool, String) {
    let helper = format!("!f(){{ echo username=x; echo password={token}; }}; f");
    let o = Command::new("git")
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "credential.helper=",
            "-c",
            &format!("credential.helper={helper}"),
        ])
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .output()
        .unwrap();
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn run(dir: &Path, args: &[&str]) {
    let (ok, err) = git(dir, "unused", args);
    assert!(ok, "git {args:?}: {err}");
}

#[test]
fn clone_push_and_policy_through_forwarder() {
    let tmp = std::env::temp_dir().join(format!("ls-proxy-fwd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let bare = tmp.join("srv/owner/repo.git");
    std::fs::create_dir_all(&bare).unwrap();
    run(&bare, &["init", "--bare", "-b", "main", "."]);
    run(&bare, &["config", "http.receivepack", "true"]);
    let seed = tmp.join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    run(&seed, &["init", "-b", "main", "."]);
    std::fs::write(seed.join("a.txt"), "hello").unwrap();
    run(&seed, &["add", "."]);
    run(&seed, &["commit", "-m", "seed"]);
    run(&seed, &["push", bare.to_str().unwrap(), "main"]);

    let bad = Arc::new(AtomicUsize::new(0));
    let up_addr = start_upstream(&tmp.join("srv"), bad.clone());
    let fake = Arc::new(Fake {
        pushes_denied: Mutex::new(vec![]),
        forwarded: AtomicUsize::new(0),
    });
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let up = Arc::new(Upstream {
        insecure_http: Some(("example.test".into(), up_addr)),
    });
    let auth: Arc<dyn Authority> = fake.clone();
    std::thread::spawn(move || serve(l, auth, up));
    let url = format!("http://127.0.0.1:{port}/git/example.test/owner/repo.git");

    // clone
    let (ok, err) = git(&tmp, "fwd-token", &["clone", &url, "work"]);
    assert!(ok, "clone: {err}");
    let work = tmp.join("work");
    assert_eq!(
        std::fs::read_to_string(work.join("a.txt")).unwrap(),
        "hello"
    );

    // allowed push of a branch
    run(&work, &["checkout", "-b", "feature"]);
    std::fs::write(work.join("b.txt"), "b").unwrap();
    run(&work, &["add", "."]);
    run(&work, &["commit", "-m", "b"]);
    let (ok, err) = git(&work, "fwd-token", &["push", "origin", "feature"]);
    assert!(ok, "push: {err}");
    let (ok, out) = git(
        &work,
        "fwd-token",
        &["ls-remote", "origin", "refs/heads/feature"],
    );
    assert!(ok, "{out}");

    // delete of protected main is refused with the rule in the message
    let (ok, err) = git(&work, "fwd-token", &["push", "origin", ":main"]);
    assert!(!ok);
    assert!(
        err.contains("protected ref refs/heads/main"),
        "stderr: {err}"
    );
    assert_eq!(fake.pushes_denied.lock().unwrap().len(), 1);
    let (ok, _) = git(
        &work,
        "fwd-token",
        &["ls-remote", "origin", "refs/heads/main"],
    );
    assert!(ok);

    // wrong token
    let (ok, err) = git(&work, "wrong", &["ls-remote", "origin"]);
    assert!(!ok);
    assert!(err.contains("403"), "stderr: {err}");

    assert_eq!(
        bad.load(SeqCst),
        0,
        "upstream saw a wrong Authorization header"
    );
    assert!(fake.forwarded.load(SeqCst) >= 4);
    let _ = std::fs::remove_dir_all(&tmp);
}
