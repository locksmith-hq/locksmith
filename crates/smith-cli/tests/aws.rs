//! M7 AWS delegation e2e: real `smith`, `locksmithd` and `aws` CLI. A fake AWS upstream (plain
//! HTTP via `LOCKSMITH_TEST_AWS_UPSTREAM`) verifies every re-signed request with the REAL secret
//! using `ls_proxy::aws::sigv4::verify`, and flags any request that carries the dummy credentials.
//! A fake STS (`LOCKSMITH_TEST_STS_ENDPOINT`) serves the contained mode. Fake secrets are built at
//! runtime.

mod common;
use common::*;
use ls_proxy::aws::sigv4::{self, ChunkReader, Request};
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant, SystemTime};

const REGION: &str = "us-east-1";
const KEY: &str = "AWS_DEV";
const ROLE: &str = "arn:aws:iam::123456789012:role/dev";

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn up_key() -> String {
    ["AKIA", "UPSTREAMREALKEY1"].concat()
}
fn up_secret() -> String {
    format!("upstream{}{}", "Secret", "/Rk27YtW9Lp+zzYYxxWWvvUU11")
}
fn sts_token() -> String {
    ["sts-session-", "token-", "Zx81Qw"].concat()
}

fn have_aws() -> bool {
    Command::new("aws")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

macro_rules! need_aws {
    () => {
        if !have_aws() {
            eprintln!("SKIP: the `aws` CLI is not installed");
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

// ---- fake AWS upstream ----

#[derive(Debug, Clone)]
struct Seen {
    host: String,
    method: String,
    target: String,
    /// Empty when the re-signed request verified with the real secret, else why not.
    problem: String,
}

type Log = Arc<Mutex<Vec<Seen>>>;

/// (head text, body) of one HTTP request, or None on EOF.
fn read_request(c: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 65536];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = c.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = s(&buf[..end]);
    let len: usize = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse().ok())?
        })
        .unwrap_or(0);
    while buf.len() < end + len {
        let n = c.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Some((head, buf[end..end + len].to_vec()))
}

fn check(head: &str, body: &[u8]) -> Seen {
    let mut lines = head.lines();
    let first = lines.next().unwrap_or("");
    let mut it = first.split(' ');
    let method = it.next().unwrap_or("").to_string();
    let target = it.next().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let hv = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
    };
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let mut problems = Vec::new();
    if head.contains("AKIALOCKSMITH") {
        problems.push("a Locksmith dummy key id reached AWS".to_string());
    }
    let sha = hv("x-amz-content-sha256");
    let req = Request {
        method: method.clone(),
        path: path.into(),
        query: query.into(),
        headers: headers.clone(),
        payload_hash: sha.clone().unwrap_or_else(|| sigv4::hex_sha256(body)),
    };
    match sigv4::parse_authorization(&hv("authorization").unwrap_or_default()) {
        Err(e) => problems.push(e),
        Ok(a) => {
            if a.access_key_id != up_key() {
                problems.push("not signed with the upstream key".into());
            }
            if let Err(e) = sigv4::verify(&req, &a, &up_secret(), SystemTime::now()) {
                problems.push(format!("upstream verify: {e}"));
            }
            match sha.as_deref() {
                Some(sigv4::STREAMING_PAYLOAD) => {
                    let key = sigv4::signing_key(&up_secret(), &a.scope);
                    let mut rd = ChunkReader::new(
                        BufReader::new(body),
                        key,
                        a.scope.clone(),
                        hv("x-amz-date").unwrap_or_default(),
                        a.signature.clone(),
                    );
                    loop {
                        match rd.next_chunk() {
                            Ok(Some(_)) => {}
                            Ok(None) => break,
                            Err(e) => {
                                problems.push(e.to_string());
                                break;
                            }
                        }
                    }
                }
                Some(h) if h.len() == 64 && h != sigv4::hex_sha256(body) => {
                    problems.push("payload hash mismatch".into())
                }
                _ => {}
            }
        }
    }
    Seen {
        host: hv("host").unwrap_or_default(),
        method,
        target,
        problem: problems.join("; "),
    }
}

fn xml_reply(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn respond(s: &Seen) -> String {
    if !s.problem.is_empty() {
        return xml_reply(
            "403 Forbidden",
            &format!(
                "<Error><Code>SignatureDoesNotMatch</Code><Message>fake AWS: {}</Message></Error>",
                s.problem
            ),
        );
    }
    if s.host.starts_with("sts.") {
        return xml_reply(
            "200 OK",
            "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/fake</Arn><UserId>AIDAFAKE</UserId><Account>123456789012</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></GetCallerIdentityResponse>",
        );
    }
    if s.method == "GET" && s.target.contains("list-type=2") {
        return xml_reply(
            "200 OK",
            "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>b</Name><Prefix></Prefix><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>hello.txt</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>&quot;x&quot;</ETag><Size>5</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>",
        );
    }
    "HTTP/1.1 200 OK\r\nETag: \"etag\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
}

fn start_aws(log: Log) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let log = log.clone();
            std::thread::spawn(move || {
                let mut c = c;
                let Some((head, body)) = read_request(&mut c) else {
                    return;
                };
                let seen = check(&head, &body);
                let _ = c.write_all(respond(&seen).as_bytes());
                log.lock().unwrap().push(seen);
            });
        }
    });
    addr
}

// ---- fake STS ----

fn decode(v: &str) -> String {
    let b = v.replace('+', " ");
    let b = b.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push(u8::from_str_radix(&String::from_utf8_lossy(&b[i + 1..i + 3]), 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Form bodies of the AssumeRole calls the fake STS received.
type Bodies = Arc<Mutex<Vec<Vec<(String, String)>>>>;

fn start_sts(bodies: Bodies) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let bodies = bodies.clone();
            std::thread::spawn(move || {
                let mut c = c;
                let Some((_, body)) = read_request(&mut c) else {
                    return;
                };
                let form = s(&body)
                    .split('&')
                    .filter_map(|kv| kv.split_once('='))
                    .map(|(k, v)| (k.to_string(), decode(v)))
                    .collect();
                bodies.lock().unwrap().push(form);
                let xml = format!(
                    "<AssumeRoleResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><AssumeRoleResult><Credentials><AccessKeyId>ASIAFAKECONTAINED01</AccessKeyId><SecretAccessKey>{}</SecretAccessKey><SessionToken>{}</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>",
                    ["contained", "Secret", "/Qq19Ww"].concat(),
                    sts_token()
                );
                let _ = c.write_all(xml_reply("200 OK", &xml).as_bytes());
            });
        }
    });
    addr
}

// ---- environment ----

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

struct Env {
    h: Home,
    run: PathBuf,
    work: PathBuf,
    daemon: Option<std::process::Child>,
    log: Log,
    sts: Bodies,
}

const PROFILE: &str = "[aws.profiles.dev]\nkey = \"AWS_DEV\"\nregion = \"us-east-1\"\n";

impl Env {
    /// `binding`: contents of `.locksmith.toml` in the work dir.
    fn new(binding: &str) -> Env {
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
        h.ready();
        let keys = format!(
            "{{\"access_key_id\":\"{}\",\"secret_access_key\":\"{}\"}}",
            up_key(),
            up_secret()
        );
        assert!(h.add(KEY, &keys).status.success());
        let log = Log::default();
        let sts = Bodies::default();
        let aws = start_aws(log.clone());
        let sts_addr = start_sts(sts.clone());
        let up: Vec<String> = ["sts", "s3"]
            .iter()
            .map(|svc| format!("{svc}.{REGION}.amazonaws.com={aws}"))
            .chain(
                ["app-bucket", "other-bucket"]
                    .iter()
                    .map(|b| format!("{b}.s3.{REGION}.amazonaws.com={aws}")),
            )
            .collect();
        let mut d = Command::new(locksmithd());
        d.env("LOCKSMITH_HOME", &h.0)
            .env("LOCKSMITH_RUNTIME_DIR", &run)
            .env("LOCKSMITH_INSECURE_TEST_KDF", "1")
            .env("LOCKSMITH_TEST_AWS_UPSTREAM", up.join(","))
            .env("LOCKSMITH_TEST_STS_ENDPOINT", format!("http://{sts_addr}/"))
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
            log,
            sts,
        }
    }

    fn smith(&self, args: &[&str]) -> Command {
        let mut c = self.h.cmd(&[]);
        c.args(args)
            .current_dir(&self.work)
            .env("LOCKSMITH_RUNTIME_DIR", &self.run)
            .env("HOME", &self.h.0)
            .env("AWS_CONFIG_FILE", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
            .env("AWS_MAX_ATTEMPTS", "1")
            .env("AWS_PAGER", "")
            .env(
                "PATH",
                format!("{}:{}", bin_dir().display(), std::env::var("PATH").unwrap()),
            );
        for p in PROXIES {
            c.env_remove(p);
        }
        for v in [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_PROFILE",
            "AWS_ENDPOINT_URL",
        ] {
            c.env_remove(v);
        }
        c
    }

    fn out(&self, args: &[&str]) -> Output {
        let mut c = self.smith(args);
        c.stdin(Stdio::null());
        c.output().unwrap()
    }

    /// `smith --passphrase-stdin <args>` outside any session.
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

    fn session_with(&self, scopes: &[&str], script: &str) -> std::process::Child {
        let mut args = vec!["--passphrase-stdin", "session", "start"];
        for sc in scopes {
            args.extend(["--scope", sc]);
        }
        args.extend(["--", "sh", "-c", script]);
        let mut c = self.smith(&args).spawn().unwrap();
        c.stdin
            .take()
            .unwrap()
            .write_all(format!("{PW}\n").as_bytes())
            .unwrap();
        c
    }

    /// Runs `script` in a session with every default scope; returns (stdout, stderr).
    fn session(&self, script: &str) -> (String, String) {
        let o = self.session_with(&[], script).wait_with_output().unwrap();
        (s(&o.stdout), s(&o.stderr))
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

    fn upstream_requests(&self) -> Vec<Seen> {
        self.log.lock().unwrap().clone()
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

fn assert_all_verified(e: &Env) {
    for r in e.upstream_requests() {
        assert_eq!(r.problem, "", "upstream rejected {r:?}");
    }
}

fn custom_policy_binding() -> String {
    format!(
        "{PROFILE}[aws.policy]\nallow = [\"s3:*\"]\nresources = [\"arn:aws:s3:::app-bucket\", \"arn:aws:s3:::app-bucket/*\"]\n"
    )
}

// ---- scenarios ----

/// Scenarios 1 and 5.
#[test]
fn run_aws_resigns_with_real_secret_redacts_and_dies_with_revoke() {
    need_aws!();
    let e = Env::new(PROFILE);
    let script = format!(
        r#"smith run --aws dev -- sh -c 'env | grep "^AWS_" > awsenv.txt; echo "SECRET=$AWS_SECRET_ACCESS_KEY"; aws sts get-caller-identity'
echo "id=$?"
{gate}
while IFS='=' read -r k v; do export "$k=$v"; done < awsenv.txt
aws sts get-caller-identity >after.out 2>after.err
echo "after=$?"
"#,
        gate = e.gate("r")
    );
    let agent = e.session_with(&[], &script);
    wait_for(&e.work.join("r.ready"));
    let envtxt = std::fs::read_to_string(e.work.join("awsenv.txt")).unwrap();
    let var = |k: &str| {
        envtxt
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap_or_else(|| panic!("{k} missing in {envtxt}"))
            .to_string()
    };
    let (akid, dummy_secret) = (var("AWS_ACCESS_KEY_ID"), var("AWS_SECRET_ACCESS_KEY"));
    assert!(
        akid.starts_with("AKIALOCKSMITH") && akid.len() == 20,
        "{akid}"
    );
    assert!(var("AWS_ENDPOINT_URL").starts_with("http://127.0.0.1:"));
    assert_eq!(var("AWS_REQUEST_CHECKSUM_CALCULATION"), "when_required");
    assert_ne!(dummy_secret, up_secret());
    let before = e.upstream_requests().len();
    assert_eq!(before, 1);

    assert!(e.out(&["revoke", "--all"]).status.success());
    std::fs::write(e.work.join("r.go"), "").unwrap();
    let o = agent.wait_with_output().unwrap();
    let out = s(&o.stdout);
    let err = s(&o.stderr);
    assert!(out.contains("id=0"), "{out} {err}");
    assert!(out.contains("123456789012"), "{out} {err}");
    assert!(out.contains("SECRET=[REDACTED"), "{out}");
    for hay in [&out, &err] {
        assert!(!hay.contains(&dummy_secret) && !hay.contains(&up_secret()));
    }
    assert!(
        !out.contains("after=0"),
        "dummy keys worked after revoke: {out}"
    );
    assert_eq!(
        e.upstream_requests().len(),
        before,
        "revoked call reached AWS"
    );
    assert_all_verified(&e);
    let ev = e.audit();
    assert!(has(&ev, "AWS_ISSUE", &akid), "{ev:?}");
    assert!(has(&ev, "ACCESS", "sts:GetCallerIdentity"), "{ev:?}");
    let all = s(&e.out(&["audit", "ls", "--json", "--limit", "200"]).stdout);
    assert!(!all.contains(&dummy_secret) && !all.contains(&up_secret()));
}

/// Scenario 2.
#[test]
fn default_policy_is_read_only() {
    need_aws!();
    let e = Env::new(PROFILE);
    let (out, err) = e.session(
        r#"smith run --aws dev -- aws s3 ls s3://app-bucket; echo "ls=$?"
smith run --aws dev -- aws s3 rm s3://app-bucket/x; echo "rm=$?"
"#,
    );
    assert!(
        out.contains("hello.txt") && out.contains("ls=0"),
        "{out} {err}"
    );
    assert!(!out.contains("rm=0"), "{out} {err}");
    let all = format!("{out}{err}");
    assert!(
        all.contains("AccessDenied") && all.contains("aws_not_allowed:s3:DeleteObject"),
        "{all}"
    );
    assert!(
        !e.upstream_requests().iter().any(|r| r.method == "DELETE"),
        "delete reached AWS"
    );
    assert_all_verified(&e);
    let ev = e.audit();
    assert!(
        has(&ev, "BLOCKED", "aws_not_allowed:s3:DeleteObject"),
        "{ev:?}"
    );
}

/// Scenario 3.
#[test]
fn custom_policy_limits_resources() {
    need_aws!();
    let e = Env::new(&custom_policy_binding());
    let (out, err) = e.session(
        r#"echo hi > f.txt
smith run --aws dev -- aws s3 cp f.txt s3://app-bucket/f.txt; echo "app=$?"
smith run --aws dev -- aws s3 cp f.txt s3://other-bucket/f.txt; echo "other=$?"
"#,
    );
    assert!(out.contains("app=0"), "{out} {err}");
    assert!(!out.contains("other=0"), "{out} {err}");
    assert!(
        format!("{out}{err}").contains("aws_resource_not_allowed"),
        "{out} {err}"
    );
    let reqs = e.upstream_requests();
    assert!(
        reqs.iter().any(|r| r.host.starts_with("app-bucket.")),
        "{reqs:?}"
    );
    assert!(
        !reqs.iter().any(|r| r.host.contains("other-bucket")),
        "{reqs:?}"
    );
    assert_all_verified(&e);
    assert!(has(&e.audit(), "BLOCKED", "aws_resource_not_allowed"));
}

/// Scenario 4.
#[test]
fn run_aws_needs_the_aws_scope() {
    let e = Env::new(PROFILE);
    let o = e
        .session_with(&["run"], r#"smith run --aws dev -- true; echo "rc=$?""#)
        .wait_with_output()
        .unwrap();
    let (out, err) = (s(&o.stdout), s(&o.stderr));
    assert!(!out.contains("rc=0"), "{out} {err}");
    assert!(err.contains("`aws` scope"), "{out} {err}");
    assert!(e.upstream_requests().is_empty());
    assert!(has(&e.audit(), "BLOCKED", ""), "no BLOCKED audit");
}

/// Scenario 6.
#[test]
fn run_aws_outside_a_session_uses_a_leased_run() {
    need_aws!();
    let e = Env::new(PROFILE);
    let o = e.with_pw(&[
        "run",
        "--aws",
        "dev",
        "--",
        "aws",
        "sts",
        "get-caller-identity",
    ]);
    let (out, err) = (s(&o.stdout), s(&o.stderr));
    assert!(o.status.success(), "{out} {err}");
    assert!(out.contains("123456789012"), "{out}");
    assert_all_verified(&e);
    assert_eq!(e.upstream_requests().len(), 1);
    // The lease ended with the child.
    let st = e.out(&["--json", "status"]);
    let v: serde_json::Value = serde_json::from_slice(&st.stdout).unwrap();
    assert_eq!(v["sessions"].as_array().map(Vec::len), Some(0), "{v}");
}

/// Scenario 7.
#[test]
fn contained_credentials_come_from_sts_with_policy_and_are_redacted() {
    let e = Env::new(&format!(
        "[aws.profiles.dev]\nkey = \"AWS_DEV\"\nregion = \"us-east-1\"\nrole_arn = \"{ROLE}\"\n[aws.policy]\nallow = [\"s3:*\"]\nresources = [\"arn:aws:s3:::app-bucket/*\"]\n"
    ));
    let o = e.with_pw(&[
        "aws",
        "creds",
        "--contained",
        "--profile",
        "dev",
        "--",
        "sh",
        "-c",
        "echo TOKEN=$AWS_SESSION_TOKEN",
    ]);
    let (out, err) = (s(&o.stdout), s(&o.stderr));
    assert!(o.status.success(), "{out} {err}");
    assert!(err.contains("Contained AWS credentials"), "{err}");
    assert!(out.contains("TOKEN=[REDACTED"), "{out}");
    assert!(!out.contains(&sts_token()) && !err.contains(&sts_token()));
    let calls = e.sts.lock().unwrap().clone();
    assert_eq!(calls.len(), 1, "{calls:?}");
    let p = |k: &str| {
        calls[0]
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(p("DurationSeconds").as_deref(), Some("900"));
    assert_eq!(p("RoleArn").as_deref(), Some(ROLE));
    let policy = p("Policy").expect("session Policy parameter");
    assert!(policy.contains("app-bucket"), "{policy}");
    assert!(e.upstream_requests().is_empty());
    assert!(has(&e.audit(), "ACCESS", "aws_contained"));
}

/// Scenario 7, error path.
#[test]
fn contained_without_role_arn_is_a_clear_error() {
    let e = Env::new(PROFILE);
    let o = e.with_pw(&[
        "aws",
        "creds",
        "--contained",
        "--profile",
        "dev",
        "--",
        "true",
    ]);
    let (out, err) = (s(&o.stdout), s(&o.stderr));
    assert!(!o.status.success(), "{out} {err}");
    assert!(err.contains("role_arn"), "{err}");
    assert!(e.sts.lock().unwrap().is_empty());
}

/// Scenario 8.
#[test]
fn doctor_reports_relay_and_policy() {
    let e = Env::new(&custom_policy_binding());
    let o = e.out(&["--json", "doctor"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|_| panic!("{} {}", s(&o.stdout), s(&o.stderr)));
    let check = |id: &str| {
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap_or_else(|| panic!("no {id} check"))
            .clone()
    };
    let relay = check("aws.relay");
    assert_eq!(relay["status"], "ok", "{relay}");
    assert!(relay["summary"].as_str().unwrap().contains("127.0.0.1:"));
    let pol = check("aws.policy");
    assert_eq!(pol["status"], "ok", "{pol}");
    assert_eq!(
        pol["summary"],
        "1 profile(s); policy: 1 allow, 0 deny, 2 resource pattern(s)"
    );
}
