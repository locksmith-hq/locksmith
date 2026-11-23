//! AWS SigV4 relay end to end (M7 1.2, 1.4) against a fake AWS on 127.0.0.1 (plain TCP via the
//! `Upstream.insecure_http` test switch). The fake verifies every re-signed request with the
//! upstream secret (`sigv4::verify`, plus `aws-chunked` chunk signatures) and checks that the
//! dummy key and secret never arrive. Driven by raw signed requests, and by the real AWS CLI when
//! installed. The `#[ignore]` Floci test covers STS, S3 (incl. a 200 MB `aws s3 cp`),
//! DynamoDB, SQS, Lambda and SSM through the relay.

use ls_proxy::Deny;
use ls_proxy::aws::policy::Policy;
use ls_proxy::aws::sigv4::{self, ChunkReader, ChunkSigner, Request, Scope};
use ls_proxy::aws::{AwsAuthority, AwsSession, Call, Credentials, relay};
use ls_proxy::http::Upstream;
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;
use zeroize::Zeroizing;

const RO_KEY: &str = "AKIALOCKSMITHREADONL";
const RW_KEY: &str = "AKIALOCKSMITHWRITEAL";
const UP_KEY: &str = "AKIAUPSTREAMREALKEY1";
const REGION: &str = "us-east-1";

/// Built at runtime so no key-shaped literal sits in the source.
fn dummy_secret() -> String {
    format!("dummy{}{}", "Secret", "/Zq81pXv3Wm+aaBBccDDeeFF00")
}
fn up_secret() -> String {
    format!("upstream{}{}", "Secret", "/Rk27YtW9Lp+zzYYxxWWvvUU11")
}
fn up_token() -> String {
    format!("upstream-session-{}", "token-77")
}

// ---- fake daemon ----

#[derive(Default)]
struct Fake {
    records: Mutex<Vec<(String, bool, String)>>,
    /// Allow-all for every key (Floci run).
    open: bool,
    upstream_secret: String,
    upstream_key: String,
    upstream_token: Option<String>,
}

impl AwsAuthority for Fake {
    fn session(&self, akid: &str, _: SocketAddr, _: SocketAddr) -> Result<AwsSession, Deny> {
        let policy = match akid {
            RW_KEY => Policy {
                allow: vec!["*".into()],
                ..Policy::default()
            },
            RO_KEY if !self.open => Policy::default(),
            RO_KEY => Policy {
                allow: vec!["*".into()],
                ..Policy::default()
            },
            _ => {
                return Err(Deny {
                    status: 403,
                    message: "unknown or revoked Locksmith dummy key".into(),
                });
            }
        };
        Ok(AwsSession {
            lease: "lease-1".into(),
            dummy_secret: Zeroizing::new(dummy_secret()),
            upstream: Credentials {
                access_key_id: self.upstream_key.clone(),
                secret_access_key: Zeroizing::new(self.upstream_secret.clone()),
                session_token: self.upstream_token.clone().map(Zeroizing::new),
            },
            policy,
        })
    }

    fn record(&self, _: &AwsSession, call: &Call, allowed: bool, rule: &str) {
        self.records.lock().unwrap().push((
            format!(
                "{} {}",
                call.action.as_deref().unwrap_or("unknown"),
                call.resource
            ),
            allowed,
            rule.to_string(),
        ));
    }
}

// ---- fake AWS ----

#[derive(Debug, Clone)]
struct Seen {
    host: String,
    method: String,
    target: String,
    /// Empty when the re-signed request verified, else why not.
    problem: String,
    decoded_len: usize,
}

fn seen() -> &'static Mutex<Vec<Seen>> {
    static S: OnceLock<Mutex<Vec<Seen>>> = OnceLock::new();
    S.get_or_init(Default::default)
}

fn read_raw_request(s: &mut TcpStream) -> Option<(Vec<u8>, usize, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 65536];
    loop {
        let mut hs = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut hs);
        if let Ok(httparse::Status::Complete(n)) = req.parse(&buf) {
            let len: usize = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                .and_then(|h| std::str::from_utf8(h.value).ok()?.trim().parse().ok())
                .unwrap_or(0);
            while buf.len() < n + len {
                let k = s.read(&mut tmp).ok()?;
                if k == 0 {
                    return None;
                }
                buf.extend_from_slice(&tmp[..k]);
            }
            let body = buf[n..n + len].to_vec();
            return Some((buf, n, body));
        }
        let k = s.read(&mut tmp).ok()?;
        if k == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..k]);
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Check one re-signed request as AWS would; returns (seen, problem).
fn check(raw: &[u8], head_len: usize, body: &[u8]) -> Seen {
    let mut hs = [httparse::EMPTY_HEADER; 64];
    let mut r = httparse::Request::new(&mut hs);
    r.parse(&raw[..head_len]).unwrap();
    let headers: Vec<(String, String)> = r
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();
    let target = r.path.unwrap_or("").to_string();
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let hv = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.trim().to_string())
    };
    let mut s = Seen {
        host: hv("host").unwrap_or_default(),
        method: r.method.unwrap_or("").into(),
        target: target.clone(),
        problem: String::new(),
        decoded_len: body.len(),
    };
    let mut problems = Vec::new();
    for leak in [RO_KEY, RW_KEY, &dummy_secret()] {
        if contains(raw, leak.as_bytes()) {
            problems.push(format!("dummy credential {} reached AWS", &leak[..8]));
        }
    }
    if hv("x-amz-security-token") != Some(up_token()) {
        problems.push("missing upstream session token".into());
    }
    let sha = hv("x-amz-content-sha256");
    let req = Request {
        method: s.method.clone(),
        path: path.into(),
        query: query.into(),
        headers: headers.clone(),
        payload_hash: sha.clone().unwrap_or_else(|| sigv4::hex_sha256(body)),
    };
    match sigv4::parse_authorization(&hv("authorization").unwrap_or_default()) {
        Err(e) => problems.push(e),
        Ok(a) => {
            if a.access_key_id != UP_KEY {
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
                    let mut n = 0;
                    loop {
                        match rd.next_chunk() {
                            Ok(Some(c)) => n += c.len(),
                            Ok(None) => break,
                            Err(e) => {
                                problems.push(e.to_string());
                                break;
                            }
                        }
                    }
                    s.decoded_len = n;
                    if hv("x-amz-decoded-content-length") != Some(n.to_string()) {
                        problems.push("decoded length mismatch".into());
                    }
                }
                Some(h) if h.len() == 64 && h != sigv4::hex_sha256(body) => {
                    problems.push("payload hash mismatch".into())
                }
                _ => {}
            }
        }
    }
    s.problem = problems.join("; ");
    s
}

fn respond(s: &Seen) -> String {
    let xml = |status: &str, body: String| {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/xml\r\nx-amz-security-token: must-not-reach-client\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    if !s.problem.is_empty() {
        return xml(
            "403 Forbidden",
            format!(
                "<Error><Code>SignatureDoesNotMatch</Code><Message>fake AWS: {}</Message></Error>",
                s.problem
            ),
        );
    }
    if s.host.starts_with("sts.") {
        return xml(
            "200 OK",
            "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/fake</Arn><UserId>AIDAFAKE</UserId><Account>123456789012</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></GetCallerIdentityResponse>".into(),
        );
    }
    if s.method == "GET" && s.target.contains("list-type=2") {
        return xml(
            "200 OK",
            "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>bucket</Name><Prefix></Prefix><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>hello.txt</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>&quot;x&quot;</ETag><Size>5</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>".into(),
        );
    }
    "HTTP/1.1 200 OK\r\nETag: \"etag\"\r\nx-amz-security-token: must-not-reach-client\r\nContent-Length: 0\r\n\r\n".into()
}

fn fake_aws() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            std::thread::spawn(move || {
                let Some((raw, n, body)) = read_raw_request(&mut c) else {
                    return;
                };
                let s = check(&raw, n, &body);
                let _ = c.write_all(respond(&s).as_bytes());
                seen().lock().unwrap().push(s);
            });
        }
    });
    addr
}

struct Env {
    relay: SocketAddr,
    fake: Arc<Fake>,
}

fn env() -> &'static Env {
    static E: OnceLock<Env> = OnceLock::new();
    E.get_or_init(|| {
        let aws = fake_aws();
        let hosts = [
            "s3.us-east-1.amazonaws.com",
            "bucket.s3.us-east-1.amazonaws.com",
            "sts.us-east-1.amazonaws.com",
            "dynamodb.us-east-1.amazonaws.com",
        ];
        let up = Upstream {
            insecure_http: hosts.iter().map(|h| (h.to_string(), aws)).collect(),
        };
        let fake = Arc::new(Fake {
            upstream_key: UP_KEY.into(),
            upstream_secret: up_secret(),
            upstream_token: Some(up_token()),
            ..Fake::default()
        });
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let auth: Arc<dyn AwsAuthority> = fake.clone();
        std::thread::spawn(move || relay::serve(l, auth, Arc::new(up)));
        Env { relay: addr, fake }
    })
}

fn seen_for(target_part: &str) -> Vec<Seen> {
    seen()
        .lock()
        .unwrap()
        .iter()
        .filter(|s| s.target.contains(target_part))
        .cloned()
        .collect()
}

// ---- raw signed requests ----

struct Signed {
    head: Vec<u8>,
    signature: String,
    date: String,
    scope: Scope,
}

/// Sign like an SDK would against the relay endpoint and return the request head.
fn sign_head(
    method: &str,
    target: &str,
    service: &str,
    akid: &str,
    secret: &str,
    extra: &[(&str, &str)],
    payload_hash: &str,
) -> Signed {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers: Vec<(String, String)> = vec![
        ("Host".into(), env().relay.to_string()),
        ("x-amz-content-sha256".into(), payload_hash.into()),
    ];
    if service != "s3" {
        headers.pop();
    }
    headers.extend(extra.iter().map(|(a, b)| (a.to_string(), b.to_string())));
    let date = sigv4::amz_date(SystemTime::now());
    let scope = Scope {
        date: date[..8].into(),
        region: REGION.into(),
        service: service.into(),
    };
    let req = Request {
        method: method.into(),
        path: path.into(),
        query: query.into(),
        headers: headers.clone(),
        payload_hash: payload_hash.into(),
    };
    let creds = Credentials {
        access_key_id: akid.into(),
        secret_access_key: Zeroizing::new(secret.into()),
        session_token: None,
    };
    let signed = sigv4::sign(&req, &creds, &scope, &date, &[]);
    let mut head = format!("{method} {target} HTTP/1.1\r\n");
    for (n, v) in headers {
        head.push_str(&format!("{n}: {v}\r\n"));
    }
    for (n, v) in &signed.headers {
        head.push_str(&format!("{n}: {}\r\n", v.as_str()));
    }
    head.push_str("\r\n");
    Signed {
        head: head.into_bytes(),
        signature: signed.signature,
        date,
        scope,
    }
}

fn send(raw: &[u8]) -> String {
    let mut c = TcpStream::connect(env().relay).unwrap();
    c.write_all(raw).unwrap();
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn simple(
    method: &str,
    target: &str,
    service: &str,
    akid: &str,
    secret: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let cl = body.len().to_string();
    let mut extra = extra.to_vec();
    if !body.is_empty() {
        extra.push(("Content-Length", &cl));
    }
    let h = sigv4::hex_sha256(body);
    let mut raw = sign_head(method, target, service, akid, secret, &extra, &h).head;
    raw.extend_from_slice(body);
    raw
}

#[test]
fn s3_list_is_resigned_virtual_hosted_and_verified_upstream() {
    let resp = send(&simple(
        "GET",
        "/bucket?list-type=2&prefix=raw-list",
        "s3",
        RO_KEY,
        &dummy_secret(),
        &[],
        b"",
    ));
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.contains("hello.txt"));
    assert!(!resp.contains("must-not-reach-client"), "{resp}");
    let s = seen_for("prefix=raw-list");
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].host, "bucket.s3.us-east-1.amazonaws.com");
    assert_eq!(s[0].target, "/?list-type=2&prefix=raw-list");
    assert_eq!(s[0].problem, "");
    let recs = env().fake.records.lock().unwrap();
    assert!(
        recs.iter()
            .any(|(c, ok, _)| *ok && c == "s3:ListBucket arn:aws:s3:::bucket")
    );
}

#[test]
fn replayed_request_is_rejected() {
    let raw = simple(
        "GET",
        "/bucket?list-type=2&prefix=replay",
        "s3",
        RO_KEY,
        &dummy_secret(),
        &[],
        b"",
    );
    assert!(send(&raw).starts_with("HTTP/1.1 200"));
    let again = send(&raw);
    assert!(again.starts_with("HTTP/1.1 403"), "{again}");
    assert!(again.contains("signature already used"), "{again}");
    assert_eq!(seen_for("prefix=replay").len(), 1);
}

#[test]
fn wrong_secret_outsider_presigned_and_missing_auth_are_rejected() {
    let r = send(&simple(
        "GET",
        "/bucket?list-type=2&prefix=wrong",
        "s3",
        RO_KEY,
        "not-the-dummy-secret",
        &[],
        b"",
    ));
    assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    assert!(r.contains("<Code>SignatureDoesNotMatch</Code>"), "{r}");

    let r = send(&simple(
        "GET",
        "/bucket?list-type=2&prefix=outsider",
        "s3",
        "AKIAOUTSIDER00000000",
        &dummy_secret(),
        &[],
        b"",
    ));
    assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    assert!(r.contains("<Code>InvalidClientTokenId</Code>"), "{r}");

    let r = send(b"GET /bucket/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=a&X-Amz-Signature=b HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(
        r.starts_with("HTTP/1.1 403") && r.contains("presigned"),
        "{r}"
    );
    let r = send(b"GET /bucket/k HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(r.contains("MissingAuthenticationToken"), "{r}");
    for p in ["wrong", "outsider"] {
        assert!(seen_for(&format!("prefix={p}")).is_empty());
    }
}

#[test]
fn policy_denial_names_the_rule_and_sends_nothing() {
    let r = send(&simple(
        "DELETE",
        "/bucket/deny-me",
        "s3",
        RO_KEY,
        &dummy_secret(),
        &[],
        b"",
    ));
    assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    assert!(r.contains("<Code>AccessDenied</Code>"), "{r}");
    assert!(
        r.contains("Locksmith policy: aws_not_allowed:s3:DeleteObject"),
        "{r}"
    );
    assert!(seen_for("deny-me").is_empty());
    let recs = env().fake.records.lock().unwrap();
    assert!(recs.iter().any(|(c, ok, rule)| !*ok
        && c == "s3:DeleteObject arn:aws:s3:::bucket/deny-me"
        && rule == "aws_not_allowed:s3:DeleteObject"));
}

#[test]
fn json_service_denial_is_json() {
    let body = br#"{"TableName":"t","Item":{"k":{"S":"v"}}}"#;
    let r = send(&simple(
        "POST",
        "/",
        "dynamodb",
        RO_KEY,
        &dummy_secret(),
        &[
            ("Content-Type", "application/x-amz-json-1.0"),
            ("X-Amz-Target", "DynamoDB_20120810.PutItem"),
        ],
        body,
    ));
    assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    assert!(
        r.contains(r#""__type":"AccessDenied""#) && r.contains("aws_not_allowed:dynamodb:PutItem"),
        "{r}"
    );
}

#[test]
fn hashed_put_is_checked_and_resigned() {
    let r = send(&simple(
        "PUT",
        "/bucket/hashed.txt",
        "s3",
        RW_KEY,
        &dummy_secret(),
        &[("Content-Type", "text/plain")],
        b"hello",
    ));
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    let s = seen_for("/hashed.txt");
    assert_eq!(s.len(), 1);
    assert_eq!(
        (s[0].host.as_str(), s[0].target.as_str()),
        ("bucket.s3.us-east-1.amazonaws.com", "/hashed.txt")
    );
    assert_eq!(s[0].problem, "");
    assert_eq!(s[0].decoded_len, 5);

    // Signed hash of another body.
    let mut raw = sign_head(
        "PUT",
        "/bucket/mismatch.txt",
        "s3",
        RW_KEY,
        &dummy_secret(),
        &[("Content-Length", "5")],
        &sigv4::hex_sha256(b"other"),
    )
    .head;
    raw.extend_from_slice(b"hello");
    let r = send(&raw);
    assert!(r.starts_with("HTTP/1.1 400"), "{r}");
    assert!(r.contains("XAmzContentSHA256Mismatch"), "{r}");
    assert!(seen_for("mismatch.txt").is_empty());
}

fn streaming_upload(key: &str, chunks: &[Vec<u8>], tamper: bool) -> String {
    let secret = dummy_secret();
    let decoded: usize = chunks.iter().map(Vec::len).sum();
    // Encoded length: each frame is `hex;chunk-signature=<64>\r\n data \r\n`, plus the final one.
    let frame = |n: usize| format!("{n:x}").len() + ";chunk-signature=".len() + 64 + 4 + n;
    let encoded: usize = chunks.iter().map(|c| frame(c.len())).sum::<usize>() + frame(0);
    let (dl, el) = (decoded.to_string(), encoded.to_string());
    let s = sign_head(
        "PUT",
        &format!("/bucket/{key}"),
        "s3",
        RW_KEY,
        &secret,
        &[
            ("Content-Encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", &dl),
            ("Content-Length", &el),
        ],
        sigv4::STREAMING_PAYLOAD,
    );
    let mut signer = ChunkSigner::new(
        sigv4::signing_key(&secret, &s.scope),
        s.scope.clone(),
        s.date.clone(),
        s.signature.clone(),
    );
    let mut raw = s.head;
    for (i, c) in chunks.iter().enumerate() {
        let mut f = signer.encode(c);
        if tamper && i == 1 {
            let last = f.len() - 3;
            f[last] ^= 1;
        }
        raw.extend_from_slice(&f);
    }
    raw.extend_from_slice(&signer.encode(&[]));
    assert_eq!(
        raw.len() - raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() - 4,
        encoded
    );
    send(&raw)
}

#[test]
fn streaming_signed_upload_is_reencoded() {
    let chunks = vec![vec![7u8; 65536], vec![8u8; 65536], b"tail-bytes".to_vec()];
    let r = streaming_upload("stream.bin", &chunks, false);
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    let s = seen_for("/stream.bin");
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].problem, "");
    assert_eq!(s[0].decoded_len, 65536 * 2 + 10);

    let r = streaming_upload("tampered.bin", &chunks, true);
    assert!(r.starts_with("HTTP/1.1 400"), "{r}");
    assert!(r.contains("chunk signature does not match"), "{r}");
}

// ---- AWS CLI ----

fn aws_cli() -> bool {
    let ok = Command::new("aws")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("note: `aws` not installed; skipping the AWS CLI checks");
    }
    ok
}

fn aws(endpoint: &str, akid: &str, secret: &str, args: &[&str]) -> Output {
    Command::new("aws")
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::temp_dir())
        .env("AWS_ACCESS_KEY_ID", akid)
        .env("AWS_SECRET_ACCESS_KEY", secret)
        .env("AWS_ENDPOINT_URL", endpoint)
        .env("AWS_REGION", REGION)
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("AWS_CONFIG_FILE", "/dev/null")
        .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
        .env("AWS_MAX_ATTEMPTS", "1")
        .env("AWS_PAGER", "")
        .output()
        .expect("run aws")
}

fn text(o: &Output) -> String {
    format!(
        "status={:?}\nstdout={}\nstderr={}",
        o.status.code(),
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn aws_cli_through_the_relay() {
    if !aws_cli() {
        return;
    }
    let ep = format!("http://{}", env().relay);
    let ds = dummy_secret();

    let o = aws(&ep, RO_KEY, &ds, &["s3", "ls", "s3://bucket"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("hello.txt"));

    let o = aws(&ep, RO_KEY, &ds, &["s3", "rm", "s3://bucket/x"]);
    assert!(!o.status.success(), "{}", text(&o));
    let t = text(&o);
    assert!(
        t.contains("AccessDenied") && t.contains("aws_not_allowed:s3:DeleteObject"),
        "{t}"
    );

    let o = aws(&ep, RO_KEY, &ds, &["sts", "get-caller-identity"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("123456789012"));

    let o = aws(&ep, RO_KEY, "wrong-secret", &["sts", "get-caller-identity"]);
    assert!(text(&o).contains("SignatureDoesNotMatch"), "{}", text(&o));

    let o = aws(
        &ep,
        "AKIAOUTSIDER00000000",
        &ds,
        &["sts", "get-caller-identity"],
    );
    assert!(text(&o).contains("InvalidClientTokenId"), "{}", text(&o));

    let dir = std::env::temp_dir().join(format!("ls-aws-relay-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("up.txt");
    std::fs::write(&f, b"uploaded through the relay").unwrap();
    let o = aws(
        &ep,
        RW_KEY,
        &ds,
        &["s3", "cp", f.to_str().unwrap(), "s3://bucket/cli-up.txt"],
    );
    assert!(o.status.success(), "{}", text(&o));
    let s = seen_for("/cli-up.txt");
    assert_eq!(s.len(), 1, "{s:?}");
    assert_eq!(s[0].problem, "");
    assert_eq!(s[0].host, "bucket.s3.us-east-1.amazonaws.com");
    let _ = std::fs::remove_dir_all(dir);
}

// ---- Floci (run with `cargo test -p ls-proxy --test aws_relay -- --ignored`) ----

struct Container(String);

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `FLOCI_URL` (e.g. `http://127.0.0.1:4566`), or a fresh `floci/floci` container.
fn floci() -> (SocketAddr, Option<Container>) {
    if let Ok(u) = std::env::var("FLOCI_URL") {
        let a = u.trim_start_matches("http://").trim_end_matches('/');
        return (a.parse().expect("FLOCI_URL host:port"), None);
    }
    let image = std::env::var("FLOCI_IMAGE").unwrap_or("floci/floci:2.5.0".into());
    let port = free_port();
    let o = Command::new("docker")
        .args(["run", "-d", "--rm", "-p"])
        .arg(format!("127.0.0.1:{port}:4566"))
        .arg(&image)
        .output()
        .expect("docker");
    assert!(o.status.success(), "docker run: {}", text(&o));
    let c = Container(String::from_utf8_lossy(&o.stdout).trim().to_string());
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    for _ in 0..120 {
        if let Ok(mut s) = TcpStream::connect(addr) {
            let _ = s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            if out.starts_with("HTTP/1.") {
                return (addr, Some(c));
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    panic!("Floci did not become healthy");
}

#[test]
#[ignore = "needs Docker (Floci) and the AWS CLI"]
fn floci_end_to_end() {
    if !aws_cli() {
        return;
    }
    let (ls, _container) = floci();
    let bucket = "locksmith-relay-e2e";
    let hosts: Vec<String> = ["sts", "s3", "dynamodb", "sqs", "lambda", "ssm"]
        .iter()
        .map(|s| format!("{s}.{REGION}.amazonaws.com"))
        .chain([format!("{bucket}.s3.{REGION}.amazonaws.com")])
        .collect();
    let up = Upstream {
        insecure_http: hosts.into_iter().map(|h| (h, ls)).collect(),
    };
    let fake = Arc::new(Fake {
        open: true,
        upstream_key: "test".into(),
        upstream_secret: "test".into(),
        ..Fake::default()
    });
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let ep = format!("http://{}", l.local_addr().unwrap());
    let auth: Arc<dyn AwsAuthority> = fake.clone();
    std::thread::spawn(move || relay::serve(l, auth, Arc::new(up)));
    let ds = dummy_secret();
    let run = |args: &[&str]| {
        let o = aws(&ep, RW_KEY, &ds, args);
        assert!(o.status.success(), "aws {}: {}", args.join(" "), text(&o));
        eprintln!("ok: aws {}", args.join(" "));
        String::from_utf8_lossy(&o.stdout).into_owned()
    };

    assert!(run(&["sts", "get-caller-identity"]).contains("Account"));

    let dir = std::env::temp_dir().join(format!("ls-aws-ls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let small = dir.join("small.txt");
    std::fs::write(&small, b"hello floci").unwrap();
    let s3 = |k: &str| format!("s3://{bucket}/{k}");
    run(&["s3", "mb", &format!("s3://{bucket}")]);
    run(&["s3", "cp", small.to_str().unwrap(), &s3("small.txt")]);
    assert!(run(&["s3", "ls", &format!("s3://{bucket}")]).contains("small.txt"));
    let back = dir.join("back.txt");
    run(&["s3", "cp", &s3("small.txt"), back.to_str().unwrap()]);
    assert_eq!(std::fs::read(&back).unwrap(), b"hello floci");

    // 200 MB: multipart, streamed through the relay. `--debug` shows the payload mode.
    let big = dir.join("big.bin");
    {
        let mut f = std::fs::File::create(&big).unwrap();
        let block: Vec<u8> = (0..1 << 20).map(|i: u32| (i * 7 % 251) as u8).collect();
        for _ in 0..200 {
            f.write_all(&block).unwrap();
        }
    }
    let o = aws(
        &ep,
        RW_KEY,
        &ds,
        &["s3", "cp", big.to_str().unwrap(), &s3("big.bin"), "--debug"],
    );
    assert!(o.status.success(), "200 MB cp: {}", text(&o));
    let dbg = String::from_utf8_lossy(&o.stderr).to_ascii_lowercase();
    let mut modes: Vec<String> = dbg
        .match_indices("'x-amz-content-sha256': ")
        .map(|(i, m)| {
            let v = dbg[i + m.len()..].trim_start_matches('b');
            let v = &v[1..];
            let v = &v[..v.find('\'').unwrap_or(0)];
            if v.len() == 64 {
                "<hex sha256>".into()
            } else {
                v.to_ascii_uppercase()
            }
        })
        .collect();
    modes.sort();
    modes.dedup();
    eprintln!("ok: aws s3 cp 200 MB; x-amz-content-sha256 modes seen: {modes:?}");
    let ls_out = run(&[
        "s3api",
        "head-object",
        "--bucket",
        bucket,
        "--key",
        "big.bin",
    ]);
    assert!(ls_out.contains("209715200"), "{ls_out}");
    run(&["s3", "rm", &s3("small.txt")]);
    run(&["s3", "rm", &s3("big.bin")]);

    run(&[
        "dynamodb",
        "create-table",
        "--table-name",
        "tbl1",
        "--attribute-definitions",
        "AttributeName=k,AttributeType=S",
        "--key-schema",
        "AttributeName=k,KeyType=HASH",
        "--billing-mode",
        "PAY_PER_REQUEST",
    ]);
    run(&[
        "dynamodb",
        "put-item",
        "--table-name",
        "tbl1",
        "--item",
        r#"{"k":{"S":"a"},"v":{"S":"b"}}"#,
    ]);
    assert!(
        run(&[
            "dynamodb",
            "get-item",
            "--table-name",
            "tbl1",
            "--key",
            r#"{"k":{"S":"a"}}"#
        ])
        .contains("\"b\"")
    );

    let q = run(&[
        "sqs",
        "create-queue",
        "--queue-name",
        "q1",
        "--query",
        "QueueUrl",
        "--output",
        "text",
    ]);
    run(&[
        "sqs",
        "send-message",
        "--queue-url",
        q.trim(),
        "--message-body",
        "hi",
    ]);

    run(&["lambda", "list-functions"]);

    run(&[
        "ssm",
        "put-parameter",
        "--name",
        "/ls/p",
        "--value",
        "v1",
        "--type",
        "String",
        "--overwrite",
    ]);
    assert!(run(&["ssm", "get-parameter", "--name", "/ls/p"]).contains("v1"));

    let recs = fake.records.lock().unwrap();
    let parts = recs
        .iter()
        .filter(|(c, ok, _)| *ok && c == &format!("s3:PutObject arn:aws:s3:::{bucket}/big.bin"))
        .count();
    eprintln!("ok: 200 MB upload went as {parts} PutObject-class calls (multipart)");
    assert!(
        parts >= 25,
        "expected a multipart upload, got {parts} calls"
    );
    for a in [
        "sts:GetCallerIdentity",
        "s3:CreateBucket",
        "s3:PutObject",
        "s3:ListBucket",
        "s3:GetObject",
        "s3:DeleteObject",
        "dynamodb:CreateTable",
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "sqs:CreateQueue",
        "sqs:SendMessage",
        "lambda:ListFunctions",
        "ssm:PutParameter",
        "ssm:GetParameter",
    ] {
        assert!(
            recs.iter()
                .any(|(c, ok, _)| *ok && c.starts_with(&format!("{a} "))),
            "no allowed {a} in {recs:?}"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}
