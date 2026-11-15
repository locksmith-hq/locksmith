//! STS AssumeRole / contained / revoke against a local mock HTTP server.

use ls_proxy::aws::Credentials;
use ls_proxy::aws::sigv4::{self, Request};
use ls_proxy::aws::sts;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::SystemTime;
use zeroize::Zeroizing;

const ROLE: &str = "arn:aws:iam::123456789012:role/team/dev";

// Fake values built at runtime so secret scanners have nothing to match.
fn base(token: bool) -> Credentials {
    Credentials {
        access_key_id: ["LS", "TESTBASEKEY"].concat(),
        secret_access_key: Zeroizing::new("base-secret-".repeat(3)),
        session_token: token.then(|| Zeroizing::new("base-token-".repeat(2))),
    }
}

struct Captured {
    headers: Vec<(String, String)>,
    body: String,
}

/// Serve one request, reply with `status` and `body`, return what was received.
fn mock(status: u16, body: String) -> (String, mpsc::Receiver<Captured>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", l.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        let mut r = BufReader::new(s.try_clone().unwrap());
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        assert!(line.starts_with("POST / "), "{line}");
        let mut headers = Vec::new();
        loop {
            line.clear();
            r.read_line(&mut line).unwrap();
            let l = line.trim_end();
            if l.is_empty() {
                break;
            }
            let (k, v) = l.split_once(':').unwrap();
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
        let len: usize = headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .map(|(_, v)| v.parse().unwrap())
            .unwrap();
        let mut b = vec![0; len];
        r.read_exact(&mut b).unwrap();
        tx.send(Captured {
            headers,
            body: String::from_utf8(b).unwrap(),
        })
        .unwrap();
        let mut s = s;
        write!(
            s,
            "HTTP/1.1 {status} X\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    (url, rx)
}

fn header<'a>(c: &'a Captured, name: &str) -> Option<&'a str> {
    c.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn params(c: &Captured) -> Vec<(String, String)> {
    c.body
        .split('&')
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap();
            (k.to_string(), decode(v))
        })
        .collect()
}

fn param(c: &Captured, k: &str) -> Option<String> {
    params(c).into_iter().find(|(n, _)| n == k).map(|(_, v)| v)
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// The request verifies with SigV4 against `secret` for `service`/`region`.
fn assert_signed(c: &Captured, secret: &str, service: &str, region: &str) {
    let auth = sigv4::parse_authorization(header(c, "authorization").unwrap()).unwrap();
    assert_eq!(auth.scope.service, service);
    assert_eq!(auth.scope.region, region);
    assert!(auth.signed_headers.iter().any(|h| h == "content-type"));
    let req = Request {
        method: "POST".into(),
        path: "/".into(),
        query: String::new(),
        headers: c.headers.clone(),
        payload_hash: sigv4::hex_sha256(c.body.as_bytes()),
    };
    sigv4::verify(&req, &auth, secret, SystemTime::now()).unwrap();
    assert!(sigv4::verify(&req, &auth, "wrong", SystemTime::now()).is_err());
}

fn ok_xml(akid: &str, secret: &str, token: &str) -> String {
    format!(
        "<AssumeRoleResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><AssumeRoleResult>\
<AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/dev/s</Arn></AssumedRoleUser>\
<Credentials><AccessKeyId>{akid}</AccessKeyId><SecretAccessKey>{secret}</SecretAccessKey>\
<SessionToken>{token}</SessionToken><Expiration>2026-11-15T12:15:00.123Z</Expiration></Credentials>\
</AssumeRoleResult></AssumeRoleResponse>"
    )
}

#[test]
fn assume_role_request_and_response() {
    let (akid, secret) = (["LS", "TESTRETKEY"].concat(), "ret-secret/".repeat(3));
    let token = "ret+token=".repeat(4);
    let (url, rx) = mock(200, ok_xml(&akid, &secret, &token.replace('&', "&amp;")));
    let b = base(true);
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}"#;
    let (c, exp) = sts::assume_role(
        &b,
        "eu-west-1",
        ROLE,
        Some("ext-id"),
        "locksmith-lease 7",
        Some(policy),
        3600,
        Some(&url),
    )
    .unwrap();
    assert_eq!(c.access_key_id, akid);
    assert_eq!(c.secret_access_key.as_str(), secret);
    assert_eq!(
        c.session_token.as_deref().map(|t| t.as_str()),
        Some(token.as_str())
    );
    assert_eq!(exp, 1_794_744_900); // 2026-11-15T12:15:00Z

    let r = rx.recv().unwrap();
    assert_eq!(param(&r, "Action").unwrap(), "AssumeRole");
    assert_eq!(param(&r, "Version").unwrap(), "2011-06-15");
    assert_eq!(param(&r, "RoleArn").unwrap(), ROLE);
    assert_eq!(param(&r, "RoleSessionName").unwrap(), "locksmith-lease-7");
    assert_eq!(param(&r, "DurationSeconds").unwrap(), "3600");
    assert_eq!(param(&r, "ExternalId").unwrap(), "ext-id");
    assert_eq!(param(&r, "Policy").unwrap(), policy);
    assert_eq!(
        header(&r, "content-type").unwrap(),
        "application/x-www-form-urlencoded; charset=utf-8"
    );
    assert_eq!(
        header(&r, "x-amz-security-token").unwrap(),
        b.session_token.as_ref().unwrap().as_str()
    );
    assert_signed(&r, &b.secret_access_key, "sts", "eu-west-1");
}

#[test]
fn assume_role_without_token_or_options() {
    let (url, rx) = mock(200, ok_xml("AK", "S", "T"));
    let b = base(false);
    sts::assume_role(&b, "us-east-1", ROLE, None, "ab", None, 900, Some(&url)).unwrap();
    let r = rx.recv().unwrap();
    assert!(header(&r, "x-amz-security-token").is_none());
    assert!(param(&r, "Policy").is_none());
    assert!(param(&r, "ExternalId").is_none());
    assert_signed(&r, &b.secret_access_key, "sts", "us-east-1");
}

#[test]
fn contained_is_15_minutes_with_policy() {
    let (url, rx) = mock(200, ok_xml("AK", "S", "T"));
    let b = base(false);
    sts::contained(
        &b,
        "us-east-1",
        ROLE,
        None,
        "smith",
        Some("{\"p\":1}"),
        Some(&url),
    )
    .unwrap();
    let r = rx.recv().unwrap();
    assert_eq!(param(&r, "DurationSeconds").unwrap(), "900");
    assert_eq!(param(&r, "Policy").unwrap(), "{\"p\":1}");
    assert!(sts::CONTAINED_NOTICE.contains("15 minutes"));
    assert!(sts::CONTAINED_NOTICE.contains("disclosed but contained"));
}

#[test]
fn contained_requires_policy() {
    let b = base(false);
    for p in [None, Some(""), Some("  ")] {
        let e = sts::contained(
            &b,
            "us-east-1",
            ROLE,
            None,
            "smith",
            p,
            Some("http://127.0.0.1:1/"),
        )
        .err()
        .unwrap();
        assert!(e.contains("session policy"), "{e}");
    }
}

#[test]
fn aws_error_maps_code_without_secrets() {
    let xml = "<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code>\
<Message>User is not authorized to perform: sts:AssumeRole</Message></Error></ErrorResponse>";
    let (url, rx) = mock(403, xml.into());
    let b = base(true);
    let e = sts::assume_role(
        &b,
        "us-east-1",
        ROLE,
        Some("ext"),
        "smith",
        Some("{}"),
        900,
        Some(&url),
    )
    .err()
    .unwrap();
    assert!(e.contains("HTTP 403"), "{e}");
    assert!(e.contains("AccessDenied"), "{e}");
    assert!(e.contains("not authorized"), "{e}");
    for s in [
        b.secret_access_key.as_str(),
        b.session_token.as_ref().unwrap().as_str(),
        &b.access_key_id,
        "Action=",
    ] {
        assert!(!e.contains(s), "{e}");
    }
    rx.recv().unwrap();
}

#[test]
fn input_validation() {
    let b = base(false);
    let ep = Some("http://127.0.0.1:1/");
    let call = |region, arn, name, dur| {
        sts::assume_role(&b, region, arn, None, name, None, dur, ep)
            .err()
            .unwrap()
    };
    assert!(call("us-east-1", "arn:aws:iam::123:role/x", "ab", 900).contains("ARN"));
    assert!(call("us-east-1", ROLE, "ab", 899).contains("duration"));
    assert!(call("us-east-1", ROLE, "ab", 43201).contains("duration"));
    assert!(call("us-east-1", ROLE, "a", 900).contains("session name"));
    assert!(call("evil.com/x", ROLE, "ab", 900).contains("region"));
    assert!(sts::revoke_older_sessions(&b, "nope", 0, ep).is_err());
}

#[test]
fn revoke_older_sessions_put_role_policy() {
    let (url, rx) = mock(200, "<PutRolePolicyResponse/>".into());
    let b = base(true);
    sts::revoke_older_sessions(&b, ROLE, 1_794_744_000, Some(&url)).unwrap();
    let r = rx.recv().unwrap();
    assert_eq!(param(&r, "Action").unwrap(), "PutRolePolicy");
    assert_eq!(param(&r, "Version").unwrap(), "2010-05-08");
    assert_eq!(param(&r, "RoleName").unwrap(), "dev");
    assert_eq!(
        param(&r, "PolicyName").unwrap(),
        "LocksmithRevokeOlderSessions"
    );
    let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"2026-11-15T12:00:00Z"}}}]}"#;
    assert_eq!(param(&r, "PolicyDocument").unwrap(), doc);
    assert_eq!(sts::revoke_policy_document(1_794_744_000), doc);
    serde_json::from_str::<serde_json::Value>(doc).unwrap();
    assert_signed(&r, &b.secret_access_key, "iam", "us-east-1");
}

/// `LOCKSTACK_URL=http://localhost:4566 cargo test -p ls-proxy --test aws_sts -- --ignored`
#[test]
#[ignore]
fn localstack_assume_role() {
    let url = std::env::var("LOCKSTACK_URL").expect("LOCKSTACK_URL");
    let b = Credentials {
        access_key_id: "test".into(),
        secret_access_key: Zeroizing::new("test".into()),
        session_token: None,
    };
    let arn = "arn:aws:iam::000000000000:role/locksmith-test";
    let (c, exp) = sts::contained(&b, "us-east-1", arn, None, "smith", Some("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"), Some(&url)).unwrap();
    assert!(!c.access_key_id.is_empty() && c.session_token.is_some());
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        exp > now && exp <= now + 900 + 60,
        "expiry {exp} vs now {now}"
    );
}
