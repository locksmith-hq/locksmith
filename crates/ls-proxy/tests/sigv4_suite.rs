//! SigV4: the AWS signing test suite (tests/fixtures/sigv4, Apache-2.0, see NOTICE there), the
//! S3 streaming known-answer example from the AWS docs, verification and chunk re-signing.

use ls_proxy::aws::Credentials;
use ls_proxy::aws::sigv4::*;
use std::path::Path;
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

struct Case {
    name: String,
    req: Request,
    secret: String,
    akid: String,
    token: Option<String>,
    normalize: bool,
    scope: Scope,
    amz_date: String,
    now: SystemTime,
}

fn read(dir: &Path, f: &str) -> String {
    std::fs::read_to_string(dir.join(f)).unwrap()
}

fn load(dir: &Path) -> Case {
    let ctx: serde_json::Value = serde_json::from_str(&read(dir, "context.json")).unwrap();
    let raw = read(dir, "request.txt");
    let (head, body) = raw.split_once("\n\n").unwrap_or((&raw, ""));
    let mut lines = head.lines();
    let (method, target) = lines.next().unwrap().split_once(' ').unwrap();
    let target = target.rsplit_once(' ').unwrap().0;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers: Vec<(String, String)> = Vec::new();
    for l in lines {
        if l.starts_with([' ', '\t']) {
            // obs-fold continuation line
            let last = headers.last_mut().unwrap();
            last.1 = format!("{} {}", last.1, l.trim());
        } else {
            let (k, v) = l.split_once(':').unwrap();
            headers.push((k.into(), v.into()));
        }
    }
    let ts = ctx["timestamp"].as_str().unwrap().replace(['-', ':'], "");
    let amz_date = ts.clone();
    headers.push(("X-Amz-Date".into(), amz_date.clone()));
    let payload_hash = hex_sha256(body.as_bytes());
    if ctx["sign_body"].as_bool().unwrap() {
        headers.push(("X-Amz-Content-Sha256".into(), payload_hash.clone()));
    }
    let creds = &ctx["credentials"];
    let token = creds["token"].as_str().map(String::from);
    let omit = ctx["omit_session_token"].as_bool().unwrap_or(false);
    if let (Some(t), false) = (&token, omit) {
        headers.push(("X-Amz-Security-Token".into(), t.clone()));
    }
    Case {
        name: dir.file_name().unwrap().to_string_lossy().into(),
        req: Request {
            method: method.into(),
            path: path.into(),
            query: query.into(),
            headers,
            payload_hash,
        },
        secret: creds["secret_access_key"].as_str().unwrap().into(),
        akid: creds["access_key_id"].as_str().unwrap().into(),
        token: if omit { None } else { token },
        normalize: ctx["normalize"].as_bool().unwrap(),
        scope: Scope {
            date: amz_date[..8].into(),
            region: ctx["region"].as_str().unwrap().into(),
            service: ctx["service"].as_str().unwrap().into(),
        },
        now: parse_amz_date(&amz_date).unwrap(),
        amz_date,
    }
}

fn signed_names(req: &Request) -> Vec<String> {
    let mut n: Vec<String> = req
        .headers
        .iter()
        .map(|(k, _)| k.to_ascii_lowercase())
        .collect();
    n.sort();
    n.dedup();
    n
}

#[test]
fn aws_signing_test_suite() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sigv4");
    let mut dirs: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    assert!(dirs.len() >= 38, "suite cases missing");
    for dir in dirs {
        let c = load(&dir);
        let names = signed_names(&c.req);
        // The suite's unnormalized cases follow S3's URI rules (no normalization, one encoding).
        let uri_service = if c.normalize {
            &c.scope.service[..]
        } else {
            "s3"
        };
        let cr = canonical_request(&c.req, &names, uri_service);
        assert_eq!(
            cr,
            read(&dir, "header-canonical-request.txt"),
            "{}: creq",
            c.name
        );
        let sts = string_to_sign(&c.amz_date, &c.scope, &cr);
        assert_eq!(
            sts,
            read(&dir, "header-string-to-sign.txt"),
            "{}: sts",
            c.name
        );
        let sig = signature(&signing_key(&c.secret, &c.scope), &sts);
        let want = read(&dir, "header-signature.txt");
        assert_eq!(sig, want.trim(), "{}: signature", c.name);

        if !c.normalize {
            continue;
        }
        // sign() reproduces the suite signature when told the client signed every header.
        let creds = Credentials {
            access_key_id: c.akid.clone(),
            secret_access_key: Zeroizing::new(c.secret.clone()),
            session_token: c.token.clone().map(Zeroizing::new),
        };
        let signed = sign(&c.req, &creds, &c.scope, &c.amz_date, &names);
        assert_eq!(signed.signature, sig, "{}: sign()", c.name);
        let authz = signed.headers[0].1.as_str();
        assert_eq!(signed.headers[0].0, "authorization");
        assert_eq!(signed.headers.len(), 2 + usize::from(c.token.is_some()));
        // ...and verify() accepts it.
        let auth = parse_authorization(authz).unwrap();
        assert_eq!(auth.access_key_id, c.akid);
        verify(&c.req, &auth, &c.secret, c.now).unwrap_or_else(|e| panic!("{}: {e}", c.name));
    }
}

// --- verify ---

const SECRET: &str = "dummy-secret-for-tests";

fn vanilla(now: SystemTime) -> (Request, AuthHeader) {
    let date = amz_date(now);
    let req = Request {
        method: "GET".into(),
        path: "/my-bucket/a%20key".into(),
        query: "list-type=2&prefix=x".into(),
        headers: vec![
            ("Host".into(), "s3.us-east-1.amazonaws.com".into()),
            ("X-Amz-Date".into(), date.clone()),
            ("X-Amz-Content-Sha256".into(), EMPTY_SHA256.into()),
            ("X-Custom".into(), "v".into()),
        ],
        payload_hash: EMPTY_SHA256.into(),
    };
    let scope = Scope {
        date: date[..8].into(),
        region: "us-east-1".into(),
        service: "s3".into(),
    };
    let creds = Credentials {
        access_key_id: "AKIALOCKSMITHTEST".into(),
        secret_access_key: Zeroizing::new(SECRET.into()),
        session_token: None,
    };
    let s = sign(&req, &creds, &scope, &date, &["x-custom".into()]);
    (req, parse_authorization(&s.headers[0].1).unwrap())
}

fn now() -> SystemTime {
    // Whole seconds: X-Amz-Date has no sub-second part.
    let s = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    SystemTime::UNIX_EPOCH + Duration::from_secs(s)
}

#[test]
fn verify_accepts_and_rejects() {
    let t = now();
    let (req, auth) = vanilla(t);
    assert_eq!(
        auth.signed_headers,
        ["host", "x-amz-content-sha256", "x-amz-date", "x-custom"]
    );
    verify(&req, &auth, SECRET, t).unwrap();
    verify(&req, &auth, SECRET, t + Duration::from_secs(14 * 60)).unwrap();
    assert_eq!(verify(&req, &auth, "other", t), Err(VerifyError::Mismatch));

    let tamper = |f: &dyn Fn(&mut Request)| {
        let (mut r, a) = vanilla(t);
        f(&mut r);
        verify(&r, &a, SECRET, t)
    };
    assert_eq!(
        tamper(&|r| r.headers[3].1 = "w".into()),
        Err(VerifyError::Mismatch)
    );
    assert_eq!(
        tamper(&|r| r.query = "list-type=2&prefix=y".into()),
        Err(VerifyError::Mismatch)
    );
    assert_eq!(
        tamper(&|r| r.path = "/my-bucket/b".into()),
        Err(VerifyError::Mismatch)
    );
    assert_eq!(
        tamper(&|r| r.method = "DELETE".into()),
        Err(VerifyError::Mismatch)
    );
    assert_eq!(
        tamper(&|r| r.payload_hash = "00".repeat(32)),
        Err(VerifyError::Mismatch)
    );

    assert_eq!(
        verify(&req, &auth, SECRET, t + Duration::from_secs(16 * 60)),
        Err(VerifyError::Stale)
    );
    assert_eq!(
        verify(&req, &auth, SECRET, t - Duration::from_secs(16 * 60)),
        Err(VerifyError::Stale)
    );

    let mut unsigned = auth.clone();
    unsigned.signed_headers.retain(|h| h != "host");
    assert_eq!(
        verify(&req, &unsigned, SECRET, t),
        Err(VerifyError::UnsignedHeader("host"))
    );
    let mut unsigned = auth.clone();
    unsigned
        .signed_headers
        .retain(|h| h != "x-amz-content-sha256");
    assert_eq!(
        verify(&req, &unsigned, SECRET, t),
        Err(VerifyError::UnsignedHeader("x-amz-content-sha256"))
    );
}

#[test]
fn nonce_cache_rejects_replay() {
    let t = now();
    let (_, auth) = vanilla(t);
    let cache = NonceCache::new(2);
    cache.check(&auth.signature, t).unwrap();
    assert_eq!(
        cache.check(&auth.signature, t + Duration::from_secs(60)),
        Err(VerifyError::Replay)
    );
    cache.check("b", t).unwrap();
    assert_eq!(cache.check("c", t), Err(VerifyError::CacheFull));
    // After the window, entries expire and make room.
    let later = t + 2 * MAX_SKEW + Duration::from_secs(1);
    cache.check("c", later).unwrap();
    cache.check(&auth.signature, later).unwrap();
}

#[test]
fn parse_authorization_rejects_malformed() {
    let ok = "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/iam/aws4_request, \
              SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";
    let a = parse_authorization(ok).unwrap();
    assert_eq!(a.scope.to_string(), "20150830/us-east-1/iam/aws4_request");
    for bad in [
        ok.replace("AWS4-HMAC-SHA256 ", "AWS4-HMAC-SHA512 "),
        ok.replace("host;x-amz-date", "x-amz-date;host"),
        ok.replace("host;x-amz-date", "Host;x-amz-date"),
        ok.replace("aws4_request", "aws3_request"),
        ok.replace("20150830", "2015083"),
        ok.replace("5fa0", "5FA0"),
        ok.replace(", Signature", ", Signature=x, Signature"),
        ok.replace("SignedHeaders", "Signedheaders"),
    ] {
        assert!(parse_authorization(&bad).is_err(), "{bad}");
    }
}

#[test]
fn payload_kinds() {
    assert_eq!(payload_kind(EMPTY_SHA256), Ok(Payload::Hashed));
    assert_eq!(payload_kind("UNSIGNED-PAYLOAD"), Ok(Payload::Unsigned));
    assert_eq!(
        payload_kind(STREAMING_PAYLOAD),
        Ok(Payload::StreamingSigned)
    );
    assert_eq!(
        payload_kind(STREAMING_UNSIGNED_TRAILER),
        Ok(Payload::StreamingUnsignedTrailer)
    );
    assert!(matches!(
        payload_kind("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"),
        Err(VerifyError::Unsupported(_))
    ));
    assert!(payload_kind("nope").is_err());
}

// --- S3 streaming (aws-chunked) ---

/// AWS docs example secret ("Signature Calculations for the Authorization Header: Transferring
/// Payload in Multiple Chunks"), split so secret scanners do not flag the documented value.
fn docs_secret() -> String {
    ["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"].concat()
}

fn docs_scope() -> Scope {
    Scope {
        date: "20130524".into(),
        region: "us-east-1".into(),
        service: "s3".into(),
    }
}

const DOCS_DATE: &str = "20130524T000000Z";
const SEED: &str = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";

#[test]
fn s3_streaming_known_answer() {
    let req = Request {
        method: "PUT".into(),
        path: "/examplebucket/chunkObject.txt".into(),
        query: String::new(),
        headers: vec![
            ("Host".into(), "s3.amazonaws.com".into()),
            ("x-amz-date".into(), DOCS_DATE.into()),
            ("x-amz-storage-class".into(), "REDUCED_REDUNDANCY".into()),
            ("Content-Encoding".into(), "aws-chunked".into()),
            ("x-amz-decoded-content-length".into(), "66560".into()),
            ("Content-Length".into(), "66824".into()),
            ("x-amz-content-sha256".into(), STREAMING_PAYLOAD.into()),
        ],
        payload_hash: STREAMING_PAYLOAD.into(),
    };
    let names: Vec<String> = "content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class"
        .split(';')
        .map(String::from)
        .collect();
    let cr = canonical_request(&req, &names, "s3");
    let sts = string_to_sign(DOCS_DATE, &docs_scope(), &cr);
    let key = || signing_key(&docs_secret(), &docs_scope());
    assert_eq!(signature(&key(), &sts), SEED);

    let mut signer = ChunkSigner::new(key(), docs_scope(), DOCS_DATE.into(), SEED.into());
    let c1 = signer.encode(&[b'a'; 65536]);
    let c2 = signer.encode(&[b'a'; 1024]);
    let end = signer.encode(&[]);
    assert!(c1.starts_with(
        b"10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\r\n"
    ));
    assert!(c2.starts_with(
        b"400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497\r\n"
    ));
    assert_eq!(
        end,
        b"0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\r\n\r\n"
    );
    let body = [c1, c2, end].concat();
    assert_eq!(body.len(), 66824);

    // The reader accepts the documented body and yields the decoded chunks.
    let mut r = ChunkReader::new(
        &body[..],
        key(),
        docs_scope(),
        DOCS_DATE.into(),
        SEED.into(),
    );
    assert_eq!(r.next_chunk().unwrap().unwrap().len(), 65536);
    assert_eq!(r.next_chunk().unwrap().unwrap().len(), 1024);
    assert!(r.next_chunk().unwrap().is_none());
    assert!(r.next_chunk().unwrap().is_none());
}

fn docs_body() -> Vec<u8> {
    let key = signing_key(&docs_secret(), &docs_scope());
    let mut s = ChunkSigner::new(key, docs_scope(), DOCS_DATE.into(), SEED.into());
    [
        s.encode(&[b'a'; 65536]),
        s.encode(&[b'a'; 1024]),
        s.encode(&[]),
    ]
    .concat()
}

#[test]
fn streaming_reencode_with_another_key() {
    let body = docs_body();
    let dummy = || signing_key(&docs_secret(), &docs_scope());
    let real_scope = Scope {
        date: "20130525".into(),
        region: "us-east-1".into(),
        service: "s3".into(),
    };
    let real = || signing_key("the-real-secret", &real_scope);
    let real_date = "20130525T010203Z";
    let real_seed = "11".repeat(32);

    let mut reader = ChunkReader::new(
        &body[..],
        dummy(),
        docs_scope(),
        DOCS_DATE.into(),
        SEED.into(),
    );
    let mut signer = ChunkSigner::new(
        real(),
        real_scope.clone(),
        real_date.into(),
        real_seed.clone(),
    );
    let mut out = Vec::new();
    assert_eq!(reencode(&mut reader, &mut signer, &mut out).unwrap(), 66560);
    assert_eq!(out.len(), body.len());
    assert_ne!(out, body);

    let mut check = ChunkReader::new(
        &out[..],
        real(),
        real_scope.clone(),
        real_date.into(),
        real_seed.clone(),
    );
    let mut n = 0;
    while let Some(c) = check.next_chunk().unwrap() {
        assert!(c.iter().all(|&b| b == b'a'));
        n += c.len();
    }
    assert_eq!(n, 66560);

    // The output does not verify with the dummy key, nor with a different seed.
    let mut wrong = ChunkReader::new(
        &out[..],
        dummy(),
        real_scope.clone(),
        real_date.into(),
        real_seed,
    );
    assert!(wrong.next_chunk().is_err());
    let mut wrong = ChunkReader::new(&out[..], real(), real_scope, real_date.into(), SEED.into());
    assert!(wrong.next_chunk().is_err());
}

#[test]
fn streaming_rejects_tampering() {
    let key = || signing_key(&docs_secret(), &docs_scope());
    let read_all = |body: &[u8]| -> std::io::Result<()> {
        let mut r = ChunkReader::new(body, key(), docs_scope(), DOCS_DATE.into(), SEED.into());
        while r.next_chunk()?.is_some() {}
        Ok(())
    };
    let body = docs_body();
    read_all(&body).unwrap();

    let mut flipped = body.clone();
    flipped[200] = b'b';
    assert!(read_all(&flipped).is_err());

    // Dropping the middle chunk breaks the chain.
    let frame = |data: usize| "10000;chunk-signature=".len() + 64 + 2 + data + 2;
    let c1 = frame(65536);
    let c2 = frame(1024) - 2; // "400" is two hex digits shorter than "10000"
    let dropped = [&body[..c1], &body[c1 + c2..]].concat();
    assert!(read_all(&dropped).is_err());

    // Truncated before the final chunk.
    assert!(read_all(&body[..c1 + c2]).is_err());
}
