//! M7 AWS: the SigV4 re-signing relay (tasks 1.2, 1.4; design D1, D2, D4).
//!
//! Agents point `AWS_ENDPOINT_URL` at `http://127.0.0.1:<port>` and sign with session dummy
//! credentials. Per request: the daemon resolves the dummy key ([`AwsAuthority::session`]), the
//! signature is verified with the dummy secret (plus a process-wide replay cache), the call is
//! mapped to an IAM action and checked against the session policy (and audited), and the request
//! is re-signed with the real credentials and sent to the AWS endpoint over TLS. S3 `aws-chunked`
//! uploads are verified and re-signed chunk by chunk. Responses are copied verbatim (minus any
//! `x-amz-security-token`). Synchronous, one thread and one request per connection. Nothing here
//! logs, and no error message carries a secret.

use super::sigv4::{self, ChunkReader, ChunkSigner, Payload, Request, Scope, VerifyError};
use super::{AwsAuthority, model};
use crate::forward::{Framer, Io, connect_to, read_head, reason};
use crate::http::{Upstream, is_hop};
use std::io::{self, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

const IO_TIMEOUT: Duration = Duration::from_secs(300);
/// Largest body buffered to hash it (hashed payloads only; streaming modes pass through).
const MAX_BODY: u64 = 64 << 20;
const MAX_RESP_HEAD: usize = 64 * 1024;
const NONCE_CAPACITY: usize = 100_000;

fn nonces() -> &'static sigv4::NonceCache {
    static N: OnceLock<sigv4::NonceCache> = OnceLock::new();
    N.get_or_init(|| sigv4::NonceCache::new(NONCE_CAPACITY))
}

/// Accept connections forever, one thread each. Plain HTTP on loopback; upstream is TLS to
/// AWS (or plain TCP for hosts in `up.insecure_http`, tests only).
pub fn serve(listener: TcpListener, auth: Arc<dyn AwsAuthority>, up: Arc<crate::http::Upstream>) {
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let (auth, up) = (auth.clone(), up.clone());
        std::thread::spawn(move || {
            let _ = handle(conn, &*auth, &up);
        });
    }
}

/// An AWS-style refusal. `status == 0` means the connection is gone or a response was already
/// started: nothing more to send.
#[derive(Debug)]
struct Fail {
    status: u16,
    code: &'static str,
    msg: String,
}

fn fail(status: u16, code: &'static str, msg: impl Into<String>) -> Fail {
    Fail {
        status,
        code,
        msg: msg.into(),
    }
}

impl From<io::Error> for Fail {
    fn from(_: io::Error) -> Self {
        fail(0, "", "")
    }
}

/// Error body format, by the service's protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proto {
    /// `json` / `rest-json`: `{"__type":…,"message":…}`.
    Json,
    /// `rest-xml` (S3) and unknown: `<Error>…</Error>`.
    RestXml,
    /// `query` / `ec2`: `<ErrorResponse><Error>…</Error></ErrorResponse>`.
    Query,
}

fn proto(service: Option<&str>, content_type: &str) -> Proto {
    match service {
        _ if content_type.contains("json") => Proto::Json,
        Some(s) if model::json_protocol(s) => Proto::Json,
        None | Some("s3") => Proto::RestXml,
        Some(_) => Proto::Query,
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The full HTTP response for `f` (no body for `HEAD`).
fn error_response(p: Proto, f: &Fail, head_only: bool) -> Vec<u8> {
    let (ctype, body) = match p {
        Proto::Json => (
            "application/x-amz-json-1.1",
            serde_json::json!({"__type": f.code, "message": f.msg}).to_string(),
        ),
        Proto::RestXml => (
            "application/xml",
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{}</Code><Message>{}</Message><RequestId>locksmith</RequestId></Error>",
                f.code,
                xml_escape(&f.msg)
            ),
        ),
        Proto::Query => (
            "text/xml",
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ErrorResponse><Error><Type>Sender</Type><Code>{}</Code><Message>{}</Message></Error><RequestId>locksmith</RequestId></ErrorResponse>",
                f.code,
                xml_escape(&f.msg)
            ),
        ),
    };
    let mut out = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nx-amzn-ErrorType: {}\r\nConnection: close\r\n\r\n",
        f.status,
        reason(f.status),
        body.len(),
        f.code
    );
    if !head_only {
        out.push_str(&body);
    }
    out.into_bytes()
}

fn verify_fail(e: VerifyError) -> Fail {
    let msg = e.to_string();
    match e {
        VerifyError::Mismatch => fail(403, "SignatureDoesNotMatch", msg),
        VerifyError::Stale => fail(403, "RequestExpired", msg),
        VerifyError::Replay => fail(403, "AccessDenied", format!("Locksmith relay: {msg}")),
        VerifyError::CacheFull => fail(503, "SlowDown", msg),
        VerifyError::Unsupported(_) => fail(
            501,
            "NotImplemented",
            format!(
                "Locksmith relay: {msg}. For this client, use `smith aws creds --contained -- <command>`."
            ),
        ),
        VerifyError::Malformed(_) | VerifyError::UnsignedHeader(_) => {
            fail(400, "IncompleteSignature", msg)
        }
    }
}

struct Ctx<'a> {
    auth: &'a dyn AwsAuthority,
    up: &'a Upstream,
    client: SocketAddr,
    server: SocketAddr,
}

fn handle(mut c: TcpStream, auth: &dyn AwsAuthority, up: &Upstream) -> io::Result<()> {
    c.set_read_timeout(Some(IO_TIMEOUT))?;
    c.set_write_timeout(Some(IO_TIMEOUT))?;
    let ctx = Ctx {
        auth,
        up,
        client: c.peer_addr()?,
        server: c.local_addr()?,
    };
    let (head, pending) = match read_head(&mut c)? {
        Ok(x) => x,
        Err(code) => {
            let f = fail(code, "InvalidRequest", "malformed HTTP request head");
            c.write_all(&error_response(Proto::RestXml, &f, false))?;
            return drain(&mut c);
        }
    };
    let head_only = head.method == "HEAD";
    let mut p = Proto::RestXml;
    match relay(&mut c, &head, &pending, &ctx, &mut p) {
        Ok(()) => Ok(()),
        Err(f) if f.status == 0 => Ok(()),
        Err(f) => {
            c.write_all(&error_response(p, &f, head_only))?;
            c.flush()?;
            drain(&mut c)
        }
    }
}

/// After an early refusal, let the client finish sending so it reads the response instead of a
/// reset.
fn drain(c: &mut TcpStream) -> io::Result<()> {
    let _ = c.shutdown(Shutdown::Write);
    c.set_read_timeout(Some(Duration::from_secs(2)))?;
    let _ = io::copy(&mut c.take(MAX_BODY), &mut io::sink());
    Ok(())
}

/// Canonical value of header `name` (trimmed, repeats comma-joined), as SigV4 sees it.
fn header(h: &[(String, String)], name: &str) -> Option<String> {
    let v: Vec<&str> = h
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
        .collect();
    (!v.is_empty()).then(|| v.join(","))
}

fn relay(
    c: &mut TcpStream,
    head: &crate::forward::Head,
    pending: &[u8],
    ctx: &Ctx<'_>,
    p: &mut Proto,
) -> Result<(), Fail> {
    let headers: Vec<(String, String)> = head
        .headers
        .iter()
        .map(|(n, v)| Some((n.clone(), String::from_utf8(v.clone()).ok()?)))
        .collect::<Option<_>>()
        .ok_or_else(|| fail(400, "InvalidRequest", "non-UTF-8 header value"))?;
    let ctype = header(&headers, "content-type")
        .unwrap_or_default()
        .to_ascii_lowercase();
    *p = proto(None, &ctype);
    if !head.path.starts_with('/') {
        return Err(fail(400, "InvalidRequest", "request target must be a path"));
    }
    let (path, query) = head.path.split_once('?').unwrap_or((&head.path, ""));
    let presigned = query.split('&').any(|kv| {
        let k = kv.split('=').next().unwrap_or("").to_ascii_lowercase();
        k == "x-amz-signature" || k == "x-amz-credential"
    });
    if presigned {
        return Err(fail(
            403,
            "AccessDenied",
            "Locksmith relay: presigned URLs (query-string authentication) are not supported; sign with the Authorization header",
        ));
    }
    let auth_value = match head.count("authorization") {
        1 => header(&headers, "authorization").unwrap_or_default(),
        _ => {
            return Err(fail(
                403,
                "MissingAuthenticationToken",
                "Locksmith relay: requests must carry exactly one SigV4 Authorization header",
            ));
        }
    };
    let auth_h =
        sigv4::parse_authorization(&auth_value).map_err(|e| fail(400, "IncompleteSignature", e))?;
    let scope = auth_h.scope.clone();
    *p = proto(Some(&scope.service), &ctype);

    // 1. Who is this (the daemon checks the peer process and the lease).
    let session = ctx
        .auth
        .session(&auth_h.access_key_id, ctx.client, ctx.server)
        .map_err(|d| {
            let code = if d.status >= 500 {
                "InternalFailure"
            } else {
                "InvalidClientTokenId"
            };
            fail(d.status, code, d.message)
        })?;

    // 2. Payload mode and, for hashed payloads, the body.
    let sha = header(&headers, "x-amz-content-sha256");
    let kind = match &sha {
        None => Payload::Hashed,
        Some(v) => sigv4::payload_kind(v).map_err(verify_fail)?,
    };
    let chunked = header(&headers, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let len: u64 = match head.count("content-length") {
        0 => 0,
        1 => header(&headers, "content-length")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| fail(400, "InvalidRequest", "bad Content-Length"))?,
        _ => return Err(fail(400, "InvalidRequest", "repeated Content-Length")),
    };
    let has_body = chunked || len > 0;
    let expect = header(&headers, "expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue"));
    let mut body = Vec::new();
    let payload_hash = match kind {
        Payload::Hashed => {
            if len > MAX_BODY {
                return Err(too_large());
            }
            if expect && has_body {
                continue_100(c)?;
            }
            body = read_body(c, pending, chunked, len)?;
            let h = sigv4::hex_sha256(&body);
            match sha {
                Some(v) if !v.eq_ignore_ascii_case(&h) => {
                    return Err(fail(
                        400,
                        "XAmzContentSHA256Mismatch",
                        "The provided 'x-amz-content-sha256' header does not match what was computed.",
                    ));
                }
                Some(v) => v,
                None => h,
            }
        }
        Payload::StreamingSigned if chunked => {
            // shortcut: aws-chunked inside Transfer-Encoding: chunked is not de-framed; no SDK
            // seen sends it (they set Content-Length). Add if one does.
            return Err(fail(
                501,
                "NotImplemented",
                "Locksmith relay: aws-chunked uploads with Transfer-Encoding: chunked are not supported",
            ));
        }
        _ => sha.unwrap_or_default(),
    };

    // 3. Signature with the dummy secret, then replay.
    let req = Request {
        method: head.method.clone(),
        path: path.to_owned(),
        query: query.to_owned(),
        headers,
        payload_hash,
    };
    let now = SystemTime::now();
    sigv4::verify(&req, &auth_h, &session.dummy_secret, now).map_err(verify_fail)?;
    nonces()
        .check(&auth_h.signature, now)
        .map_err(verify_fail)?;

    // 4. Policy (audited either way).
    let call = model::resolve(
        &scope.service,
        &scope.region,
        &req.method,
        path,
        query,
        &req.headers,
        &body,
    );
    let decision = session.policy.decide(&call);
    let rule = decision
        .as_ref()
        .err()
        .map_or("aws_allowed", String::as_str);
    ctx.auth.record(&session, &call, decision.is_ok(), rule);
    if let Err(rule) = decision {
        return Err(fail(
            403,
            "AccessDenied",
            format!("Locksmith policy: {rule}"),
        ));
    }

    // 5. Re-sign for the real endpoint and forward.
    let inbound_host = header(&req.headers, "host");
    let (host, up_path) =
        upstream_target(&scope.service, &scope.region, path, inbound_host.as_deref()).ok_or_else(
            || {
                fail(
                    400,
                    "InvalidRequest",
                    format!(
                        "Locksmith relay: no AWS endpoint for service {} in region {}",
                        scope.service, scope.region
                    ),
                )
            },
        )?;
    let hashed_len =
        (kind == Payload::Hashed && (has_body || !body.is_empty())).then_some(body.len());
    let up_req = Request {
        method: req.method.clone(),
        path: up_path,
        query: req.query.clone(),
        headers: forward_headers(&req.headers, &host, hashed_len),
        payload_hash: req.payload_hash.clone(),
    };
    let date = sigv4::amz_date(SystemTime::now());
    let up_scope = Scope {
        date: date[..8].to_owned(),
        ..scope.clone()
    };
    let signed = sigv4::sign(
        &up_req,
        &session.upstream,
        &up_scope,
        &date,
        &auth_h.signed_headers,
    );
    let mut out = Zeroizing::new(Vec::with_capacity(2048));
    out.extend_from_slice(format!("{} {}", up_req.method, up_req.path).as_bytes());
    if !up_req.query.is_empty() {
        out.push(b'?');
        out.extend_from_slice(up_req.query.as_bytes());
    }
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for (n, v) in &up_req.headers {
        out.extend_from_slice(format!("{n}: {v}\r\n").as_bytes());
    }
    for (n, v) in &signed.headers {
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");

    let upstream_err = || {
        fail(
            502,
            "ServiceUnavailable",
            "Locksmith relay: AWS endpoint unavailable",
        )
    };
    let mut upstream = connect_to(&host, ctx.up.plain(&host)).map_err(|_| upstream_err())?;
    upstream.write_all(&out).map_err(|_| upstream_err())?;
    drop(out);
    match kind {
        Payload::Hashed => upstream.write_all(&body).map_err(|_| upstream_err())?,
        Payload::Unsigned | Payload::StreamingUnsignedTrailer => {
            if expect && has_body {
                continue_100(c)?;
            }
            pass_body(c, pending, chunked, len, &mut *upstream)?;
        }
        Payload::StreamingSigned => {
            let decoded: u64 = header(&req.headers, "x-amz-decoded-content-length")
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| {
                    fail(
                        400,
                        "MissingContentLength",
                        "missing x-amz-decoded-content-length",
                    )
                })?;
            if expect {
                continue_100(c)?;
            }
            let in_date = req.header("x-amz-date").unwrap_or_default();
            let src = BufReader::new(pending.chain(&mut *c).take(len));
            let mut reader = ChunkReader::new(
                src,
                sigv4::signing_key(&session.dummy_secret, &scope),
                scope.clone(),
                in_date,
                auth_h.signature.clone(),
            );
            let mut signer = ChunkSigner::new(
                sigv4::signing_key(&session.upstream.secret_access_key, &up_scope),
                up_scope.clone(),
                date.clone(),
                signed.signature.clone(),
            );
            let mut counted = Counted {
                inner: &mut *upstream,
                n: 0,
            };
            let n = sigv4::reencode(&mut reader, &mut signer, &mut counted)
                .map_err(|e| fail(400, "IncompleteBody", e.to_string()))?;
            if n != decoded {
                return Err(fail(
                    400,
                    "IncompleteBody",
                    "decoded body length differs from x-amz-decoded-content-length",
                ));
            }
            if counted.n != len {
                return Err(fail(
                    400,
                    "InvalidRequest",
                    "aws-chunked framing must be canonical (lowercase hex sizes, no padding)",
                ));
            }
        }
    }
    upstream.flush().map_err(|_| upstream_err())?;
    drop(session);

    let Ok(Some((resp, rest))) = read_response_head(&mut *upstream) else {
        return Err(upstream_err());
    };
    c.write_all(&resp)?;
    c.write_all(&rest)?;
    let _ = io::copy(&mut *upstream, c);
    c.flush()?;
    Ok(())
}

fn too_large() -> Fail {
    fail(
        413,
        "EntityTooLarge",
        "Locksmith relay: signed (hashed) payloads are limited to 64 MiB; use multipart or streaming uploads",
    )
}

fn continue_100(c: &mut TcpStream) -> io::Result<()> {
    c.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
    c.flush()
}

/// Read the whole request body (de-chunked), at most [`MAX_BODY`].
fn read_body(c: &mut TcpStream, pending: &[u8], chunked: bool, len: u64) -> Result<Vec<u8>, Fail> {
    let mut f = Framer::new(chunked, len, true);
    let bad = || fail(400, "IncompleteBody", "malformed request body");
    f.feed(pending).map_err(|_| bad())?;
    let mut tmp = [0u8; 16384];
    while !f.done() {
        if f.decoded.len() as u64 > MAX_BODY {
            return Err(too_large());
        }
        let n = c.read(&mut tmp)?;
        if n == 0 {
            return Err(bad());
        }
        f.feed(&tmp[..n]).map_err(|_| bad())?;
    }
    if f.decoded.len() as u64 > MAX_BODY {
        return Err(too_large());
    }
    Ok(f.decoded)
}

/// Copy the request body to `up` as framed on the wire (Content-Length or chunked).
fn pass_body(
    c: &mut TcpStream,
    pending: &[u8],
    chunked: bool,
    len: u64,
    up: &mut dyn Io,
) -> Result<(), Fail> {
    let mut f = Framer::new(chunked, len, false);
    let bad = || fail(400, "IncompleteBody", "malformed request body");
    let used = f.feed(pending).map_err(|_| bad())?;
    up.write_all(&pending[..used])?;
    let mut tmp = [0u8; 65536];
    while !f.done() {
        let n = c.read(&mut tmp)?;
        if n == 0 {
            return Err(fail(0, "", ""));
        }
        let used = f.feed(&tmp[..n]).map_err(|_| bad())?;
        up.write_all(&tmp[..used])?;
    }
    Ok(())
}

struct Counted<'a> {
    inner: &'a mut dyn Io,
    n: u64,
}

impl Write for Counted<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(b)?;
        self.n += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Upstream host and path. Non-S3: the service endpoint, path unchanged. S3: the bucket comes
/// from a virtual-hosted inbound host (`bucket.localhost`) or else the first path segment (SDKs
/// use path-style against `127.0.0.1`); the request goes virtual-hosted when the endpoint host
/// carries the bucket (bucket segment stripped from the path), else path-style.
fn upstream_target(
    service: &str,
    region: &str,
    path: &str,
    inbound_host: Option<&str>,
) -> Option<(String, String)> {
    if service != "s3" {
        return Some((
            model::endpoint_host(service, region, None)?,
            path.to_owned(),
        ));
    }
    let (bucket, rest, path_style) = match inbound_host.and_then(model::s3_bucket_from_host) {
        Some(b) => (Some(b), path.to_owned(), format!("/{b}{path}")),
        None => {
            let p = path.strip_prefix('/').unwrap_or(path);
            let (b, r) = p
                .split_once('/')
                .map_or((p, "/".to_owned()), |(b, r)| (b, format!("/{r}")));
            ((!b.is_empty()).then_some(b), r, path.to_owned())
        }
    };
    let host = model::endpoint_host("s3", region, bucket)?;
    let virtual_hosted = bucket.is_some_and(|b| host.starts_with(&format!("{b}.")));
    Some((host, if virtual_hosted { rest } else { path_style }))
}

/// Headers to forward (before [`sigv4::sign`] adds its own): the upstream `Host` first; drops
/// hop-by-hop headers (and those named in `Connection`), `Expect`, and the inbound
/// `Authorization`, `X-Amz-Date` and `X-Amz-Security-Token`. With `hashed_len` (a buffered
/// body) the framing becomes `Content-Length: <hashed_len>`.
fn forward_headers(
    headers: &[(String, String)],
    host: &str,
    hashed_len: Option<usize>,
) -> Vec<(String, String)> {
    let named: Vec<String> = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(',').map(|s| s.trim().to_ascii_lowercase()))
        .collect();
    let mut out = vec![("Host".to_owned(), host.to_owned())];
    out.extend(
        headers
            .iter()
            .filter(|(n, _)| {
                let l = n.to_ascii_lowercase();
                !(is_hop(&l)
                    || named.contains(&l)
                    || matches!(
                        l.as_str(),
                        "host" | "expect" | "authorization" | "x-amz-date" | "x-amz-security-token"
                    )
                    || (hashed_len.is_some()
                        && matches!(l.as_str(), "content-length" | "transfer-encoding")))
            })
            .cloned(),
    );
    if let Some(n) = hashed_len {
        out.push(("Content-Length".to_owned(), n.to_string()));
    }
    out
}

/// The upstream status line and headers, re-emitted with `Connection: close` and without any
/// `x-amz-security-token`; plus body bytes already read.
fn read_response_head(up: &mut dyn Io) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let mut hs = [httparse::EMPTY_HEADER; 128];
        let mut resp = httparse::Response::new(&mut hs);
        match resp.parse(&buf) {
            Ok(httparse::Status::Complete(n)) => {
                let code = resp.code.unwrap_or(502);
                if code < 200 {
                    buf.drain(..n);
                    continue;
                }
                return Ok(Some((response_head(&resp), buf[n..].to_vec())));
            }
            Ok(httparse::Status::Partial) => {}
            Err(_) => return Ok(None),
        }
        if buf.len() >= MAX_RESP_HEAD {
            return Ok(None);
        }
        let n = up.read(&mut tmp)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn response_head(resp: &httparse::Response<'_, '_>) -> Vec<u8> {
    let code = resp.code.unwrap_or(502);
    let mut out = format!("HTTP/1.1 {code} {}\r\n", resp.reason.unwrap_or("")).into_bytes();
    for h in resp.headers.iter() {
        let l = h.name.to_ascii_lowercase();
        if matches!(
            l.as_str(),
            "connection" | "keep-alive" | "x-amz-security-token"
        ) {
            continue;
        }
        out.extend_from_slice(h.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(h.value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn s3_path_style_becomes_virtual_hosted() {
        let t = |path, host| upstream_target("s3", "us-east-1", path, host).unwrap();
        let local = Some("127.0.0.1:4566");
        assert_eq!(
            t("/bucket/a/b.txt", local),
            (
                "bucket.s3.us-east-1.amazonaws.com".into(),
                "/a/b.txt".into()
            )
        );
        assert_eq!(
            t("/bucket", local),
            ("bucket.s3.us-east-1.amazonaws.com".into(), "/".into())
        );
        assert_eq!(
            t("/bucket/", local),
            ("bucket.s3.us-east-1.amazonaws.com".into(), "/".into())
        );
        // ListBuckets: no bucket.
        assert_eq!(
            t("/", local),
            ("s3.us-east-1.amazonaws.com".into(), "/".into())
        );
        // Not DNS-compatible: stays path-style, path untouched.
        assert_eq!(
            t("/my.dotted.bucket/k", local),
            (
                "s3.us-east-1.amazonaws.com".into(),
                "/my.dotted.bucket/k".into()
            )
        );
        // Virtual-hosted inbound (`bucket.localhost`).
        assert_eq!(
            t("/k", Some("bucket.localhost:9000")),
            ("bucket.s3.us-east-1.amazonaws.com".into(), "/k".into())
        );
        assert_eq!(
            t("/k", Some("my.dotted.localhost")),
            ("s3.us-east-1.amazonaws.com".into(), "/my.dotted/k".into())
        );
    }

    #[test]
    fn other_services_keep_path() {
        assert_eq!(
            upstream_target("dynamodb", "eu-west-1", "/", None).unwrap(),
            ("dynamodb.eu-west-1.amazonaws.com".into(), "/".into())
        );
        assert!(upstream_target("nope", "us-east-1", "/", None).is_none());
        assert!(upstream_target("sts", "US_EAST", "/", None).is_none());
    }

    #[test]
    fn header_rebuild_drops_inbound_auth_and_hop_headers() {
        let inbound = h(&[
            ("Host", "127.0.0.1:1234"),
            (
                "Authorization",
                "AWS4-HMAC-SHA256 Credential=AKIALOCKSMITHX/...",
            ),
            ("X-Amz-Date", "20260101T000000Z"),
            ("X-Amz-Security-Token", "tok"),
            ("Connection", "keep-alive, X-Custom"),
            ("X-Custom", "1"),
            ("Keep-Alive", "timeout=5"),
            ("Expect", "100-continue"),
            ("Transfer-Encoding", "chunked"),
            ("Content-Type", "application/x-amz-json-1.0"),
            ("X-Amz-Target", "DynamoDB_20120810.GetItem"),
        ]);
        let out = forward_headers(&inbound, "dynamodb.us-east-1.amazonaws.com", Some(12));
        assert_eq!(
            out,
            h(&[
                ("Host", "dynamodb.us-east-1.amazonaws.com"),
                ("Content-Type", "application/x-amz-json-1.0"),
                ("X-Amz-Target", "DynamoDB_20120810.GetItem"),
                ("Content-Length", "12"),
            ])
        );
        // Pass-through bodies keep their framing.
        let out = forward_headers(&inbound, "h", None);
        assert!(out.iter().any(|(n, _)| n == "Transfer-Encoding"));
        assert!(!out.iter().any(|(n, _)| n == "Content-Length"));
    }

    #[test]
    fn error_bodies_follow_the_protocol() {
        let f = fail(403, "AccessDenied", "Locksmith policy: a<b&c");
        let s = |p, head| String::from_utf8(error_response(p, &f, head)).unwrap();
        let x = s(Proto::RestXml, false);
        assert!(x.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(x.contains(
            "<Error><Code>AccessDenied</Code><Message>Locksmith policy: a&lt;b&amp;c</Message>"
        ));
        assert!(s(Proto::Query, false).contains("<ErrorResponse><Error><Type>Sender</Type>"));
        let j = s(Proto::Json, false);
        let body = j.split("\r\n\r\n").nth(1).unwrap();
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["__type"], "AccessDenied");
        assert_eq!(v["message"], "Locksmith policy: a<b&c");
        assert!(j.contains("x-amzn-ErrorType: AccessDenied\r\n"));
        // HEAD: headers only, Content-Length still describes the body.
        assert!(s(Proto::RestXml, true).ends_with("\r\n\r\n"));
    }

    #[test]
    fn protocol_by_service() {
        assert_eq!(proto(Some("s3"), ""), Proto::RestXml);
        assert_eq!(proto(Some("sts"), ""), Proto::Query);
        assert_eq!(proto(Some("dynamodb"), ""), Proto::Json);
        assert_eq!(proto(Some("lambda"), ""), Proto::Json);
        // SQS speaks both; the request's content type decides.
        assert_eq!(proto(Some("sqs"), ""), Proto::Query);
        assert_eq!(
            proto(Some("sqs"), "application/x-amz-json-1.0"),
            Proto::Json
        );
        assert_eq!(proto(None, ""), Proto::RestXml);
    }

    #[test]
    fn response_drops_security_token() {
        let raw = b"HTTP/1.1 200 OK\r\nx-amz-security-token: t\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
        let mut hs = [httparse::EMPTY_HEADER; 8];
        let mut r = httparse::Response::new(&mut hs);
        r.parse(raw).unwrap();
        let out = String::from_utf8(response_head(&r)).unwrap();
        assert_eq!(
            out,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    }
}
