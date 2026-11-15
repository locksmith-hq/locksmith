//! AWS Signature Version 4, header-based (`Authorization: AWS4-HMAC-SHA256 ...`).
//!
//! The relay uses this module twice per request: [`verify`] checks the agent's signature with the
//! session's dummy secret, then [`sign`] produces fresh headers signed with the real credentials.
//! S3 `aws-chunked` uploads (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) are re-signed chunk by chunk
//! with [`ChunkReader`] (verify, dummy key) and [`ChunkSigner`] (re-sign, real key).
//!
//! Spec: <https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html>.
//! Secrets and derived signing keys stay in `Zeroizing` buffers or inside `ring` keys; no type
//! here that holds one implements Debug, Display or Clone.

use super::Credentials;
use ring::{digest, hmac};
use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::io::{self, BufRead, Read, Write};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// How far `X-Amz-Date` may be from the relay's clock (AWS uses the same window).
pub const MAX_SKEW: Duration = Duration::from_secs(15 * 60);
/// Hex SHA-256 of the empty string.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
pub const STREAMING_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
pub const STREAMING_UNSIGNED_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
const STREAMING_SIGNED_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
/// Largest `aws-chunked` chunk accepted (SDKs use 64 KiB to 8 MiB).
pub const MAX_CHUNK: usize = 16 << 20;

/// Credential scope: `<date>/<region>/<service>/aws4_request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// `YYYYMMDD`.
    pub date: String,
    pub region: String,
    pub service: String,
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}/aws4_request",
            self.date, self.region, self.service
        )
    }
}

/// A parsed `Authorization` header. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthHeader {
    pub access_key_id: String,
    pub scope: Scope,
    /// Lowercase, sorted, unique.
    pub signed_headers: Vec<String>,
    /// 64 lowercase hex characters.
    pub signature: String,
}

/// Parse `AWS4-HMAC-SHA256 Credential=AKID/YYYYMMDD/region/service/aws4_request,
/// SignedHeaders=a;b, Signature=hex`.
pub fn parse_authorization(value: &str) -> Result<AuthHeader, String> {
    let rest = value
        .trim()
        .strip_prefix(ALGORITHM)
        .filter(|r| r.starts_with(' '))
        .ok_or("authorization: not AWS4-HMAC-SHA256")?;
    let (mut cred, mut signed, mut sig) = (None, None, None);
    for part in rest.split(',') {
        let (k, v) = part
            .trim()
            .split_once('=')
            .ok_or("authorization: malformed component")?;
        let slot = match k {
            "Credential" => &mut cred,
            "SignedHeaders" => &mut signed,
            "Signature" => &mut sig,
            _ => return Err(format!("authorization: unknown component {k}")),
        };
        if slot.replace(v).is_some() {
            return Err(format!("authorization: duplicate {k}"));
        }
    }
    let (cred, signed, sig) = match (cred, signed, sig) {
        (Some(c), Some(h), Some(s)) => (c, h, s),
        _ => return Err("authorization: missing Credential, SignedHeaders or Signature".into()),
    };
    let parts: Vec<&str> = cred.split('/').collect();
    let [akid, date, region, service, "aws4_request"] = parts[..] else {
        return Err("authorization: malformed Credential".into());
    };
    if akid.is_empty() || region.is_empty() || service.is_empty() {
        return Err("authorization: empty Credential field".into());
    }
    if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return Err("authorization: malformed scope date".into());
    }
    let signed_headers: Vec<String> = signed.split(';').map(str::to_string).collect();
    let token = |h: &String| {
        !h.is_empty()
            && h.bytes()
                .all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase() && b != b':')
    };
    if !signed_headers.iter().all(token) || !signed_headers.windows(2).all(|w| w[0] < w[1]) {
        return Err("authorization: SignedHeaders must be lowercase, sorted and unique".into());
    }
    if sig.len() != 64 || unhex(sig).is_none() || sig.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err("authorization: malformed Signature".into());
    }
    Ok(AuthHeader {
        access_key_id: akid.into(),
        scope: Scope {
            date: date.into(),
            region: region.into(),
            service: service.into(),
        },
        signed_headers,
        signature: sig.into(),
    })
}

/// The parts of an HTTP request that SigV4 covers.
pub struct Request {
    pub method: String,
    /// Path exactly as on the wire (already percent-encoded once by the client).
    pub path: String,
    /// Raw query string without `?`.
    pub query: String,
    /// Header (name, value) pairs in wire order; names in any case, repeats allowed.
    pub headers: Vec<(String, String)>,
    /// The `x-amz-content-sha256` value when the client sent one, else the hex SHA-256 of the
    /// body. When it is a hex hash the caller must check it against the body it forwards.
    pub payload_hash: String,
}

impl Request {
    /// Canonical (trimmed, space-collapsed, comma-joined) value of header `name`, if present.
    pub fn header(&self, name: &str) -> Option<String> {
        header_value(&pairs(&self.headers), name)
    }
}

fn pairs(h: &[(String, String)]) -> Vec<(&str, &str)> {
    h.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

fn header_value(headers: &[(&str, &str)], name: &str) -> Option<String> {
    let vals: Vec<String> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    (!vals.is_empty()).then(|| vals.join(","))
}

/// Canonical request for `req` with `signed_headers` (lowercase, sorted). `service` picks the URI
/// rules: `s3` uses the path as sent (no normalization, single encoding); every other service
/// removes dot segments and empty segments and encodes the path again (double encoding).
pub fn canonical_request(req: &Request, signed_headers: &[String], service: &str) -> String {
    canonical(req, &pairs(&req.headers), signed_headers, service)
}

fn canonical(req: &Request, headers: &[(&str, &str)], signed: &[String], service: &str) -> String {
    let uri = if service == "s3" {
        uri_encode(req.path.as_bytes(), true, true)
    } else {
        uri_encode(normalize_path(&req.path).as_bytes(), true, false)
    };
    let mut out = format!("{}\n{}\n{}\n", req.method, uri, canonical_query(&req.query));
    for name in signed {
        let v = header_value(headers, name).unwrap_or_default();
        let _ = writeln!(out, "{name}:{v}");
    }
    let _ = write!(out, "\n{}\n{}", signed.join(";"), req.payload_hash);
    out
}

fn normalize_path(path: &str) -> String {
    let mut segs: Vec<&str> = Vec::new();
    for s in path.split('/') {
        match s {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    let mut out = format!("/{}", segs.join("/"));
    let dir = path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..");
    if dir && out.len() > 1 {
        out.push('/');
    }
    out
}

fn canonical_query(query: &str) -> String {
    let enc = |s: &str| uri_encode(&percent_decode(s), false, false);
    let mut kv: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (enc(k), enc(v))
        })
        .collect();
    kv.sort();
    let kv: Vec<String> = kv.into_iter().map(|(k, v)| format!("{k}={v}")).collect();
    kv.join("&")
}

/// RFC 3986 encoding: everything but unreserved characters (and `/` when `slash`) becomes `%XX`.
/// With `keep_escapes`, existing `%XX` escapes are copied through instead of re-encoded.
fn uri_encode(b: &[u8], slash: bool, keep_escapes: bool) -> String {
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_alphanumeric() || b"-._~".contains(&c) || (slash && c == b'/') {
            out.push(c as char);
        } else if keep_escapes && c == b'%' && is_escape(&b[i..]) {
            out.push_str(&String::from_utf8_lossy(&b[i..i + 3]));
            i += 2;
        } else {
            let _ = write!(out, "%{c:02X}");
        }
        i += 1;
    }
    out
}

fn is_escape(b: &[u8]) -> bool {
    b.len() >= 3 && b[0] == b'%' && b[1].is_ascii_hexdigit() && b[2].is_ascii_hexdigit()
}

// shortcut: `+` is kept literal (SDKs send `%20` for spaces); revisit if a client sends `+`.
fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if is_escape(&b[i..]) {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap_or(0));
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// `AWS4-HMAC-SHA256\n<amz_date>\n<scope>\n<hex sha256(canonical_request)>`.
pub fn string_to_sign(amz_date: &str, scope: &Scope, canonical_request: &str) -> String {
    format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        hex_sha256(canonical_request.as_bytes())
    )
}

/// The derived per-day, per-region, per-service key. No Debug/Clone.
pub struct SigningKey(hmac::Key);

impl SigningKey {
    fn verify(&self, data: &str, signature_hex: &str) -> bool {
        unhex(signature_hex).is_some_and(|sig| hmac::verify(&self.0, data.as_bytes(), &sig).is_ok())
    }
}

/// `kSigning = HMAC(HMAC(HMAC(HMAC("AWS4" + secret, date), region), service), "aws4_request")`.
pub fn signing_key(secret: &str, scope: &Scope) -> SigningKey {
    let mut k = Zeroizing::new(format!("AWS4{secret}").into_bytes());
    for part in [&scope.date, &scope.region, &scope.service, "aws4_request"] {
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &k), part.as_bytes());
        k = Zeroizing::new(tag.as_ref().to_vec());
    }
    SigningKey(hmac::Key::new(hmac::HMAC_SHA256, &k))
}

/// Hex HMAC-SHA256 of `string_to_sign` with `key`.
pub fn signature(key: &SigningKey, string_to_sign: &str) -> String {
    hex(hmac::sign(&key.0, string_to_sign.as_bytes()).as_ref())
}

/// Why an inbound request was refused. Messages carry no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    Malformed(String),
    /// A header that must be covered by the signature is not in `SignedHeaders`.
    UnsignedHeader(&'static str),
    /// `X-Amz-Date` is more than [`MAX_SKEW`] from the relay's clock.
    Stale,
    Mismatch,
    Replay,
    /// The replay cache is full of live entries; failing closed.
    CacheFull,
    /// A valid AWS feature this relay does not implement.
    Unsupported(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed request: {m}"),
            Self::UnsignedHeader(h) => write!(f, "header {h} must be signed"),
            Self::Stale => write!(f, "X-Amz-Date is more than 15 minutes from the relay clock"),
            Self::Mismatch => write!(f, "signature does not match"),
            Self::Replay => write!(f, "signature already used"),
            Self::CacheFull => write!(f, "replay cache full"),
            Self::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify `req` against `auth` with `secret`. Checks, in order: `host`, `x-amz-date` and (when
/// sent) `x-amz-content-sha256` are signed; `X-Amz-Date` parses, matches the scope date and is
/// within [`MAX_SKEW`] of `now`; the signature matches (constant-time). Replay is checked
/// separately with [`NonceCache`].
pub fn verify(
    req: &Request,
    auth: &AuthHeader,
    secret: &str,
    now: SystemTime,
) -> Result<(), VerifyError> {
    let signed = |h: &str| auth.signed_headers.iter().any(|s| s == h);
    for h in ["host", "x-amz-date", "x-amz-content-sha256"] {
        if !signed(h) && (h != "x-amz-content-sha256" || req.header(h).is_some()) {
            return Err(VerifyError::UnsignedHeader(h));
        }
    }
    let amz_date = req
        .header("x-amz-date")
        .ok_or_else(|| VerifyError::Malformed("missing X-Amz-Date".into()))?;
    let t = parse_amz_date(&amz_date).map_err(VerifyError::Malformed)?;
    if amz_date[..8] != auth.scope.date {
        return Err(VerifyError::Malformed(
            "scope date differs from X-Amz-Date".into(),
        ));
    }
    let skew = now.duration_since(t).unwrap_or_else(|e| e.duration());
    if skew > MAX_SKEW {
        return Err(VerifyError::Stale);
    }
    let cr = canonical_request(req, &auth.signed_headers, &auth.scope.service);
    let sts = string_to_sign(&amz_date, &auth.scope, &cr);
    if !signing_key(secret, &auth.scope).verify(&sts, &auth.signature) {
        return Err(VerifyError::Mismatch);
    }
    Ok(())
}

/// Bounded, thread-safe set of signatures seen within their validity window (design D2).
pub struct NonceCache {
    capacity: usize,
    seen: Mutex<HashMap<String, SystemTime>>,
}

impl NonceCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Record `signature` (already verified at `now`); refuse it if it was seen and could still
    /// be valid. A verified request's date is within `now ± MAX_SKEW`, so it expires by
    /// `now + 2 * MAX_SKEW`. When full of live entries this fails closed with `CacheFull`.
    pub fn check(&self, signature: &str, now: SystemTime) -> Result<(), VerifyError> {
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        if seen.get(signature).is_some_and(|exp| *exp > now) {
            return Err(VerifyError::Replay);
        }
        if seen.len() >= self.capacity {
            seen.retain(|_, exp| *exp > now);
            if seen.len() >= self.capacity {
                return Err(VerifyError::CacheFull);
            }
        }
        seen.insert(signature.to_string(), now + 2 * MAX_SKEW);
        Ok(())
    }
}

/// Headers produced by [`sign`]. Values are zeroized on drop (one may be a session token).
pub struct Signed {
    /// `authorization`, `x-amz-date` and, with a session token, `x-amz-security-token`. The
    /// caller replaces any header of the same name before forwarding.
    pub headers: Vec<(&'static str, Zeroizing<String>)>,
    /// The new signature: the seed for [`ChunkSigner`] on streaming uploads.
    pub signature: String,
}

/// Sign `req` with `creds`. Any `authorization`, `x-amz-date` or `x-amz-security-token` in
/// `req.headers` is ignored. Signed headers: `host`, `x-amz-*`, `content-type`, `content-md5`,
/// plus every name in `client_signed` (the agent's `SignedHeaders`) that is still in
/// `req.headers`. `req.headers` must be exactly what will be forwarded.
pub fn sign(
    req: &Request,
    creds: &Credentials,
    scope: &Scope,
    amz_date: &str,
    client_signed: &[String],
) -> Signed {
    let replaced = ["authorization", "x-amz-date", "x-amz-security-token"];
    let mut headers: Vec<(&str, &str)> = pairs(&req.headers)
        .into_iter()
        .filter(|(k, _)| !replaced.iter().any(|r| k.eq_ignore_ascii_case(r)))
        .collect();
    headers.push(("x-amz-date", amz_date));
    if let Some(t) = &creds.session_token {
        headers.push(("x-amz-security-token", t.as_str()));
    }
    let mut names: Vec<String> = headers
        .iter()
        .map(|(k, _)| k.to_ascii_lowercase())
        .filter(|n| {
            n == "host"
                || n.starts_with("x-amz-")
                || n == "content-type"
                || n == "content-md5"
                || client_signed.contains(n)
        })
        .collect();
    names.sort();
    names.dedup();
    let cr = Zeroizing::new(canonical(req, &headers, &names, &scope.service));
    let sts = string_to_sign(amz_date, scope, &cr);
    let sig = signature(&signing_key(&creds.secret_access_key, scope), &sts);
    let auth = format!(
        "{ALGORITHM} Credential={}/{scope}, SignedHeaders={}, Signature={sig}",
        creds.access_key_id,
        names.join(";")
    );
    let mut out = vec![
        ("authorization", Zeroizing::new(auth)),
        ("x-amz-date", Zeroizing::new(amz_date.to_string())),
    ];
    if let Some(t) = &creds.session_token {
        out.push(("x-amz-security-token", t.clone()));
    }
    Signed {
        headers: out,
        signature: sig,
    }
}

/// `YYYYMMDDTHHMMSSZ` for `t`.
pub fn amz_date(t: SystemTime) -> String {
    let t = time::OffsetDateTime::from(t);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// Parse `YYYYMMDDTHHMMSSZ`.
pub fn parse_amz_date(s: &str) -> Result<SystemTime, String> {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        b[r].iter().try_fold(0u32, |n, c| {
            c.is_ascii_digit().then(|| n * 10 + u32::from(c - b'0'))
        })
    };
    let bad = || format!("malformed X-Amz-Date {s:?}");
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return Err(bad());
    }
    let f = |r| digits(r).ok_or_else(bad);
    let (y, mo, d) = (f(0..4)?, f(4..6)?, f(6..8)?);
    let (h, mi, sec) = (f(9..11)?, f(11..13)?, f(13..15)?);
    let month = time::Month::try_from(mo as u8).map_err(|_| bad())?;
    let ts = time::Date::from_calendar_date(y as i32, month, d as u8)
        .and_then(|date| date.with_hms(h as u8, mi as u8, sec as u8))
        .map_err(|_| bad())?
        .assume_utc()
        .unix_timestamp();
    Ok(UNIX_EPOCH + Duration::from_secs(u64::try_from(ts).map_err(|_| bad())?))
}

/// How the payload of a request is covered, from its `x-amz-content-sha256` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payload {
    /// A hex SHA-256 of the body.
    Hashed,
    /// `UNSIGNED-PAYLOAD`: body passes through.
    Unsigned,
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`: re-sign with [`ChunkReader`] + [`ChunkSigner`].
    StreamingSigned,
    /// `STREAMING-UNSIGNED-PAYLOAD-TRAILER`: `aws-chunked` without signatures; passes through.
    StreamingUnsignedTrailer,
}

pub fn payload_kind(x_amz_content_sha256: &str) -> Result<Payload, VerifyError> {
    match x_amz_content_sha256 {
        UNSIGNED_PAYLOAD => Ok(Payload::Unsigned),
        STREAMING_PAYLOAD => Ok(Payload::StreamingSigned),
        STREAMING_UNSIGNED_TRAILER => Ok(Payload::StreamingUnsignedTrailer),
        STREAMING_SIGNED_TRAILER => Err(VerifyError::Unsupported(
            "signed streaming trailers (STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER); \
             disable flexible checksums or use contained STS"
                .into(),
        )),
        v if v.starts_with("STREAMING-") => {
            Err(VerifyError::Unsupported(format!("payload mode {v}")))
        }
        v if v.len() == 64 && unhex(v).is_some() => Ok(Payload::Hashed),
        _ => Err(VerifyError::Malformed("bad x-amz-content-sha256".into())),
    }
}

/// String to sign for one `aws-chunked` chunk; `chunk_hash` is the hex SHA-256 of its data.
pub fn chunk_string_to_sign(
    prev_signature: &str,
    amz_date: &str,
    scope: &Scope,
    chunk_hash: &str,
) -> String {
    format!(
        "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{prev_signature}\n{EMPTY_SHA256}\n{chunk_hash}"
    )
}

/// Signature of chunk `data` chained from `prev_signature` (the seed for the first chunk).
pub fn chunk_signature(
    key: &SigningKey,
    prev_signature: &str,
    amz_date: &str,
    scope: &Scope,
    data: &[u8],
) -> String {
    signature(
        key,
        &chunk_string_to_sign(prev_signature, amz_date, scope, &hex_sha256(data)),
    )
}

/// Emits `aws-chunked` frames signed with `key`, chained from the seed signature.
pub struct ChunkSigner {
    key: SigningKey,
    scope: Scope,
    amz_date: String,
    prev: String,
}

impl ChunkSigner {
    /// `seed` is [`Signed::signature`]; `scope`/`amz_date` are the ones [`sign`] used.
    pub fn new(key: SigningKey, scope: Scope, amz_date: String, seed: String) -> Self {
        Self {
            key,
            scope,
            amz_date,
            prev: seed,
        }
    }

    /// One frame `hex-size;chunk-signature=sig\r\n data \r\n`. Empty `data` is the final frame.
    pub fn encode(&mut self, data: &[u8]) -> Vec<u8> {
        let sig = chunk_signature(&self.key, &self.prev, &self.amz_date, &self.scope, data);
        let mut out = format!("{:x};chunk-signature={sig}\r\n", data.len()).into_bytes();
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
        self.prev = sig;
        out
    }
}

/// Reads `aws-chunked` frames and verifies each chunk signature with `key`, chained from the
/// seed signature (the request's `Authorization` signature).
pub struct ChunkReader<R> {
    inner: R,
    key: SigningKey,
    scope: Scope,
    amz_date: String,
    prev: String,
    done: bool,
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("aws-chunked: {msg}"))
}

impl<R: BufRead> ChunkReader<R> {
    pub fn new(inner: R, key: SigningKey, scope: Scope, amz_date: String, seed: String) -> Self {
        Self {
            inner,
            key,
            scope,
            amz_date,
            prev: seed,
            done: false,
        }
    }

    /// The next verified chunk's data; `Ok(None)` after the final zero-size chunk.
    pub fn next_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.done {
            return Ok(None);
        }
        let mut line = Vec::new();
        (&mut self.inner).take(128).read_until(b'\n', &mut line)?;
        let line = line
            .strip_suffix(b"\r\n")
            .and_then(|l| std::str::from_utf8(l).ok())
            .ok_or_else(|| bad("malformed chunk header"))?;
        let (size, sig) = line
            .split_once(";chunk-signature=")
            .ok_or_else(|| bad("missing chunk-signature"))?;
        let size = usize::from_str_radix(size, 16).map_err(|_| bad("bad chunk size"))?;
        if size > MAX_CHUNK {
            return Err(bad("chunk too large"));
        }
        let mut data = vec![0; size];
        self.inner.read_exact(&mut data)?;
        let mut crlf = [0; 2];
        self.inner.read_exact(&mut crlf)?;
        if &crlf != b"\r\n" {
            return Err(bad("missing CRLF after chunk"));
        }
        let sts = chunk_string_to_sign(&self.prev, &self.amz_date, &self.scope, &hex_sha256(&data));
        if !self.key.verify(&sts, sig) {
            return Err(bad("chunk signature does not match"));
        }
        self.prev = sig.to_string();
        if size == 0 {
            self.done = true;
            return Ok(None);
        }
        Ok(Some(data))
    }
}

/// Verify every chunk from `reader` and write it re-signed by `signer` (final frame included).
/// Chunk sizes are kept, so the encoded length (`Content-Length`) is unchanged. Returns the
/// decoded byte count, to check against `x-amz-decoded-content-length`.
pub fn reencode<R: BufRead, W: Write>(
    reader: &mut ChunkReader<R>,
    signer: &mut ChunkSigner,
    out: &mut W,
) -> io::Result<u64> {
    let mut n = 0;
    while let Some(chunk) = reader.next_chunk()? {
        n += chunk.len() as u64;
        out.write_all(&signer.encode(&chunk))?;
    }
    out.write_all(&signer.encode(&[]))?;
    Ok(n)
}

pub fn hex_sha256(data: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, data).as_ref())
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}
