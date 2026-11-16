//! HTTP relay (M6 design D1–D4): host forwarding at `http://127.0.0.1:<port>/h/<host>/<path>`
//! and explicit-proxy mode (`CONNECT`, TLS terminated with a leaf from the local CA).
//!
//! Synchronous, one thread per connection, one request per connection (`Connection: close`), like
//! the Git forwarder. A request must carry exactly one opaque `lsk_` token. The daemon's
//! [`HttpAuthority`] checks it (peer process, lease, host allowlist, placement) and hands back
//! the real credential, which is written only into the token's configured placement of the
//! upstream request (never the body). Responses are decoded (gzip, deflate, br, zstd), redacted
//! with the real credential and re-sent chunked with identity encoding. Nothing here logs.

use crate::Deny;
use crate::forward::{Framer, Head, Io, connect_to, read_head, reason};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ls_redact::{Redactor, Secret};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use zeroize::Zeroizing;

const IO_TIMEOUT: Duration = Duration::from_secs(300);

// ---- opaque tokens (design D1) ----

pub const TOKEN_PREFIX: &str = "lsk_";
/// Base62 characters for 32 random bytes.
pub const TOKEN_CHARS: usize = 43;
/// Characters of a token shown by `smith token ls` (prefix plus 8).
pub const SHOWN: usize = 12;
const B62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Big-endian base62 of 32 bytes, left-padded to [`TOKEN_CHARS`].
pub fn base62(b: &[u8; 32]) -> String {
    let mut n = *b;
    let mut out = [b'0'; TOKEN_CHARS];
    for slot in out.iter_mut().rev() {
        let mut rem = 0u32;
        for byte in n.iter_mut() {
            let cur = rem * 256 + u32::from(*byte);
            *byte = (cur / 62) as u8;
            rem = cur % 62;
        }
        *slot = B62[rem as usize];
    }
    String::from_utf8(out.to_vec()).expect("ascii")
}

/// `lsk_` + 32 random bytes in base62.
pub fn new_token() -> String {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .expect("OS RNG");
    format!("{TOKEN_PREFIX}{}", base62(&b))
}

/// Every distinct well-formed opaque token in `s`, in order of appearance.
pub fn find_tokens(s: &[u8]) -> Vec<String> {
    let p = TOKEN_PREFIX.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i + p.len() + TOKEN_CHARS <= s.len() {
        let before_ok = i == 0 || !s[i - 1].is_ascii_alphanumeric();
        if before_ok && s[i..].starts_with(p) {
            let body = &s[i + p.len()..];
            let n = body
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric())
                .count();
            if n == TOKEN_CHARS {
                let t = String::from_utf8_lossy(&s[i..i + p.len() + n]).into_owned();
                if !out.contains(&t) {
                    out.push(t);
                }
            }
            i += p.len() + n;
            continue;
        }
        i += 1;
    }
    out
}

/// What `smith token ls` may show of a token.
pub fn shown(token: &str) -> String {
    token.chars().take(SHOWN).collect()
}

// ---- placements and allowlists (design D2) ----

/// Where the credential goes in the upstream request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// The `Authorization` header; the token is replaced in place (`Bearer`, `Token`, bare).
    Bearer,
    /// Inside `Authorization: Basic base64(user:pass)`, as user or password.
    Basic,
    /// A named header (lowercase), the token replaced in place.
    Header(String),
    /// A query parameter.
    Query(String),
}

impl Placement {
    pub fn parse(s: &str) -> Result<Placement, String> {
        let s = s.trim();
        let bad =
            || format!("invalid placement {s:?} (bearer, basic, header:<Name> or query:<param>)");
        let lower = s.to_ascii_lowercase();
        match lower.as_str() {
            "bearer" => return Ok(Placement::Bearer),
            "basic" => return Ok(Placement::Basic),
            _ => {}
        }
        if let Some(n) = lower.strip_prefix("header:") {
            let ok = !n.is_empty()
                && n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b));
            return match (ok, n) {
                (false, _) => Err(bad()),
                (true, "authorization") => Ok(Placement::Bearer),
                (true, n) if is_hop(n) || n == "cookie" => Err(format!(
                    "header {n} cannot carry a credential through the relay"
                )),
                (true, n) => Ok(Placement::Header(n.to_string())),
            };
        }
        if lower.starts_with("query:") {
            let p = &s["query:".len()..];
            let ok = !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
            return if ok {
                Ok(Placement::Query(p.to_string()))
            } else {
                Err(bad())
            };
        }
        Err(bad())
    }

    /// Comma-separated list, at least one.
    pub fn parse_list(s: &str) -> Result<Vec<Placement>, String> {
        let mut v: Vec<Placement> = Vec::new();
        for p in s.split(',').filter(|p| !p.trim().is_empty()) {
            let p = Placement::parse(p)?;
            if !v.contains(&p) {
                v.push(p);
            }
        }
        if v.is_empty() {
            return Err("empty placement".into());
        }
        Ok(v)
    }
}

impl std::fmt::Display for Placement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Placement::Bearer => f.write_str("bearer"),
            Placement::Basic => f.write_str("basic"),
            Placement::Header(n) => write!(f, "header:{n}"),
            Placement::Query(p) => write!(f, "query:{p}"),
        }
    }
}

pub fn placements_str(v: &[Placement]) -> String {
    v.iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// `name[:port]` with DNS characters only.
pub fn valid_host(h: &str) -> bool {
    let (name, port) = match h.rsplit_once(':') {
        Some((n, p)) => (n, Some(p)),
        None => (h, None),
    };
    !name.is_empty()
        && name.len() <= 253
        && !name.starts_with(['.', '-'])
        && !name.ends_with('.')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-.".contains(&b))
        && port.is_none_or(|p| p.parse::<u16>().is_ok_and(|p| p > 0))
}

/// A host or `*.suffix` allowlist entry.
pub fn valid_host_pattern(h: &str) -> bool {
    match h.strip_prefix("*.") {
        Some(s) => valid_host(s) && s.contains('.') && !s.contains(':'),
        None => valid_host(h),
    }
}

/// `host` (as requested; `:443` is the default) against an allowlist of exact hosts and
/// `*.suffix` entries (subdomains only, not the apex).
pub fn host_allowed(allow: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let bare = host.strip_suffix(":443").unwrap_or(&host);
    allow.iter().any(|a| {
        let a = a.to_ascii_lowercase();
        match a.strip_prefix("*.") {
            Some(sfx) => bare
                .strip_suffix(sfx)
                .is_some_and(|pre| pre.len() > 1 && pre.ends_with('.')),
            None => a == bare,
        }
    })
}

/// The swap rules (design D2): the host must be allowlisted and the token must sit in one of its
/// placements. On refusal: `(audit rule, message)`.
pub fn check(
    hosts: &[String],
    placements: &[Placement],
    host: &str,
    found: &[Placement],
) -> Result<(), (&'static str, String)> {
    if !host_allowed(hosts, host) {
        return Err((
            "http_host_not_allowed",
            format!("{host} is not in this token's host allowlist; nothing was sent"),
        ));
    }
    if !found.iter().any(|f| placements.contains(f)) {
        return Err((
            "http_wrong_placement",
            format!(
                "this token must be sent as {}; nothing was sent",
                placements_str(placements)
            ),
        ));
    }
    Ok(())
}

// ---- the daemon's side ----

/// One relayed request as the authority sees it.
pub struct Attempt<'a> {
    pub token: &'a str,
    /// Where the token was found (header and query locations).
    pub found: &'a [Placement],
    /// Upstream host (lowercase, may carry `:port`).
    pub host: &'a str,
    pub client: SocketAddr,
    pub server: SocketAddr,
}

/// What the daemon allows for one request.
pub struct HttpGrant {
    /// The real credential. Never logged; written only into `placements`.
    pub secret: Zeroizing<Vec<u8>>,
    pub placements: Vec<Placement>,
    /// Redaction label (the vault key name).
    pub label: String,
}

/// Implemented by `locksmithd`. Both calls audit their own refusals.
pub trait HttpAuthority: Send + Sync {
    fn authorize(&self, a: &Attempt<'_>) -> Result<HttpGrant, Deny>;
    /// Explicit-proxy mode: the TLS server config (a CA-signed leaf) for `host`, or a refusal
    /// when the host is not enabled or the CA is not installed. Never a blind tunnel.
    fn intercept(
        &self,
        host: &str,
        client: SocketAddr,
        server: SocketAddr,
    ) -> Result<Arc<rustls::ServerConfig>, Deny>;
}

/// Where requests go. The default is TLS to `<host>` (port 443).
#[derive(Default, Clone)]
pub struct Upstream {
    /// Test-only: requests for these hosts go over plain TCP to the address.
    pub insecure_http: Vec<(String, SocketAddr)>,
}

impl Upstream {
    /// `host=addr[,host=addr…]` (the debug-build test switch format).
    pub fn parse(v: &str) -> Upstream {
        Upstream {
            insecure_http: v
                .split(',')
                .filter_map(|e| {
                    let (h, a) = e.split_once('=')?;
                    Some((h.trim().to_ascii_lowercase(), a.trim().parse().ok()?))
                })
                .collect(),
        }
    }

    pub(crate) fn plain(&self, host: &str) -> Option<SocketAddr> {
        self.insecure_http
            .iter()
            .find(|(h, _)| h.eq_ignore_ascii_case(host))
            .map(|(_, a)| *a)
    }
}

/// Accepts connections forever, one thread each.
pub fn serve(listener: TcpListener, auth: Arc<dyn HttpAuthority>, up: Arc<Upstream>) {
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let (auth, up) = (auth.clone(), up.clone());
        std::thread::spawn(move || {
            let _ = handle(conn, &*auth, &up);
        });
    }
}

/// `/h/<host>[/path][?query]` -> (host, `/path?query`).
pub fn parse_route(target: &str) -> Option<(String, String)> {
    let rest = target.strip_prefix("/h/")?;
    let (host, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let host = host.to_ascii_lowercase();
    if !valid_host(&host) || path.bytes().any(|b| b <= b' ' || b >= 0x7f) {
        return None;
    }
    let path = match path.chars().next() {
        None => "/".to_string(),
        Some('?') => format!("/{path}"),
        Some(_) => path.to_string(),
    };
    Some((host, path))
}

fn reply(c: &mut dyn Io, status: u16, msg: &str) -> io::Result<()> {
    write!(
        c,
        "HTTP/1.1 {status} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}\n",
        reason(status),
        msg.len() + 1
    )?;
    c.flush()
}

fn handle(mut c: TcpStream, auth: &dyn HttpAuthority, up: &Upstream) -> io::Result<()> {
    c.set_read_timeout(Some(IO_TIMEOUT))?;
    c.set_write_timeout(Some(IO_TIMEOUT))?;
    let (client, server) = (c.peer_addr()?, c.local_addr()?);
    let (head, pending) = match read_head(&mut c)? {
        Ok(x) => x,
        Err(code) => return reply(&mut c, code, "bad request"),
    };
    if head.method == "CONNECT" {
        return connect(c, &head, client, server, auth, up);
    }
    let Some((host, path)) = parse_route(&head.path) else {
        return reply(
            &mut c,
            404,
            "Locksmith HTTP relay: use http://127.0.0.1:<port>/h/<host>/<path>, or HTTPS_PROXY with `smith http ca install`",
        );
    };
    let ctx = Ctx {
        auth,
        up,
        client,
        server,
    };
    relay(&mut c, head, pending, &host, &path, &ctx)
}

/// Explicit-proxy mode (design D4): only for enabled hosts, TLS terminated locally.
fn connect(
    mut c: TcpStream,
    head: &Head,
    client: SocketAddr,
    server: SocketAddr,
    auth: &dyn HttpAuthority,
    up: &Upstream,
) -> io::Result<()> {
    let target = head.path.to_ascii_lowercase();
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(0)),
        None => (target.clone(), 443),
    };
    if port == 0 || !valid_host(&host) {
        return reply(&mut c, 400, "bad CONNECT target");
    }
    let cfg = match auth.intercept(&host, client, server) {
        Ok(cfg) => cfg,
        Err(d) => return reply(&mut c, d.status, &d.message),
    };
    c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    c.flush()?;
    let conn = rustls::ServerConnection::new(cfg).map_err(io::Error::other)?;
    let mut tls = rustls::StreamOwned::new(conn, c);
    let (head, pending) = match read_head(&mut tls)? {
        Ok(x) => x,
        Err(code) => return reply(&mut tls, code, "bad request"),
    };
    let upstream_host = if port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    // origin-form, or absolute-form for this same host
    let path = match head.path.split_once("://") {
        Some((_, rest)) => match rest.find(['/', '?']) {
            Some(i) if rest[..i].eq_ignore_ascii_case(&upstream_host) => rest[i..].to_string(),
            None if rest.eq_ignore_ascii_case(&upstream_host) => "/".into(),
            _ => return reply(&mut tls, 400, "request host differs from the CONNECT host"),
        },
        None if head.path.starts_with('/') => head.path.clone(),
        None => return reply(&mut tls, 400, "bad request target"),
    };
    let ctx = Ctx {
        auth,
        up,
        client,
        server,
    };
    let r = relay(&mut tls, head, pending, &upstream_host, &path, &ctx);
    tls.conn.send_close_notify();
    let _ = tls.flush();
    r
}

struct Ctx<'a> {
    auth: &'a dyn HttpAuthority,
    up: &'a Upstream,
    client: SocketAddr,
    server: SocketAddr,
}

pub(crate) fn is_hop(l: &str) -> bool {
    matches!(
        l,
        "connection" | "keep-alive" | "proxy-connection" | "te" | "trailer" | "upgrade"
    ) || l.starts_with("proxy-")
}

fn basic_decode(v: &[u8]) -> Option<Vec<u8>> {
    let v = std::str::from_utf8(v).ok()?.trim();
    let (scheme, b64) = v.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    STANDARD.decode(b64.trim()).ok()
}

/// Every (token, placement) in the request's headers and query.
fn locate(head: &Head, path: &str) -> Vec<(String, Placement)> {
    let mut out = Vec::new();
    for (n, v) in &head.headers {
        let l = n.to_ascii_lowercase();
        if is_hop(&l) || l == "host" {
            continue;
        }
        if l == "authorization" {
            if let Some(dec) = basic_decode(v) {
                out.extend(find_tokens(&dec).into_iter().map(|t| (t, Placement::Basic)));
            }
            out.extend(find_tokens(v).into_iter().map(|t| (t, Placement::Bearer)));
        } else {
            let p = Placement::Header(l);
            out.extend(find_tokens(v).into_iter().map(|t| (t, p.clone())));
        }
    }
    if let Some((_, q)) = path.split_once('?') {
        for kv in q.split('&') {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            let p = Placement::Query(k.to_string());
            out.extend(
                find_tokens(v.as_bytes())
                    .into_iter()
                    .map(|t| (t, p.clone())),
            );
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn replace(hay: &[u8], needle: &[u8], with: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(hay.len() + with.len()));
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(needle) {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

fn percent(v: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(v.len() * 3));
    for &b in v {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
    }
    out
}

/// The header value with the token swapped, when this header is one of the placements.
fn swap_header(
    l: &str,
    v: &[u8],
    token: &[u8],
    secret: &[u8],
    places: &[Placement],
) -> Zeroizing<Vec<u8>> {
    if l == "authorization" {
        if places.contains(&Placement::Basic)
            && let Some(dec) = basic_decode(v).map(Zeroizing::new)
            && contains(&dec, token)
        {
            let swapped = replace(&dec, token, secret);
            let enc = Zeroizing::new(STANDARD.encode(&*swapped));
            let mut out = Zeroizing::new(b"Basic ".to_vec());
            out.extend_from_slice(enc.as_bytes());
            return out;
        }
        if places.contains(&Placement::Bearer) && contains(v, token) {
            return replace(v, token, secret);
        }
    } else if places.contains(&Placement::Header(l.to_string())) && contains(v, token) {
        return replace(v, token, secret);
    }
    Zeroizing::new(v.to_vec())
}

fn swap_query(path: &str, token: &[u8], secret: &[u8], places: &[Placement]) -> Zeroizing<Vec<u8>> {
    let Some((p, q)) = path.split_once('?') else {
        return Zeroizing::new(path.as_bytes().to_vec());
    };
    let mut out = Zeroizing::new(p.as_bytes().to_vec());
    out.push(b'?');
    for (i, kv) in q.split('&').enumerate() {
        if i > 0 {
            out.push(b'&');
        }
        match kv.split_once('=') {
            Some((k, v))
                if places.contains(&Placement::Query(k.to_string()))
                    && contains(v.as_bytes(), token) =>
            {
                out.extend_from_slice(k.as_bytes());
                out.push(b'=');
                out.extend_from_slice(&replace(v.as_bytes(), token, &percent(secret)));
            }
            _ => out.extend_from_slice(kv.as_bytes()),
        }
    }
    out
}

/// The upstream request head: credential swapped into its placements, hop-by-hop headers and
/// the client's `Host` dropped, our own `Accept-Encoding` (so the body can be cleansed).
fn upstream_head(
    head: &Head,
    host: &str,
    path: &str,
    token: &str,
    secret: &[u8],
    places: &[Placement],
    chunked: bool,
) -> Zeroizing<Vec<u8>> {
    let tok = token.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(1024));
    out.extend_from_slice(head.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(&swap_query(path, tok, secret, places));
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(b"\r\nConnection: close\r\nAccept-Encoding: gzip, deflate, br, zstd\r\n");
    let named = conn_named(&head.headers);
    for (n, v) in &head.headers {
        let l = n.to_ascii_lowercase();
        if is_hop(&l)
            || named.contains(&l)
            || matches!(l.as_str(), "host" | "expect" | "accept-encoding")
            || (chunked && l == "content-length")
        {
            continue;
        }
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&swap_header(&l, v, tok, secret, places));
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Header names listed in `Connection` (hop-by-hop by declaration).
fn conn_named(headers: &[(String, Vec<u8>)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| {
            String::from_utf8_lossy(v)
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn relay(
    c: &mut dyn Io,
    head: Head,
    pending: Vec<u8>,
    host: &str,
    path: &str,
    ctx: &Ctx<'_>,
) -> io::Result<()> {
    let found = locate(&head, path);
    let mut tokens: Vec<&str> = Vec::new();
    for (t, _) in &found {
        if !tokens.contains(&t.as_str()) {
            tokens.push(t);
        }
    }
    let token = match tokens.as_slice() {
        [] => {
            return reply(
                c,
                401,
                "Locksmith HTTP relay: no opaque token (lsk_…) in the request; get one with `smith token issue <KEY>`",
            );
        }
        [t] => t.to_string(),
        _ => return reply(c, 400, "more than one Locksmith token in the request"),
    };
    let places: Vec<Placement> = found.iter().map(|(_, p)| p.clone()).collect();
    let grant = match ctx.auth.authorize(&Attempt {
        token: &token,
        found: &places,
        host,
        client: ctx.client,
        server: ctx.server,
    }) {
        Ok(g) => g,
        Err(d) => return reply(c, d.status, &d.message),
    };
    if grant.secret.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return reply(
            c,
            502,
            "the stored credential cannot be sent in an HTTP request",
        );
    }

    let chunked = head.header("transfer-encoding").is_some_and(|v| {
        String::from_utf8_lossy(v)
            .to_ascii_lowercase()
            .contains("chunked")
    });
    let len = match head.header("content-length") {
        None => 0,
        Some(v) if head.count("content-length") == 1 => {
            match std::str::from_utf8(v)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
            {
                Some(n) => n,
                None => return reply(c, 400, "bad request"),
            }
        }
        Some(_) => return reply(c, 400, "bad request"),
    };
    let mut framer = Framer::new(chunked, len, false);
    let Ok(used) = framer.feed(&pending) else {
        return reply(c, 400, "bad request body");
    };
    let mut upstream = match connect_to(host, ctx.up.plain(host)) {
        Ok(u) => u,
        // The network guard (M10e D3): its message names no secret, only the host.
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return reply(c, 403, &e.to_string());
        }
        Err(_) => return reply(c, 502, "upstream unavailable"),
    };
    let out = upstream_head(
        &head,
        host,
        path,
        &token,
        &grant.secret,
        &grant.placements,
        chunked,
    );
    if upstream.write_all(&out).is_err() || upstream.write_all(&pending[..used]).is_err() {
        return reply(c, 502, "upstream unavailable");
    }
    drop(out);
    if head
        .header("expect")
        .is_some_and(|v| v.eq_ignore_ascii_case(b"100-continue"))
        && !framer.done()
    {
        c.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        c.flush()?;
    }
    let mut tmp = [0u8; 16384];
    while !framer.done() {
        let n = c.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        let Ok(used) = framer.feed(&tmp[..n]) else {
            return Ok(());
        };
        upstream.write_all(&tmp[..used])?;
    }
    upstream.flush()?;

    let redactor = Redactor::new(&[Secret::new(grant.label.clone(), &grant.secret)]);
    drop(grant);
    let Ok(Some((resp, rest))) = read_resp(&mut *upstream) else {
        return reply(c, 502, "upstream unavailable");
    };
    respond(c, &head.method, resp, rest, upstream, &redactor)
}

struct Resp {
    status: u16,
    reason: String,
    headers: Vec<(String, Vec<u8>)>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| String::from_utf8_lossy(v).trim().to_ascii_lowercase())
    }

    /// Every coding named by all `name` headers, in order (`gzip, br` and two `gzip` lines alike).
    fn codings(&self, name: &str) -> Vec<String> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| {
                String::from_utf8_lossy(v)
                    .split(',')
                    .map(|c| c.trim().to_ascii_lowercase())
                    .filter(|c| !c.is_empty())
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

/// Reads the final (non-1xx) response head and any body bytes already read.
fn read_resp(up: &mut dyn Io) -> io::Result<Option<(Resp, Vec<u8>)>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let mut hs = [httparse::EMPTY_HEADER; 128];
        let mut r = httparse::Response::new(&mut hs);
        match r.parse(&buf) {
            Ok(httparse::Status::Complete(n)) => {
                let code = r.code.unwrap_or(502);
                if (100..200).contains(&code) {
                    if code == 101 {
                        return Ok(None);
                    }
                    buf.drain(..n);
                    continue;
                }
                let resp = Resp {
                    status: code,
                    reason: r.reason.unwrap_or("").to_string(),
                    headers: r
                        .headers
                        .iter()
                        .map(|h| (h.name.to_string(), h.value.to_vec()))
                        .collect(),
                };
                return Ok(Some((resp, buf[n..].to_vec())));
            }
            Ok(httparse::Status::Partial) => {}
            Err(_) => return Ok(None),
        }
        if buf.len() >= 64 * 1024 {
            return Ok(None);
        }
        let n = up.read(&mut tmp)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// The upstream body without its framing: Content-Length, chunked, or until EOF.
struct Body {
    up: Box<dyn Io>,
    framer: Option<Framer>,
    raw: Vec<u8>,
    out: Vec<u8>,
    pos: usize,
}

impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos < self.out.len() {
                let n = buf.len().min(self.out.len() - self.pos);
                buf[..n].copy_from_slice(&self.out[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            self.out.clear();
            self.pos = 0;
            let data = if self.raw.is_empty() {
                if self.framer.as_ref().is_some_and(Framer::done) {
                    return Ok(0);
                }
                let mut tmp = vec![0u8; 16384];
                let n = match self.up.read(&mut tmp) {
                    // A TLS close without close_notify ends an EOF-delimited body.
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => 0,
                    r => r?,
                };
                if n == 0 {
                    return match self.framer {
                        None => Ok(0),
                        Some(_) => Err(io::ErrorKind::UnexpectedEof.into()),
                    };
                }
                tmp.truncate(n);
                tmp
            } else {
                std::mem::take(&mut self.raw)
            };
            match &mut self.framer {
                None => self.out = data,
                Some(f) => {
                    f.feed(&data)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad framing"))?;
                    self.out = std::mem::take(&mut f.decoded);
                }
            }
        }
    }
}

/// Records whether the body ended with an error (then the client gets no final chunk).
struct Guard<R> {
    inner: R,
    failed: Arc<AtomicBool>,
}

impl<R: Read> Read for Guard<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).inspect_err(|_| {
            self.failed.store(true, Ordering::SeqCst);
        })
    }
}

struct Chunked<'a>(&'a mut dyn Io);

impl Write for Chunked<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if b.is_empty() {
            return Ok(0);
        }
        write!(self.0, "{:x}\r\n", b.len())?;
        self.0.write_all(b)?;
        self.0.write_all(b"\r\n")?;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// Response cleansing (design D3): headers redacted, body decoded, redacted as a stream and
/// re-sent chunked with identity encoding, so streaming (SSE) responses still stream.
fn respond(
    c: &mut dyn Io,
    method: &str,
    resp: Resp,
    rest: Vec<u8>,
    up: Box<dyn Io>,
    redactor: &Redactor,
) -> io::Result<()> {
    let no_body = method.eq_ignore_ascii_case("HEAD") || matches!(resp.status, 204 | 304);
    // Fail closed on anything but one known content-coding and plain chunked framing: a body
    // still encoded after our decoding (stacked or repeated codings, `Transfer-Encoding: gzip`)
    // would reach the client unredacted, and the client can decode it (gate A3b).
    let coding = match resp.codings("content-encoding").as_slice() {
        [] => String::new(),
        [one] => one.clone(),
        _ => return reply(c, 502, "upstream used stacked content-encodings"),
    };
    let chunked = match resp.codings("transfer-encoding").as_slice() {
        [] => false,
        [one] if one == "chunked" => true,
        _ => return reply(c, 502, "upstream used an unsupported transfer-encoding"),
    };
    let len = resp
        .header("content-length")
        .and_then(|v| v.parse::<u64>().ok());
    let empty = no_body || (!chunked && len == Some(0));
    let framer = match (chunked, len) {
        (true, _) => Some(Framer::new(true, 0, true)),
        (false, Some(n)) => Some(Framer::new(false, n, true)),
        (false, None) => None,
    };
    let body = Body {
        up,
        framer,
        raw: rest,
        out: Vec::new(),
        pos: 0,
    };
    let src: Box<dyn Read + Send> = match coding.as_str() {
        _ if empty => Box::new(io::empty()),
        "" | "identity" => Box::new(body),
        "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(body)),
        "deflate" => Box::new(flate2::read::ZlibDecoder::new(body)),
        "br" => Box::new(brotli_decompressor::Decompressor::new(body, 8192)),
        "zstd" => match ruzstd::decoding::StreamingDecoder::new(body) {
            Ok(d) => Box::new(d),
            Err(_) => return reply(c, 502, "upstream sent a bad zstd body"),
        },
        // Fail closed: a body we cannot decode cannot be cleansed.
        _ => return reply(c, 502, "upstream used an unsupported content-encoding"),
    };
    let named = conn_named(&resp.headers);
    let mut out = format!("HTTP/1.1 {} {}\r\n", resp.status, resp.reason).into_bytes();
    for (n, v) in &resp.headers {
        let l = n.to_ascii_lowercase();
        if is_hop(&l)
            || named.contains(&l)
            || matches!(
                l.as_str(),
                "transfer-encoding" | "content-length" | "content-encoding"
            )
        {
            continue;
        }
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&redactor.redact_all(v));
        out.extend_from_slice(b"\r\n");
    }
    if no_body {
        out.extend_from_slice(b"Connection: close\r\n\r\n");
        c.write_all(&out)?;
        return c.flush();
    }
    out.extend_from_slice(b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
    c.write_all(&out)?;
    c.flush()?;
    let failed = Arc::new(AtomicBool::new(false));
    let src = Guard {
        inner: src,
        failed: failed.clone(),
    };
    ls_redact::relay(src, Chunked(&mut *c), redactor);
    if failed.load(Ordering::SeqCst) {
        return Ok(()); // truncated: no final chunk, so the client sees an incomplete body
    }
    c.write_all(b"0\r\n\r\n")?;
    c.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_base62_and_findable() {
        let t = new_token();
        assert!(t.starts_with(TOKEN_PREFIX));
        assert_eq!(t.len(), TOKEN_PREFIX.len() + TOKEN_CHARS);
        assert!(t[4..].bytes().all(|b| b.is_ascii_alphanumeric()));
        assert_ne!(t, new_token());
        assert_eq!(base62(&[0; 32]), "0".repeat(TOKEN_CHARS));
        assert_eq!(base62(&[0xff; 32]).len(), TOKEN_CHARS);
        let mut one = [0u8; 32];
        one[31] = 61;
        assert!(base62(&one).ends_with("0z"));
        let s = format!("Bearer {t}, again {t}; x{t} {t}0 {}", &t[..20]);
        assert_eq!(find_tokens(s.as_bytes()), std::slice::from_ref(&t));
        assert_eq!(shown(&t).len(), SHOWN);
    }

    #[test]
    fn placements_parse_and_print() {
        for (s, p) in [
            ("bearer", Placement::Bearer),
            ("Basic", Placement::Basic),
            ("header:X-Api-Key", Placement::Header("x-api-key".into())),
            ("header:Authorization", Placement::Bearer),
            ("query:api_key", Placement::Query("api_key".into())),
        ] {
            assert_eq!(Placement::parse(s), Ok(p.clone()), "{s}");
            assert_eq!(Placement::parse(&p.to_string()), Ok(p));
        }
        for bad in [
            "",
            "body",
            "header:",
            "header:a b",
            "query:",
            "header:Cookie",
            "header:Proxy-Authorization",
        ] {
            assert!(Placement::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(
            Placement::parse_list("header:apikey, bearer,bearer").unwrap(),
            [Placement::Header("apikey".into()), Placement::Bearer]
        );
    }

    #[test]
    fn host_allowlist() {
        let allow = vec!["api.stripe.com".to_string(), "*.myshopify.com".to_string()];
        for (h, ok) in [
            ("api.stripe.com", true),
            ("API.Stripe.com:443", true),
            ("api.stripe.com:8443", false),
            ("api.stripe.com.evil.example", false),
            ("evil.example", false),
            ("shop.myshopify.com", true),
            ("myshopify.com", false),
            ("x.notmyshopify.com", false),
        ] {
            assert_eq!(host_allowed(&allow, h), ok, "{h}");
        }
        assert!(valid_host_pattern("*.x.com") && !valid_host_pattern("*.com"));
        assert!(
            !valid_host("a..b") && !valid_host("-a") && !valid_host("a:0") && valid_host("a:1")
        );
    }

    #[test]
    fn routes() {
        assert_eq!(
            parse_route("/h/API.stripe.com/v1/charges?limit=3"),
            Some(("api.stripe.com".into(), "/v1/charges?limit=3".into()))
        );
        assert_eq!(
            parse_route("/h/x.test"),
            Some(("x.test".into(), "/".into()))
        );
        assert_eq!(
            parse_route("/h/x.test?a=1"),
            Some(("x.test".into(), "/?a=1".into()))
        );
        for bad in ["/x/y", "/h/", "/h/a b/x", "/h/a@b/x", "/h/x.test/\x01"] {
            assert!(parse_route(bad).is_none(), "{bad}");
        }
    }

    fn head(headers: &[(&str, &str)]) -> Head {
        Head {
            method: "POST".into(),
            path: "/".into(),
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.as_bytes().to_vec()))
                .collect(),
        }
    }

    #[test]
    fn swap_only_in_placement() {
        let t = new_token();
        let secret = b"real secret/+=value";
        let basic = STANDARD.encode(format!("{t}:"));
        let h = head(&[
            ("Authorization", &format!("Basic {basic}")),
            ("X-Api-Key", &format!("Token {t}")),
            ("X-Other", &t),
            ("Host", "127.0.0.1"),
            ("Connection", "close, X-Drop"),
            ("X-Drop", "1"),
            ("Accept-Encoding", "identity"),
        ]);
        let path = format!("/v1/x?key={t}&other={t}");
        let found: Vec<Placement> = locate(&h, &path).into_iter().map(|(_, p)| p).collect();
        assert_eq!(
            found,
            [
                Placement::Basic,
                Placement::Header("x-api-key".into()),
                Placement::Header("x-other".into()),
                Placement::Query("key".into()),
                Placement::Query("other".into()),
            ]
        );
        let places = [
            Placement::Basic,
            Placement::Header("x-api-key".into()),
            Placement::Query("key".into()),
        ];
        let out = upstream_head(&h, "api.x.test", &path, &t, secret, &places, false);
        let s = String::from_utf8_lossy(&out);
        let want_basic = STANDARD.encode(b"real secret/+=value:");
        assert!(
            s.starts_with("POST /v1/x?key=real%20secret%2F%2B%3Dvalue&other="),
            "{s}"
        );
        assert!(
            s.contains(&format!("Authorization: Basic {want_basic}\r\n")),
            "{s}"
        );
        assert!(
            s.contains("X-Api-Key: Token real secret/+=value\r\n"),
            "{s}"
        );
        assert!(s.contains(&format!("X-Other: {t}\r\n")), "{s}");
        assert!(
            s.contains("Host: api.x.test\r\n") && !s.contains("127.0.0.1"),
            "{s}"
        );
        assert!(!s.contains("X-Drop") && !s.contains("identity"), "{s}");
        // Not a placement: nothing swapped.
        let out = upstream_head(
            &h,
            "api.x.test",
            &path,
            &t,
            secret,
            &[Placement::Bearer],
            false,
        );
        assert!(!contains(&out, b"real secret"));
    }

    #[test]
    fn check_rules() {
        let hosts = vec!["api.x.test".to_string()];
        let pl = [Placement::Bearer];
        assert!(check(&hosts, &pl, "api.x.test", &[Placement::Bearer]).is_ok());
        assert_eq!(
            check(&hosts, &pl, "evil.example", &[Placement::Bearer])
                .unwrap_err()
                .0,
            "http_host_not_allowed"
        );
        assert_eq!(
            check(&hosts, &pl, "api.x.test", &[Placement::Query("k".into())])
                .unwrap_err()
                .0,
            "http_wrong_placement"
        );
    }
}
