//! Synchronous Git smart-HTTP forwarder (design D1, D2, D4).
//!
//! One thread per client connection. The upstream request carries the grant's `Authorization`
//! header and `Connection: close`; the response is copied verbatim until upstream EOF. Nothing in
//! this module logs, and the upstream credential never appears in a client-visible message.

use crate::{Authority, RefUpdate, Route, policy};
use base64::Engine;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

const MAX_HEAD: usize = 64 * 1024;
const MAX_COMMANDS: usize = 1 << 20;
const IO_TIMEOUT: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Where requests go. The default is TLS to `<host>:443`.
#[derive(Default)]
pub struct Upstream {
    /// Test-only: requests for this host go over plain TCP to this address.
    pub insecure_http: Option<(String, SocketAddr)>,
}

pub(crate) trait Io: Read + Write + Send {}
impl<T: Read + Write + Send> Io for T {}

/// Accepts connections forever, one thread each.
pub fn serve(listener: TcpListener, auth: Arc<dyn Authority>, up: Arc<Upstream>) {
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let (auth, up) = (auth.clone(), up.clone());
        std::thread::spawn(move || {
            let _ = handle(conn, &*auth, &up);
        });
    }
}

/// Parses `/git/<host>/<owner>/<repo>.git/<rest>[?query]`.
pub fn parse_route(path: &str) -> Option<Route> {
    let (path, query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q.to_string())),
        None => (path, None),
    };
    if path
        .bytes()
        .any(|b| b <= b' ' || b == b'%' || b == b'\\' || b >= 0x7f)
    {
        return None;
    }
    let segs: Vec<&str> = path.strip_prefix("/git/")?.split('/').collect();
    if segs.iter().any(|s| s.is_empty() || *s == "." || *s == "..") {
        return None;
    }
    let host = segs[0].to_ascii_lowercase();
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-.:".contains(&b))
    {
        return None;
    }
    // owner/repo needs at least two segments; the first `.git` segment ends the repo path.
    let end = segs
        .iter()
        .skip(3)
        .position(|s| s.ends_with(".git"))
        .map(|p| p + 3);
    let end = match segs.get(2) {
        Some(s) if s.ends_with(".git") => 2,
        _ => end?,
    };
    let mut repo = segs[1..=end].join("/");
    repo.truncate(repo.len() - 4);
    if segs[end] == ".git" {
        return None;
    }
    let rest = segs[end + 1..].join("/");
    if rest.is_empty() {
        return None;
    }
    Some(Route {
        host,
        repo,
        rest,
        query,
    })
}

pub(crate) struct Head {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: Vec<(String, Vec<u8>)>,
}

impl Head {
    pub(crate) fn header(&self, name: &str) -> Option<&[u8]> {
        let mut it = self
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name));
        it.next().map(|(_, v)| v.as_slice())
    }
    pub(crate) fn count(&self, name: &str) -> usize {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .count()
    }
    fn token(&self) -> Option<String> {
        let v = std::str::from_utf8(self.header("authorization")?).ok()?;
        let b64 = v
            .strip_prefix("Basic ")
            .or_else(|| v.strip_prefix("basic "))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .ok()?;
        let s = String::from_utf8(raw).ok()?;
        s.split_once(':').map(|(_, p)| p.to_string())
    }
}

/// Reads the request head. `Err(status)` means reply with that status.
pub(crate) fn read_head(c: &mut dyn Read) -> io::Result<Result<(Head, Vec<u8>), u16>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let mut hs = [httparse::EMPTY_HEADER; 96];
        let mut req = httparse::Request::new(&mut hs);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(n)) => {
                let head = Head {
                    method: req.method.unwrap_or_default().to_string(),
                    path: req.path.unwrap_or_default().to_string(),
                    headers: req
                        .headers
                        .iter()
                        .map(|h| (h.name.to_string(), h.value.to_vec()))
                        .collect(),
                };
                return Ok(Ok((head, buf[n..].to_vec())));
            }
            Ok(httparse::Status::Partial) => {}
            Err(httparse::Error::TooManyHeaders) => return Ok(Err(431)),
            Err(_) => return Ok(Err(400)),
        }
        if buf.len() >= MAX_HEAD {
            return Ok(Err(431));
        }
        let n = c.read(&mut tmp)?;
        if n == 0 {
            return Ok(Err(400));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

#[derive(Clone, Copy)]
enum St {
    Len(u64),
    ChSize,
    ChData(u64),
    ChCrlf(u8),
    Trailer,
    Done,
}

/// Finds the end of a request body (Content-Length or chunked) in a raw byte stream, optionally
/// collecting the de-chunked payload. The raw bytes are forwarded unchanged.
pub(crate) struct Framer {
    st: St,
    line: Vec<u8>,
    collect: bool,
    pub(crate) decoded: Vec<u8>,
}

impl Framer {
    pub(crate) fn new(chunked: bool, len: u64, collect: bool) -> Self {
        let st = match (chunked, len) {
            (true, _) => St::ChSize,
            (false, 0) => St::Done,
            (false, n) => St::Len(n),
        };
        Framer {
            st,
            line: Vec::new(),
            collect,
            decoded: Vec::new(),
        }
    }

    pub(crate) fn done(&self) -> bool {
        matches!(self.st, St::Done)
    }

    /// Consumes bytes of `d` that belong to the body; returns how many.
    pub(crate) fn feed(&mut self, d: &[u8]) -> Result<usize, ()> {
        let mut i = 0;
        while i < d.len() {
            match self.st {
                St::Done => break,
                St::Len(n) | St::ChData(n) => {
                    let t = ((d.len() - i) as u64).min(n) as usize;
                    if self.collect {
                        self.decoded.extend_from_slice(&d[i..i + t]);
                    }
                    i += t;
                    let n = n - t as u64;
                    self.st = match (self.st, n) {
                        (St::Len(_), 0) => St::Done,
                        (St::Len(_), n) => St::Len(n),
                        (_, 0) => St::ChCrlf(2),
                        (_, n) => St::ChData(n),
                    };
                }
                St::ChCrlf(k) => {
                    let want = if k == 2 { b'\r' } else { b'\n' };
                    if d[i] != want {
                        return Err(());
                    }
                    i += 1;
                    self.st = if k == 1 { St::ChSize } else { St::ChCrlf(1) };
                }
                St::ChSize | St::Trailer => {
                    let b = d[i];
                    i += 1;
                    if b != b'\n' {
                        self.line.push(b);
                        if self.line.len() > 1024 {
                            return Err(());
                        }
                        continue;
                    }
                    let line = std::mem::take(&mut self.line);
                    let line = line.strip_suffix(b"\r").unwrap_or(&line);
                    if matches!(self.st, St::Trailer) {
                        if line.is_empty() {
                            self.st = St::Done;
                        }
                        continue;
                    }
                    let hex = line.split(|&c| c == b';').next().unwrap_or_default();
                    if hex.is_empty() || !hex.iter().all(u8::is_ascii_hexdigit) {
                        return Err(());
                    }
                    let size = u64::from_str_radix(std::str::from_utf8(hex).map_err(|_| ())?, 16)
                        .map_err(|_| ())?;
                    self.st = if size == 0 {
                        St::Trailer
                    } else {
                        St::ChData(size)
                    };
                }
            }
        }
        Ok(i)
    }
}

pub(crate) fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        _ => "Error",
    }
}

fn reply(c: &mut TcpStream, status: u16, msg: &str) -> io::Result<()> {
    let www = if status == 401 {
        "WWW-Authenticate: Basic realm=\"locksmith\"\r\n"
    } else {
        ""
    };
    write!(
        c,
        "HTTP/1.1 {status} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n{www}Connection: close\r\n\r\n{msg}",
        reason(status),
        msg.len()
    )?;
    c.flush()
}

/// Reply, then swallow the rest of the client's upload so Git reads the response, not a reset.
fn reply_drain(c: &mut TcpStream, status: u16, msg: &str) -> io::Result<()> {
    reply(c, status, msg)?;
    drain(c)
}

fn drain(c: &mut TcpStream) -> io::Result<()> {
    c.set_read_timeout(Some(Duration::from_secs(2)))?;
    let (mut left, mut tmp) = (64usize << 20, [0u8; 16384]);
    while left > 0 {
        match c.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => left = left.saturating_sub(n),
        }
    }
    Ok(())
}

fn pkt(out: &mut Vec<u8>, payload: &[u8]) {
    out.extend_from_slice(format!("{:04x}", payload.len() + 4).as_bytes());
    out.extend_from_slice(payload);
}

/// Git only prints the body of a refused push when it arrives as a receive-pack report (a bare
/// 403 shows just "error: 403"), so answer 200 with `ng` per ref plus a sideband message.
fn reject_push(c: &mut TcpStream, cmds: &[u8], updates: &[RefUpdate], why: &str) -> io::Result<()> {
    let first_len = std::str::from_utf8(&cmds[..4])
        .ok()
        .and_then(|h| usize::from_str_radix(h, 16).ok());
    let caps = first_len
        .and_then(|l| cmds.get(4..l))
        .and_then(|p| {
            p.iter()
                .position(|&b| b == 0)
                .map(|i| String::from_utf8_lossy(&p[i + 1..]).into_owned())
        })
        .unwrap_or_default();
    if !caps
        .split_whitespace()
        .any(|x| x.starts_with("report-status"))
    {
        return reply_drain(c, 403, why);
    }
    let why = why.replace(['\n', '\r'], " ");
    let mut report = Vec::new();
    pkt(&mut report, b"unpack ok\n");
    for u in updates {
        pkt(&mut report, format!("ng {} {why}\n", u.name).as_bytes());
    }
    report.extend_from_slice(b"0000");
    let mut body = Vec::new();
    if caps.split_whitespace().any(|x| x.starts_with("side-band")) {
        pkt(&mut body, format!("\x02locksmith: {why}\n").as_bytes());
        pkt(&mut body, &[&[1u8][..], &report].concat());
        body.extend_from_slice(b"0000");
    } else {
        body = report;
    }
    write!(
        c,
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-git-receive-pack-result\r\nCache-Control: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    c.write_all(&body)?;
    c.flush()?;
    drain(c)
}

fn handle(mut c: TcpStream, auth: &dyn Authority, up: &Upstream) -> io::Result<()> {
    c.set_read_timeout(Some(IO_TIMEOUT))?;
    c.set_write_timeout(Some(IO_TIMEOUT))?;
    let (client, server) = (c.peer_addr()?, c.local_addr()?);
    let (head, mut pending) = match read_head(&mut c)? {
        Ok(x) => x,
        Err(code) => return reply(&mut c, code, "bad request"),
    };
    let Some(route) = parse_route(&head.path) else {
        return reply(&mut c, 404, "not found");
    };
    let token = head.token();
    let grant = match auth.authorize(token.as_deref(), client, server, &route) {
        Ok(g) => g,
        Err(d) => return reply(&mut c, d.status, &d.message),
    };

    let is_push = route.rest == "git-receive-pack";
    if is_push && head.method != "POST" {
        return reply(&mut c, 405, "method not allowed");
    }
    // Fail closed: the command list is inspected in clear, so any content coding is refused.
    if is_push
        && head
            .header("content-encoding")
            .is_some_and(|v| !v.eq_ignore_ascii_case(b"identity"))
    {
        return reply(&mut c, 415, "content-encoding is not supported for pushes");
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
                None => return reply(&mut c, 400, "bad request"),
            }
        }
        Some(_) => return reply(&mut c, 400, "bad request"),
    };

    let mut framer = Framer::new(chunked, len, is_push);
    let mut held: Vec<u8> = Vec::new(); // raw body bytes read from the client, not yet sent
    let mut tmp = [0u8; 16384];
    if head
        .header("expect")
        .is_some_and(|v| v.eq_ignore_ascii_case(b"100-continue"))
        && !framer.done()
    {
        c.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
    }
    loop {
        let Ok(used) = framer.feed(&pending) else {
            return reply(&mut c, 400, "bad request body");
        };
        held.extend_from_slice(&pending[..used]);
        if !is_push {
            break;
        }
        if framer.decoded.len() > MAX_COMMANDS {
            return reply_drain(&mut c, 413, "ref update list too large");
        }
        match policy::commands_end(&framer.decoded) {
            Err(e) => return reply(&mut c, 400, &e),
            Ok(Some(end)) => {
                let cmds = &framer.decoded[..end];
                let updates = policy::parse_commands(cmds);
                let verdict = match &updates {
                    Ok(u) => policy::check(u, &grant.protected),
                    Err(e) => Err(e.clone()),
                };
                if let Err(why) = verdict {
                    auth.push_denied(&route, &grant, &why);
                    return match updates {
                        Ok(u) if !u.is_empty() => reject_push(&mut c, cmds, &u, &why),
                        _ => reply_drain(&mut c, 403, &why),
                    };
                }
                break;
            }
            Ok(None) if framer.done() => return reply(&mut c, 400, "bad request body"),
            Ok(None) => {}
        }
        let n = c.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        pending = tmp[..n].to_vec();
    }

    let Ok(mut upstream) = connect(up, &route.host) else {
        return reply(&mut c, 502, "upstream unavailable");
    };
    let mut out = format!("{} /{}.git/{}", head.method, route.repo, route.rest);
    if let Some(q) = &route.query {
        out.push('?');
        out.push_str(q);
    }
    out.push_str(" HTTP/1.1\r\nHost: ");
    out.push_str(&route.host);
    out.push_str("\r\nAuthorization: ");
    out.push_str(&grant.upstream_auth);
    out.push_str("\r\nConnection: close\r\n");
    let mut out = out.into_bytes();
    for (n, v) in &head.headers {
        let l = n.to_ascii_lowercase();
        let drop = matches!(
            l.as_str(),
            "authorization" | "connection" | "keep-alive" | "host" | "te" | "expect"
        ) || l.starts_with("proxy-")
            || (chunked && l == "content-length");
        if !drop {
            out.extend_from_slice(format!("{n}: ").as_bytes());
            out.extend_from_slice(v);
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&held);
    if upstream.write_all(&out).is_err() {
        return reply(&mut c, 502, "upstream unavailable");
    }
    drop((out, held));
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
    auth.forwarded(&route, &grant, &route.rest);

    match read_response_head(&mut *upstream) {
        Ok(Some((head, rest))) => {
            c.write_all(&head)?;
            c.write_all(&rest)?;
            // Upstream EOF (or a TLS close without close_notify) ends the response.
            let _ = io::copy(&mut upstream, &mut c);
            c.flush()
        }
        _ => reply(&mut c, 502, "upstream unavailable"),
    }
}

/// Reads the upstream status line and headers; returns the rewritten head (Connection: close)
/// and any body bytes already read.
fn read_response_head(up: &mut dyn Io) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let mut hs = [httparse::EMPTY_HEADER; 96];
        let mut resp = httparse::Response::new(&mut hs);
        match resp.parse(&buf) {
            Ok(httparse::Status::Complete(n)) => {
                let code = resp.code.unwrap_or(502);
                if code < 200 {
                    buf.drain(..n);
                    continue;
                }
                let mut out =
                    format!("HTTP/1.1 {code} {}\r\n", resp.reason.unwrap_or("")).into_bytes();
                for h in resp.headers.iter() {
                    if h.name.eq_ignore_ascii_case("connection")
                        || h.name.eq_ignore_ascii_case("keep-alive")
                    {
                        continue;
                    }
                    out.extend_from_slice(h.name.as_bytes());
                    out.extend_from_slice(b": ");
                    out.extend_from_slice(h.value);
                    out.extend_from_slice(b"\r\n");
                }
                out.extend_from_slice(b"Connection: close\r\n\r\n");
                return Ok(Some((out, buf[n..].to_vec())));
            }
            Ok(httparse::Status::Partial) => {}
            Err(_) => return Ok(None),
        }
        if buf.len() >= MAX_HEAD {
            return Ok(None);
        }
        let n = up.read(&mut tmp)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn other(msg: &str) -> io::Error {
    io::Error::other(msg.to_string())
}

fn dial(host: &str, port: u16) -> io::Result<TcpStream> {
    connect_any((host, port).to_socket_addrs()?)
}

fn connect_any(addrs: impl IntoIterator<Item = SocketAddr>) -> io::Result<TcpStream> {
    let mut last = other("no address");
    for a in addrs {
        match TcpStream::connect_timeout(&a, CONNECT_TIMEOUT) {
            Ok(s) => {
                s.set_read_timeout(Some(IO_TIMEOUT))?;
                s.set_write_timeout(Some(IO_TIMEOUT))?;
                return Ok(s);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

// ---- network guard (M10e D3) ----

static ALLOW_PRIVATE: RwLock<Vec<SocketAddr>> = RwLock::new(Vec::new());

/// Exact `ip:port` upstreams the relays may reach although private (the agent policy's
/// `[relay] allow_private`, set by the daemon at unlock). Metadata addresses stay blocked.
pub fn set_allow_private(v: Vec<SocketAddr>) {
    *ALLOW_PRIVATE.write().unwrap_or_else(|e| e.into_inner()) = v;
}

fn allow_private() -> Vec<SocketAddr> {
    ALLOW_PRIVATE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Cloud instance metadata (AWS/GCP/Azure IPv4, AWS IPv6): never reachable, even if allowlisted.
pub fn is_metadata(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v) => v == Ipv4Addr::new(169, 254, 169, 254),
        IpAddr::V6(v) => v == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254),
    }
}

/// Not a public internet address: loopback, RFC 1918, link-local, carrier-grade NAT,
/// unspecified / "this network", broadcast, IPv6 ULA and link-local; IPv4-mapped IPv6 is judged
/// as the IPv4 address it carries.
pub fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v) => {
            let [a, b, ..] = v.octets();
            v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                || v.is_broadcast()
                || a == 0
                || (a == 100 && b & 0xc0 == 64)
        }
        IpAddr::V6(v) => {
            v.is_loopback()
                || v.is_unspecified()
                || v.is_unique_local()
                || v.is_unicast_link_local()
        }
    }
}

/// Name resolution, injectable for tests (a rebinding stub).
pub type Resolve<'a> = &'a dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>>;

fn system_resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    Ok((host, port).to_socket_addrs()?.collect())
}

/// Resolve `host` once and keep the addresses the relays may reach: public ones, plus private
/// ones listed exactly in `allow`; metadata never. Fails when nothing is left.
pub fn checked_addrs(
    host: &str,
    port: u16,
    allow: &[SocketAddr],
    resolve: Resolve<'_>,
) -> io::Result<Vec<SocketAddr>> {
    let ok: Vec<SocketAddr> = resolve(host, port)?
        .into_iter()
        .filter(|a| {
            let ip = a.ip().to_canonical();
            !is_metadata(ip)
                && (!is_private(ip)
                    || allow
                        .iter()
                        .any(|x| x.ip().to_canonical() == ip && x.port() == a.port()))
        })
        .collect();
    if ok.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{host}:{port} resolves only to private, loopback or metadata addresses; the \
                 relay refused it (the human can allow an exact ip:port with [relay] \
                 allow_private in the agent policy)"
            ),
        ));
    }
    Ok(ok)
}

/// Connect to one of the addresses [`checked_addrs`] kept. The name is resolved exactly once,
/// so a DNS answer that changes later (rebinding) cannot redirect the connection.
pub fn dial_checked(
    host: &str,
    port: u16,
    allow: &[SocketAddr],
    resolve: Resolve<'_>,
) -> io::Result<TcpStream> {
    connect_any(checked_addrs(host, port, allow, resolve)?)
}

fn connect(up: &Upstream, host: &str) -> io::Result<Box<dyn Io>> {
    let plain = up
        .insecure_http
        .as_ref()
        .filter(|(h, _)| h.eq_ignore_ascii_case(host))
        .map(|(_, a)| *a);
    connect_to(host, plain)
}

/// TLS to `host` (`name[:port]`, default 443), or plain TCP to `plain` (test switch, debug
/// builds only; it bypasses the network guard). Direct connections go through the network guard
/// ([`dial_checked`]). shortcut: through `HTTPS_PROXY` the proxy resolves the name, so the guard
/// does not apply there; add a check-then-CONNECT-by-IP if a proxied setup needs it.
pub(crate) fn connect_to(host: &str, plain: Option<SocketAddr>) -> io::Result<Box<dyn Io>> {
    if let Some(addr) = plain {
        let s = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
        s.set_read_timeout(Some(IO_TIMEOUT))?;
        s.set_write_timeout(Some(IO_TIMEOUT))?;
        return Ok(Box::new(s));
    }
    let (name, port) = match host.rsplit_once(':') {
        Some((n, p)) => (n, p.parse().map_err(|_| other("bad port"))?),
        None => (host, 443),
    };
    let tcp = match proxy_for(name)? {
        Some(p) => tunnel(&p, name, port)?,
        None => dial_checked(name, port, &allow_private(), &system_resolve)?,
    };
    let sn =
        rustls::pki_types::ServerName::try_from(name.to_string()).map_err(|_| other("bad host"))?;
    let conn = rustls::ClientConnection::new(tls_config(), sn).map_err(|_| other("tls"))?;
    Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
}

pub(crate) fn tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .expect("ring provider supports default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

struct Proxy {
    host: String,
    port: u16,
    /// `Basic …` value; never printed.
    auth: Option<String>,
}

fn env_any(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|n| std::env::var(n).ok())
        .filter(|v| !v.is_empty())
}

/// `HTTPS_PROXY` unless `NO_PROXY` matches. shortcut: userinfo is not percent-decoded and only
/// `http://` proxies are supported; upgrade when a customer needs otherwise.
fn proxy_for(host: &str) -> io::Result<Option<Proxy>> {
    let Some(url) = env_any(&["HTTPS_PROXY", "https_proxy"]) else {
        return Ok(None);
    };
    if let Some(np) = env_any(&["NO_PROXY", "no_proxy"]) {
        for e in np.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let e = e.trim_start_matches("*.").trim_start_matches('.');
            if e == "*"
                || host.eq_ignore_ascii_case(e)
                || host
                    .to_ascii_lowercase()
                    .ends_with(&format!(".{}", e.to_ascii_lowercase()))
            {
                return Ok(None);
            }
        }
    }
    let rest = match url.split_once("://") {
        Some(("http", r)) => r,
        Some(_) => return Err(other("unsupported proxy scheme")),
        None => &url,
    };
    let rest = rest.trim_end_matches('/');
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().map_err(|_| other("bad proxy port"))?),
        None => (hostport, 80),
    };
    let auth = userinfo.map(|u| {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(u)
        )
    });
    Ok(Some(Proxy {
        host: host.to_string(),
        port,
        auth,
    }))
}

fn tunnel(p: &Proxy, host: &str, port: u16) -> io::Result<TcpStream> {
    let mut s = dial(&p.host, p.port)?;
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(a) = &p.auth {
        req.push_str(&format!("Proxy-Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes())?;
    // Byte-wise so no tunnelled bytes are consumed with the proxy's reply.
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if buf.len() > 16 * 1024 || s.read(&mut b)? == 0 {
            return Err(other("proxy tunnel failed"));
        }
        buf.push(b[0]);
    }
    let mut hs = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut hs);
    match resp.parse(&buf) {
        Ok(httparse::Status::Complete(_)) if resp.code == Some(200) => Ok(s),
        _ => Err(other("proxy tunnel failed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn guard_ranges() {
        for p in [
            "127.0.0.1",
            "127.9.9.9",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "0.1.2.3",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(is_private(ip(p)), "{p} should be private");
        }
        for p in [
            "8.8.8.8",
            "1.1.1.1",
            "100.63.255.255",
            "100.128.0.1",
            "172.32.0.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_private(ip(p)), "{p} should be public");
        }
        for m in ["169.254.169.254", "::ffff:169.254.169.254", "fd00:ec2::254"] {
            assert!(is_metadata(ip(m)), "{m}");
        }
        assert!(!is_metadata(ip("169.254.169.253")));
    }

    #[test]
    fn guard_filters_resolved_addresses_and_honours_the_exact_allowlist() {
        let sa = |s: &str| s.parse::<SocketAddr>().unwrap();
        let fixed = |v: Vec<SocketAddr>| move |_: &str, _: u16| Ok(v.clone());
        // Mixed answer: only the public address is kept.
        let r = fixed(vec![sa("10.0.0.5:443"), sa("93.184.215.14:443")]);
        assert_eq!(
            checked_addrs("x.test", 443, &[], &r).unwrap(),
            [sa("93.184.215.14:443")]
        );
        // Private only: refused with a message naming the policy knob.
        let r = fixed(vec![sa("127.0.0.1:3000")]);
        let e = checked_addrs("x.test", 3000, &[], &r).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("allow_private"), "{e}");
        // Exact ip:port only: another port, or another loopback address, stays blocked.
        assert!(checked_addrs("x.test", 3000, &[sa("127.0.0.1:3000")], &r).is_ok());
        assert!(checked_addrs("x.test", 3000, &[sa("127.0.0.1:3001")], &r).is_err());
        assert!(checked_addrs("x.test", 3000, &[sa("127.0.0.2:3000")], &r).is_err());
        // Mapped form of an allowlisted address is the same address.
        let r = fixed(vec![sa("[::ffff:127.0.0.1]:3000")]);
        assert!(checked_addrs("x.test", 3000, &[sa("127.0.0.1:3000")], &r).is_ok());
        // Metadata: refused even when allowlisted, in either family.
        for m in [
            "169.254.169.254:80",
            "[fd00:ec2::254]:80",
            "[::ffff:169.254.169.254]:80",
        ] {
            let r = fixed(vec![sa(m)]);
            assert!(checked_addrs("meta.test", 80, &[sa(m)], &r).is_err(), "{m}");
        }
    }

    /// DNS rebinding: the first answer is checked and dialled; a later, different answer is never
    /// asked for. Conversely a blocked first answer is refused without connecting anywhere.
    #[test]
    fn guard_resolves_once_and_dials_the_checked_address() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let good = l.local_addr().unwrap();
        let calls = AtomicUsize::new(0);
        let rebinding = |_: &str, _: u16| {
            Ok(match calls.fetch_add(1, Ordering::SeqCst) {
                0 => vec![good],
                _ => vec!["10.9.9.9:1".parse().unwrap()],
            })
        };
        let s = dial_checked("rebind.test", good.port(), &[good], &rebinding).unwrap();
        assert_eq!(s.peer_addr().unwrap(), good);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "resolved exactly once");
        let (accepted, _) = l.accept().unwrap();
        drop(accepted);

        // Public at check time is what an attacker hopes for; private first is refused outright.
        let calls = AtomicUsize::new(0);
        let private_first = |_: &str, _: u16| {
            Ok(match calls.fetch_add(1, Ordering::SeqCst) {
                0 => vec![good],
                _ => vec!["93.184.215.14:443".parse().unwrap()],
            })
        };
        let e = dial_checked("rebind.test", good.port(), &[], &private_first).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn routes() {
        let r =
            parse_route("/git/GitHub.com/acme/app.git/info/refs?service=git-upload-pack").unwrap();
        assert_eq!(r.host, "github.com");
        assert_eq!(r.repo, "acme/app");
        assert_eq!(r.rest, "info/refs");
        assert_eq!(r.query.as_deref(), Some("service=git-upload-pack"));
        let r = parse_route("/git/gitlab.com/g/sub/app.git/git-receive-pack").unwrap();
        assert_eq!(
            (r.repo.as_str(), r.rest.as_str(), r.query),
            ("g/sub/app", "git-receive-pack", None)
        );
    }

    #[test]
    fn bad_routes() {
        for p in [
            "/git/h/o/r.git",
            "/git/h/o/r.git/",
            "/git/h/o/r/info/refs",
            "/git/h/../r.git/info/refs",
            "/git/h/o//r.git/info/refs",
            "/git/h/o/r.git/../x",
            "/git/h/o/r.git/%2e%2e/x",
            "/git/h/r.git/info/refs",
            "/git/h/o/.git/info/refs",
            "/x/h/o/r.git/info/refs",
            "/git/h@x/o/r.git/info/refs",
        ] {
            assert!(parse_route(p).is_none(), "{p}");
        }
    }

    #[test]
    fn framer_chunked_and_length() {
        let mut f = Framer::new(true, 0, true);
        let body = b"4\r\nabcd\r\n3;x=y\r\nefg\r\n0\r\n\r\nNEXT";
        assert_eq!(f.feed(&body[..5]), Ok(5));
        assert_eq!(f.feed(&body[5..]), Ok(body.len() - 5 - 4));
        assert!(f.done());
        assert_eq!(f.decoded, b"abcdefg");
        let mut f = Framer::new(false, 3, false);
        assert_eq!(f.feed(b"abcde"), Ok(3));
        assert!(f.done());
        assert!(Framer::new(true, 0, false).feed(b"zz\r\n").is_err());
    }
}
