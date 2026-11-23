//! Postgres relay: frontend/backend protocol 3.x.
//!
//! Client side: answer `SSLRequest` and `GSSENCRequest` with `N` (the local leg is loopback and
//! plain), forward `CancelRequest` upstream, and accept the `StartupMessage` without asking for a
//! password, but only once the gate admits the peer. Upstream: TLS per the target's mode
//! (`SSLRequest`), then SCRAM-SHA-256, md5, or cleartext (TLS or loopback only) with the vault
//! password. After the upstream `AuthenticationOk` the client gets its own `AuthenticationOk` and
//! the streams are spliced; `ErrorResponse`/`NoticeResponse` from the server are redacted.

use super::{
    Creds, Filter, Gate, MAX_AUTH_MSG, Relay, TlsMode, Up, is_loopback, other, read_exact_vec,
    scram,
};
use ls_redact::Redactor;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use zeroize::Zeroizing;

const SSL_REQUEST: u32 = 80_877_103;
const GSSENC_REQUEST: u32 = 80_877_104;
const CANCEL_REQUEST: u32 = 80_877_102;
const AUTH_OK: [u8; 9] = [b'R', 0, 0, 0, 8, 0, 0, 0, 0];

/// The client's first real packet.
enum Startup {
    /// Protocol version and `name=value` parameters.
    Params(u32, Vec<(String, String)>),
    /// The whole cancel packet (length included), forwarded verbatim.
    Cancel(Vec<u8>),
}

/// Read until a StartupMessage or CancelRequest, declining TLS and GSS encryption.
fn read_startup(c: &mut TcpStream) -> io::Result<Startup> {
    for _ in 0..4 {
        let mut len = [0u8; 4];
        c.read_exact(&mut len)?;
        let n = u32::from_be_bytes(len) as usize;
        if !(8..=10_000).contains(&n) {
            return Err(other("bad startup packet length"));
        }
        let body = read_exact_vec(c, n - 4)?;
        let code = u32::from_be_bytes(body[..4].try_into().expect("4 bytes"));
        match code {
            SSL_REQUEST | GSSENC_REQUEST => c.write_all(b"N")?,
            CANCEL_REQUEST => {
                let mut p = len.to_vec();
                p.extend_from_slice(&body);
                return Ok(Startup::Cancel(p));
            }
            v if v >> 16 == 3 => {
                let mut params = Vec::new();
                let mut it = body[4..].split(|b| *b == 0);
                while let (Some(k), Some(v)) = (it.next(), it.next()) {
                    if k.is_empty() {
                        break;
                    }
                    params.push((
                        String::from_utf8_lossy(k).into_owned(),
                        String::from_utf8_lossy(v).into_owned(),
                    ));
                }
                return Ok(Startup::Params(v, params));
            }
            _ => {
                let _ = send_error(c, "0A000", "unsupported frontend protocol");
                return Err(other("unsupported protocol"));
            }
        }
    }
    Err(other("too many negotiation requests"))
}

fn error_response(code: &str, msg: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (t, v) in [(b'S', "FATAL"), (b'V', "FATAL"), (b'C', code), (b'M', msg)] {
        body.push(t);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    frame(b'E', &body)
}

fn send_error(c: &mut TcpStream, code: &str, msg: &str) -> io::Result<()> {
    c.write_all(&error_response(code, &format!("Locksmith: {msg}")))
}

fn frame(t: u8, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(body.len() + 5);
    m.push(t);
    m.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
    m.extend_from_slice(body);
    m
}

/// A zeroized message (holds password material).
fn frame_z(t: u8, body: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(frame(t, body))
}

fn read_msg(r: &mut impl Read) -> io::Result<(u8, Vec<u8>)> {
    let mut h = [0u8; 5];
    r.read_exact(&mut h)?;
    let n = u32::from_be_bytes(h[1..5].try_into().expect("4 bytes")) as usize;
    if !(4..=MAX_AUTH_MSG).contains(&n) {
        return Err(other("bad upstream message length"));
    }
    Ok((h[0], read_exact_vec(r, n - 4)?))
}

/// Redact the text of an `E`/`N` message body and re-frame it.
fn scrub(t: u8, body: &[u8], r: &Redactor) -> Vec<u8> {
    frame(t, &r.redact_all(body))
}

/// Open the upstream leg: TCP, then `SSLRequest` unless TLS is disabled.
fn open(relay: &Relay, creds: &Creds) -> io::Result<Up> {
    let mut tcp = relay.connect_upstream()?;
    let mode = relay.target.tls;
    if mode == TlsMode::Disable {
        return Ok(Up::Plain(tcp));
    }
    tcp.write_all(&8u32.to_be_bytes())?;
    tcp.write_all(&SSL_REQUEST.to_be_bytes())?;
    let mut a = [0u8; 1];
    tcp.read_exact(&mut a)?;
    match (a[0], mode) {
        (b'S', _) => relay.tls(tcp, creds),
        (b'N', TlsMode::Prefer) => Ok(Up::Plain(tcp)),
        (b'N', _) => Err(other(
            "the upstream server does not offer TLS (tls = \"require\")",
        )),
        _ => Err(other("unexpected upstream reply to SSLRequest")),
    }
}

/// Run upstream authentication. On success returns the open, authenticated leg. `Err(Some(m))`
/// is a server message (already redacted) to pass to the client.
fn authenticate(
    relay: &Relay,
    creds: &Creds,
    up: &mut Up,
    version: u32,
    params: &[(String, String)],
    client: &mut TcpStream,
    red: &Redactor,
) -> io::Result<Result<(), Vec<u8>>> {
    let t = &relay.target;
    let client_db = params
        .iter()
        .find(|(k, _)| k == "database")
        .map(|(_, v)| v.clone());
    let db = t.database.clone().or(client_db).unwrap_or(t.user.clone());
    let mut body = version.to_be_bytes().to_vec();
    let mut put = |k: &str, v: &str| {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    };
    put("user", &t.user);
    put("database", &db);
    for (k, v) in params {
        if k != "user" && k != "database" {
            put(k, v);
        }
    }
    body.push(0);
    let mut m = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    m.extend_from_slice(&body);
    up.write_all(&m)?;
    up.flush()?;

    let mut sasl: Option<scram::Client> = None;
    loop {
        let (ty, b) = read_msg(up)?;
        match ty {
            b'E' => return Ok(Err(scrub(b'E', &b, red))),
            b'N' => client.write_all(&scrub(b'N', &b, red))?,
            // NegotiateProtocolVersion: the client must see it.
            b'v' => client.write_all(&frame(b'v', &b))?,
            b'R' if b.len() >= 4 => {
                let code = u32::from_be_bytes(b[..4].try_into().expect("4 bytes"));
                let data = &b[4..];
                match code {
                    0 => return Ok(Ok(())),
                    3 => {
                        if !up.is_tls() && !is_loopback(&t.host) {
                            return Err(other(
                                "upstream asked for a cleartext password without TLS; refused",
                            ));
                        }
                        let mut p = Zeroizing::new(creds.password.to_vec());
                        p.push(0);
                        up.write_all(&frame_z(b'p', &p))?;
                    }
                    5 if data.len() == 4 => {
                        up.write_all(&frame_z(
                            b'p',
                            &md5_password(&creds.password, &t.user, data),
                        ))?;
                    }
                    10 => {
                        let mechs: Vec<&[u8]> = data.split(|b| *b == 0).collect();
                        if !mechs.contains(&&b"SCRAM-SHA-256"[..]) {
                            return Err(other("upstream offers no supported SASL mechanism"));
                        }
                        let c = scram::Client::new("");
                        let first = c.first_message();
                        let mut p = b"SCRAM-SHA-256\0".to_vec();
                        p.extend_from_slice(&(first.len() as u32).to_be_bytes());
                        p.extend_from_slice(first.as_bytes());
                        up.write_all(&frame(b'p', &p))?;
                        sasl = Some(c);
                    }
                    11 => {
                        let c = sasl.as_mut().ok_or_else(|| other("SASL out of order"))?;
                        let f = c
                            .final_message(&creds.password, data)
                            .map_err(|e| other(&e))?;
                        up.write_all(&frame_z(b'p', f.as_bytes()))?;
                    }
                    12 => {
                        let c = sasl.as_ref().ok_or_else(|| other("SASL out of order"))?;
                        c.verify(data).map_err(|e| other(&e))?;
                    }
                    _ => {
                        return Err(other(
                            "upstream asked for an unsupported authentication method",
                        ));
                    }
                }
                up.flush()?;
            }
            _ => return Err(other("unexpected upstream message during authentication")),
        }
    }
}

/// `"md5" + hex(md5(hex(md5(password + user)) + salt))` with a trailing NUL.
/// Sans-IO helper shared with the gateway (D3).
pub fn md5_password(pw: &[u8], user: &str, salt: &[u8]) -> Zeroizing<Vec<u8>> {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(pw);
    h.update(user.as_bytes());
    let inner = Zeroizing::new(hex(&h.finalize()));
    let mut h = Md5::new();
    h.update(inner.as_bytes());
    h.update(salt);
    let mut out = Zeroizing::new(b"md5".to_vec());
    out.extend_from_slice(hex(&h.finalize()).as_bytes());
    out.push(0);
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One accepted client connection.
pub fn serve(relay: &Relay, gate: &dyn Gate, mut c: TcpStream) -> io::Result<()> {
    c.set_read_timeout(Some(super::HANDSHAKE_TIMEOUT))?;
    c.set_write_timeout(Some(super::HANDSHAKE_TIMEOUT))?;
    let (peer, local) = (c.peer_addr()?, c.local_addr()?);
    let startup = read_startup(&mut c)?;
    let creds = match gate.admit(peer, local) {
        Ok(x) => x,
        Err(m) => return send_error(&mut c, "28000", &m),
    };
    let track = relay.track(&c)?;
    let red = creds.redactor();
    let (version, params) = match startup {
        Startup::Cancel(p) => {
            // Best effort, like the server: no reply either way.
            if let Ok(mut up) = open(relay, &creds) {
                let _ = up.write_all(&p).and_then(|_| up.flush());
            }
            return Ok(());
        }
        Startup::Params(v, p) => (v, p),
    };
    let mut up = match open(relay, &creds) {
        Ok(u) => u,
        Err(e) => {
            let m = red.redact_all(e.to_string().as_bytes());
            return send_error(
                &mut c,
                "08001",
                &format!(
                    "cannot reach upstream {}: {}",
                    relay.target.name,
                    String::from_utf8_lossy(&m)
                ),
            );
        }
    };
    track.add(up.tcp())?;
    match authenticate(relay, &creds, &mut up, version, &params, &mut c, &red) {
        Ok(Ok(())) => {}
        Ok(Err(msg)) => return c.write_all(&msg),
        Err(e) => {
            let m = red.redact_all(e.to_string().as_bytes());
            return send_error(
                &mut c,
                "28000",
                &format!(
                    "upstream authentication for {} failed: {}",
                    relay.target.name,
                    String::from_utf8_lossy(&m)
                ),
            );
        }
    }
    drop(creds);
    c.write_all(&AUTH_OK)?;
    super::splice(c, up, Box::new(PgFilter::new(red)))?;
    drop(track);
    Ok(())
}

/// Frames the backend stream; `E` and `N` messages are buffered, redacted and re-framed, all
/// others pass through as they arrive.
pub(crate) struct PgFilter {
    red: Redactor,
    head: Vec<u8>,
    /// Bytes of the current message body still to come.
    left: usize,
    /// Buffered body of an E/N message (its type in `head[0]`).
    held: Option<Vec<u8>>,
}

impl PgFilter {
    pub(crate) fn new(red: Redactor) -> Self {
        PgFilter {
            red,
            head: Vec::with_capacity(5),
            left: 0,
            held: None,
        }
    }
}

impl Filter for PgFilter {
    fn push(&mut self, mut d: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(d.len());
        while !d.is_empty() {
            if self.left == 0 && self.held.is_none() {
                let need = 5 - self.head.len();
                let k = need.min(d.len());
                self.head.extend_from_slice(&d[..k]);
                d = &d[k..];
                if self.head.len() < 5 {
                    break;
                }
                let n = (u32::from_be_bytes(self.head[1..5].try_into().expect("4 bytes")) as usize)
                    .saturating_sub(4);
                let scrub = matches!(self.head[0], b'E' | b'N') && n <= MAX_AUTH_MSG;
                if scrub {
                    self.held = Some(Vec::with_capacity(n));
                    self.left = n;
                } else {
                    out.extend_from_slice(&self.head);
                    self.head.clear();
                    self.left = n;
                }
                if n == 0 {
                    self.finish(&mut out);
                }
                continue;
            }
            let k = self.left.min(d.len());
            match &mut self.held {
                Some(h) => h.extend_from_slice(&d[..k]),
                None => out.extend_from_slice(&d[..k]),
            }
            self.left -= k;
            d = &d[k..];
            if self.left == 0 {
                self.finish(&mut out);
            }
        }
        out
    }
}

impl PgFilter {
    fn finish(&mut self, out: &mut Vec<u8>) {
        if let Some(h) = self.held.take() {
            out.extend_from_slice(&scrub(self.head[0], &h, &self.red));
        }
        self.head.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{Closed, Open, target};
    use super::super::{Kind, Settings};
    use super::*;
    use ls_redact::Secret;
    use std::net::TcpListener;
    use std::sync::Arc;

    fn startup(user: &str, db: &str) -> Vec<u8> {
        let mut b = 196_608u32.to_be_bytes().to_vec();
        for (k, v) in [("user", user), ("database", db), ("application_name", "t")] {
            b.extend_from_slice(k.as_bytes());
            b.push(0);
            b.extend_from_slice(v.as_bytes());
            b.push(0);
        }
        b.push(0);
        let mut m = ((b.len() + 4) as u32).to_be_bytes().to_vec();
        m.extend_from_slice(&b);
        m
    }

    #[test]
    fn filter_redacts_errors_and_keeps_framing() {
        let red = Redactor::new(&[Secret::new("PG_PW", b"hunter2-secret-pw")]);
        let mut f = PgFilter::new(red);
        let mut stream = frame(b'D', b"\x00\x01\x00\x00\x00\x03abc");
        stream.extend(error_response("XX000", "bad value hunter2-secret-pw here"));
        stream.extend(frame(b'Z', b"I"));
        // Feed one byte at a time: framing must survive any split.
        let mut out = Vec::new();
        for b in &stream {
            out.extend(f.push(std::slice::from_ref(b)));
        }
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("hunter2"), "{s}");
        assert!(s.contains("[REDACTED:PG_PW]"));
        // Re-parse: D, E, Z with consistent lengths.
        let mut r = &out[..];
        let types: Vec<u8> = std::iter::from_fn(|| read_msg(&mut r).ok().map(|(t, _)| t)).collect();
        assert_eq!(types, b"DEZ");
    }

    #[test]
    fn md5_matches_libpq() {
        // Computed with Python's hashlib: "md5" + md5(md5("secret" + "app").hex + salt).hex.
        let got = md5_password(b"secret", "app", &[1, 2, 3, 4]);
        assert_eq!(&got[..], b"md5911f527656472583a006e7727877b33e\0");
    }

    /// Outside the session: an ErrorResponse, no upstream contact.
    #[test]
    fn refused_peer_gets_error_response() {
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = up.local_addr().unwrap().port();
        up.set_nonblocking(true).unwrap();
        let r = Relay::start(
            target(Kind::Postgres, port, TlsMode::Disable),
            "ls_t".into(),
            Arc::new(Closed),
            Settings::default(),
        )
        .unwrap();
        let mut c = TcpStream::connect(r.addr()).unwrap();
        c.write_all(&8u32.to_be_bytes()).unwrap();
        c.write_all(&SSL_REQUEST.to_be_bytes()).unwrap();
        let mut a = [0u8; 1];
        c.read_exact(&mut a).unwrap();
        assert_eq!(&a, b"N");
        c.write_all(&startup("me", "x")).unwrap();
        let (t, b) = read_msg(&mut c).unwrap();
        assert_eq!(t, b'E');
        assert!(String::from_utf8_lossy(&b).contains("outside the session"));
        assert!(up.accept().is_err(), "upstream was contacted");
    }

    /// md5 upstream (plain loopback): the relay authenticates with the vault password, forces
    /// the configured user and database, and relays post-auth messages.
    #[test]
    fn md5_upstream_then_splice() {
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = up.local_addr().unwrap().port();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = up.accept().unwrap();
            let mut len = [0u8; 4];
            s.read_exact(&mut len).unwrap();
            let body = read_exact_vec(&mut s, u32::from_be_bytes(len) as usize - 4).unwrap();
            let text = String::from_utf8_lossy(&body).into_owned();
            assert!(
                text.contains("user\0app\0database\0appdb\0application_name\0t\0"),
                "{text:?}"
            );
            s.write_all(&frame(b'R', &[0, 0, 0, 5, 9, 8, 7, 6]))
                .unwrap();
            let (t, p) = read_msg(&mut s).unwrap();
            assert_eq!(t, b'p');
            let ok = p == *md5_password(b"pw-123", "app", &[9, 8, 7, 6]);
            if !ok {
                s.write_all(&error_response("28P01", "password authentication failed"))
                    .unwrap();
                return false;
            }
            s.write_all(&AUTH_OK).unwrap();
            s.write_all(&frame(b'S', b"server_version\x0016\x00"))
                .unwrap();
            s.write_all(&frame(b'Z', b"I")).unwrap();
            let (t, q) = read_msg(&mut s).unwrap();
            assert_eq!(t, b'Q');
            s.write_all(&error_response(
                "42000",
                &format!("echo {}", String::from_utf8_lossy(&q)),
            ))
            .unwrap();
            true
        });
        let r = Relay::start(
            target(Kind::Postgres, port, TlsMode::Disable),
            "ls_t".into(),
            Arc::new(Open(b"pw-123")),
            Settings::default(),
        )
        .unwrap();
        let mut c = TcpStream::connect(r.addr()).unwrap();
        c.write_all(&startup("someone-else", "otherdb")).unwrap();
        let (t, b) = read_msg(&mut c).unwrap();
        assert_eq!((t, b.as_slice()), (b'R', &[0u8, 0, 0, 0][..]));
        assert_eq!(read_msg(&mut c).unwrap().0, b'S');
        assert_eq!(read_msg(&mut c).unwrap().0, b'Z');
        c.write_all(&frame(b'Q', b"select 'pw-123'\0")).unwrap();
        let (t, b) = read_msg(&mut c).unwrap();
        assert_eq!(t, b'E');
        let s = String::from_utf8_lossy(&b);
        assert!(
            !s.contains("pw-123") && s.contains("[REDACTED:DB_PW]"),
            "{s}"
        );
        assert!(srv.join().unwrap(), "upstream rejected the md5 response");
        let t = std::time::Instant::now();
        while r.open_connections() > 0 && t.elapsed().as_secs() < 5 {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(r.open_connections(), 0);
    }
}
