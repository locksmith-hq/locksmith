//! MySQL / MariaDB relay: client/server protocol 4.1.
//!
//! The upstream greeting is read first, so the client sees the real server version and
//! capabilities (minus TLS and compression, which only apply to the upstream leg). The client is
//! offered `mysql_native_password` with a throwaway scramble and accepted whatever it answers.
//! Upstream: TLS per the target's mode (in-protocol `SSLRequest`), then `caching_sha2_password`
//! (fast auth, or full auth with the cleartext password over TLS) or `mysql_native_password`,
//! following auth-switch requests. After the upstream OK the client gets that OK and the streams
//! are spliced; ERR packets from the server are redacted.

use super::{Creds, Filter, Gate, MAX_AUTH_MSG, Relay, TlsMode, Up, is_loopback, other};
use ls_redact::Redactor;
use ring::digest;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use zeroize::Zeroizing;

const CONNECT_WITH_DB: u32 = 1 << 3;
const COMPRESS: u32 = 1 << 5;
const PROTOCOL_41: u32 = 1 << 9;
const SSL: u32 = 1 << 11;
const SECURE_CONNECTION: u32 = 1 << 15;
const PLUGIN_AUTH: u32 = 1 << 19;
const CONNECT_ATTRS: u32 = 1 << 20;
const PLUGIN_AUTH_LENENC: u32 = 1 << 21;
const ZSTD: u32 = 1 << 26;
const MFA: u32 = 1 << 28;
/// Capabilities that only make sense on the upstream leg (or that the relay does not speak).
const UPSTREAM_ONLY: u32 = SSL | COMPRESS | ZSTD | MFA;

const NATIVE: &str = "mysql_native_password";
const CACHING_SHA2: &str = "caching_sha2_password";
const CLEAR: &str = "mysql_clear_password";

fn read_packet(r: &mut impl Read) -> io::Result<(u8, Vec<u8>)> {
    let mut h = [0u8; 4];
    r.read_exact(&mut h)?;
    let n = u32::from_le_bytes([h[0], h[1], h[2], 0]) as usize;
    if n > MAX_AUTH_MSG {
        return Err(other("handshake packet too large"));
    }
    Ok((h[3], super::read_exact_vec(r, n)?))
}

fn packet(seq: u8, payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let n = payload.len() as u32;
    let mut p = Zeroizing::new(Vec::with_capacity(payload.len() + 4));
    p.extend_from_slice(&n.to_le_bytes()[..3]);
    p.push(seq);
    p.extend_from_slice(payload);
    p
}

fn write_packet(w: &mut impl Write, seq: u8, payload: &[u8]) -> io::Result<()> {
    w.write_all(&packet(seq, payload))?;
    w.flush()
}

/// ERR packet. `sqlstate: None` for the pre-handshake form (no `#XXXXX`).
fn err_payload(code: u16, sqlstate: Option<&str>, msg: &str) -> Vec<u8> {
    let mut p = vec![0xff];
    p.extend_from_slice(&code.to_le_bytes());
    if let Some(s) = sqlstate {
        p.push(b'#');
        p.extend_from_slice(s.as_bytes());
    }
    p.extend_from_slice(format!("Locksmith: {msg}").as_bytes());
    p
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, b) = self.0.split_at_checked(n)?;
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    /// NUL-terminated; a missing NUL takes the rest.
    fn cstr(&mut self) -> &'a [u8] {
        let i = self.0.iter().position(|b| *b == 0);
        let s = &self.0[..i.unwrap_or(self.0.len())];
        self.0 = &self.0[i.map_or(self.0.len(), |i| i + 1)..];
        s
    }
    fn lenenc(&mut self) -> Option<u64> {
        match self.u8()? {
            n @ 0..=250 => Some(n as u64),
            0xfc => self.u16().map(u64::from),
            0xfd => self
                .take(3)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], 0]) as u64),
            0xfe => self
                .take(8)
                .map(|b| u64::from_le_bytes(b.try_into().expect("8"))),
            _ => None,
        }
    }
}

struct Greeting {
    version: Vec<u8>,
    conn_id: u32,
    scramble: Vec<u8>,
    caps: u32,
    charset: u8,
    status: u16,
    reserved: Vec<u8>,
    plugin: String,
}

fn parse_greeting(p: &[u8]) -> Option<Greeting> {
    let mut c = Cursor(p);
    if c.u8()? != 10 {
        return None;
    }
    let version = c.cstr().to_vec();
    let conn_id = c.u32()?;
    let mut scramble = c.take(8)?.to_vec();
    c.u8()?;
    let lo = c.u16()? as u32;
    let charset = c.u8()?;
    let status = c.u16()?;
    let hi = c.u16()? as u32;
    let auth_len = c.u8()? as usize;
    let reserved = c.take(10)?.to_vec();
    let caps = lo | hi << 16;
    if caps & SECURE_CONNECTION != 0 {
        let n = auth_len.saturating_sub(8).max(13);
        let part = c.take(n.min(c.0.len()))?;
        scramble.extend_from_slice(part.strip_suffix(&[0]).unwrap_or(part));
    }
    let plugin = if caps & PLUGIN_AUTH != 0 {
        String::from_utf8_lossy(c.cstr()).into_owned()
    } else {
        NATIVE.into()
    };
    Some(Greeting {
        version,
        conn_id,
        scramble,
        caps,
        charset,
        status,
        reserved,
        plugin,
    })
}

/// The greeting the local client sees: upstream version, capabilities minus upstream-only ones,
/// a fresh random scramble, `mysql_native_password`.
fn client_greeting(g: &Greeting, caps: u32) -> Vec<u8> {
    let scramble: [u8; 20] = super::random();
    let scramble = scramble.map(|b| b % 94 + 33); // printable, no NUL
    let mut p = vec![10];
    p.extend_from_slice(&g.version);
    p.push(0);
    p.extend_from_slice(&g.conn_id.to_le_bytes());
    p.extend_from_slice(&scramble[..8]);
    p.push(0);
    p.extend_from_slice(&(caps as u16).to_le_bytes());
    p.push(g.charset);
    p.extend_from_slice(&g.status.to_le_bytes());
    p.extend_from_slice(&((caps >> 16) as u16).to_le_bytes());
    p.push(21);
    p.extend_from_slice(&g.reserved);
    p.extend_from_slice(&scramble[8..]);
    p.push(0);
    p.extend_from_slice(NATIVE.as_bytes());
    p.push(0);
    p
}

struct ClientHello {
    caps: u32,
    max_packet: u32,
    charset: u8,
    filler: Vec<u8>,
    database: Option<String>,
}

fn parse_client_hello(p: &[u8]) -> Option<ClientHello> {
    let mut c = Cursor(p);
    let caps = c.u32()?;
    let max_packet = c.u32()?;
    let charset = c.u8()?;
    let filler = c.take(23)?.to_vec();
    if caps & SSL != 0 && c.0.is_empty() {
        return None; // an SSLRequest: not offered on the local leg
    }
    c.cstr(); // user: ignored, the configured one is used
    if caps & PLUGIN_AUTH_LENENC != 0 {
        let n = c.lenenc()? as usize;
        c.take(n)?;
    } else if caps & SECURE_CONNECTION != 0 {
        let n = c.u8()? as usize;
        c.take(n)?;
    } else {
        c.cstr();
    }
    let database = (caps & CONNECT_WITH_DB != 0)
        .then(|| String::from_utf8_lossy(c.cstr()).into_owned())
        .filter(|d| !d.is_empty());
    Some(ClientHello {
        caps,
        max_packet,
        charset,
        filler,
        database,
    })
}

fn sha1(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut c = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    parts.iter().for_each(|p| c.update(p));
    Zeroizing::new(c.finish().as_ref().to_vec())
}

fn sha256(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut c = digest::Context::new(&digest::SHA256);
    parts.iter().for_each(|p| c.update(p));
    Zeroizing::new(c.finish().as_ref().to_vec())
}

fn xor(a: &[u8], b: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(a.iter().zip(b).map(|(x, y)| x ^ y).collect())
}

/// `SHA1(pw) XOR SHA1(scramble + SHA1(SHA1(pw)))`.
fn native_response(pw: &[u8], scramble: &[u8]) -> Zeroizing<Vec<u8>> {
    if pw.is_empty() {
        return Zeroizing::new(Vec::new());
    }
    let h1 = sha1(&[pw]);
    let h2 = sha1(&[&h1]);
    xor(&h1, &sha1(&[scramble, &h2]))
}

/// `SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) + scramble)`.
fn sha2_response(pw: &[u8], scramble: &[u8]) -> Zeroizing<Vec<u8>> {
    if pw.is_empty() {
        return Zeroizing::new(Vec::new());
    }
    let h1 = sha256(&[pw]);
    let h2 = sha256(&[&h1]);
    xor(&h1, &sha256(&[&h2, scramble]))
}

fn plugin_response(
    plugin: &str,
    pw: &[u8],
    scramble: &[u8],
    secure: bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let s = &scramble[..scramble.len().min(20)];
    match plugin {
        NATIVE => Ok(native_response(pw, s)),
        CACHING_SHA2 => Ok(sha2_response(pw, s)),
        CLEAR if secure => {
            let mut v = Zeroizing::new(pw.to_vec());
            v.push(0);
            Ok(v)
        }
        CLEAR => Err(other(
            "upstream asked for a cleartext password without TLS; refused",
        )),
        p => Err(other(&format!(
            "upstream authentication plugin {p} is not supported (use caching_sha2_password or mysql_native_password)"
        ))),
    }
}

/// Upstream OK payload, or a redacted ERR payload for the client.
type Outcome = Result<Vec<u8>, Vec<u8>>;

/// The upstream handshake. `Ok(Ok(ok_payload))`, or `Ok(Err(err_payload))` (already redacted)
/// for a server ERR the client should see.
fn authenticate(
    relay: &Relay,
    creds: &Creds,
    up: Up,
    g: &Greeting,
    hello: &ClientHello,
    red: &Redactor,
) -> io::Result<(Up, Outcome)> {
    let t = &relay.target;
    let tls = match t.tls {
        TlsMode::Disable => false,
        _ if g.caps & SSL != 0 => true,
        TlsMode::Prefer => false,
        TlsMode::Require => {
            return Err(other(
                "the upstream server does not offer TLS (tls = \"require\")",
            ));
        }
    };
    let mut caps = (hello.caps & g.caps & !UPSTREAM_ONLY & !CONNECT_ATTRS)
        | PROTOCOL_41
        | SECURE_CONNECTION
        | PLUGIN_AUTH
        | (g.caps & PLUGIN_AUTH_LENENC);
    let db = t.database.clone().or(hello.database.clone());
    if db.is_some() {
        caps |= CONNECT_WITH_DB;
    } else {
        caps &= !CONNECT_WITH_DB;
    }
    if tls {
        caps |= SSL;
    }
    let mut head = Vec::with_capacity(32);
    head.extend_from_slice(&caps.to_le_bytes());
    head.extend_from_slice(&hello.max_packet.to_le_bytes());
    head.push(hello.charset);
    head.extend_from_slice(&hello.filler);
    let mut seq = 1u8;
    let mut up = up;
    if tls {
        write_packet(&mut up, seq, &head)?;
        seq += 1;
        let Up::Plain(tcp) = up else {
            return Err(other("TLS negotiated twice"));
        };
        up = relay.tls(tcp, creds)?;
    }
    let mut plugin = g.plugin.clone();
    let mut scramble = g.scramble.clone();
    let mut p = Zeroizing::new(head);
    p.extend_from_slice(t.user.as_bytes());
    p.push(0);
    let secure = up.is_tls() || is_loopback(&t.host);
    // An unsupported initial plugin: answer as native and let the server switch.
    let auth = match plugin_response(&plugin, &creds.password, &scramble, secure) {
        Ok(a) => a,
        Err(_) => {
            plugin = NATIVE.into();
            native_response(&creds.password, &scramble[..scramble.len().min(20)])
        }
    };
    // Responses are < 251 bytes: a one-byte length works for both the length-encoded and the
    // SECURE_CONNECTION form.
    p.push(auth.len() as u8);
    p.extend_from_slice(&auth);
    if let Some(d) = &db {
        p.extend_from_slice(d.as_bytes());
        p.push(0);
    }
    p.extend_from_slice(plugin.as_bytes());
    p.push(0);
    write_packet(&mut up, seq, &p)?;
    loop {
        let (s, r) = read_packet(&mut up)?;
        seq = s.wrapping_add(1);
        match r.first() {
            Some(0x00) => return Ok((up, Ok(r))),
            Some(0xff) => return Ok((up, Err(red.redact_all(&r)))),
            Some(0xfe) if r.len() > 1 => {
                let mut c = Cursor(&r[1..]);
                plugin = String::from_utf8_lossy(c.cstr()).into_owned();
                let d = c.0;
                scramble = d.strip_suffix(&[0]).unwrap_or(d).to_vec();
                let a = plugin_response(&plugin, &creds.password, &scramble, up.is_tls())?;
                write_packet(&mut up, seq, &a)?;
            }
            Some(0x01) if plugin == CACHING_SHA2 && r.len() == 2 && r[1] == 3 => {} // fast auth OK
            Some(0x01) if plugin == CACHING_SHA2 && r.len() == 2 && r[1] == 4 => {
                if !up.is_tls() {
                    return Err(other(
                        "caching_sha2_password full authentication needs TLS upstream (set tls = \"require\"); the RSA key exchange is not supported",
                    ));
                }
                let mut v = Zeroizing::new(creds.password.to_vec());
                v.push(0);
                write_packet(&mut up, seq, &v)?;
            }
            _ => return Err(other("unexpected upstream packet during authentication")),
        }
    }
}

/// One accepted client connection.
pub fn serve(relay: &Relay, gate: &dyn Gate, mut c: TcpStream) -> io::Result<()> {
    c.set_read_timeout(Some(super::HANDSHAKE_TIMEOUT))?;
    c.set_write_timeout(Some(super::HANDSHAKE_TIMEOUT))?;
    let (peer, local) = (c.peer_addr()?, c.local_addr()?);
    let creds = match gate.admit(peer, local) {
        Ok(x) => x,
        Err(m) => return write_packet(&mut c, 0, &err_payload(1045, None, &m)),
    };
    let track = relay.track(&c)?;
    let red = creds.redactor();
    let fail = |c: &mut TcpStream, seq: u8, e: io::Error| {
        let m = red.redact_all(e.to_string().as_bytes());
        let m = format!(
            "upstream {} failed: {}",
            relay.target.name,
            String::from_utf8_lossy(&m)
        );
        let st = (seq > 0).then_some("08S01");
        write_packet(c, seq, &err_payload(2013, st, &m))
    };
    let tcp = match relay.connect_upstream() {
        Ok(t) => t,
        Err(e) => return fail(&mut c, 0, e),
    };
    track.add(&tcp)?;
    let mut up = Up::Plain(tcp);
    let (_, gp) = match read_packet(&mut up) {
        Ok(x) => x,
        Err(e) => return fail(&mut c, 0, e),
    };
    if gp.first() == Some(&0xff) {
        return write_packet(&mut c, 0, &red.redact_all(&gp));
    }
    let Some(g) = parse_greeting(&gp) else {
        return fail(&mut c, 0, other("unrecognized upstream greeting"));
    };
    let caps = (g.caps & !UPSTREAM_ONLY) | PLUGIN_AUTH | SECURE_CONNECTION;
    write_packet(&mut c, 0, &client_greeting(&g, caps))?;
    let (_, hp) = read_packet(&mut c)?;
    let Some(hello) = parse_client_hello(&hp) else {
        return write_packet(
            &mut c,
            2,
            &err_payload(
                1043,
                Some("08S01"),
                "bad handshake (TLS to the local relay is not supported; use --ssl-mode=DISABLED)",
            ),
        );
    };
    let (up, res) = match authenticate(relay, &creds, up, &g, &hello, &red) {
        Ok(x) => x,
        Err(e) => return fail(&mut c, 2, e),
    };
    drop(creds);
    match res {
        Ok(ok) => write_packet(&mut c, 2, &ok)?,
        Err(e) => return write_packet(&mut c, 2, &e),
    }
    super::splice(c, up, Box::new(MyFilter::new(red)))?;
    drop(track);
    Ok(())
}

/// Frames the server stream; ERR packets (payload starting 0xFF) are buffered, redacted and
/// re-framed, everything else passes through as it arrives.
pub(crate) struct MyFilter {
    red: Redactor,
    head: Vec<u8>,
    left: usize,
    held: Option<Vec<u8>>,
    /// The previous packet was 0xFFFFFF long: this one continues it (not a new message).
    cont: bool,
}

impl MyFilter {
    pub(crate) fn new(red: Redactor) -> Self {
        MyFilter {
            red,
            head: Vec::with_capacity(5),
            left: 0,
            held: None,
            cont: false,
        }
    }
}

fn len3(h: &[u8]) -> usize {
    u32::from_le_bytes([h[0], h[1], h[2], 0]) as usize
}

impl Filter for MyFilter {
    fn push(&mut self, mut d: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(d.len());
        loop {
            if self.left == 0 && self.held.is_none() {
                // The 4-byte header plus the first payload byte (to recognize ERR).
                let need = if self.head.len() < 4 || len3(&self.head) == 0 {
                    4
                } else {
                    5
                };
                if self.head.len() < need {
                    if d.is_empty() {
                        break;
                    }
                    let k = (need - self.head.len()).min(d.len());
                    self.head.extend_from_slice(&d[..k]);
                    d = &d[k..];
                    continue;
                }
                let n = len3(&self.head);
                let is_err = n > 0 && !self.cont && self.head[4] == 0xff && n < 0xff_ffff;
                self.cont = n == 0xff_ffff;
                if is_err {
                    self.held = Some(vec![0xff]);
                    self.left = n - 1;
                    if self.left == 0 {
                        self.finish(&mut out);
                    }
                } else {
                    out.extend_from_slice(&self.head);
                    self.head.clear();
                    self.left = n.saturating_sub(1);
                }
                continue;
            }
            if d.is_empty() {
                break;
            }
            let k = self.left.min(d.len());
            match &mut self.held {
                Some(h) => h.extend_from_slice(&d[..k]),
                None => out.extend_from_slice(&d[..k]),
            }
            self.left -= k;
            d = &d[k..];
            if self.left == 0 && self.held.is_some() {
                self.finish(&mut out);
            }
        }
        out
    }
}

impl MyFilter {
    fn finish(&mut self, out: &mut Vec<u8>) {
        if let Some(h) = self.held.take() {
            let seq = self.head[3];
            out.extend_from_slice(&packet(seq, &self.red.redact_all(&h)));
        }
        self.head.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{Closed, Open, target};
    use super::super::{Kind, Settings};
    use super::*;
    use std::net::TcpListener;
    use std::sync::Arc;

    const PW: &[u8] = b"my-sql-pw-777";

    fn greeting(plugin: &str, scramble: &[u8; 20], caps: u32) -> Vec<u8> {
        let mut p = vec![10];
        p.extend_from_slice(b"8.0.36-fake\0");
        p.extend_from_slice(&7u32.to_le_bytes());
        p.extend_from_slice(&scramble[..8]);
        p.push(0);
        p.extend_from_slice(&(caps as u16).to_le_bytes());
        p.push(45);
        p.extend_from_slice(&2u16.to_le_bytes());
        p.extend_from_slice(&((caps >> 16) as u16).to_le_bytes());
        p.push(21);
        p.extend_from_slice(&[0; 10]);
        p.extend_from_slice(&scramble[8..]);
        p.push(0);
        p.extend_from_slice(plugin.as_bytes());
        p.push(0);
        p
    }

    const SERVER_CAPS: u32 = PROTOCOL_41
        | SECURE_CONNECTION
        | PLUGIN_AUTH
        | PLUGIN_AUTH_LENENC
        | CONNECT_WITH_DB
        | CONNECT_ATTRS
        | (1 << 24);

    /// What the fake server does after reading the handshake response.
    #[derive(Clone, Copy)]
    enum Flow {
        Native,
        Sha2Fast,
        Sha2Full,
        SwitchToNative,
    }

    /// Fake server: greets, checks the response (user, db, scramble), answers per `flow`, then
    /// answers one COM_QUERY with an ERR echoing the query. Returns whether auth succeeded.
    fn fake_server(flow: Flow) -> (u16, std::thread::JoinHandle<bool>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let scr = *b"abcdefghijklmnopqrst";
            let plugin = match flow {
                Flow::Native => NATIVE,
                _ => CACHING_SHA2,
            };
            write_packet(&mut s, 0, &greeting(plugin, &scr, SERVER_CAPS)).unwrap();
            let (seq, p) = read_packet(&mut s).unwrap();
            assert_eq!(seq, 1);
            let mut c = Cursor(&p);
            let caps = c.u32().unwrap();
            assert_eq!(caps & (SSL | CONNECT_ATTRS), 0);
            c.take(28).unwrap();
            assert_eq!(c.cstr(), b"app");
            let n = c.lenenc().unwrap() as usize;
            let auth = c.take(n).unwrap().to_vec();
            assert_eq!(c.cstr(), b"appdb");
            assert_eq!(c.cstr(), plugin.as_bytes());
            let ok = vec![0u8, 0, 0, 2, 0, 0, 0];
            let good = match flow {
                Flow::Native => auth == *native_response(PW, &scr),
                Flow::Sha2Fast => {
                    let g = auth == *sha2_response(PW, &scr);
                    if g {
                        write_packet(&mut s, 2, &[1, 3]).unwrap();
                    }
                    g
                }
                Flow::Sha2Full => {
                    write_packet(&mut s, 2, &[1, 4]).unwrap();
                    return false;
                }
                Flow::SwitchToNative => {
                    let scr2 = *b"ZYXWVUTSRQPONMLKJIHG";
                    let mut sw = vec![0xfe];
                    sw.extend_from_slice(NATIVE.as_bytes());
                    sw.push(0);
                    sw.extend_from_slice(&scr2);
                    sw.push(0);
                    write_packet(&mut s, 2, &sw).unwrap();
                    let (seq, a) = read_packet(&mut s).unwrap();
                    assert_eq!(seq, 3);
                    a == *native_response(PW, &scr2)
                }
            };
            if !good {
                let e = err_payload(1045, Some("28000"), "Access denied");
                write_packet(&mut s, 2, &e).unwrap();
                return false;
            }
            write_packet(&mut s, 2, &ok).unwrap();
            let (seq, q) = read_packet(&mut s).unwrap();
            assert_eq!((seq, q[0]), (0, 3));
            let mut e = vec![0xff, 0x28, 0x04, b'#'];
            e.extend_from_slice(b"42000near '");
            e.extend_from_slice(&q[1..]);
            write_packet(&mut s, 1, &e).unwrap();
            true
        });
        (port, h)
    }

    /// A client: read the greeting, answer with an empty password and another user.
    fn client(addr: std::net::SocketAddr) -> (TcpStream, Vec<u8>) {
        let mut c = TcpStream::connect(addr).unwrap();
        let (seq, g) = read_packet(&mut c).unwrap();
        assert_eq!(seq, 0);
        let g = parse_greeting(&g).unwrap();
        assert_eq!(g.plugin, NATIVE);
        assert_eq!(g.version, b"8.0.36-fake");
        assert_eq!(g.caps & SSL, 0);
        let caps = PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH | (1 << 24);
        let mut p = caps.to_le_bytes().to_vec();
        p.extend_from_slice(&(1u32 << 24).to_le_bytes());
        p.push(45);
        p.extend_from_slice(&[0; 23]);
        p.extend_from_slice(b"root\0");
        p.push(0);
        p.extend_from_slice(b"mysql_native_password\0");
        write_packet(&mut c, 1, &p).unwrap();
        let (seq, r) = read_packet(&mut c).unwrap();
        assert_eq!(seq, 2);
        (c, r)
    }

    fn relay(port: u16, gate: Arc<dyn Gate>) -> Arc<Relay> {
        Relay::start(
            target(Kind::Mysql, port, TlsMode::Disable),
            "ls_t".into(),
            gate,
            Settings::default(),
        )
        .unwrap()
    }

    fn query_echo_is_redacted(mut c: TcpStream) {
        let mut q = vec![3u8];
        q.extend_from_slice(b"select 'my-sql-pw-777'");
        write_packet(&mut c, 0, &q).unwrap();
        let (seq, e) = read_packet(&mut c).unwrap();
        assert_eq!((seq, e[0]), (1, 0xff));
        let s = String::from_utf8_lossy(&e);
        assert!(
            !s.contains("my-sql-pw-777") && s.contains("[REDACTED:DB_PW]"),
            "{s}"
        );
    }

    #[test]
    fn native_password() {
        let (port, srv) = fake_server(Flow::Native);
        let r = relay(port, Arc::new(Open(PW)));
        let (c, ok) = client(r.addr());
        assert_eq!(ok[0], 0, "{:?}", String::from_utf8_lossy(&ok));
        query_echo_is_redacted(c);
        assert!(srv.join().unwrap());
    }

    #[test]
    fn caching_sha2_fast_auth() {
        let (port, srv) = fake_server(Flow::Sha2Fast);
        let r = relay(port, Arc::new(Open(PW)));
        let (c, ok) = client(r.addr());
        assert_eq!(ok[0], 0, "{:?}", String::from_utf8_lossy(&ok));
        query_echo_is_redacted(c);
        assert!(srv.join().unwrap());
    }

    #[test]
    fn auth_switch_to_native() {
        let (port, srv) = fake_server(Flow::SwitchToNative);
        let r = relay(port, Arc::new(Open(PW)));
        let (c, ok) = client(r.addr());
        assert_eq!(ok[0], 0, "{:?}", String::from_utf8_lossy(&ok));
        query_echo_is_redacted(c);
        assert!(srv.join().unwrap());
    }

    #[test]
    fn caching_sha2_full_auth_needs_tls() {
        let (port, srv) = fake_server(Flow::Sha2Full);
        let r = relay(port, Arc::new(Open(PW)));
        let (_c, e) = client(r.addr());
        let s = String::from_utf8_lossy(&e);
        assert_eq!(e[0], 0xff);
        assert!(s.contains("needs TLS"), "{s}");
        assert!(!srv.join().unwrap());
    }

    #[test]
    fn refused_peer_never_reaches_upstream() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let r = relay(l.local_addr().unwrap().port(), Arc::new(Closed));
        let mut c = TcpStream::connect(r.addr()).unwrap();
        let (seq, e) = read_packet(&mut c).unwrap();
        assert_eq!((seq, e[0]), (0, 0xff));
        assert!(String::from_utf8_lossy(&e).contains("outside the session"));
        assert!(l.accept().is_err());
    }

    #[test]
    fn filter_keeps_framing_across_splits() {
        let red = Redactor::new(&[ls_redact::Secret::new("K", b"secret-value-1")]);
        let mut f = MyFilter::new(red);
        let mut s = packet(1, &[1, 2, 3]).to_vec();
        s.extend_from_slice(&packet(2, &[]));
        s.extend_from_slice(&packet(3, b"\xff\x01\x00#HY000oops secret-value-1"));
        s.extend_from_slice(&packet(4, &[0xfe, 0, 0]));
        let mut out = Vec::new();
        for b in &s {
            out.extend(f.push(std::slice::from_ref(b)));
        }
        let mut r = &out[..];
        let mut got = Vec::new();
        while let Ok((seq, p)) = read_packet(&mut r) {
            got.push((seq, p));
        }
        assert_eq!(got.len(), 4);
        assert_eq!(got[0], (1, vec![1, 2, 3]));
        assert_eq!(got[1], (2, vec![]));
        let e = String::from_utf8_lossy(&got[2].1);
        assert!(
            e.contains("[REDACTED:K]") && !e.contains("secret-value"),
            "{e}"
        );
        assert_eq!(got[3], (4, vec![0xfe, 0, 0]));
    }
}
