//! Redis relay. Redis has no server greeting, so the relay authenticates first: it sends
//! `AUTH [user] <password>` upstream (TLS per the target's mode; Redis cannot negotiate TLS, so
//! `prefer` means `require`), swallows the `+OK`, then splices. An upstream error is redacted and
//! shown to the client as a RESP error. Later traffic passes verbatim (RESP is not framed for
//! redaction; the relay never sends the password after AUTH).

use super::{Gate, Raw, Relay, TlsMode, Up, other};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use zeroize::Zeroizing;

fn bulk(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(format!("${}\r\n", b.len()).as_bytes());
    out.extend_from_slice(b);
    out.extend_from_slice(b"\r\n");
}

/// RESP `AUTH` command (zeroized: it holds the password).
fn auth_command(user: &str, pw: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(Vec::new());
    let parts: Vec<&[u8]> = if user.is_empty() {
        vec![b"AUTH", pw]
    } else {
        vec![b"AUTH", user.as_bytes(), pw]
    };
    v.extend_from_slice(format!("*{}\r\n", parts.len()).as_bytes());
    for p in parts {
        bulk(&mut v, p);
    }
    v
}

/// One CRLF-terminated line (at most 64 KiB), byte by byte so nothing after it is consumed.
fn read_line(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while !line.ends_with(b"\r\n") {
        if line.len() > 64 * 1024 {
            return Err(other("upstream reply too long"));
        }
        if r.read(&mut b)? == 0 {
            return Err(other("upstream closed the connection"));
        }
        line.push(b[0]);
    }
    Ok(line)
}

fn resp_error(msg: &str) -> Vec<u8> {
    format!("-ERR Locksmith: {}\r\n", msg.replace(['\r', '\n'], " ")).into_bytes()
}

/// One accepted client connection.
pub fn serve(relay: &Relay, gate: &dyn Gate, mut c: TcpStream) -> io::Result<()> {
    c.set_read_timeout(Some(super::HANDSHAKE_TIMEOUT))?;
    c.set_write_timeout(Some(super::HANDSHAKE_TIMEOUT))?;
    let (peer, local) = (c.peer_addr()?, c.local_addr()?);
    let creds = match gate.admit(peer, local) {
        Ok(x) => x,
        Err(m) => return c.write_all(&resp_error(&m)),
    };
    let track = relay.track(&c)?;
    let red = creds.redactor();
    let fail = |c: &mut TcpStream, e: io::Error| {
        let m = red.redact_all(e.to_string().as_bytes());
        c.write_all(&resp_error(&format!(
            "upstream {} failed: {}",
            relay.target.name,
            String::from_utf8_lossy(&m)
        )))
    };
    let mut up = match relay.connect_upstream().and_then(|tcp| {
        track.add(&tcp)?;
        match relay.target.tls {
            TlsMode::Disable => Ok(Up::Plain(tcp)),
            TlsMode::Require | TlsMode::Prefer => relay.tls(tcp, &creds),
        }
    }) {
        Ok(u) => u,
        Err(e) => return fail(&mut c, e),
    };
    if !creds.password.is_empty() {
        let r = up
            .write_all(&auth_command(&relay.target.user, &creds.password))
            .and_then(|_| up.flush())
            .and_then(|_| read_line(&mut up));
        match r {
            Ok(l) if l.starts_with(b"+") => {}
            Ok(l) if l.starts_with(b"-") => return c.write_all(&red.redact_all(&l)),
            Ok(_) => return fail(&mut c, other("unexpected reply to AUTH")),
            Err(e) => return fail(&mut c, e),
        }
    }
    drop(creds);
    super::splice(c, up, Box::new(Raw))?;
    drop(track);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{Closed, Open, target};
    use super::super::{Kind, Settings};
    use super::*;
    use std::io::BufRead;
    use std::net::TcpListener;
    use std::sync::Arc;

    #[test]
    fn auth_command_encoding() {
        assert_eq!(
            &auth_command("", b"pw")[..],
            b"*2\r\n$4\r\nAUTH\r\n$2\r\npw\r\n"
        );
        assert_eq!(
            &auth_command("app", b"p w")[..],
            b"*3\r\n$4\r\nAUTH\r\n$3\r\napp\r\n$3\r\np w\r\n"
        );
    }

    #[test]
    fn injects_auth_and_swallows_reply() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let srv = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut r = std::io::BufReader::new(s.try_clone().unwrap());
            let mut w = s;
            let mut got = String::new();
            for _ in 0..7 {
                r.read_line(&mut got).unwrap();
            }
            assert_eq!(got, "*3\r\n$4\r\nAUTH\r\n$3\r\napp\r\n$5\r\nrd-pw\r\n");
            w.write_all(b"+OK\r\n").unwrap();
            let mut ping = String::new();
            r.read_line(&mut ping).unwrap();
            assert_eq!(ping, "PING\r\n");
            w.write_all(b"+PONG\r\n").unwrap();
        });
        let r = Relay::start(
            target(Kind::Redis, port, TlsMode::Disable),
            "ls_t".into(),
            Arc::new(Open(b"rd-pw")),
            Settings::default(),
        )
        .unwrap();
        let mut c = TcpStream::connect(r.addr()).unwrap();
        c.write_all(b"PING\r\n").unwrap();
        let mut buf = [0u8; 7];
        c.read_exact(&mut buf).unwrap();
        assert_eq!(
            &buf, b"+PONG\r\n",
            "the AUTH reply must not reach the client"
        );
        srv.join().unwrap();
    }

    #[test]
    fn refused_peer_gets_resp_error() {
        let r = Relay::start(
            target(Kind::Redis, 1, TlsMode::Disable),
            "ls_t".into(),
            Arc::new(Closed),
            Settings::default(),
        )
        .unwrap();
        let mut c = TcpStream::connect(r.addr()).unwrap();
        let mut s = String::new();
        c.read_to_string(&mut s).unwrap();
        assert!(s.starts_with("-ERR Locksmith: process is outside"), "{s}");
    }
}
