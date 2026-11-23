//! Database relays (M6 design D5, D7): a password-less loopback listener per session and target.
//!
//! The relay speaks the database's own handshake to the local client and accepts it without a
//! password, but only after the daemon's [`Gate`] has checked that every process holding the
//! client socket is inside the lease's session tree. It then authenticates upstream with the vault
//! password (or mTLS client certificate), over TLS by default, and splices the two streams.
//! Server error and notice messages are scrubbed through the redactor on the way back.
//!
//! Synchronous like the Git forwarder: one thread per direction per connection, no tokio. Every
//! accepted socket and every upstream socket is registered with its [`Relay`], so
//! [`Relay::close`] (revoke, expiry, session end) shuts down both legs at once. Nothing here logs,
//! and the password never reaches a client-visible message.

pub mod mysql;
pub mod postgres;
pub mod redis;
pub mod scram;

use ls_redact::{Redactor, Secret};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use zeroize::Zeroizing;

/// Handshake phase only; a relayed query may run for hours.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest message accepted while authenticating (either side).
const MAX_AUTH_MSG: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Postgres,
    Mysql,
    Redis,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        match s.to_ascii_lowercase().as_str() {
            "postgres" | "postgresql" => Some(Kind::Postgres),
            "mysql" | "mariadb" => Some(Kind::Mysql),
            "redis" => Some(Kind::Redis),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Postgres => "postgres",
            Kind::Mysql => "mysql",
            Kind::Redis => "redis",
        }
    }
    pub fn default_port(self) -> u16 {
        match self {
            Kind::Postgres => 5432,
            Kind::Mysql => 3306,
            Kind::Redis => 6379,
        }
    }
}

/// Upstream TLS policy. TLS, when used, always verifies the server certificate and name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// TLS or fail.
    Require,
    /// TLS when the server offers it (Postgres and MySQL negotiate in-protocol), else plain.
    /// Redis has no negotiation, so `prefer` means `require` there.
    Prefer,
    Disable,
}

impl TlsMode {
    pub fn parse(s: &str) -> Option<TlsMode> {
        match s.to_ascii_lowercase().as_str() {
            "require" => Some(TlsMode::Require),
            "prefer" => Some(TlsMode::Prefer),
            "disable" => Some(TlsMode::Disable),
            _ => None,
        }
    }

    /// `require` for remote hosts. Loopback upstreams default to `prefer` (Postgres, MySQL) or
    /// `disable` (Redis, which cannot negotiate).
    pub fn default_for(kind: Kind, host: &str) -> TlsMode {
        match (is_loopback(host), kind) {
            (false, _) => TlsMode::Require,
            (true, Kind::Redis) => TlsMode::Disable,
            (true, _) => TlsMode::Prefer,
        }
    }
}

pub fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// One configured upstream (from `[db.<name>]`; names only, never values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub name: String,
    pub kind: Kind,
    pub host: String,
    pub port: u16,
    /// Upstream user; may be empty for Redis (`AUTH <password>`).
    pub user: String,
    pub database: Option<String>,
    pub tls: TlsMode,
}

/// Credentials for one upstream connection, read from the vault per connection and dropped
/// (zeroized) when the handshake is done. No Debug, Display or Clone.
pub struct Creds {
    /// Vault key name, used as the redaction label.
    pub label: String,
    pub password: Zeroizing<Vec<u8>>,
    /// PEM client certificate chain and private key for mTLS.
    pub client_cert: Option<Zeroizing<Vec<u8>>>,
    pub client_key: Option<Zeroizing<Vec<u8>>>,
}

impl Creds {
    fn redactor(&self) -> Redactor {
        if self.password.is_empty() {
            return Redactor::new(&[]);
        }
        Redactor::new(&[Secret::new(&self.label, &self.password)])
    }
}

/// Decides each accepted connection. Implemented by `locksmithd`, one instance per relay.
pub trait Gate: Send + Sync {
    /// `client`/`server` are the accepted socket's endpoints (to find the peer processes).
    /// `Err` carries a message that is safe to show the client.
    fn admit(&self, client: SocketAddr, server: SocketAddr) -> Result<Creds, String>;
}

/// Relay-wide settings chosen by the daemon.
#[derive(Default, Clone)]
pub struct Settings {
    /// Extra trust anchors for upstream TLS (debug-build test CA only).
    pub extra_roots: Vec<CertificateDer<'static>>,
}

impl Settings {
    /// Settings trusting the PEM certificates in `pem` in addition to the system roots.
    pub fn with_test_roots(pem: &[u8]) -> Settings {
        Settings {
            extra_roots: CertificateDer::pem_slice_iter(pem)
                .filter_map(Result::ok)
                .collect(),
        }
    }
}

/// A loopback listener for one target under one lease, plus every connection it relays.
pub struct Relay {
    pub target: Target,
    pub lease: String,
    addr: SocketAddr,
    closed: AtomicBool,
    conns: Mutex<HashMap<u64, Vec<TcpStream>>>,
    next: AtomicU64,
    settings: Settings,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Relay {
    /// Bind `127.0.0.1:0` and accept in a background thread.
    pub fn start(
        target: Target,
        lease: String,
        gate: Arc<dyn Gate>,
        settings: Settings,
    ) -> io::Result<Arc<Relay>> {
        let l = TcpListener::bind(("127.0.0.1", 0))?;
        let r = Arc::new(Relay {
            target,
            lease,
            addr: l.local_addr()?,
            closed: AtomicBool::new(false),
            conns: Mutex::default(),
            next: AtomicU64::new(0),
            settings,
        });
        let me = r.clone();
        std::thread::spawn(move || me.accept(l, gate));
        Ok(r)
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Relayed connections currently open.
    pub fn open_connections(&self) -> usize {
        lock(&self.conns).len()
    }

    fn accept(self: Arc<Self>, l: TcpListener, gate: Arc<dyn Gate>) {
        for c in l.incoming() {
            if self.is_closed() {
                break;
            }
            let Ok(c) = c else { continue };
            let (me, gate) = (self.clone(), gate.clone());
            std::thread::spawn(move || {
                let _ = match me.target.kind {
                    Kind::Postgres => postgres::serve(&me, &*gate, c),
                    Kind::Mysql => mysql::serve(&me, &*gate, c),
                    Kind::Redis => redis::serve(&me, &*gate, c),
                };
            });
        }
        // The listener drops here and the port is released.
    }

    /// Stop accepting and shut down both legs of every relayed connection. Idempotent.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        for (_, socks) in lock(&self.conns).drain() {
            for s in socks {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
        // Wake the accept loop so it sees the flag.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
    }

    /// Register a socket of a new connection; the guard unregisters it. `Err` if the relay
    /// closed meanwhile (the socket is shut down then).
    fn track(&self, s: &TcpStream) -> io::Result<Track<'_>> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let t = Track { relay: self, id };
        t.add(s)?;
        Ok(t)
    }

    fn connect_upstream(&self) -> io::Result<TcpStream> {
        let t = &self.target;
        let mut last = io::Error::new(io::ErrorKind::NotFound, "host did not resolve");
        for a in (t.host.as_str(), t.port).to_socket_addrs()? {
            match TcpStream::connect_timeout(&a, CONNECT_TIMEOUT) {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    s.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
                    s.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
                    return Ok(s);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// TLS client handshake over `tcp`, verifying the certificate for the configured host.
    fn tls(&self, tcp: TcpStream, creds: &Creds) -> io::Result<Up> {
        let cfg = client_config(&self.settings, creds)?;
        let host = self
            .target
            .host
            .trim_start_matches('[')
            .trim_end_matches(']');
        let name = ServerName::try_from(host.to_string())
            .map_err(|_| other("invalid upstream host name for TLS"))?;
        let conn = rustls::ClientConnection::new(cfg, name)
            .map_err(|e| other(&format!("TLS setup failed: {e}")))?;
        let mut s = rustls::StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn
                .complete_io(&mut s.sock)
                .map_err(|e| other(&format!("upstream TLS handshake failed: {e}")))?;
        }
        Ok(Up::Tls(Box::new(s)))
    }
}

struct Track<'a> {
    relay: &'a Relay,
    id: u64,
}

impl Track<'_> {
    fn add(&self, s: &TcpStream) -> io::Result<()> {
        let c = s.try_clone()?;
        let mut m = lock(&self.relay.conns);
        if self.relay.is_closed() {
            let _ = s.shutdown(Shutdown::Both);
            return Err(other("the session's database relay was closed"));
        }
        m.entry(self.id).or_default().push(c);
        Ok(())
    }
}

impl Drop for Track<'_> {
    fn drop(&mut self) {
        if let Some(socks) = lock(&self.relay.conns).remove(&self.id) {
            for s in socks {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
    }
}

pub(crate) fn other(m: &str) -> io::Error {
    io::Error::other(m.to_string())
}

fn roots(extra: &[CertificateDer<'static>]) -> rustls::RootCertStore {
    static BASE: OnceLock<rustls::RootCertStore> = OnceLock::new();
    let mut r = BASE
        .get_or_init(|| {
            let mut r = rustls::RootCertStore::empty();
            r.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
            r.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            r
        })
        .clone();
    r.add_parsable_certificates(extra.iter().cloned());
    r
}

fn client_config(s: &Settings, creds: &Creds) -> io::Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let b = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|_| other("TLS setup failed"))?
        .with_root_certificates(roots(&s.extra_roots));
    let cfg = match (&creds.client_cert, &creds.client_key) {
        (Some(c), Some(k)) => {
            let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(c)
                .collect::<Result<_, _>>()
                .map_err(|_| other("the client certificate in the vault is not valid PEM"))?;
            let key = PrivateKeyDer::from_pem_slice(k)
                .map_err(|_| other("the client key in the vault is not valid PEM"))?;
            b.with_client_auth_cert(chain, key)
                .map_err(|_| other("the client certificate and key do not match"))?
        }
        _ => b.with_no_client_auth(),
    };
    Ok(Arc::new(cfg))
}

/// The upstream leg: plain TCP or TLS over TCP.
pub(crate) enum Up {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Up {
    fn tcp(&self) -> &TcpStream {
        match self {
            Up::Plain(s) => s,
            Up::Tls(s) => &s.sock,
        }
    }
    pub(crate) fn is_tls(&self) -> bool {
        matches!(self, Up::Tls(_))
    }
}

impl Read for Up {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Up::Plain(s) => s.read(b),
            Up::Tls(s) => s.read(b),
        }
    }
}

impl Write for Up {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match self {
            Up::Plain(s) => s.write(b),
            Up::Tls(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Up::Plain(s) => s.flush(),
            Up::Tls(s) => s.flush(),
        }
    }
}

/// Rewrites the server-to-client byte stream (frame-aware redaction). Must preserve framing.
pub(crate) trait Filter: Send {
    fn push(&mut self, data: &[u8]) -> Vec<u8>;
}

/// Pass-through.
pub(crate) struct Raw;
impl Filter for Raw {
    fn push(&mut self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

/// Copy bytes both ways until either side ends, then shut both down. Timeouts are cleared:
/// queries may run long. Returns when both directions have stopped.
pub(crate) fn splice(client: TcpStream, up: Up, mut filter: Box<dyn Filter>) -> io::Result<()> {
    client.set_read_timeout(None)?;
    client.set_write_timeout(None)?;
    up.tcp().set_read_timeout(None)?;
    up.tcp().set_write_timeout(None)?;
    let up_tcp = up.tcp().try_clone()?;
    let stop: Arc<dyn Fn() + Send + Sync> = {
        let (a, b) = (client.try_clone()?, up_tcp);
        Arc::new(move || {
            let _ = a.shutdown(Shutdown::Both);
            let _ = b.shutdown(Shutdown::Both);
        })
    };
    match up {
        Up::Plain(u) => {
            let (mut c_r, mut u_w) = (client.try_clone()?, u.try_clone()?);
            let stop2 = stop.clone();
            let t = std::thread::spawn(move || {
                let _ = io::copy(&mut c_r, &mut u_w);
                stop2();
            });
            let (mut u_r, mut c_w) = (u, client);
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                match u_r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if c_w.write_all(&filter.push(&buf[..n])).is_err() {
                            break;
                        }
                    }
                }
            }
            stop();
            let _ = t.join();
        }
        Up::Tls(s) => {
            let rustls::StreamOwned { mut conn, sock } = *s;
            let mut client = client;
            // Server messages already decrypted during the handshake phase (they often share a
            // TLS record with the authentication result) go first.
            let mut early = Vec::new();
            let mut tmp = vec![0u8; 32 * 1024];
            loop {
                match conn.reader().read(&mut tmp) {
                    Ok(0) => break,
                    Ok(k) => early.extend_from_slice(&tmp[..k]),
                    Err(_) => break,
                }
            }
            if !early.is_empty() {
                client.write_all(&filter.push(&early))?;
            }
            let conn = Arc::new(Mutex::new(conn));
            // Ordered TLS record output: taken while holding `conn`, written after releasing it.
            let wire = Arc::new(Mutex::new(sock.try_clone()?));
            let (conn2, wire2, stop2) = (conn.clone(), wire.clone(), stop.clone());
            let mut c_r = client.try_clone()?;
            let t = std::thread::spawn(move || {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    let n = match c_r.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let mut out = Vec::new();
                    let mut g = lock(&conn2);
                    if g.writer().write_all(&buf[..n]).is_err() {
                        break;
                    }
                    while g.wants_write() {
                        if g.write_tls(&mut out).is_err() {
                            break;
                        }
                    }
                    let mut w = lock(&wire2);
                    drop(g);
                    if w.write_all(&out).is_err() {
                        break;
                    }
                }
                stop2();
            });
            let (mut sock_r, mut c_w) = (sock, client);
            let mut raw = vec![0u8; 32 * 1024];
            let mut plain = vec![0u8; 32 * 1024];
            'outer: loop {
                let n = match sock_r.read(&mut raw) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut got = Vec::new();
                let mut out = Vec::new();
                let mut eof = false;
                let mut g = lock(&conn);
                let mut rd = &raw[..n];
                while !rd.is_empty() {
                    if g.read_tls(&mut rd).is_err() || g.process_new_packets().is_err() {
                        break 'outer;
                    }
                    loop {
                        match g.reader().read(&mut plain) {
                            Ok(0) => {
                                eof = true;
                                break;
                            }
                            Ok(k) => got.extend_from_slice(&plain[..k]),
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => break 'outer,
                        }
                    }
                }
                while g.wants_write() {
                    if g.write_tls(&mut out).is_err() {
                        break 'outer;
                    }
                }
                let w = (!out.is_empty()).then(|| lock(&wire));
                drop(g);
                if let Some(mut w) = w
                    && w.write_all(&out).is_err()
                {
                    break;
                }
                if !got.is_empty() && c_w.write_all(&filter.push(&got)).is_err() {
                    break;
                }
                if eof {
                    break;
                }
            }
            stop();
            let _ = t.join();
        }
    }
    Ok(())
}

pub(crate) fn read_exact_vec(r: &mut impl Read, n: usize) -> io::Result<Vec<u8>> {
    let mut v = vec![0u8; n];
    r.read_exact(&mut v)?;
    Ok(v)
}

/// Random bytes from the OS (ring's system RNG).
pub(crate) fn random<const N: usize>() -> [u8; N] {
    use ring::rand::SecureRandom;
    let mut b = [0u8; N];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .expect("OS RNG");
    b
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;

    /// Admits everything with a fixed password.
    pub struct Open(pub &'static [u8]);
    impl Gate for Open {
        fn admit(&self, _: SocketAddr, _: SocketAddr) -> Result<Creds, String> {
            Ok(Creds {
                label: "DB_PW".into(),
                password: Zeroizing::new(self.0.to_vec()),
                client_cert: None,
                client_key: None,
            })
        }
    }

    pub struct Closed;
    impl Gate for Closed {
        fn admit(&self, _: SocketAddr, _: SocketAddr) -> Result<Creds, String> {
            Err("process is outside the session".into())
        }
    }

    pub fn target(kind: Kind, port: u16, tls: TlsMode) -> Target {
        Target {
            name: "t".into(),
            kind,
            host: "127.0.0.1".into(),
            port,
            user: "app".into(),
            database: Some("appdb".into()),
            tls,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_parsing() {
        assert_eq!(Kind::parse("PostgreSQL"), Some(Kind::Postgres));
        assert_eq!(Kind::parse("mariadb"), Some(Kind::Mysql));
        assert_eq!(Kind::parse("mongo"), None);
        assert_eq!(TlsMode::parse("REQUIRE"), Some(TlsMode::Require));
        assert_eq!(TlsMode::parse("verify-full"), None);
        assert_eq!(
            TlsMode::default_for(Kind::Postgres, "db.example.com"),
            TlsMode::Require
        );
        assert_eq!(
            TlsMode::default_for(Kind::Postgres, "localhost"),
            TlsMode::Prefer
        );
        assert_eq!(
            TlsMode::default_for(Kind::Redis, "127.0.0.1"),
            TlsMode::Disable
        );
        assert_eq!(TlsMode::default_for(Kind::Redis, "[::1]"), TlsMode::Disable);
        assert_eq!(
            TlsMode::default_for(Kind::Mysql, "10.0.0.1"),
            TlsMode::Require
        );
    }

    /// A closed relay shuts down tracked sockets and refuses new tracking.
    #[test]
    fn close_shuts_down_tracked_sockets() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut b, _) = l.accept().unwrap();
        let r = Relay::start(
            testutil::target(Kind::Redis, 1, TlsMode::Disable),
            "ls_x".into(),
            Arc::new(testutil::Closed),
            Settings::default(),
        )
        .unwrap();
        let t = r.track(&a).unwrap();
        assert_eq!(r.open_connections(), 1);
        r.close();
        let mut buf = [0u8; 1];
        assert_eq!(b.read(&mut buf).unwrap(), 0, "peer sees EOF");
        assert!(r.track(&a).is_err());
        drop(t);
        assert_eq!(r.open_connections(), 0);
        // The listener is gone shortly after close.
        std::thread::sleep(Duration::from_millis(100));
        assert!(TcpStream::connect(r.addr()).is_err());
    }
}
