//! The Postgres upstream leg (D3 tasks 3.1 to 3.3).
//!
//! For an authorized [`PgSession`] this connects to the binding's pinned addresses with the
//! binding's TLS mode, sends the bound `user` and `database` plus the allow-listed client
//! parameters only (design decision 6), and answers the upstream's authentication with the
//! decrypted password: SCRAM-SHA-256 and md5 through the sans-IO helpers of `ls-proxy::db`,
//! cleartext only when the leg is verified TLS or the binding host is loopback. The client sees
//! one ordinary `AuthenticationOk`.
//!
//! After the upstream `AuthenticationOk` the `ParameterStatus` messages and `ReadyForQuery` are
//! forwarded, `BackendKeyData` is replaced with a gateway-issued random key (decision 7), and the
//! two directions are spliced. Backend messages are framed so that `ErrorResponse` and
//! `NoticeResponse` are redacted of the password; every other message is streamed through
//! unbuffered, so row data is never held in memory or inspected.
//!
//! TLS modes follow libpq: `require` encrypts without verifying the certificate, `verify-full`
//! verifies the chain and host name. Because an unverified channel can be intercepted, a
//! cleartext password is sent only over `verify-full` TLS or to a loopback host (stricter than
//! "any TLS").
//!
//! The password lives only in `SecretBytes` and `Zeroizing` buffers; nothing here logs a
//! message body, a parameter value or the password. Logs carry slugs and ids.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use ls_proxy::db::is_loopback;
use ls_proxy::db::postgres::md5_password;
use ls_proxy::db::scram;
use ls_redact::{Redactor, Secret};
use pgwire::error::ErrorInfo;
use pgwire::messages::Message;
use pgwire::messages::cancel::CancelRequest;
use pgwire::messages::response::ErrorResponse;
use pgwire::messages::startup::{BackendKeyData, SecretKey, SslRequest, Startup};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter, copy, split,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use super::listener::{TlsSetupError, sqlstate};
use super::{ClientIo, PgSession, PgUpstream};
use crate::config::PgTls;
use crate::decrypt::BoxFuture;

/// Per address TCP connect, and the whole TLS negotiation.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the upstream may take to answer one authentication step.
const AUTH_STEP_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest message accepted while authenticating (the server's own authentication messages are
/// tiny).
const MAX_AUTH_MESSAGE: usize = 64 * 1024;
/// Largest `ErrorResponse` or `NoticeResponse` the relay buffers for redaction.
const MAX_NOTICE: usize = 1024 * 1024;
/// `AuthenticationOk`.
const AUTH_OK: [u8; 9] = [b'R', 0, 0, 0, 8, 0, 0, 0, 0];

trait UpIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> UpIo for T {}

/// An open upstream leg.
struct Upstream {
    io: Box<dyn UpIo>,
    /// TLS with the certificate chain and host name verified (`verify-full`).
    verified: bool,
}

/// Where an upstream lives: the addresses the address guard accepted (no second resolution).
#[derive(Clone)]
struct Target {
    addrs: Vec<SocketAddr>,
    host: String,
    tls: PgTls,
}

/// Opens upstream legs (and cancel connections) per TLS mode.
pub struct Connector {
    verified: TlsConnector,
    unverified: TlsConnector,
}

impl Connector {
    /// `verified` is the client configuration for `verify-full` (production: `ls_http::tls_config`).
    /// The `require` configuration encrypts without verifying, as libpq's `sslmode=require`.
    pub fn new(verified: rustls::ClientConfig) -> Result<Self, TlsSetupError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let unverified = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|_| TlsSetupError::Config)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate { provider }))
            .with_no_client_auth();
        Ok(Self {
            verified: TlsConnector::from(Arc::new(verified)),
            unverified: TlsConnector::from(Arc::new(unverified)),
        })
    }

    async fn connect(&self, target: &Target) -> io::Result<Upstream> {
        let mut tcp = tcp_connect(&target.addrs).await?;
        let _ = tcp.set_nodelay(true);
        if target.tls == PgTls::Disable {
            return Ok(Upstream {
                io: Box::new(tcp),
                verified: false,
            });
        }
        send_message(&mut tcp, &SslRequest::new()).await?;
        let answer = tokio::time::timeout(CONNECT_TIMEOUT, tcp.read_u8())
            .await
            .map_err(|_| timed_out())??;
        if answer != b'S' {
            return Err(other("the upstream does not offer TLS"));
        }
        let host = target.host.trim_start_matches('[').trim_end_matches(']');
        let name = ServerName::try_from(host.to_owned())
            .map_err(|_| other("invalid upstream host name for TLS"))?;
        let verify = target.tls == PgTls::VerifyFull;
        let connector = if verify {
            &self.verified
        } else {
            &self.unverified
        };
        let tls = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp))
            .await
            .map_err(|_| timed_out())??;
        Ok(Upstream {
            io: Box::new(tls),
            verified: verify,
        })
    }
}

/// `sslmode=require`: any certificate is accepted, signatures are still checked.
#[derive(Debug)]
struct AnyCertificate {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn tcp_connect(addrs: &[SocketAddr]) -> io::Result<TcpStream> {
    let mut last = other("the binding has no upstream address");
    for addr in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = e,
            Err(_) => last = timed_out(),
        }
    }
    Err(last)
}

fn other(msg: &'static str) -> io::Error {
    io::Error::other(msg)
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "timed out")
}

/// One session's entry in the cancel map: where the upstream is and its real key.
struct CancelEntry {
    target: Target,
    pid: i32,
    secret: SecretKey,
}

/// Maps the gateway-issued `BackendKeyData` of open sessions to the upstream key (design
/// decision 7). A `CancelRequest` with an unknown key is ignored, as Postgres does.
pub struct CancelMap {
    connector: Arc<Connector>,
    entries: Mutex<HashMap<[u8; 8], CancelEntry>>,
}

/// Removes the session's cancel entry when dropped (session close).
pub struct CancelGuard {
    map: Arc<CancelMap>,
    key: [u8; 8],
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.map
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.key);
    }
}

impl CancelMap {
    fn new(connector: Arc<Connector>) -> Self {
        Self {
            connector,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Number of open sessions with a cancel entry.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Issue a random key for a session and remember the upstream's.
    fn register(
        self: &Arc<Self>,
        target: Target,
        pid: i32,
        secret: SecretKey,
    ) -> (CancelGuard, BackendKeyData) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let mut entry = Some(CancelEntry {
            target,
            pid,
            secret,
        });
        loop {
            let random = uuid::Uuid::new_v4().into_bytes();
            let gateway_pid =
                i32::from_be_bytes([random[0] & 0x7f, random[1], random[2], random[3]]).max(1);
            let mut key = [0u8; 8];
            key[..4].copy_from_slice(&gateway_pid.to_be_bytes());
            key[4..].copy_from_slice(&random[4..8]);
            if entries.contains_key(&key) {
                continue;
            }
            let secret = i32::from_be_bytes([random[4], random[5], random[6], random[7]]);
            entries.insert(key, entry.take().expect("inserted once"));
            let data = BackendKeyData::new(gateway_pid, SecretKey::I32(secret));
            return (
                CancelGuard {
                    map: self.clone(),
                    key,
                },
                data,
            );
        }
    }

    /// Forward a client's `CancelRequest` to the mapped upstream; nothing for an unknown key.
    /// Best effort, no answer either way.
    pub async fn cancel(&self, pid: i32, secret: &SecretKey) {
        let secret = secret.to_bytes();
        let Ok(secret): Result<[u8; 4], _> = secret[..].try_into() else {
            return;
        };
        let mut key = [0u8; 8];
        key[..4].copy_from_slice(&pid.to_be_bytes());
        key[4..].copy_from_slice(&secret);
        let found = {
            let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
            entries
                .get(&key)
                .map(|e| (e.target.clone(), e.pid, e.secret.clone()))
        };
        let Some((target, upstream_pid, upstream_secret)) = found else {
            return;
        };
        let Ok(mut up) = self.connector.connect(&target).await else {
            tracing::info!(reason = "cancel_connect", "pg: cancel not forwarded");
            return;
        };
        let packet = CancelRequest::new(upstream_pid, upstream_secret);
        if send_message(&mut up.io, &packet).await.is_ok() {
            // The server closes without a reply; wait for that so the request is not cut short.
            let mut sink = [0u8; 1];
            let _ = tokio::time::timeout(CONNECT_TIMEOUT, up.io.read(&mut sink)).await;
        }
    }
}

/// Why a session could not be relayed. Every variant has a fixed client-facing text: nothing the
/// upstream said reaches the client except redacted `E`/`N` after authentication.
enum Fail {
    /// Could not connect (TCP, TLS, no TLS offered).
    Connect,
    /// The upstream rejected the credentials or the SCRAM proof was refused.
    Auth,
    /// The upstream asked for a cleartext password on an unverified, non-loopback leg.
    Cleartext,
    /// The upstream broke the protocol.
    Protocol,
    /// An I/O error; the client was already told or is gone.
    Io,
    /// The upstream's `ErrorResponse` was already forwarded (redacted).
    Reported,
}

impl Fail {
    fn slug(&self) -> &'static str {
        match self {
            Self::Connect => "upstream_connect",
            Self::Auth => "upstream_auth",
            Self::Cleartext => "cleartext_refused",
            Self::Protocol => "upstream_protocol",
            Self::Io => "upstream_io",
            Self::Reported => "upstream_error",
        }
    }

    /// The `ErrorResponse` for the client, if one is still owed.
    fn reply(&self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::Connect => Some((
                sqlstate::UNABLE_TO_CONNECT,
                "the upstream database is unavailable",
            )),
            Self::Auth => Some((
                sqlstate::UNABLE_TO_CONNECT,
                "the gateway could not authenticate to the upstream database",
            )),
            Self::Cleartext => Some((
                sqlstate::UNABLE_TO_CONNECT,
                "the upstream database requires a cleartext password on an insecure connection",
            )),
            Self::Protocol => Some((
                sqlstate::PROTOCOL_VIOLATION,
                "the upstream database sent an unexpected message",
            )),
            Self::Io | Self::Reported => None,
        }
    }
}

impl From<io::Error> for Fail {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

/// The relay upstream: plugs into the listener as its [`PgUpstream`].
pub struct PgRelayUpstream {
    connector: Arc<Connector>,
    cancels: Arc<CancelMap>,
}

impl PgRelayUpstream {
    pub fn new(connector: Connector) -> Self {
        let connector = Arc::new(connector);
        Self {
            cancels: Arc::new(CancelMap::new(connector.clone())),
            connector,
        }
    }

    /// The cancel map the listener uses for `CancelRequest`.
    pub fn cancel_map(&self) -> Arc<CancelMap> {
        self.cancels.clone()
    }

    async fn run(&self, session: PgSession, mut client: Box<dyn ClientIo>) {
        match self.relay(&session, &mut client).await {
            Ok(()) => {}
            Err(fail) => {
                tracing::info!(
                    agent.id = %session.agent.agent_id,
                    secret.id = %session.binding.secret_id,
                    reason = fail.slug(),
                    "pg: session ended"
                );
                if let Some((code, message)) = fail.reply() {
                    let err = ErrorResponse::from(ErrorInfo::new(
                        "FATAL".to_owned(),
                        code.to_owned(),
                        message.to_owned(),
                    ));
                    let _ = send_message(&mut client, &err).await;
                }
            }
        }
        let _ = client.shutdown().await;
    }

    async fn relay(&self, session: &PgSession, client: &mut Box<dyn ClientIo>) -> Result<(), Fail> {
        let target = Target {
            addrs: session.addrs.clone(),
            host: session.binding.host.clone(),
            tls: session.binding.tls,
        };
        let mut up = self
            .connector
            .connect(&target)
            .await
            .map_err(|_| Fail::Connect)?;
        authenticate(&mut up, session).await?;

        let redactor = Redactor::new(&[Secret::new("pg-password", session.password.expose())]);
        client.write_all(&AUTH_OK).await?;
        let mut guard = None;
        loop {
            let (tag, body) = read_message(&mut up.io, MAX_NOTICE).await?;
            match tag {
                b'S' => write_frame(client, tag, &body).await?,
                b'K' => {
                    if body.len() < 8 {
                        return Err(Fail::Protocol);
                    }
                    let pid = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                    let secret = SecretKey::Bytes(Bytes::copy_from_slice(&body[4..]));
                    let (g, gateway_key) = self.cancels.register(target.clone(), pid, secret);
                    guard = Some(g);
                    send_message(client, &gateway_key)
                        .await
                        .map_err(|_| Fail::Io)?;
                }
                b'N' => write_frame(client, tag, &redactor.redact_all(&body)).await?,
                b'E' => {
                    write_frame(client, tag, &redactor.redact_all(&body)).await?;
                    client.flush().await?;
                    return Err(Fail::Reported);
                }
                b'Z' => {
                    write_frame(client, tag, &body).await?;
                    client.flush().await?;
                    break;
                }
                _ => return Err(Fail::Protocol),
            }
        }

        // Splice. The guard lives until the session closes, then the cancel entry goes.
        let (mut client_read, client_write) = split(&mut *client);
        let (up_read, mut up_write) = split(up.io);
        let mut client_write = BufWriter::new(client_write);
        let to_upstream = async {
            let r = copy(&mut client_read, &mut up_write).await;
            let _ = up_write.shutdown().await;
            r
        };
        let to_client = backend_to_client(BufReader::new(up_read), &mut client_write, &redactor);
        tokio::select! {
            _ = to_upstream => {}
            _ = to_client => {}
        }
        let _ = client_write.flush().await;
        let _ = client_write.shutdown().await;
        drop(guard);
        Ok(())
    }
}

impl PgUpstream for PgRelayUpstream {
    fn serve(&self, session: PgSession, client: Box<dyn ClientIo>) -> BoxFuture<'_, ()> {
        Box::pin(self.run(session, client))
    }
}

/// Answer the upstream's authentication requests until `AuthenticationOk`.
async fn authenticate(up: &mut Upstream, session: &PgSession) -> Result<(), Fail> {
    let binding = &session.binding;
    let mut startup = Startup::new();
    for (k, v) in &session.client_parameters {
        startup.parameters.insert(k.clone(), v.clone());
    }
    // Inserted last: the bound identity wins over any parameter of the same name.
    startup
        .parameters
        .insert("user".to_owned(), binding.user.clone());
    startup
        .parameters
        .insert("database".to_owned(), binding.database.clone());
    send_message(&mut up.io, &startup).await?;

    let cleartext_ok = up.verified || is_loopback(&binding.host);
    let password = session.password.expose();
    let mut sasl: Option<scram::Client> = None;
    loop {
        let (tag, body) = tokio::time::timeout(
            AUTH_STEP_TIMEOUT,
            read_message(&mut up.io, MAX_AUTH_MESSAGE),
        )
        .await
        .map_err(|_| Fail::Io)??;
        match tag {
            b'E' => return Err(Fail::Auth),
            // Notices and version negotiation before authentication are not relayed.
            b'N' | b'v' => {}
            b'R' if body.len() >= 4 => {
                let code = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let data = &body[4..];
                match code {
                    0 => return Ok(()),
                    3 => {
                        if !cleartext_ok {
                            return Err(Fail::Cleartext);
                        }
                        let mut p = Zeroizing::new(password.to_vec());
                        p.push(0);
                        write_secret_frame(&mut up.io, b'p', &p).await?;
                    }
                    5 if data.len() == 4 => {
                        let hashed = md5_password(password, &binding.user, data);
                        write_secret_frame(&mut up.io, b'p', &hashed).await?;
                    }
                    10 => {
                        if !data
                            .split(|b| *b == 0)
                            .any(|m| m == b"SCRAM-SHA-256".as_slice())
                        {
                            return Err(Fail::Protocol);
                        }
                        let c = scram::Client::new("");
                        let first = c.first_message();
                        let mut p = b"SCRAM-SHA-256\0".to_vec();
                        p.extend_from_slice(&(first.len() as u32).to_be_bytes());
                        p.extend_from_slice(first.as_bytes());
                        write_frame(&mut up.io, b'p', &p).await?;
                        sasl = Some(c);
                    }
                    11 => {
                        let c = sasl.as_mut().ok_or(Fail::Protocol)?;
                        let last = c
                            .final_message(password, data)
                            .map_err(|_| Fail::Protocol)?;
                        write_secret_frame(&mut up.io, b'p', last.as_bytes()).await?;
                    }
                    12 => {
                        let c = sasl.as_ref().ok_or(Fail::Protocol)?;
                        c.verify(data).map_err(|_| Fail::Auth)?;
                    }
                    _ => return Err(Fail::Protocol),
                }
            }
            _ => return Err(Fail::Protocol),
        }
    }
}

/// Backend to client: `E` and `N` are buffered and redacted, every other message is streamed.
async fn backend_to_client<R, W>(
    mut reader: BufReader<R>,
    writer: &mut W,
    redactor: &Redactor,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let mut head = [0u8; 5];
        reader.read_exact(&mut head).await?;
        let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        let Some(body_len) = len.checked_sub(4) else {
            return Err(other("bad backend message length"));
        };
        if matches!(head[0], b'E' | b'N') {
            if body_len > MAX_NOTICE {
                return Err(other("oversized backend notice"));
            }
            let mut body = vec![0u8; body_len];
            reader.read_exact(&mut body).await?;
            write_frame(writer, head[0], &redactor.redact_all(&body)).await?;
        } else {
            writer.write_all(&head).await?;
            let copied = copy(&mut (&mut reader).take(body_len as u64), writer).await?;
            if copied != body_len as u64 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        if reader.buffer().is_empty() {
            writer.flush().await?;
        }
    }
}

/// One tagged message: its tag and body.
async fn read_message<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> io::Result<(u8, Vec<u8>)> {
    let tag = r.read_u8().await?;
    let len = r.read_u32().await? as usize;
    let body_len = len
        .checked_sub(4)
        .filter(|n| *n <= max)
        .ok_or_else(|| other("bad upstream message length"))?;
    let mut body = vec![0u8; body_len];
    r.read_exact(&mut body).await?;
    Ok((tag, body))
}

fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(body.len() + 5);
    m.push(tag);
    m.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
    m.extend_from_slice(body);
    m
}

async fn write_frame<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    tag: u8,
    body: &[u8],
) -> io::Result<()> {
    w.write_all(&frame(tag, body)).await
}

/// A message holding password material: the framed copy is zeroized.
async fn write_secret_frame<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    tag: u8,
    body: &[u8],
) -> io::Result<()> {
    let framed = Zeroizing::new(frame(tag, body));
    w.write_all(&framed).await?;
    w.flush().await
}

async fn send_message<W: AsyncWrite + Unpin + ?Sized, M: Message>(
    w: &mut W,
    msg: &M,
) -> io::Result<()> {
    let mut buf = BytesMut::new();
    msg.encode(&mut buf)
        .map_err(|_| other("message could not be encoded"))?;
    w.write_all(&buf).await?;
    w.flush().await
}

#[cfg(test)]
#[path = "pg_relay_tests.rs"]
mod pg_relay;
