//! The Postgres listener (D3 tasks 2.1 to 2.3).
//!
//! Per connection, under one handshake deadline:
//! 1. Before TLS: `GSSENCRequest` is answered `N`, `SSLRequest` is answered `S` and TLS is
//!    accepted (tokio-rustls, `ring`). A `StartupMessage` without TLS is refused with SQLSTATE
//!    `28000` and the connection closed. A `CancelRequest` (before or inside TLS, as libpq sends
//!    it) is forwarded through the cancel map (task 3.3) and closed without an answer.
//! 2. Over TLS: the `StartupMessage` (pgwire codec). The `database` parameter names the binding;
//!    `user` is required by the protocol but never routes. Only [`super::FORWARDED_PARAMETERS`]
//!    are kept for the upstream.
//! 3. `AuthenticationCleartextPassword`; the password message carries the agent token, verified
//!    with [`crate::auth::AgentAuth`]. A bad token is `28P01`.
//! 4. Check order (design decision 4): binding (`3D000`) → relay grant (`28000`) → address guard
//!    (`28000`) → decrypt → [`PgUpstream::serve`]. Nothing before the decrypt fetches material or
//!    calls the KMS, and nothing connects upstream before every check passed.
//!
//! Every refusal after the binding is known appends one `db.session.denied` event (policy
//! denials, an unresolvable upstream, a material or decrypt failure). A bad token or an unbound
//! database has no agent or no secret for the ledger to name, so it is logged by slug only. Errors sent
//! to the client are fixed texts: they never echo the token, the database name or a parameter.
//! Logs carry slugs and ids only.

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::{Buf, BufMut, BytesMut};
use pgwire::error::ErrorInfo;
use pgwire::messages::cancel::CancelRequest;
use pgwire::messages::response::ErrorResponse;
use pgwire::messages::startup::{
    Authentication, GssEncRequest, MESSAGE_TYPE_BYTE_PASSWORD_MESSAGE_FAMILY,
    NegotiateProtocolVersion, SslRequest, Startup,
};
use pgwire::messages::{DecodeContext, Message};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::upstream::CancelMap;
use super::{FORWARDED_PARAMETERS, PgSession, PgUpstream};
use crate::audit::{AuditError, CloseReason, EventKind, Outcome, RelayEvent, SessionClose};
use crate::auth::AgentIdentity;
use crate::config::PgBinding;
use crate::decrypt::DecryptError;
use crate::egress::{self, EgressError};
use crate::grants::allows_relay;
use crate::relay::Relay;
use crate::ttl::MAX_CACHE_TTL;

/// Largest pre-authentication packet (startup, password), as Postgres's own limit.
const MAX_STARTUP_PACKET: usize = 10_000;
/// How many `GSSENCRequest`/`SSLRequest` negotiations a client may send before startup.
const MAX_NEGOTIATIONS: usize = 2;
/// The ALPN protocol libpq 17+ offers.
const ALPN_POSTGRESQL: &[u8] = b"postgresql";

/// SQLSTATEs the listener answers with (fixed; design decision 4).
pub mod sqlstate {
    /// `invalid_authorization_specification`: no TLS, no grant, address refused.
    pub const INVALID_AUTHORIZATION: &str = "28000";
    /// `invalid_password`: the agent token did not verify.
    pub const INVALID_PASSWORD: &str = "28P01";
    /// `invalid_catalog_name`: the database names no binding.
    pub const INVALID_CATALOG: &str = "3D000";
    /// `protocol_violation`.
    pub const PROTOCOL_VIOLATION: &str = "08P01";
    /// `sqlclient_unable_to_establish_sqlconnection`: upstream unresolvable, decrypt failed.
    pub const UNABLE_TO_CONNECT: &str = "08001";
    /// `feature_not_supported`: the upstream leg is not available.
    pub const NOT_SUPPORTED: &str = "0A000";
}

/// Listener timing.
#[derive(Debug, Clone, Copy)]
pub struct PgListenerOptions {
    /// From accept until the session is handed upstream (TLS, startup, token, checks, decrypt).
    pub handshake_timeout: Duration,
    /// How often an open session re-checks its grant and token expiry (at most the grant cache
    /// TTL, so a revocation closes the session within it).
    pub watch_interval: Duration,
}

impl Default for PgListenerOptions {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            watch_interval: MAX_CACHE_TTL,
        }
    }
}

/// The listener's TLS identity could not be loaded. Carries no key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsSetupError {
    Certificate,
    Key,
    Config,
}

impl std::fmt::Display for TlsSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Certificate => "pg listener certificate is not a PEM certificate chain",
            Self::Key => "pg listener key is not a PEM private key",
            Self::Config => "pg listener TLS configuration was rejected",
        })
    }
}

impl std::error::Error for TlsSetupError {}

/// A TLS acceptor from a PEM chain and key (rustls with the `ring` provider, TLS 1.2 and 1.3).
pub fn tls_acceptor(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsAcceptor, TlsSetupError> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsSetupError::Certificate)?;
    if certs.is_empty() {
        return Err(TlsSetupError::Certificate);
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| TlsSetupError::Key)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsSetupError::Config)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| TlsSetupError::Config)?;
    config.alpn_protocols = vec![ALPN_POSTGRESQL.to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Why a connection ended before the upstream. `slug` is what logs and spans see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// The peer went away or sent bytes that are not a packet; closed without an answer.
    Io,
    /// Answered with an `ErrorResponse`.
    Answer {
        code: &'static str,
        message: &'static str,
        slug: &'static str,
    },
}

impl Refusal {
    const fn answer(code: &'static str, message: &'static str, slug: &'static str) -> Self {
        Self::Answer {
            code,
            message,
            slug,
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::Answer { slug, .. } => slug,
        }
    }
}

const PLAINTEXT: Refusal = Refusal::answer(
    sqlstate::INVALID_AUTHORIZATION,
    "TLS is required (sslmode=require or verify-full)",
    "plaintext",
);
const PROTOCOL: Refusal = Refusal::answer(
    sqlstate::PROTOCOL_VIOLATION,
    "unexpected message during startup",
    "protocol",
);
const NO_USER: Refusal = Refusal::answer(
    sqlstate::INVALID_AUTHORIZATION,
    "no user name specified in startup packet",
    "no_user",
);
const BAD_TOKEN: Refusal = Refusal::answer(
    sqlstate::INVALID_PASSWORD,
    "password authentication failed: the password must be a valid agent token",
    "bad_token",
);
const UNBOUND: Refusal = Refusal::answer(
    sqlstate::INVALID_CATALOG,
    "database is not bound on this gateway",
    "unbound",
);
const NOT_PERMITTED: Refusal = Refusal::answer(
    sqlstate::INVALID_AUTHORIZATION,
    "access to this database is not permitted",
    "denied",
);
const UNREACHABLE: Refusal = Refusal::answer(
    sqlstate::UNABLE_TO_CONNECT,
    "the upstream database is unavailable",
    "upstream_unreachable",
);

impl From<io::Error> for Refusal {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

/// The Postgres listener. Cheap to share; one task per connection.
pub struct PgListener {
    relay: Arc<Relay>,
    tls: TlsAcceptor,
    upstream: Arc<dyn PgUpstream>,
    options: PgListenerOptions,
    cancels: Option<Arc<CancelMap>>,
}

impl PgListener {
    pub fn new(
        relay: Arc<Relay>,
        tls: TlsAcceptor,
        upstream: Arc<dyn PgUpstream>,
        options: PgListenerOptions,
    ) -> Self {
        Self {
            relay,
            tls,
            upstream,
            options,
            cancels: None,
        }
    }

    /// Forward `CancelRequest`s through `cancels` (without one they are closed unanswered).
    #[must_use]
    pub fn with_cancel_map(mut self, cancels: Arc<CancelMap>) -> Self {
        self.cancels = Some(cancels);
        self
    }

    /// A `CancelRequest` packet: forward it if the key is known. Never answered.
    async fn cancel(&self, mut packet: BytesMut) {
        let Some(cancels) = &self.cancels else { return };
        if let Ok(Some(c)) = CancelRequest::decode(&mut packet, &DecodeContext::default()) {
            cancels.cancel(c.pid, &c.secret_key).await;
        }
    }

    /// Accept connections until the listener fails.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let this = self.clone();
            tokio::spawn(async move { this.connection(stream).await });
        }
    }

    /// One connection: handshake under the deadline, then the upstream.
    pub async fn connection(&self, stream: TcpStream) {
        let _ = stream.set_nodelay(true);
        let deadline = self.options.handshake_timeout;
        match tokio::time::timeout(deadline, self.handshake(stream)).await {
            Ok(Some((session, client))) => self.run_session(session, client).await,
            Ok(None) => {}
            Err(_) => tracing::info!(reason = "handshake_timeout", "pg: connection refused"),
        }
    }

    /// One authorized session: `db.session.opened` before any upstream connect (no event, no
    /// session), the relay raced against the revocation watcher, then `db.session.closed`.
    async fn run_session(&self, session: PgSession, mut client: Box<dyn super::ClientIo>) {
        let (agent_id, secret_id, version) = (
            session.agent.agent_id,
            session.binding.secret_id,
            session.binding.version,
        );
        let (host, port) = (session.binding.host.clone(), session.binding.port);
        let (expires_at, stats) = (session.token_expires_at, session.stats.clone());
        let event = |kind, attempt_id| RelayEvent {
            kind,
            agent_id,
            secret_id,
            version,
            method: None,
            host: Some(host.clone()),
            port: Some(port),
            status: None,
            attempt_id,
            issued: None,
            connection: None,
        };
        let opened_id = match self
            .relay
            .audit()
            .append(event(EventKind::DbOpened, None))
            .await
        {
            Ok(id) => id,
            Err(e) => {
                // Fail closed: the ledger could not record the session, so it does not start.
                tracing::warn!(
                    agent.id = %agent_id,
                    secret.id = %secret_id,
                    error = %e,
                    "pg: db.session.opened not recorded, session refused"
                );
                refuse(&mut client, UNREACHABLE).await;
                return;
            }
        };
        let started = tokio::time::Instant::now();
        let reason = tokio::select! {
            () = self.upstream.serve(session, client) => stats.own_reason(),
            r = self.watch(agent_id, secret_id, expires_at) => r,
        };
        let closed = SessionClose {
            reason,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            bytes_in: stats.bytes_in.load(Ordering::Relaxed),
            bytes_out: stats.bytes_out.load(Ordering::Relaxed),
        };
        tracing::info!(
            agent.id = %agent_id,
            secret.id = %secret_id,
            reason = reason.as_str(),
            duration_ms = closed.duration_ms,
            "pg: session closed"
        );
        for _ in 0..3 {
            match self
                .relay
                .audit()
                .append(event(EventKind::DbClosed(closed), Some(opened_id)))
                .await
            {
                Ok(_) | Err(AuditError::Rejected) => return,
                Err(AuditError::Unavailable) => {}
            }
        }
        tracing::warn!(agent.id = %agent_id, "pg: db.session.closed event not recorded");
    }

    /// Returns when the session must end: the token expired, or the grant is gone (or could not
    /// be read for three checks in a row). Dropping the relay future closes both legs.
    async fn watch(&self, agent_id: Uuid, secret_id: Uuid, expires_at: i64) -> CloseReason {
        let mut failures = 0u8;
        loop {
            tokio::time::sleep(self.options.watch_interval).await;
            let now = time::OffsetDateTime::now_utc();
            if now.unix_timestamp() >= expires_at {
                return CloseReason::Expired;
            }
            match self.relay.grants().grants_uncached(agent_id).await {
                Ok(g) => {
                    failures = 0;
                    if !allows_relay(&g, secret_id, now) {
                        return CloseReason::Revoked;
                    }
                }
                Err(e) => {
                    failures += 1;
                    tracing::warn!(
                        reason = e.as_str(),
                        failures,
                        "pg: session grant re-check failed"
                    );
                    if failures >= 3 {
                        return CloseReason::Error;
                    }
                }
            }
        }
    }

    /// TLS, startup and every check. `None` when the connection was refused (and answered).
    async fn handshake(&self, mut tcp: TcpStream) -> Option<(PgSession, Box<dyn super::ClientIo>)> {
        // Before TLS: negotiate, never read a startup message in the clear.
        match negotiate(&mut tcp).await {
            Ok(Negotiated::Tls) => {}
            Ok(Negotiated::Cancel(packet)) => {
                self.cancel(packet).await;
                return None;
            }
            Err(r) => {
                refuse(&mut tcp, r).await;
                return None;
            }
        }
        let mut tls = match self.tls.accept(tcp).await {
            Ok(s) => s,
            Err(_) => {
                tracing::info!(reason = "tls_handshake", "pg: connection refused");
                return None;
            }
        };
        match self.authorize(&mut tls).await {
            Ok(session) => Some((session, Box::new(tls))),
            Err(r) => {
                refuse(&mut tls, r).await;
                None
            }
        }
    }

    /// Startup, token and the check order, over TLS.
    async fn authorize<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        s: &mut S,
    ) -> Result<PgSession, Refusal> {
        let mut packet = read_untyped(s).await?;
        if CancelRequest::is_cancel_request_packet(&packet) {
            self.cancel(packet).await;
            return Err(Refusal::Io);
        }
        if request_code(&packet).is_some() {
            // A second SSLRequest or GSSENCRequest inside TLS.
            return Err(PROTOCOL);
        }
        let startup = Startup::decode(&mut packet, &DecodeContext::default())
            .ok()
            .flatten()
            .ok_or(PROTOCOL)?;
        let mut params = startup.parameters;
        let user = params.remove("user").filter(|u| !u.is_empty());
        if user.is_none() {
            return Err(NO_USER);
        }
        // Postgres's default: the database is the user name when not given.
        let database = params
            .remove("database")
            .filter(|d| !d.is_empty())
            .or(user)
            .unwrap_or_default();
        // Only protocol 3.0 is served: a newer minor or `_pq_.` options are negotiated down.
        let unsupported: Vec<String> = params
            .keys()
            .filter(|k| k.starts_with("_pq_."))
            .cloned()
            .collect();
        if startup.protocol_number_minor != 0 || !unsupported.is_empty() {
            write_message(s, &NegotiateProtocolVersion::new(0, unsupported.clone())).await?;
        }
        let client_parameters: BTreeMap<String, String> = params
            .into_iter()
            .filter(|(k, _)| FORWARDED_PARAMETERS.contains(&k.as_str()))
            .collect();

        write_message(s, &Authentication::CleartextPassword).await?;
        s.flush().await?;
        let token = read_password(s).await?;
        let (agent, token_exp) = match self.relay.auth().verify_expiring(token.as_str()).await {
            Ok(a) => a,
            Err(e) => {
                tracing::info!(reason = e.as_str(), "pg: agent token refused");
                return Err(BAD_TOKEN);
            }
        };
        drop(token);
        self.check(agent, token_exp, &database, client_parameters)
            .await
    }

    /// Binding → relay grant → address guard → decrypt (design decision 4).
    async fn check(
        &self,
        agent: AgentIdentity,
        token_exp: i64,
        database: &str,
        client_parameters: BTreeMap<String, String>,
    ) -> Result<PgSession, Refusal> {
        let relay = &self.relay;
        let Some(binding) = relay.bindings().pg_by_name(database) else {
            // No binding, so no secret for the ledger to name: logs only.
            tracing::info!(agent.id = %agent.agent_id, reason = "unbound", "pg: session refused");
            return Err(UNBOUND);
        };
        let grants = match relay.grants().grants(agent.agent_id).await {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(reason = e.as_str(), "pg: agent grants could not be read");
                self.deny(agent, binding, Outcome::GrantsUnavailable).await;
                return Err(NOT_PERMITTED);
            }
        };
        let now = time::OffsetDateTime::now_utc();
        if !allows_relay(&grants, binding.secret_id, now) {
            self.deny(agent, binding, Outcome::NoGrant).await;
            return Err(NOT_PERMITTED);
        }
        drop(grants);
        let addrs = match egress::check_host(
            &binding.host,
            binding.port,
            binding.allow_private_hosts,
            relay.resolver(),
        )
        .await
        {
            Ok(a) => a,
            Err(EgressError::AddressNotAllowed | EgressError::HostNotAllowed) => {
                self.deny(agent, binding, Outcome::DeniedAddress).await;
                return Err(NOT_PERMITTED);
            }
            Err(EgressError::Unresolvable) => {
                self.deny(agent, binding, Outcome::UpstreamUnreachable)
                    .await;
                return Err(UNREACHABLE);
            }
        };
        let password = match relay
            .decryptor()
            .decrypt(binding.secret_id, binding.version)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                let why = match e {
                    DecryptError::Material(_) => Outcome::MaterialError,
                    DecryptError::Unwrap(_) | DecryptError::Open => Outcome::DecryptFailed,
                };
                self.deny(agent, binding, why).await;
                return Err(UNREACHABLE);
            }
        };
        Ok(PgSession {
            agent,
            binding: binding.clone(),
            addrs,
            client_parameters,
            password,
            token_expires_at: token_exp,
            stats: Arc::default(),
        })
    }

    /// Log and append one `db.session.denied` event. The host is the binding's (configuration).
    async fn deny(&self, agent: AgentIdentity, binding: &PgBinding, why: Outcome) {
        tracing::info!(
            agent.id = %agent.agent_id,
            secret.id = %binding.secret_id,
            reason = why.as_str(),
            "pg: session refused"
        );
        let ev = RelayEvent {
            kind: EventKind::DbDenied(why),
            agent_id: agent.agent_id,
            secret_id: binding.secret_id,
            version: binding.version,
            method: None,
            host: Some(binding.host.clone()),
            port: Some(binding.port),
            status: None,
            attempt_id: None,
            issued: None,
            connection: None,
        };
        if let Err(e) = self.relay.audit().append(ev).await {
            tracing::warn!(error = %e, "pg: db.session.denied event not recorded");
        }
    }
}

/// The negotiation request a packet carries (`SSLRequest` or `GSSENCRequest`), if any.
fn request_code(packet: &[u8]) -> Option<i32> {
    if packet.len() != 8 {
        return None;
    }
    let code = (&packet[4..8]).get_i32();
    [
        SslRequest::BODY_MAGIC_NUMBER,
        GssEncRequest::BODY_MAGIC_NUMBER,
    ]
    .contains(&code)
    .then_some(code)
}

/// What the pre-TLS negotiation ended with.
enum Negotiated {
    /// `SSLRequest` answered `S`: accept TLS now.
    Tls,
    /// A `CancelRequest` packet sent in the clear.
    Cancel(BytesMut),
}

/// Before TLS: answer `GSSENCRequest` with `N`, accept `SSLRequest` with `S`, hand a cancel
/// request on. A startup message is refused.
async fn negotiate(tcp: &mut TcpStream) -> Result<Negotiated, Refusal> {
    for _ in 0..MAX_NEGOTIATIONS {
        let packet = read_untyped(tcp).await?;
        match request_code(&packet) {
            Some(SslRequest::BODY_MAGIC_NUMBER) => {
                tcp.write_all(b"S").await?;
                tcp.flush().await?;
                return Ok(Negotiated::Tls);
            }
            Some(_) => {
                tcp.write_all(b"N").await?;
                tcp.flush().await?;
            }
            None if CancelRequest::is_cancel_request_packet(&packet) => {
                return Ok(Negotiated::Cancel(packet));
            }
            None => return Err(PLAINTEXT),
        }
    }
    Err(PLAINTEXT)
}

/// One length-prefixed packet without a type byte (startup phase), length prefix included.
async fn read_untyped<S: AsyncRead + Unpin>(s: &mut S) -> Result<BytesMut, Refusal> {
    let len = s.read_i32().await?;
    let len = usize::try_from(len).map_err(|_| PROTOCOL)?;
    if !(8..=MAX_STARTUP_PACKET).contains(&len) {
        return Err(PROTOCOL);
    }
    let mut buf = BytesMut::with_capacity(len);
    buf.put_i32(len as i32);
    buf.resize(len, 0);
    s.read_exact(&mut buf[4..]).await?;
    Ok(buf)
}

/// The password message: the agent token. Parsed here rather than through pgwire's
/// `PasswordMessageFamily` so every buffer holding the token is zeroized.
async fn read_password<S: AsyncRead + Unpin>(s: &mut S) -> Result<Zeroizing<String>, Refusal> {
    let tag = s.read_u8().await?;
    if tag != MESSAGE_TYPE_BYTE_PASSWORD_MESSAGE_FAMILY {
        return Err(PROTOCOL);
    }
    let len = usize::try_from(s.read_i32().await?).map_err(|_| PROTOCOL)?;
    if !(5..=MAX_STARTUP_PACKET).contains(&len) {
        return Err(PROTOCOL);
    }
    let mut body = Zeroizing::new(vec![0u8; len - 4]);
    s.read_exact(&mut body).await?;
    // A C string filling the body exactly.
    let Some((&0, text)) = body.split_last() else {
        return Err(PROTOCOL);
    };
    if text.contains(&0) {
        return Err(PROTOCOL);
    }
    match std::str::from_utf8(text) {
        Ok(t) => Ok(Zeroizing::new(t.to_owned())),
        // Not text, so not a token.
        Err(_) => Err(BAD_TOKEN),
    }
}

async fn write_message<S: AsyncWrite + Unpin, M: Message>(
    s: &mut S,
    msg: &M,
) -> Result<(), Refusal> {
    let mut buf = BytesMut::new();
    msg.encode(&mut buf).map_err(|_| Refusal::Io)?;
    s.write_all(&buf).await?;
    buf.zeroize();
    Ok(())
}

/// Answer a refusal with a fixed `FATAL` error (or nothing for I/O) and close.
async fn refuse<S: AsyncWrite + Unpin>(s: &mut S, r: Refusal) {
    tracing::info!(
        reason = r.slug(),
        "pg: connection closed before the upstream"
    );
    if let Refusal::Answer { code, message, .. } = r {
        let err = ErrorResponse::from(ErrorInfo::new(
            "FATAL".to_owned(),
            code.to_owned(),
            message.to_owned(),
        ));
        let _ = write_message(s, &err).await;
        let _ = s.flush().await;
    }
    let _ = s.shutdown().await;
}

/// The upstream leg until group 3 lands: every authorized session is answered `0A000` and
/// closed, and the password is dropped (zeroized) unused.
pub struct UpstreamUnavailable;

impl PgUpstream for UpstreamUnavailable {
    fn serve(
        &self,
        session: PgSession,
        mut client: Box<dyn super::ClientIo>,
    ) -> crate::decrypt::BoxFuture<'_, ()> {
        Box::pin(async move {
            drop(session);
            refuse(
                &mut client,
                Refusal::answer(
                    sqlstate::NOT_SUPPORTED,
                    "the Postgres relay upstream is not available yet",
                    "upstream_unavailable",
                ),
            )
            .await;
        })
    }
}

#[cfg(test)]
#[path = "pg_auth_tests.rs"]
mod pg_auth;
