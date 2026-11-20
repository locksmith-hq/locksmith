//! Postgres relay (D3): a TLS pgwire listener that authenticates agents by their agent token and
//! relays a session to a bound database with the stored password injected upstream.
//!
//! - [`listener`]: the TCP listener, TLS before startup, agent-token auth and the check order
//!   (design decision 4) up to the decrypt; it hands an authorized session to a [`PgUpstream`].
//!
//! - [`upstream`]: the upstream leg (SCRAM/md5 with the decrypted password, splice and redaction,
//!   cancel map); it plugs in through [`PgUpstream`].

pub mod listener;
pub mod upstream;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use ls_envelope::SecretBytes;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::auth::AgentIdentity;
use crate::config::PgBinding;
use crate::decrypt::BoxFuture;

pub use listener::{PgListener, PgListenerOptions, TlsSetupError, tls_acceptor};
pub use upstream::{CancelMap, Connector, PgRelayUpstream};

/// The client side of a session after TLS and authentication.
pub trait ClientIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ClientIo for T {}

/// Startup parameters a client may pass through to the upstream (design decision 6). Everything
/// else, `user`, `database` and `options` included, is dropped.
pub const FORWARDED_PARAMETERS: &[&str] = &[
    "application_name",
    "client_encoding",
    "DateStyle",
    "TimeZone",
    "extra_float_digits",
];

/// Counters the upstream leg fills while it relays, read by the listener for `db.session.closed`.
/// Byte counts are the protocol bytes spliced after `ReadyForQuery`; never content.
#[derive(Debug, Default)]
pub struct SessionStats {
    /// Client to upstream.
    pub bytes_in: AtomicU64,
    /// Upstream to client.
    pub bytes_out: AtomicU64,
    /// Which side ended a spliced session (`ENDED_*`).
    ended: AtomicU8,
}

impl SessionStats {
    const ENDED_CLIENT: u8 = 1;
    const ENDED_UPSTREAM: u8 = 2;

    pub fn add_in(&self, n: usize) {
        self.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn add_out(&self, n: usize) {
        self.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn ended_by_client(&self) {
        self.ended.store(Self::ENDED_CLIENT, Ordering::Relaxed);
    }

    pub fn ended_by_upstream(&self) {
        self.ended.store(Self::ENDED_UPSTREAM, Ordering::Relaxed);
    }

    /// The reason for a session that ended on its own (not by the revocation watcher).
    pub fn own_reason(&self) -> crate::audit::CloseReason {
        use crate::audit::CloseReason;
        match self.ended.load(Ordering::Relaxed) {
            Self::ENDED_CLIENT => CloseReason::ClientClosed,
            Self::ENDED_UPSTREAM => CloseReason::UpstreamClosed,
            _ => CloseReason::Error,
        }
    }
}

/// An authorized session: every check passed and the password is decrypted. No `Debug` or
/// `Clone`: it holds the password.
pub struct PgSession {
    pub agent: AgentIdentity,
    pub binding: PgBinding,
    /// The upstream addresses the address guard accepted; the upstream leg connects only to
    /// these (no second resolution).
    pub addrs: Vec<SocketAddr>,
    /// The allow-listed client startup parameters ([`FORWARDED_PARAMETERS`]).
    pub client_parameters: BTreeMap<String, String>,
    /// The binding's database password, zeroized on drop.
    pub password: SecretBytes,
    /// The agent token's `exp` (Unix seconds): the session ends when it passes.
    pub token_expires_at: i64,
    /// Filled by the upstream leg; read by the listener for the closing event.
    pub stats: Arc<SessionStats>,
}

/// The upstream leg: authenticates with the session's password and relays the client. Called
/// only after every check of the listener passed.
pub trait PgUpstream: Send + Sync {
    fn serve(&self, session: PgSession, client: Box<dyn ClientIo>) -> BoxFuture<'_, ()>;
}
