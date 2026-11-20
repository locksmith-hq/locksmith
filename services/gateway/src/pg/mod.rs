//! Postgres relay (D3): a TLS pgwire listener that authenticates agents by their agent token and
//! relays a session to a bound database with the stored password injected upstream.
//!
//! - [`listener`]: the TCP listener, TLS before startup, agent-token auth and the check order
//!   (design decision 4) up to the decrypt; it hands an authorized session to a [`PgUpstream`].
//!
//! The upstream leg (SCRAM/md5 with the decrypted password, splice and redaction, cancel map) is
//! group 3 of the change and plugs in through [`PgUpstream`].

pub mod listener;

use std::collections::BTreeMap;
use std::net::SocketAddr;

use ls_envelope::SecretBytes;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::auth::AgentIdentity;
use crate::config::PgBinding;
use crate::decrypt::BoxFuture;

pub use listener::{PgListener, PgListenerOptions, TlsSetupError, tls_acceptor};

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
}

/// The upstream leg: authenticates with the session's password and relays the client. Called
/// only after every check of the listener passed.
pub trait PgUpstream: Send + Sync {
    fn serve(&self, session: PgSession, client: Box<dyn ClientIo>) -> BoxFuture<'_, ()>;
}
