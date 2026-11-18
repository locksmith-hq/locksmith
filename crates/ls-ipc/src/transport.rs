//! Local transport behind the daemon protocol (change x1-apps-all-platforms, task 1.2).
//!
//! The frame format in the crate root is transport-independent: it only needs [`Read`] and
//! [`Write`]. These traits name the rest a client and a server need from the OS (connect, bind,
//! accept, clone, timeouts) so a second implementation (Windows named pipes, task 1.3) can sit
//! next to the Unix one without changing callers or the wire format.
//!
//! Peer identity is deliberately not part of these traits yet: on Unix the daemon attests every
//! accepted stream with `ls_platform::proc::Peer::of` and `ls_broker::Manifest` refuses a peer
//! of another OS user; that path is unchanged by this module.

use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

/// One connected, bidirectional, blocking byte stream to or from the daemon.
pub trait Transport: Read + Write + Send + Sized + 'static {
    /// Connect to the endpoint at `path` (a socket path on Unix).
    fn connect(path: &Path) -> io::Result<Self>;
    /// A second handle to the same connection (e.g. a writer for another thread).
    fn try_clone(&self) -> io::Result<Self>;
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()>;
}

/// Server side: a bound endpoint that yields one [`Transport`] per client.
pub trait Listener: Sized + Send + 'static {
    type Stream: Transport;
    /// Bind the endpoint at `path`, reachable by the current OS user only (on Unix the socket
    /// file is made 0600; the caller still keeps its directory private). Fails if `path` exists.
    fn bind(path: &Path) -> io::Result<Self>;
    /// Wait for the next client.
    fn accept(&self) -> io::Result<Self::Stream>;
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};

    impl Transport for UnixStream {
        fn connect(path: &Path) -> io::Result<Self> {
            UnixStream::connect(path)
        }
        fn try_clone(&self) -> io::Result<Self> {
            UnixStream::try_clone(self)
        }
        fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
            UnixStream::set_read_timeout(self, d)
        }
        fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
            UnixStream::set_write_timeout(self, d)
        }
    }

    impl Listener for UnixListener {
        type Stream = UnixStream;
        fn bind(path: &Path) -> io::Result<Self> {
            let l = UnixListener::bind(path)?;
            if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
                drop(l);
                let _ = std::fs::remove_file(path);
                return Err(e);
            }
            Ok(l)
        }
        fn accept(&self) -> io::Result<UnixStream> {
            UnixListener::accept(self).map(|(s, _)| s)
        }
    }
}

/// The host OS transport: Unix domain sockets on macOS and Linux.
#[cfg(unix)]
pub type DefaultTransport = std::os::unix::net::UnixStream;
/// The host OS listener matching [`DefaultTransport`].
#[cfg(unix)]
pub type DefaultListener = std::os::unix::net::UnixListener;
