//! Local transport behind the daemon protocol (change x1-apps-all-platforms, task 1.2).
//!
//! The frame format in the crate root is transport-independent: it only needs [`Read`] and
//! [`Write`]. These traits name the rest a client and a server need from the OS (connect, bind,
//! accept, clone, timeouts) so a second implementation (Windows named pipes, task 1.3) can sit
//! next to the Unix one without changing callers or the wire format.
//!
//! Peer identity is not part of these traits: on Unix the daemon attests every accepted stream
//! with `ls_platform::proc::Peer::of` and `ls_broker::Manifest` refuses a peer of another OS
//! user. On Windows (task 1.3, `windows` module) the transport itself enforces it: a
//! current-user-only DACL on every pipe instance plus a token-SID check of the peer on both ends.

use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

/// One connected, bidirectional, blocking byte stream to or from the daemon.
pub trait Transport: Read + Write + Send + Sized + 'static {
    /// Connect to the endpoint at `path` (a socket path on Unix; on Windows the pipe named by
    /// [`pipe_name`]).
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
    /// file is made 0600 and the caller still keeps its directory private; on Windows the pipe
    /// gets a protected current-user-only DACL). Fails if the endpoint exists.
    fn bind(path: &Path) -> io::Result<Self>;
    /// Wait for the next client.
    fn accept(&self) -> io::Result<Self::Stream>;
}

/// Windows has no socket file: the endpoint for `path` is the named pipe
/// `\\.\pipe\locksmith-<path>` (backslashes become `/`, the only character a pipe name may
/// not contain), so per-user runtime directories give per-user pipes. A `path` that already is a
/// `\\.\pipe\` name is used as is. Pure string mapping, available on every OS for tests.
pub fn pipe_name(path: &Path) -> io::Result<String> {
    const PREFIX: &str = r"\\.\pipe\";
    let p = path.to_string_lossy();
    let name = match p.strip_prefix(PREFIX) {
        Some(rest) => format!("{PREFIX}{rest}"),
        None => format!("{PREFIX}locksmith-{}", p.replace('\\', "/")),
    };
    let rest = &name[PREFIX.len()..];
    if rest.is_empty() || rest.contains('\\') || name.encode_utf16().count() > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path does not map to a valid named pipe name",
        ));
    }
    Ok(name)
}

/// SDDL for a protected DACL with one entry: generic-all for the user SID `sid` (`S-1-...`).
/// `P` blocks inherited entries, so no other principal (not Everyone, not anonymous) gets access.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn user_only_sddl(sid: &str) -> String {
    format!("D:P(A;;GA;;;{sid})")
}

#[cfg(windows)]
mod windows;

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

/// The host OS transport: named pipes on Windows.
#[cfg(windows)]
pub type DefaultTransport = windows::PipeStream;
/// The host OS listener matching [`DefaultTransport`].
#[cfg(windows)]
pub type DefaultListener = windows::PipeListener;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_maps_paths_per_user() {
        assert_eq!(
            pipe_name(Path::new(r"C:\Users\a\AppData\run\locksmithd.sock")).unwrap(),
            r"\\.\pipe\locksmith-C:/Users/a/AppData/run/locksmithd.sock"
        );
        assert_ne!(
            pipe_name(Path::new(r"C:\Users\a\run\d.sock")).unwrap(),
            pipe_name(Path::new(r"C:\Users\b\run\d.sock")).unwrap()
        );
        assert_eq!(
            pipe_name(Path::new(r"\\.\pipe\explicit")).unwrap(),
            r"\\.\pipe\explicit"
        );
    }

    #[test]
    fn pipe_name_rejects_invalid() {
        assert!(pipe_name(Path::new(r"\\.\pipe\")).is_err());
        assert!(pipe_name(Path::new(r"\\.\pipe\a\b")).is_err());
        assert!(pipe_name(Path::new(&"x".repeat(300))).is_err());
    }

    #[test]
    fn sddl_grants_only_the_given_user_and_blocks_inheritance() {
        let s = user_only_sddl("S-1-5-21-1-2-3-1001");
        assert_eq!(s, "D:P(A;;GA;;;S-1-5-21-1-2-3-1001)");
        assert!(
            !s.contains("WD") && !s.contains("AN"),
            "no Everyone or anonymous ACE"
        );
    }
}
