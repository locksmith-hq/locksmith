//! Task x1 1.2/1.4: the daemon protocol over the [`Transport`]/[`Listener`] traits, on the host
//! OS transport. Spec ipc "Round trip on every OS" and "Foreign peer refused".
#![cfg(unix)]

use ls_ipc::{
    Client, DefaultListener, DefaultTransport, Frame, Listener, Passphrase, Request, Response,
    Transport, read_frame, write_frame,
};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const FOREIGN_SOCK_ENV: &str = "LS_IPC_TEST_FOREIGN_SOCK";
const NOBODY: u32 = 65534;

fn tmp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ls-ipc-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Kernel-reported OS user of the peer, through the daemon's own attestation code.
fn peer_uid(s: &DefaultTransport) -> io::Result<u32> {
    ls_platform::proc::Peer::of(s).map(|p| p.uid)
}

/// Serve one connection the way the daemon does: attest first, close a peer of another OS user
/// before reading anything (same rule as `ls_broker::Manifest::matched`), then answer frames.
/// Returns the peer's uid.
fn serve_one<L: Listener>(
    l: &L,
    handled: &AtomicUsize,
    attest: impl Fn(&L::Stream) -> io::Result<u32>,
) -> io::Result<u32> {
    let mut s = l.accept()?;
    let uid = attest(&s)?;
    if uid != ls_platform::current_uid() {
        return Ok(uid); // dropped: closed without handling a request
    }
    while let Some(Frame::Msg(req)) = read_frame::<Request>(&mut s)? {
        handled.fetch_add(1, Ordering::SeqCst);
        let resp = match req {
            Request::Ping => Response::Pong {
                version: "test".into(),
            },
            Request::Unlock { passphrase } if passphrase.expose() == b"pw" => Response::Ok,
            _ => Response::Error {
                code: ls_ipc::ErrorCode::BadRequest,
                message: "unexpected".into(),
            },
        };
        write_frame(&mut s, &resp)?;
    }
    Ok(uid)
}

fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn round_trip_through_the_trait() {
    let dir = tmp_dir("rt");
    let sock = dir.join("d.sock");
    let l = <DefaultListener as Listener>::bind(&sock).unwrap();
    assert_eq!(mode(&sock), 0o600, "bound endpoint is current-user only");
    let handled = Arc::new(AtomicUsize::new(0));
    let h = handled.clone();
    let server = std::thread::spawn(move || serve_one(&l, &h, peer_uid));

    let mut c = Client::<DefaultTransport>::connect_via(&sock).unwrap();
    Transport::set_read_timeout(&c.stream, Some(Duration::from_secs(10))).unwrap();
    Transport::set_write_timeout(&c.stream, Some(Duration::from_secs(10))).unwrap();
    assert!(matches!(
        c.call(&Request::Ping).unwrap(),
        Response::Pong { .. }
    ));
    // A second handle to the same connection, as `smith run` uses for its signal writer.
    let mut tx = Transport::try_clone(&c.stream).unwrap();
    write_frame(
        &mut tx,
        &Request::Unlock {
            passphrase: Passphrase::new(b"pw".to_vec()),
        },
    )
    .unwrap();
    assert_eq!(c.recv().unwrap(), Response::Ok);
    drop((c, tx));

    assert_eq!(server.join().unwrap().unwrap(), ls_platform::current_uid());
    assert_eq!(handled.load(Ordering::SeqCst), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The unparameterized `Client` (the public API callers use) is the host transport.
#[test]
fn default_client_is_the_host_transport() {
    let dir = tmp_dir("default");
    let sock = dir.join("d.sock");
    let l = DefaultListener::bind(&sock).unwrap();
    let handled = Arc::new(AtomicUsize::new(0));
    let h = handled.clone();
    let server = std::thread::spawn(move || serve_one(&l, &h, peer_uid));
    let mut c: Client = Client::connect(&sock).unwrap();
    assert!(matches!(
        c.call(&Request::Ping).unwrap(),
        Response::Pong { .. }
    ));
    drop(c);
    server.join().unwrap().unwrap();
    assert_eq!(handled.load(Ordering::SeqCst), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bind_refuses_an_existing_endpoint() {
    let dir = tmp_dir("exists");
    let sock = dir.join("d.sock");
    let _l = <DefaultListener as Listener>::bind(&sock).unwrap();
    assert!(<DefaultListener as Listener>::bind(&sock).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn connect_to_a_missing_endpoint_fails() {
    let dir = tmp_dir("missing");
    assert!(Client::<DefaultTransport>::connect_via(&dir.join("none.sock")).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A client running as another OS user (uid 65534) reaches the endpoint (permissions opened up
/// on purpose) and is closed before any request is handled. Needs root to switch user; other
/// runs skip with a note.
#[test]
fn foreign_peer_is_closed_without_handling_a_request() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    if ls_platform::current_uid() != 0 {
        eprintln!("skipped: switching to another OS user needs root");
        return;
    }
    let dir = tmp_dir("foreign");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let sock = dir.join("d.sock");
    let l = <DefaultListener as Listener>::bind(&sock).unwrap();
    // Simulate a misconfigured endpoint so the peer check is the only barrier left.
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666)).unwrap();
    let handled = Arc::new(AtomicUsize::new(0));
    let h = handled.clone();
    let server = std::thread::spawn(move || serve_one(&l, &h, peer_uid));

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["foreign_peer_client", "--exact", "--nocapture"])
        .env(FOREIGN_SOCK_ENV, &sock)
        .uid(NOBODY)
        .gid(NOBODY)
        .status()
        .unwrap();
    assert!(status.success(), "foreign client: {status}");
    assert_eq!(server.join().unwrap().unwrap(), NOBODY);
    assert_eq!(handled.load(Ordering::SeqCst), 0, "no request handled");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Child half of the test above; a no-op unless started by it.
#[test]
fn foreign_peer_client() {
    let Some(sock) = std::env::var_os(FOREIGN_SOCK_ENV) else {
        return;
    };
    assert_eq!(ls_platform::current_uid(), NOBODY);
    let mut c = Client::<DefaultTransport>::connect_via(Path::new(&sock)).unwrap();
    Transport::set_read_timeout(&c.stream, Some(Duration::from_secs(10))).unwrap();
    match c.call(&Request::Ping) {
        Ok(_) => panic!("foreign peer got a response"),
        Err(e) => assert!(
            !matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "connection was left open: {e}"
        ),
    }
}
