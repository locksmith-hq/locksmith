//! Task x1 1.3: the daemon protocol over the Windows named-pipe transport. Compile-checked on
//! Linux (`--target x86_64-pc-windows-gnu`); runs on the Windows runner in `ci-platforms` (4.2).
//! Spec ipc "Round trip on every OS". The foreign-user case needs a second Windows account and
//! is covered by the DACL plus the SID check in `transport/windows.rs`.
#![cfg(windows)]

use ls_ipc::{
    Client, DefaultListener, DefaultTransport, Frame, Listener, Passphrase, Request, Response,
    Transport, read_frame, write_frame,
};
use std::path::PathBuf;
use std::time::Duration;

fn pipe(name: &str) -> PathBuf {
    PathBuf::from(format!(
        r"\\.\pipe\ls-ipc-test-{name}-{}",
        std::process::id()
    ))
}

fn serve(l: DefaultListener, conns: usize) -> std::thread::JoinHandle<usize> {
    std::thread::spawn(move || {
        let mut handled = 0;
        for _ in 0..conns {
            let mut s = l.accept().unwrap();
            while let Some(Frame::Msg(req)) = read_frame::<Request>(&mut s).unwrap() {
                handled += 1;
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
                write_frame(&mut s, &resp).unwrap();
            }
        }
        handled
    })
}

#[test]
fn round_trip_over_named_pipe() {
    let p = pipe("rt");
    let server = serve(<DefaultListener as Listener>::bind(&p).unwrap(), 2);

    let mut c = Client::<DefaultTransport>::connect_via(&p).unwrap();
    Transport::set_read_timeout(&c.stream, Some(Duration::from_secs(10))).unwrap();
    assert!(matches!(
        c.call(&Request::Ping).unwrap(),
        Response::Pong { .. }
    ));
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

    // A second client gets the successor instance.
    let mut c2: Client = Client::connect(&p).unwrap();
    assert!(matches!(
        c2.call(&Request::Ping).unwrap(),
        Response::Pong { .. }
    ));
    drop(c2);
    assert_eq!(server.join().unwrap(), 3);
}

#[test]
fn bind_refuses_a_taken_pipe_name() {
    let p = pipe("taken");
    let _l = <DefaultListener as Listener>::bind(&p).unwrap();
    assert!(<DefaultListener as Listener>::bind(&p).is_err());
}

#[test]
fn connect_to_a_missing_pipe_fails() {
    assert!(Client::<DefaultTransport>::connect_via(&pipe("missing")).is_err());
}

#[test]
fn read_timeout_fires() {
    let p = pipe("timeout");
    let l = <DefaultListener as Listener>::bind(&p).unwrap();
    let server = std::thread::spawn(move || {
        let s = l.accept().unwrap();
        std::thread::sleep(Duration::from_secs(2));
        drop(s);
    });
    let mut c = Client::<DefaultTransport>::connect_via(&p).unwrap();
    Transport::set_read_timeout(&c.stream, Some(Duration::from_millis(200))).unwrap();
    let e = c.recv().unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
    server.join().unwrap();
}
