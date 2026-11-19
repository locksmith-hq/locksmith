//! The app's commands as plain functions over the daemon socket (design D2), testable without
//! a Tauri runtime. Secret values come only from a [`SecurePrompt`] and go only into a request
//! frame; every return value is a `ls_ipc::desktop` view type (design D1).

use crate::secure_input::SecurePrompt;
use ls_ipc::desktop::{
    AuditVerifyView, CommandError, CommandErrorCode, RelayInfo, SecureOutcome, StatusView,
};
use ls_ipc::{AuditEvent, Client, ErrorCode, HttpTokenInfo, Passphrase, Request, Response};
use std::path::PathBuf;
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, CommandError>;

fn cmd_err(code: CommandErrorCode, message: impl Into<String>) -> CommandError {
    CommandError {
        code,
        message: message.into(),
    }
}

/// A daemon error passes through; anything else is a protocol surprise.
fn unexpected(r: Response) -> CommandError {
    match r {
        Response::Error { code, message } => cmd_err(code.into(), message),
        _ => cmd_err(CommandErrorCode::Unexpected, "unexpected daemon response"),
    }
}

/// Move the typed text into a zeroizing request value without copying it.
fn secret(mut v: Zeroizing<String>) -> Passphrase {
    Passphrase::new(std::mem::take(&mut *v).into_bytes())
}

pub struct Daemon {
    pub socket: PathBuf,
}

impl Default for Daemon {
    fn default() -> Self {
        Daemon {
            socket: ls_ipc::socket_path(),
        }
    }
}

impl Daemon {
    fn call(&self, req: &Request) -> Result<Response> {
        let mut c = Client::connect(&self.socket).map_err(|e| {
            cmd_err(
                CommandErrorCode::Unavailable,
                format!("cannot reach locksmithd at {}: {e}", self.socket.display()),
            )
        })?;
        c.call(req)
            .map_err(|e| cmd_err(CommandErrorCode::Unavailable, format!("locksmithd: {e}")))
    }

    fn ok(&self, req: &Request) -> Result<()> {
        match self.call(req)? {
            Response::Ok => Ok(()),
            r => Err(unexpected(r)),
        }
    }

    pub fn status(&self) -> Result<StatusView> {
        match self.call(&Request::Status)? {
            Response::Status { locked, leases } => Ok(StatusView { locked, leases }),
            r => Err(unexpected(r)),
        }
    }

    /// Liveness probe for the headless smoke test: the daemon answers `Ping` with its version.
    pub fn health(&self) -> Result<String> {
        match self.call(&Request::Ping)? {
            Response::Pong { version } => Ok(version),
            r => Err(unexpected(r)),
        }
    }

    pub fn lock(&self) -> Result<()> {
        self.ok(&Request::Lock)
    }

    pub fn unlock_secure(&self, prompt: &dyn SecurePrompt) -> Result<SecureOutcome> {
        let Some(v) = prompt.ask("Unlock Locksmith", "Enter your vault passphrase.") else {
            return Ok(SecureOutcome::Cancelled);
        };
        self.ok(&Request::Unlock {
            passphrase: secret(v),
        })?;
        Ok(SecureOutcome::Submitted)
    }

    pub fn revoke(&self, id: Option<String>) -> Result<u32> {
        match self.call(&Request::Revoke { id })? {
            Response::Revoked { count } => Ok(count),
            r => Err(unexpected(r)),
        }
    }

    pub fn audit_list(&self, limit: u32) -> Result<Vec<AuditEvent>> {
        match self.call(&Request::AuditList { limit })? {
            Response::Audit { events } => Ok(events),
            r => Err(unexpected(r)),
        }
    }

    pub fn audit_verify(&self) -> Result<AuditVerifyView> {
        match self.call(&Request::AuditVerify)? {
            Response::AuditVerify {
                events,
                broken_at,
                detail,
            } => Ok(AuditVerifyView {
                events,
                broken_at,
                detail,
            }),
            r => Err(unexpected(r)),
        }
    }

    pub fn key_names(&self, project: String, env: String) -> Result<Vec<String>> {
        match self.call(&Request::KeyNames { project, env })? {
            Response::Keys { keys } => Ok(keys),
            r => Err(unexpected(r)),
        }
    }

    pub fn put_secret_secure(
        &self,
        prompt: &dyn SecurePrompt,
        project: String,
        env: String,
        name: String,
    ) -> Result<SecureOutcome> {
        let msg = format!("Value for {name} in {project}/{env}.");
        let Some(v) = prompt.ask("Store a secret", &msg) else {
            return Ok(SecureOutcome::Cancelled);
        };
        self.ok(&Request::SecretPut {
            project,
            env,
            name,
            value: secret(v),
        })?;
        Ok(SecureOutcome::Submitted)
    }

    pub fn token_list(&self) -> Result<Vec<HttpTokenInfo>> {
        match self.call(&Request::TokenList)? {
            Response::HttpTokens { tokens } => Ok(tokens),
            r => Err(unexpected(r)),
        }
    }

    pub fn token_revoke(&self, token: String) -> Result<u32> {
        match self.call(&Request::TokenRevoke { token: Some(token) })? {
            Response::Revoked { count } => Ok(count),
            r => Err(unexpected(r)),
        }
    }

    /// A relay that is not running (daemon `Internal`) shows as `null`; other errors fail.
    pub fn relay_info(&self) -> Result<RelayInfo> {
        let mut out = RelayInfo::default();
        for req in [Request::GitInfo, Request::HttpInfo, Request::AwsInfo] {
            match self.call(&req)? {
                Response::GitInfo { port, .. } => out.git_port = Some(port),
                Response::HttpInfo { port, ca_hosts } => {
                    out.http_port = Some(port);
                    out.ca_hosts = ca_hosts;
                }
                Response::AwsInfo { port } => out.aws_port = Some(port),
                Response::Error {
                    code: ErrorCode::Internal,
                    ..
                } => {}
                r => return Err(unexpected(r)),
            }
        }
        Ok(out)
    }
}

#[cfg(all(test, unix))] // the mock daemon is a UnixListener
mod tests {
    use super::*;
    use ls_ipc::{Frame, read_frame, write_frame};
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;

    const SECRET: &str = "correct-horse-battery-staple-4711";

    struct MockPrompt(Option<&'static str>);
    impl SecurePrompt for MockPrompt {
        fn ask(&self, _: &str, _: &str) -> Option<Zeroizing<String>> {
            self.0.map(|s| Zeroizing::new(s.to_string()))
        }
    }

    /// What the mock daemon saw: the request kind plus any secret bytes it carried.
    type Seen = (String, Vec<u8>);

    /// A mock `locksmithd`: a UnixListener speaking the ls-ipc framing in a temp runtime dir.
    /// Answers each request with `answer` and reports what it received.
    fn mock_daemon(
        tag: &str,
        answer: fn(&Request) -> Response,
    ) -> (Daemon, mpsc::Receiver<Seen>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("lsdk-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join(ls_ipc::SOCKET_FILE);
        let l = UnixListener::bind(&socket).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                while let Ok(Some(Frame::Msg(req))) = read_frame::<Request>(&mut s) {
                    let seen = match &req {
                        Request::Unlock { passphrase } => {
                            ("Unlock".into(), passphrase.expose().to_vec())
                        }
                        Request::SecretPut {
                            project,
                            env,
                            name,
                            value,
                        } => (
                            format!("SecretPut {project}/{env}/{name}"),
                            value.expose().to_vec(),
                        ),
                        _ => ("other".into(), vec![]),
                    };
                    let _ = tx.send(seen);
                    if write_frame(&mut s, &answer(&req)).is_err() {
                        break;
                    }
                }
            }
        });
        (Daemon { socket }, rx, dir)
    }

    /// The command result as the webview would receive it (Tauri serializes with serde_json).
    fn webview_json<T: serde::Serialize>(r: &Result<T>) -> String {
        match r {
            Ok(v) => serde_json::to_string(v).unwrap(),
            Err(e) => serde_json::to_string(e).unwrap(),
        }
    }

    #[test]
    fn unlock_value_reaches_daemon_and_never_the_webview() {
        let (d, rx, dir) = mock_daemon("unlock", |_| Response::Ok);
        let r = d.unlock_secure(&MockPrompt(Some(SECRET)));
        let json = webview_json(&r);
        assert_eq!(json, "\"submitted\"");
        assert!(!json.contains(SECRET));
        assert_eq!(
            rx.recv().unwrap(),
            ("Unlock".into(), SECRET.as_bytes().to_vec())
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn secret_put_value_reaches_daemon_and_never_the_webview() {
        let (d, rx, dir) = mock_daemon("put", |_| Response::Ok);
        let r = d.put_secret_secure(
            &MockPrompt(Some(SECRET)),
            "shop".into(),
            "dev".into(),
            "STRIPE_KEY".into(),
        );
        let json = webview_json(&r);
        assert_eq!(json, "\"submitted\"");
        assert!(!json.contains(SECRET));
        assert_eq!(
            rx.recv().unwrap(),
            (
                "SecretPut shop/dev/STRIPE_KEY".into(),
                SECRET.as_bytes().to_vec()
            )
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cancel_sends_nothing_and_daemon_errors_carry_no_value() {
        let (d, rx, dir) = mock_daemon("deny", |_| Response::Error {
            code: ErrorCode::Denied,
            message: "wrong passphrase".into(),
        });
        let r = d.unlock_secure(&MockPrompt(None));
        assert_eq!(webview_json(&r), "\"cancelled\"");
        assert!(rx.try_recv().is_err(), "cancel must not contact the daemon");

        let r = d.unlock_secure(&MockPrompt(Some(SECRET)));
        let json = webview_json(&r);
        assert_eq!(json, r#"{"code":"Denied","message":"wrong passphrase"}"#);
        assert!(!json.contains(SECRET));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn health_reports_version_and_fails_when_daemon_is_down() {
        let (d, _rx, dir) = mock_daemon("health", |_| Response::Pong {
            version: "1.2.3".into(),
        });
        assert_eq!(d.health().unwrap(), "1.2.3");
        let (d2, _rx2, dir2) = mock_daemon("health-bad", |_| Response::Ok);
        assert_eq!(d2.health().unwrap_err().code, CommandErrorCode::Unexpected);
        let gone = Daemon {
            socket: dir.join("missing.sock"),
        };
        assert_eq!(
            gone.health().unwrap_err().code,
            CommandErrorCode::Unavailable
        );
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(dir2);
    }

    #[test]
    fn views_and_errors_map_from_daemon_responses() {
        let (d, _rx, dir) = mock_daemon("views", |req| match req {
            Request::Status => Response::Status {
                locked: true,
                leases: vec![],
            },
            Request::GitInfo => Response::GitInfo {
                port: 7,
                include: "/x".into(),
                hosts: vec![],
            },
            Request::HttpInfo => Response::Error {
                code: ErrorCode::Internal,
                message: "HTTP relay is not running".into(),
            },
            Request::AwsInfo => Response::AwsInfo { port: 9 },
            _ => Response::Pong {
                version: "0".into(),
            },
        });
        assert_eq!(webview_json(&d.status()), r#"{"locked":true,"leases":[]}"#);
        assert_eq!(
            webview_json(&d.relay_info()),
            r#"{"git_port":7,"http_port":null,"aws_port":9,"ca_hosts":[]}"#
        );
        assert_eq!(d.lock().unwrap_err().code, CommandErrorCode::Unexpected);
        let gone = Daemon {
            socket: dir.join("missing.sock"),
        };
        assert_eq!(
            gone.status().unwrap_err().code,
            CommandErrorCode::Unavailable
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
