//! Doctor checks for the daemon, its socket, the process hardening and the audit ledger.
//! Each check is a small pure function over its inputs (a daemon reply, file contents, a path)
//! so the tests run without a daemon. The `run` functions only gather those inputs.

use ls_diag::{Check, Outcome};
use ls_ipc::{Client, ErrorCode, Request, Response};
use std::io;
use std::path::Path;

const PTRACE_SCOPE: &str = "/proc/sys/kernel/yama/ptrace_scope";

/// One request on a fresh connection to the daemon.
fn ask(req: &Request) -> io::Result<Response> {
    Client::connect(&ls_ipc::socket_path())?.call(req)
}

fn ping_outcome(reply: io::Result<Response>) -> Outcome {
    match reply {
        Ok(Response::Pong { version }) => Outcome::ok(format!("locksmithd {version} is running")),
        Ok(_) => Outcome::warn(
            "daemon sent an unexpected reply to ping",
            "smith daemon install",
        ),
        Err(_) => Outcome::warn("daemon not running", "smith daemon install"),
    }
}

fn running() -> Outcome {
    ping_outcome(ask(&Request::Ping))
}

fn socket_perms_at(runtime: &Path, socket: &Path) -> Outcome {
    if !runtime.exists() {
        return Outcome::skip(format!("{} not created yet", runtime.display()));
    }
    match ls_core::is_private_dir(runtime) {
        Ok(true) => {}
        Ok(false) => {
            return Outcome::fail(
                format!("{} is readable by other users", runtime.display()),
                format!("chmod 700 '{}'", runtime.display()),
            );
        }
        Err(e) => {
            return Outcome::fail(
                format!("cannot stat runtime dir: {e}"),
                "check ownership of the directory",
            );
        }
    }
    #[cfg(not(unix))]
    {
        // No socket file: the named pipe carries its own current-user-only DACL (ls-ipc).
        let _ = socket;
        Outcome::ok("runtime directory is private; the daemon pipe is current-user only")
    }
    #[cfg(unix)]
    match std::fs::metadata(socket) {
        Ok(m) if std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o077 != 0 => {
            Outcome::fail(
                "daemon socket is accessible to other users",
                format!("chmod 600 '{}'", socket.display()),
            )
        }
        Ok(_) => Outcome::ok("runtime directory and daemon socket are private to the current user"),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            Outcome::ok("runtime directory is private (0700)")
        }
        Err(e) => Outcome::fail(
            format!("cannot stat daemon socket: {e}"),
            "check ownership of the runtime directory",
        ),
    }
}

fn socket_perms() -> Outcome {
    socket_perms_at(&ls_ipc::runtime_dir(), &ls_ipc::socket_path())
}

fn attestation_outcome(reply: io::Result<Response>) -> Outcome {
    match reply {
        Ok(Response::Status { .. }) => Outcome::ok("daemon attests this smith binary"),
        Ok(Response::Error {
            code: ErrorCode::Denied,
            ..
        }) => Outcome::fail(
            "daemon does not recognise this smith binary (reinstall, or restart the daemon after an update)",
            "smith daemon install",
        ),
        Ok(_) => Outcome::skip("daemon sent an unexpected reply to status"),
        Err(_) => Outcome::skip("daemon not running"),
    }
}

fn attestation() -> Outcome {
    attestation_outcome(ask(&Request::Status))
}

/// `contents` is the Yama sysctl file; `NotFound` means the Yama LSM is not built or enabled.
fn ptrace_outcome(contents: io::Result<String>) -> Outcome {
    let s = match contents {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Outcome::warn(
                "Yama is absent; the kernel does not restrict same-user attach",
                "enable the Yama LSM",
            );
        }
        Err(e) => {
            return Outcome::warn(
                format!("cannot read Yama ptrace_scope: {e}"),
                "check permissions on /proc/sys/kernel/yama",
            );
        }
    };
    match s.trim().parse::<u8>() {
        Ok(0) => Outcome::warn(
            "any same-user process can attach to Locksmith processes",
            "sudo sysctl kernel.yama.ptrace_scope=1",
        ),
        Ok(n) => Outcome::ok(format!(
            "Yama ptrace_scope is {n}, same-user attach is restricted"
        )),
        Err(_) => Outcome::warn(
            "unrecognised Yama ptrace_scope value",
            format!("cat {PTRACE_SCOPE}"),
        ),
    }
}

fn with_pidfd_note(mut out: Outcome, has_pidfd: bool) -> Outcome {
    if !has_pidfd {
        out.summary
            .push_str("; kernel lacks pidfd; falling back to pid+start time");
    }
    out
}

fn ptrace_scope() -> Outcome {
    if !cfg!(target_os = "linux") {
        return Outcome::skip("not applicable on this OS");
    }
    with_pidfd_note(
        ptrace_outcome(std::fs::read_to_string(PTRACE_SCOPE)),
        ls_platform::proc::has_pidfd(),
    )
}

fn core_dumps_outcome(r: io::Result<()>) -> Outcome {
    match r {
        Ok(()) => Outcome::ok("Locksmith processes disable core dumps"),
        Err(e) => Outcome::fail(
            format!("cannot disable core dumps: {e}"),
            "check the RLIMIT_CORE limit for this user",
        ),
    }
}

fn core_dumps() -> Outcome {
    core_dumps_outcome(ls_platform::probe_core_dumps())
}

fn audit_outcome(reply: io::Result<Response>) -> Outcome {
    match reply {
        Ok(Response::AuditVerify {
            broken_at: None,
            events,
            ..
        }) => Outcome::ok(format!("{events} audit events, chain intact")),
        Ok(Response::AuditVerify {
            broken_at: Some(n), ..
        }) => Outcome::fail(
            format!("audit ledger broken at event {n}"),
            "smith audit verify",
        ),
        Ok(Response::Error {
            code: ErrorCode::Locked,
            ..
        })
        | Err(_) => Outcome::skip("vault locked; run `smith audit verify`"),
        Ok(_) => Outcome::skip("daemon sent an unexpected reply to audit verify"),
    }
}

fn audit_chain() -> Outcome {
    audit_outcome(ask(&Request::AuditVerify))
}

inventory::submit! { Check { id: "daemon.running", run: running } }
inventory::submit! { Check { id: "daemon.socket_perms", run: socket_perms } }
inventory::submit! { Check { id: "daemon.attestation_selftest", run: attestation } }
inventory::submit! { Check { id: "platform.ptrace_scope", run: ptrace_scope } }
inventory::submit! { Check { id: "platform.core_dumps", run: core_dumps } }
inventory::submit! { Check { id: "audit.chain", run: audit_chain } }

#[cfg(test)]
mod tests {
    use super::*;
    use ls_diag::Status;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// Asserts the exact status, summary and remediation a branch must produce.
    #[track_caller]
    fn expect(out: &Outcome, status: Status, summary: &str, remediation: Option<&str>) {
        assert_eq!(out.status, status, "status for {summary:?}");
        assert_eq!(out.summary, summary);
        assert_eq!(out.remediation.as_deref(), remediation);
    }

    fn refused() -> io::Error {
        io::Error::from(io::ErrorKind::ConnectionRefused)
    }

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("ls-broker-doctor-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn ping_reports_version_or_warns_when_not_running() {
        let pong = Response::Pong {
            version: "1.2.3".into(),
        };
        expect(
            &ping_outcome(Ok(pong)),
            Status::Ok,
            "locksmithd 1.2.3 is running",
            None,
        );
        expect(
            &ping_outcome(Err(refused())),
            Status::Warn,
            "daemon not running",
            Some("smith daemon install"),
        );
        expect(
            &ping_outcome(Ok(Response::Ok)),
            Status::Warn,
            "daemon sent an unexpected reply to ping",
            Some("smith daemon install"),
        );
    }

    #[test]
    fn socket_perms_branches() {
        let t = Tmp::new("sock");
        let runtime = t.0.join("run");
        let socket = runtime.join(ls_ipc::SOCKET_FILE);

        // No runtime directory yet: nothing to check.
        expect(
            &socket_perms_at(&runtime, &socket),
            Status::Skip,
            &format!("{} not created yet", runtime.display()),
            None,
        );

        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o755)).unwrap();
        expect(
            &socket_perms_at(&runtime, &socket),
            Status::Fail,
            &format!("{} is readable by other users", runtime.display()),
            Some(&format!("chmod 700 '{}'", runtime.display())),
        );

        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        expect(
            &socket_perms_at(&runtime, &socket),
            Status::Ok,
            "runtime directory is private (0700)",
            None,
        );

        std::fs::write(&socket, b"").unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
        expect(
            &socket_perms_at(&runtime, &socket),
            Status::Fail,
            "daemon socket is accessible to other users",
            Some(&format!("chmod 600 '{}'", socket.display())),
        );

        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        expect(
            &socket_perms_at(&runtime, &socket),
            Status::Ok,
            "runtime directory and daemon socket are private to the current user",
            None,
        );
    }

    #[test]
    fn attestation_branches() {
        let status = Response::Status {
            locked: false,
            leases: vec![],
        };
        expect(
            &attestation_outcome(Ok(status)),
            Status::Ok,
            "daemon attests this smith binary",
            None,
        );
        expect(
            &attestation_outcome(Ok(Response::Error {
                code: ErrorCode::Denied,
                message: "not attested".into(),
            })),
            Status::Fail,
            "daemon does not recognise this smith binary (reinstall, or restart the daemon after an update)",
            Some("smith daemon install"),
        );
        expect(
            &attestation_outcome(Err(refused())),
            Status::Skip,
            "daemon not running",
            None,
        );
        expect(
            &attestation_outcome(Ok(Response::Error {
                code: ErrorCode::Internal,
                message: "boom".into(),
            })),
            Status::Skip,
            "daemon sent an unexpected reply to status",
            None,
        );
    }

    #[test]
    fn ptrace_scope_branches() {
        expect(
            &ptrace_outcome(Ok("0\n".into())),
            Status::Warn,
            "any same-user process can attach to Locksmith processes",
            Some("sudo sysctl kernel.yama.ptrace_scope=1"),
        );
        expect(
            &ptrace_outcome(Ok("1\n".into())),
            Status::Ok,
            "Yama ptrace_scope is 1, same-user attach is restricted",
            None,
        );
        expect(
            &ptrace_outcome(Ok("2".into())),
            Status::Ok,
            "Yama ptrace_scope is 2, same-user attach is restricted",
            None,
        );
        expect(
            &ptrace_outcome(Err(io::Error::from(io::ErrorKind::NotFound))),
            Status::Warn,
            "Yama is absent; the kernel does not restrict same-user attach",
            Some("enable the Yama LSM"),
        );
        expect(
            &ptrace_outcome(Ok("garbage".into())),
            Status::Warn,
            "unrecognised Yama ptrace_scope value",
            Some(&format!("cat {PTRACE_SCOPE}")),
        );
    }

    #[test]
    fn pidfd_note_is_appended_only_without_pidfd() {
        expect(
            &with_pidfd_note(Outcome::ok("base"), false),
            Status::Ok,
            "base; kernel lacks pidfd; falling back to pid+start time",
            None,
        );
        expect(
            &with_pidfd_note(Outcome::ok("base"), true),
            Status::Ok,
            "base",
            None,
        );
        expect(
            &with_pidfd_note(Outcome::warn("base", "fix"), false),
            Status::Warn,
            "base; kernel lacks pidfd; falling back to pid+start time",
            Some("fix"),
        );
    }

    #[test]
    fn core_dumps_branches() {
        expect(
            &core_dumps_outcome(Ok(())),
            Status::Ok,
            "Locksmith processes disable core dumps",
            None,
        );
        expect(
            &core_dumps_outcome(Err(io::Error::from(io::ErrorKind::PermissionDenied))),
            Status::Fail,
            "cannot disable core dumps: permission denied",
            Some("check the RLIMIT_CORE limit for this user"),
        );
    }

    #[test]
    fn audit_chain_branches() {
        let intact = Response::AuditVerify {
            events: 42,
            broken_at: None,
            detail: String::new(),
        };
        expect(
            &audit_outcome(Ok(intact)),
            Status::Ok,
            "42 audit events, chain intact",
            None,
        );
        let broken = Response::AuditVerify {
            events: 42,
            broken_at: Some(7),
            detail: "hash mismatch".into(),
        };
        expect(
            &audit_outcome(Ok(broken)),
            Status::Fail,
            "audit ledger broken at event 7",
            Some("smith audit verify"),
        );
        expect(
            &audit_outcome(Ok(Response::Error {
                code: ErrorCode::Locked,
                message: "locked".into(),
            })),
            Status::Skip,
            "vault locked; run `smith audit verify`",
            None,
        );
        expect(
            &audit_outcome(Err(refused())),
            Status::Skip,
            "vault locked; run `smith audit verify`",
            None,
        );
    }
}
