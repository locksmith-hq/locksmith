//! Secret ingress: passphrase and value input, agent detection, KDF parameter choice.

use crate::Fail;
use ls_core::ExitCode;
use ls_crypto::kdf::KdfParams;
use std::io::{BufRead, Read};
use zeroize::Zeroizing;

pub struct Opts {
    pub json: bool,
    pub passphrase_stdin: bool,
    /// Debug builds only: read the init confirmation words from stdin.
    pub test_confirm: bool,
}

/// Production always uses `KdfParams::MINIMUM`. The `LOCKSMITH_INSECURE_TEST_KDF` override is
/// compiled out of release builds (`cfg(debug_assertions)`), so a release binary ignores it.
pub fn kdf() -> (KdfParams, bool) {
    #[cfg(debug_assertions)]
    if std::env::var("LOCKSMITH_INSECURE_TEST_KDF").as_deref() == Ok("1") {
        return (
            KdfParams {
                m_kib: 64,
                t: 1,
                p: 1,
            },
            true,
        );
    }
    (KdfParams::MINIMUM, false)
}

fn io_fail(e: std::io::Error) -> Fail {
    Fail(ExitCode::Failure, format!("cannot read input: {e}"))
}

fn trim_nl(mut s: String) -> Zeroizing<String> {
    while s.ends_with('\n') || s.ends_with('\r') {
        s.pop();
    }
    Zeroizing::new(s)
}

/// One line from stdin (the shared stdin buffer, so later `read_to_end` continues after it).
pub fn read_line_stdin() -> Result<Zeroizing<String>, Fail> {
    let mut s = String::new();
    let n = std::io::stdin().lock().read_line(&mut s).map_err(io_fail)?;
    if n == 0 {
        return Err(Fail(
            ExitCode::Failure,
            "unexpected end of input on stdin".into(),
        ));
    }
    Ok(trim_nl(s))
}

/// No-echo prompt on the controlling terminal.
pub fn prompt_secret(prompt: &str) -> Result<Zeroizing<String>, Fail> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|e| {
            Fail(
                ExitCode::Failure,
                format!(
                    "no terminal for a no-echo prompt ({e}); use --passphrase-stdin or --stdin"
                ),
            )
        })
}

pub fn passphrase(o: &Opts, prompt: &str) -> Result<Zeroizing<String>, Fail> {
    if o.passphrase_stdin {
        read_line_stdin()
    } else {
        prompt_secret(prompt)
    }
}

pub fn new_passphrase(o: &Opts) -> Result<Zeroizing<String>, Fail> {
    let p = if o.passphrase_stdin {
        read_line_stdin()?
    } else {
        let a = prompt_secret("New passphrase: ")?;
        if *a != *prompt_secret("Repeat new passphrase: ")? {
            return Err(Fail(ExitCode::Usage, "passphrases do not match".into()));
        }
        a
    };
    if p.is_empty() {
        return Err(Fail(ExitCode::Usage, "passphrase must not be empty".into()));
    }
    Ok(p)
}

/// Whole stdin as a secret value; one trailing newline is dropped (`echo v | smith add K --stdin`).
pub fn read_value_stdin() -> Result<Vec<u8>, Fail> {
    let mut v = Vec::new();
    std::io::stdin()
        .lock()
        .read_to_end(&mut v)
        .map_err(io_fail)?;
    if v.ends_with(b"\n") {
        v.pop();
        if v.ends_with(b"\r") {
            v.pop();
        }
    }
    Ok(v)
}

/// Line typed on the controlling terminal (echoed), for yes/no questions.
pub fn tty_line(prompt: &str) -> Option<String> {
    eprint!("{prompt}");
    let tty = std::fs::File::open("/dev/tty").ok()?;
    let mut s = String::new();
    std::io::BufReader::new(tty).read_line(&mut s).ok()?;
    Some(s.trim().to_string())
}

/// Name of the first AI-agent marker found in the environment.
pub fn agent_detected() -> Option<String> {
    std::env::vars_os()
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .find(|k| k == "CLAUDECODE" || k == "CURSOR_TRACE_ID" || k.starts_with("CODEX_"))
}
