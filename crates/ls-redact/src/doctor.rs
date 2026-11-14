//! Doctor checks for the redactor and for PTY support (used by `smith run`).

use crate::{Redactor, Secret};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ls_diag::{Check, Outcome};

const LABEL: &str = "SELFTEST";
const CANARY: &[u8] = b"selftest-canary-0123456789";
const FIX: &str = "reinstall Locksmith and file a bug";

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Each form must come out as the label, with no trace of the canary left.
fn check_form(r: &Redactor, name: &str, input: &[u8], canary_form: &[u8]) -> Result<(), String> {
    let out = r.redact_all(input);
    let marker = format!("[REDACTED:{LABEL}]");
    if !contains(&out, marker.as_bytes()) || contains(&out, canary_form) {
        return Err(format!("{name} form was not redacted"));
    }
    Ok(())
}

fn run_selftest() -> Result<(), String> {
    let r = Redactor::new(&[Secret::new(LABEL, CANARY)]);
    let b64 = STANDARD.encode(CANARY).into_bytes();
    let hex: Vec<u8> = CANARY
        .iter()
        .flat_map(|b| format!("{b:02x}").into_bytes())
        .collect();
    check_form(&r, "plain", CANARY, CANARY)?;
    check_form(&r, "base64", &b64, &b64)?;
    check_form(&r, "hex", &hex, &hex)?;

    // One byte per write, flushing after each, so the held-back logic is exercised.
    let mut s = r.stream();
    let mut out = Vec::new();
    for b in CANARY.chunks(1) {
        out.extend(s.push(b));
        out.extend(s.flush_idle());
    }
    out.extend(s.finish());
    let marker = format!("[REDACTED:{LABEL}]");
    if !contains(&out, marker.as_bytes()) || contains(&out, CANARY) {
        return Err("streamed plain form was not redacted".into());
    }
    Ok(())
}

fn selftest() -> Outcome {
    match run_selftest() {
        Ok(()) => Outcome::ok("redactor masks plain, base64, hex and streamed forms"),
        Err(why) => Outcome::fail(format!("redactor self-test failed: {why}"), FIX),
    }
}

#[cfg(unix)]
fn pty_available() -> Outcome {
    if std::path::Path::new("/dev/ptmx").exists() {
        Outcome::ok("/dev/ptmx is present; smith run can use a PTY")
    } else {
        Outcome::warn(
            "/dev/ptmx is missing",
            "smith run will fall back to pipe mode",
        )
    }
}

#[cfg(not(unix))]
fn pty_available() -> Outcome {
    Outcome::skip("PTY mode is unix-only")
}

inventory::submit! { Check { id: "redact.selftest", run: selftest } }
inventory::submit! { Check { id: "run.pty_available", run: pty_available } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_passes() {
        assert!(run_selftest().is_ok(), "{:?}", run_selftest());
        assert_eq!(selftest().status, ls_diag::Status::Ok);
    }
}
