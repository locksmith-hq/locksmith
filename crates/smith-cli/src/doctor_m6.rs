//! Doctor checks for M6 HTTP delegation: `http.relay` and `http.ca_constraints`. Pure functions
//! over explicit facts (like doctor_m5), so the tests need no daemon or CA on disk.

use ls_diag::{Check, Outcome};
use ls_ipc::{Client, Request, Response};
use ls_proxy::ca;

const REINSTALL: &str = "smith http ca uninstall && smith http ca install";

/// `reply`: `None` when the daemon is not running.
fn relay_outcome(reply: Option<std::io::Result<Response>>) -> Outcome {
    match reply {
        None => Outcome::skip("locksmithd is not running"),
        Some(Ok(Response::HttpInfo { port, .. })) => {
            Outcome::ok(format!("listening on 127.0.0.1:{port}"))
        }
        Some(Ok(Response::Error { message, .. })) => Outcome::fail(message, "smith daemon status"),
        Some(Ok(_)) => Outcome::fail("unexpected daemon reply", "smith daemon status"),
        Some(Err(e)) => Outcome::fail(format!("daemon did not answer: {e}"), "smith daemon status"),
    }
}

/// `cert`: the installed CA certificate (PEM), if any. `enabled`: the hosts file.
fn ca_outcome(cert: Option<&str>, enabled: &[String]) -> Outcome {
    let Some(pem) = cert else {
        return Outcome::skip("explicit-proxy mode is off (no local CA)");
    };
    let Ok(info) = ca::inspect(pem) else {
        return Outcome::fail("cannot parse the local CA certificate", REINSTALL);
    };
    if !info.is_ca || !info.constrained || info.permitted_dns.is_empty() || !info.excludes_ip {
        return Outcome::fail(
            "local CA is not name-constrained (it could sign certificates for any site)",
            REINSTALL,
        );
    }
    let mut want: Vec<String> = enabled
        .iter()
        .map(|h| h.trim_start_matches("*.").to_string())
        .collect();
    want.sort();
    want.dedup();
    let mut have = info.permitted_dns.clone();
    have.sort();
    if have != want {
        return Outcome::warn(
            format!(
                "CA constraints ({}) differ from the enabled hosts ({})",
                have.join(", "),
                want.join(", ")
            ),
            REINSTALL,
        );
    }
    Outcome::ok(format!(
        "local CA constrained to {} host(s): {}",
        have.len(),
        have.join(", ")
    ))
}

/// Never starts the daemon.
fn relay() -> Outcome {
    let reply = Client::connect_default()
        .ok()
        .map(|mut c| c.call(&Request::HttpInfo));
    relay_outcome(reply)
}

fn ca_constraints() -> Outcome {
    let cfg = ls_core::config_dir();
    let pem = std::fs::read_to_string(ca::cert_path(&cfg)).ok();
    ca_outcome(pem.as_deref(), &ca::enabled_hosts(&cfg))
}

inventory::submit! { Check { id: "http.relay", run: relay } }
inventory::submit! { Check { id: "http.ca_constraints", run: ca_constraints } }

#[cfg(test)]
mod tests {
    use super::*;
    use ls_diag::Status;
    use ls_ipc::ErrorCode;

    #[track_caller]
    fn expect(out: &Outcome, status: Status, summary: &str, remediation: Option<&str>) {
        assert_eq!(out.status, status, "status for {summary:?}");
        assert_eq!(out.summary, summary);
        assert_eq!(out.remediation.as_deref(), remediation);
    }

    #[test]
    fn relay_branches() {
        expect(
            &relay_outcome(None),
            Status::Skip,
            "locksmithd is not running",
            None,
        );
        let info = Response::HttpInfo {
            port: 4243,
            ca_hosts: vec![],
        };
        expect(
            &relay_outcome(Some(Ok(info))),
            Status::Ok,
            "listening on 127.0.0.1:4243",
            None,
        );
        let e = Response::Error {
            code: ErrorCode::Internal,
            message: "HTTP relay is not running".into(),
        };
        expect(
            &relay_outcome(Some(Ok(e))),
            Status::Fail,
            "HTTP relay is not running",
            Some("smith daemon status"),
        );
        expect(
            &relay_outcome(Some(Ok(Response::Ok))),
            Status::Fail,
            "unexpected daemon reply",
            Some("smith daemon status"),
        );
        expect(
            &relay_outcome(Some(Err(std::io::Error::other("boom")))),
            Status::Fail,
            "daemon did not answer: boom",
            Some("smith daemon status"),
        );
    }

    #[test]
    fn ca_branches() {
        expect(
            &ca_outcome(None, &[]),
            Status::Skip,
            "explicit-proxy mode is off (no local CA)",
            None,
        );
        expect(
            &ca_outcome(Some("not a cert"), &[]),
            Status::Fail,
            "cannot parse the local CA certificate",
            Some(REINSTALL),
        );
        let hosts = vec!["api.stripe.com".to_string(), "*.myshopify.com".to_string()];
        let good = ca::generate(&hosts).unwrap();
        expect(
            &ca_outcome(Some(&good.cert_pem), &hosts),
            Status::Ok,
            "local CA constrained to 2 host(s): api.stripe.com, myshopify.com",
            None,
        );
        expect(
            &ca_outcome(Some(&good.cert_pem), &["api.openai.com".into()]),
            Status::Warn,
            "CA constraints (api.stripe.com, myshopify.com) differ from the enabled hosts (api.openai.com)",
            Some(REINSTALL),
        );
        // An unconstrained CA (any self-signed CA without the extension) fails.
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::default();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let open = p.self_signed(&key).unwrap().pem();
        expect(
            &ca_outcome(Some(&open), &hosts),
            Status::Fail,
            "local CA is not name-constrained (it could sign certificates for any site)",
            Some(REINSTALL),
        );
    }
}
