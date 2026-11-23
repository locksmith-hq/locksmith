//! Doctor check `db.gateway` (D3): when a hosted-gateway Postgres listener is configured
//! (`LOCKSMITH_DB_GATEWAY`, the same value `smith db connect --gateway` reads), probe that it is
//! reachable over TLS and that `~/.pgpass` has no entry for that host (libpq would offer a stored
//! database password to the gateway; the gateway needs the agent token, and a stored password for
//! the host is a credential the agent could read). Pure over explicit facts, like `doctor_m6_db`;
//! the wrapper gathers the TLS probe and the pgpass file. Never reads or prints a password: only
//! line numbers of matching entries are reported.

use crate::db_cmd::GatewayTarget;
use ls_diag::{CheckSet, Outcome};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

/// 1-based line numbers of `~/.pgpass` entries whose host field names `host` or is `*`.
/// Comments and blank lines are skipped. Escaped colons (`\:`) do not end the field.
pub fn pgpass_matches(contents: &str, host: &str) -> Vec<usize> {
    contents
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .filter(|(_, l)| {
            let mut field = String::new();
            let mut chars = l.chars();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        if let Some(n) = chars.next() {
                            field.push(n);
                        }
                    }
                    ':' => break,
                    c => field.push(c),
                }
            }
            field == "*" || field.eq_ignore_ascii_case(host)
        })
        .map(|(i, _)| i + 1)
        .collect()
}

/// `target`: the configured gateway (`Err` when `LOCKSMITH_DB_GATEWAY` is malformed). `tls`: the
/// probe result. `pgpass`: matching line numbers.
pub fn outcome(
    target: Option<Result<&GatewayTarget, &str>>,
    tls: &dyn Fn(&GatewayTarget) -> Result<(), String>,
    pgpass: &dyn Fn(&str) -> Vec<usize>,
) -> Outcome {
    let t = match target {
        None => {
            return Outcome::skip(
                "no database gateway configured (set LOCKSMITH_DB_GATEWAY or use \
                 `smith db connect --gateway`)",
            );
        }
        Some(Err(e)) => {
            return Outcome::fail(
                format!("LOCKSMITH_DB_GATEWAY is invalid: {e}"),
                "set it to host[:port] of the gateway's Postgres listener",
            );
        }
        Some(Ok(t)) => t,
    };
    let (host, port) = (&t.host, t.port);
    if let Err(e) = tls(t) {
        return Outcome::fail(
            format!("gateway Postgres listener {host}:{port} is not reachable over TLS ({e})"),
            "check LOCKSMITH_GATEWAY_PG_LISTEN and its certificate on the gateway, the host and \
             port, and --ca-cert for a private CA",
        );
    }
    let hits = pgpass(host);
    if !hits.is_empty() {
        let lines: Vec<String> = hits.iter().map(usize::to_string).collect();
        return Outcome::warn(
            format!(
                "~/.pgpass has an entry for {host} (line {}): a stored password could be read by \
                 an agent",
                lines.join(", ")
            ),
            "remove the entry; the gateway authenticates with the agent token (PGPASSWORD) only",
        );
    }
    Outcome::ok(format!(
        "gateway Postgres listener {host}:{port} reachable over TLS; no ~/.pgpass entry for {host}"
    ))
}

fn root_store(extra_pem: Option<&[u8]>) -> rustls::RootCertStore {
    let mut r = rustls::RootCertStore::empty();
    r.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    r.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = extra_pem {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
            .filter_map(Result::ok)
            .collect();
        r.add_parsable_certificates(certs);
    }
    r
}

/// Postgres `SSLRequest`, expect `S`, then a verified TLS handshake (system roots plus the file in
/// `PGSSLROOTCERT`). No startup message is sent, so no session and no credential is involved.
pub fn probe_tls(t: &GatewayTarget, extra_pem: Option<&[u8]>) -> Result<(), String> {
    let t0 = Duration::from_secs(3);
    let addrs: Vec<_> = (t.host.as_str(), t.port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .collect();
    let mut last = "host did not resolve".to_string();
    let mut tcp = None;
    for a in addrs {
        match TcpStream::connect_timeout(&a, t0) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = e.to_string(),
        }
    }
    let mut tcp = tcp.ok_or(last)?;
    let _ = tcp.set_read_timeout(Some(t0));
    let _ = tcp.set_write_timeout(Some(t0));
    tcp.write_all(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f])
        .map_err(|e| e.to_string())?;
    let mut b = [0u8; 1];
    tcp.read_exact(&mut b).map_err(|e| e.to_string())?;
    if b[0] != b'S' {
        return Err("the listener does not offer TLS".into());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|_| "TLS setup failed".to_string())?
        .with_root_certificates(root_store(extra_pem))
        .with_no_client_auth();
    let name = ServerName::try_from(t.host.clone()).map_err(|_| "invalid host name")?;
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name)
        .map_err(|_| "TLS setup failed".to_string())?;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp)
            .map_err(|e| format!("TLS handshake failed: {e}"))?;
    }
    conn.send_close_notify();
    let _ = conn.complete_io(&mut tcp);
    Ok(())
}

fn pgpass_path() -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var_os("PGPASSFILE") {
        return Some(p.into());
    }
    #[cfg(windows)]
    let p = std::env::var_os("APPDATA")
        .map(|a| std::path::PathBuf::from(a).join("postgresql/pgpass.conf"));
    #[cfg(not(windows))]
    let p = std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".pgpass"));
    p
}

fn run() -> Vec<(String, Outcome)> {
    let raw = std::env::var("LOCKSMITH_DB_GATEWAY")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let parsed = raw.as_deref().map(GatewayTarget::parse);
    let target = parsed.as_ref().map(|r| r.as_ref().map_err(String::as_str));
    let root_pem = std::env::var_os("PGSSLROOTCERT").and_then(|p| std::fs::read(p).ok());
    let o = outcome(target, &|t| probe_tls(t, root_pem.as_deref()), &|host| {
        pgpass_path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|c| pgpass_matches(&c, host))
            .unwrap_or_default()
    });
    vec![("db.gateway".to_string(), o)]
}

inventory::submit! { CheckSet { prefix: "db.gateway", run } }

#[cfg(test)]
mod tests {
    use super::*;
    use ls_diag::Status;

    fn gw() -> GatewayTarget {
        GatewayTarget {
            host: "gw.example.com".into(),
            port: 5433,
        }
    }

    #[test]
    fn pgpass_matching_reports_lines_only() {
        let f = "# comment\n\ngw.example.com:5432:*:app:s3cret\notherhost:*:*:*:x\n*:*:*:*:y\nGW.EXAMPLE.COM:*:*:*:z\ngw\\:x:1:2:3:4\n";
        assert_eq!(pgpass_matches(f, "gw.example.com"), vec![3, 5, 6]);
        assert!(pgpass_matches(f, "nothing.example").iter().all(|l| *l == 5));
        assert!(pgpass_matches("", "h").is_empty());
    }

    #[test]
    fn db_gateway_branches() {
        let up = |_: &GatewayTarget| Ok(());
        let down = |_: &GatewayTarget| Err("connection refused".to_string());
        let none = |_: &str| Vec::new();
        let hit = |_: &str| vec![3usize, 7];

        let o = outcome(None, &up, &none);
        assert_eq!(o.status, Status::Skip);
        let o = outcome(Some(Err("bad")), &up, &none);
        assert_eq!(o.status, Status::Fail);
        let t = gw();
        let o = outcome(Some(Ok(&t)), &down, &hit);
        assert_eq!(o.status, Status::Fail);
        assert_eq!(
            o.summary,
            "gateway Postgres listener gw.example.com:5433 is not reachable over TLS (connection refused)"
        );
        let o = outcome(Some(Ok(&t)), &up, &hit);
        assert_eq!(o.status, Status::Warn);
        assert!(o.summary.contains("line 3, 7"), "{}", o.summary);
        assert!(!o.summary.contains("s3cret"));
        let o = outcome(Some(Ok(&t)), &up, &none);
        assert_eq!(o.status, Status::Ok);
    }

    #[test]
    fn probe_refuses_a_plaintext_listener() {
        use std::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 8];
            s.read_exact(&mut b).unwrap();
            assert_eq!(b, [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]);
            s.write_all(b"N").unwrap();
        });
        let t = GatewayTarget {
            host: "127.0.0.1".into(),
            port,
        };
        let e = probe_tls(&t, None).unwrap_err();
        assert!(e.contains("does not offer TLS"), "{e}");
        h.join().unwrap();
        // Nothing listening: refused.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        assert!(
            probe_tls(
                &GatewayTarget {
                    host: "127.0.0.1".into(),
                    port
                },
                None
            )
            .is_err()
        );
    }

    #[test]
    fn probe_accepts_a_listener_with_a_trusted_certificate() {
        use std::net::TcpListener;
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = ck.cert.pem();
        let der = ck.cert.der().clone();
        let key =
            rustls::pki_types::PrivateKeyDer::try_from(ck.signing_key.serialize_der()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let scfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der], key)
            .unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 8];
            s.read_exact(&mut b).unwrap();
            s.write_all(b"S").unwrap();
            let mut conn = rustls::ServerConnection::new(Arc::new(scfg)).unwrap();
            while conn.is_handshaking() {
                conn.complete_io(&mut s).unwrap();
            }
        });
        let t = GatewayTarget {
            host: "localhost".into(),
            port,
        };
        probe_tls(&t, Some(cert_pem.as_bytes())).unwrap();
        h.join().unwrap();
    }
}
