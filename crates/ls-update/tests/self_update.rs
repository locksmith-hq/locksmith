//! Self-update against a local HTTP fixture: valid, tampered hash, bad signature, interrupted download.

use ls_update::{Error, Outcome, Source, Updater};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;

/// Serves `files`; for paths in `truncate`, advertises the full length but sends half and closes.
fn serve(files: HashMap<String, Vec<u8>>, truncate: Vec<String>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = stream.unwrap();
            let mut req = [0u8; 2048];
            let n = s.read(&mut req).unwrap_or(0);
            let line = String::from_utf8_lossy(&req[..n]);
            let path = line
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .trim_start_matches('/')
                .to_string();
            match files.get(&path) {
                Some(body) => {
                    let _ = write!(
                        s,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let send = if truncate.contains(&path) {
                        &body[..body.len() / 2]
                    } else {
                        &body[..]
                    };
                    let _ = s.write_all(send);
                }
                None => {
                    let _ = s.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                }
            }
        }
    });
    format!("http://{addr}")
}

struct Fixture {
    base: String,
    pubkey: String,
    exe: PathBuf,
    _dir: PathBuf,
}

const NEW_BIN: &[u8] = b"#!/bin/sh\necho 'smith 9.9.9'\n";
const OLD_BIN: &[u8] = b"#!/bin/sh\necho 'smith 0.0.1'\n";

fn fixture(name: &str, tamper_hash: bool, bad_sig: bool, truncate: bool) -> Fixture {
    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let hash = hex::encode(Sha256::digest(NEW_BIN));
    let manifest = format!(
        r#"{{"version":"9.9.9","targets":{{"test-target":{{"name":"smith-test","sha256":"{}"}}}}}}"#,
        if tamper_hash { "00".repeat(32) } else { hash }
    );
    let signed: &[u8] = if bad_sig {
        b"{\"version\":\"9.9.9\",\"targets\":{}}"
    } else {
        manifest.as_bytes()
    };
    let sig = minisign::sign(
        Some(&kp.pk),
        &kp.sk,
        std::io::Cursor::new(signed),
        None,
        None,
    )
    .unwrap();
    let mut files = HashMap::new();
    files.insert("manifest.json".into(), manifest.into_bytes());
    files.insert("manifest.json.minisig".into(), sig.to_string().into_bytes());
    files.insert("smith-test".into(), NEW_BIN.to_vec());
    let base = serve(
        files,
        if truncate {
            vec!["smith-test".into()]
        } else {
            vec![]
        },
    );

    let dir = std::env::temp_dir().join(format!("ls-update-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exe = dir.join("smith");
    std::fs::write(&exe, OLD_BIN).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    Fixture {
        base,
        pubkey: kp.pk.to_base64(),
        exe,
        _dir: dir,
    }
}

fn updater(f: &Fixture) -> Updater {
    Updater {
        source: Source::Http(f.base.clone()),
        pubkey_b64: f.pubkey.clone(),
        target: "test-target".into(),
        current: semver::Version::new(0, 0, 1),
    }
}

fn leftovers(f: &Fixture) -> usize {
    std::fs::read_dir(f.exe.parent().unwrap()).unwrap().count() - 1
}

#[test]
fn check_reports_available_without_installing() {
    let f = fixture("check", false, false, false);
    let out = updater(&f).check().unwrap();
    assert_eq!(
        out,
        Outcome::Available {
            current: "0.0.1".into(),
            latest: "9.9.9".into()
        }
    );
    assert_eq!(std::fs::read(&f.exe).unwrap(), OLD_BIN);
}

#[test]
fn valid_update_replaces_binary() {
    let f = fixture("valid", false, false, false);
    let out = updater(&f).install(&f.exe).unwrap();
    assert_eq!(
        out,
        Outcome::Installed {
            from: "0.0.1".into(),
            to: "9.9.9".into()
        }
    );
    assert_eq!(std::fs::read(&f.exe).unwrap(), NEW_BIN);
    assert_eq!(leftovers(&f), 0);
}

#[test]
fn tampered_hash_keeps_old_binary() {
    let f = fixture("hash", true, false, false);
    let err = updater(&f).install(&f.exe).unwrap_err();
    assert!(matches!(err, Error::HashMismatch { .. }), "{err}");
    assert_eq!(std::fs::read(&f.exe).unwrap(), OLD_BIN);
    assert_eq!(leftovers(&f), 0);
}

#[test]
fn bad_signature_is_rejected() {
    let f = fixture("sig", false, true, false);
    let err = updater(&f).install(&f.exe).unwrap_err();
    assert!(matches!(err, Error::BadSignature), "{err}");
    assert_eq!(std::fs::read(&f.exe).unwrap(), OLD_BIN);
}

#[test]
fn interrupted_download_keeps_old_binary() {
    let f = fixture("cut", false, false, true);
    assert!(updater(&f).install(&f.exe).is_err());
    assert_eq!(std::fs::read(&f.exe).unwrap(), OLD_BIN);
    assert_eq!(leftovers(&f), 0);
}

#[test]
fn embedded_pubkey_parses() {
    assert!(minisign_verify::PublicKey::from_base64(ls_update::EMBEDDED_PUBKEY.trim()).is_ok());
}
