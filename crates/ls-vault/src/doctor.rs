//! Doctor checks for the vault. They read the header only, so they never need an unlock.
//! Each check takes the vault dir so tests can use a temp dir.

use crate::header::{self, HEADER_FILE};
use crate::{check_perms, exists};
use ls_diag::{Check, Outcome, Status};
use std::path::Path;

fn vault_dir() -> std::path::PathBuf {
    // Same location `smith vault` uses.
    ls_core::config_dir().join("vault")
}

fn skip_no_vault() -> Outcome {
    Outcome {
        status: Status::Skip,
        summary: "no vault yet".into(),
        remediation: Some("smith vault init".into()),
        fixable: false,
    }
}

fn present_at(dir: &Path) -> Outcome {
    if exists(dir) {
        Outcome::ok(format!("vault found in {}", dir.display()))
    } else {
        skip_no_vault()
    }
}

fn perms_at(dir: &Path) -> Outcome {
    if !exists(dir) {
        return skip_no_vault();
    }
    match check_perms(dir) {
        Ok(()) => Outcome::ok("vault files are private to the current user"),
        Err(e) => Outcome::fail("vault permissions are unsafe", e.to_string()),
    }
}

fn kdf_at(dir: &Path) -> Outcome {
    if !exists(dir) {
        return skip_no_vault();
    }
    match header::read(dir) {
        Ok((body, _)) if body.kdf.meets_minimum() => {
            Outcome::ok("argon2id parameters meet the minimum")
        }
        Ok(_) => Outcome::warn(
            "argon2id parameters are below the minimum",
            "smith vault passwd",
        ),
        Err(e) => Outcome::fail("vault header is unreadable", e.to_string()),
    }
}

fn wraps_at(dir: &Path) -> Outcome {
    if !exists(dir) {
        return skip_no_vault();
    }
    match header::read(dir) {
        Ok((body, _)) => {
            let passphrase = !body.pass_wrap.to_sealed().ct.is_empty();
            let recovery = !body.recovery_wrap.to_sealed().ct.is_empty();
            match (passphrase, recovery) {
                (true, true) => Outcome::ok("passphrase and recovery wraps are present"),
                (true, false) => Outcome::warn(
                    "recovery wrap is missing; a forgotten passphrase cannot be recovered",
                    "smith vault recovery rotate",
                ),
                (false, _) => Outcome::fail(
                    "passphrase wrap is missing; the vault cannot be unlocked",
                    format!("restore {HEADER_FILE} from a backup"),
                ),
            }
        }
        Err(e) => Outcome::fail("vault header is unreadable", e.to_string()),
    }
}

fn present() -> Outcome {
    present_at(&vault_dir())
}
fn perms() -> Outcome {
    perms_at(&vault_dir())
}
fn kdf_params() -> Outcome {
    kdf_at(&vault_dir())
}
fn wraps() -> Outcome {
    wraps_at(&vault_dir())
}

inventory::submit! { Check { id: "vault.present", run: present } }
inventory::submit! { Check { id: "vault.perms", run: perms } }
inventory::submit! { Check { id: "vault.kdf_params", run: kdf_params } }
inventory::submit! { Check { id: "vault.wraps", run: wraps } }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{Body, FORMAT, SealedDto};
    use ls_crypto::SecretKey32;
    use ls_crypto::aead::Sealed;
    use ls_crypto::kdf::KdfParams;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    const WEAK: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    struct Tmp(std::path::PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("ls-vault-doctor-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            Tmp(p.join("vault"))
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
        }
    }

    /// Writes a well-formed header without a real KDF run; `recovery` empty means no recovery wrap.
    fn fake_header(dir: &Path, kdf: KdfParams, recovery: Vec<u8>) {
        ls_platform::fs::ensure_private_dir(dir).unwrap();
        let wrap = |ct: Vec<u8>| SealedDto::from(&Sealed { nonce: [0; 12], ct });
        let body = Body {
            format: FORMAT,
            vault_id: [1; 16],
            vk_version: 1,
            kdf,
            salt: [2; 32],
            pass_wrap: wrap(vec![1; 48]),
            recovery_wrap: wrap(recovery),
            created_at: 0,
        };
        header::write(dir, &body, &SecretKey32::random().unwrap()).unwrap();
    }

    #[test]
    fn missing_vault_skips_every_check() {
        let t = Tmp::new("none");
        for out in [
            present_at(&t.0),
            perms_at(&t.0),
            kdf_at(&t.0),
            wraps_at(&t.0),
        ] {
            assert_eq!(out.status, Status::Skip);
            assert_eq!(out.summary, "no vault yet");
        }
        assert_eq!(
            present_at(&t.0).remediation.as_deref(),
            Some("smith vault init")
        );
    }

    #[test]
    fn present_vault_is_ok() {
        let t = Tmp::new("present");
        fake_header(&t.0, KdfParams::MINIMUM, vec![3; 48]);
        assert_eq!(present_at(&t.0).status, Status::Ok);
    }

    #[cfg(unix)]
    #[test]
    fn perms_fail_on_world_readable_dir_then_pass() {
        let t = Tmp::new("perms");
        fake_header(&t.0, KdfParams::MINIMUM, vec![3; 48]);
        std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        let out = perms_at(&t.0);
        assert_eq!(out.status, Status::Fail);
        assert!(out.remediation.unwrap().contains("chmod 700"));
        std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(perms_at(&t.0).status, Status::Ok);
    }

    #[test]
    fn weak_kdf_warns_and_minimum_is_ok() {
        let t = Tmp::new("kdf");
        fake_header(&t.0, WEAK, vec![3; 48]);
        let out = kdf_at(&t.0);
        assert_eq!(out.status, Status::Warn);
        assert_eq!(out.remediation.as_deref(), Some("smith vault passwd"));

        fake_header(&t.0, KdfParams::MINIMUM, vec![3; 48]);
        assert_eq!(kdf_at(&t.0).status, Status::Ok);
    }

    #[test]
    fn missing_recovery_wrap_warns() {
        let t = Tmp::new("wraps");
        fake_header(&t.0, KdfParams::MINIMUM, vec![3; 48]);
        assert_eq!(wraps_at(&t.0).status, Status::Ok);

        fake_header(&t.0, KdfParams::MINIMUM, vec![]);
        let out = wraps_at(&t.0);
        assert_eq!(out.status, Status::Warn);
        assert_eq!(
            out.remediation.as_deref(),
            Some("smith vault recovery rotate")
        );
    }
}
