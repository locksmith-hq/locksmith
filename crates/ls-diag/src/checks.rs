//! M0 foundation checks.

use crate::{Check, Outcome};

fn platform_supported() -> Outcome {
    let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
    match (os, arch) {
        ("macos" | "linux", "aarch64" | "x86_64") => {
            Outcome::ok(format!("{os}/{arch} is supported"))
        }
        ("windows", _) => Outcome::warn(
            format!("{os}/{arch}: preview until M16"),
            "use WSL2 for full support",
        ),
        _ => Outcome::fail(
            format!("{os}/{arch} is not supported"),
            "see docs for supported platforms",
        ),
    }
}

fn config_dir_perms() -> Outcome {
    config_dir_perms_at(&ls_core::config_dir())
}

fn config_dir_perms_at(dir: &std::path::Path) -> Outcome {
    if !dir.exists() {
        return Outcome::skip(format!("{} not created yet", dir.display()));
    }
    match ls_platform::fs::is_private(dir) {
        Ok(true) => Outcome::ok("config directory is private to the current user"),
        Ok(false) => Outcome::fail(
            format!("{} is readable by other users", dir.display()),
            ls_platform::fs::private_dir_fix(dir),
        ),
        Err(e) => Outcome::fail(
            format!("cannot stat config dir: {e}"),
            "check ownership of the directory",
        ),
    }
}

fn binary_signature() -> Outcome {
    #[cfg(target_os = "macos")]
    {
        let Ok(exe) = std::env::current_exe() else {
            return Outcome::warn("cannot locate own binary", "reinstall Locksmith");
        };
        match std::process::Command::new("codesign")
            .arg("--verify")
            .arg(&exe)
            .output()
        {
            Ok(o) if o.status.success() => Outcome::ok("code signature is valid"),
            Ok(_) => Outcome::warn(
                "binary is not signed (development build)",
                "install an official release for a signed binary",
            ),
            Err(e) => Outcome::warn(
                format!("codesign unavailable: {e}"),
                "install Xcode command line tools",
            ),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        // shortcut: Linux has no platform signature; provenance check lands with `smith self verify` (M16).
        Outcome::skip("no platform code signature on this OS")
    }
}

inventory::submit! { Check { id: "platform.supported", run: platform_supported } }
inventory::submit! { Check { id: "fs.config_dir_perms", run: config_dir_perms } }
inventory::submit! { Check { id: "binary.signature", run: binary_signature } }

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::Status;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn world_readable_config_dir_fails_with_chmod_fix() {
        let dir = std::env::temp_dir().join(format!("ls-diag-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let out = config_dir_perms_at(&dir);
        assert_eq!(out.status, Status::Fail);
        assert!(out.remediation.unwrap().contains("chmod 700"));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(config_dir_perms_at(&dir).status, Status::Ok);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
