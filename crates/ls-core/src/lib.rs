//! Core types and config paths shared by every Locksmith binary.

use std::io;
use std::path::{Path, PathBuf};

/// Stable process exit codes (spec: cli-core "Stable exit codes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    Ok = 0,
    Failure = 1,
    Usage = 2,
    Blocked = 3,
    Locked = 4,
    NotFound = 5,
}

/// Root for config and data. `LOCKSMITH_HOME` overrides it (tests, portable installs).
pub fn config_dir() -> PathBuf {
    if let Some(h) = std::env::var_os("LOCKSMITH_HOME") {
        return PathBuf::from(h);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Locksmith")
    } else if let Some(x) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(x).join("locksmith")
    } else {
        home.join(".config/locksmith")
    }
}

/// Create `path` (and parents) and force mode 0700 on the leaf directory.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// True when the directory is not accessible to group or others.
#[cfg(unix)]
pub fn is_private_dir(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    Ok(std::fs::metadata(path)?.permissions().mode() & 0o077 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn private_dir_is_0700() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join(format!("ls-core-test-{}", std::process::id()));
        let dir = tmp.join("a/b");
        ensure_private_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        assert!(is_private_dir(&dir).unwrap());
        std::fs::remove_dir_all(tmp).unwrap();
    }
}
