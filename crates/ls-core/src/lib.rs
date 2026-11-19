//! Core types and config paths shared by every Locksmith binary.

use std::path::PathBuf;

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
/// Windows: `%APPDATA%\Locksmith`. Owner-only permissions live in `ls_platform::fs`.
pub fn config_dir() -> PathBuf {
    if let Some(h) = std::env::var_os("LOCKSMITH_HOME") {
        return PathBuf::from(h);
    }
    if cfg!(windows)
        && let Some(a) = std::env::var_os("APPDATA")
    {
        return PathBuf::from(a).join("Locksmith");
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
