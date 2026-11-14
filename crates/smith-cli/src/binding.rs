//! `.locksmith.toml`: names the project, default environment and allowed keys. Never holds values.

use crate::Fail;
use ls_core::ExitCode;
use ls_redact::Redactor;
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub const FILE: &str = ".locksmith.toml";

#[derive(Deserialize, Default, Debug, PartialEq)]
pub struct Binding {
    pub project: Option<String>,
    pub env: Option<String>,
    #[serde(default)]
    pub keys: Vec<String>,
}

/// Nearest binding walking up from `start` to the git root (or only `start` outside a repo).
pub fn find(start: &Path) -> Option<PathBuf> {
    let root = start
        .ancestors()
        .find(|d| d.join(".git").exists())
        .unwrap_or(start);
    start
        .ancestors()
        .take_while(|d| d.starts_with(root))
        .map(|d| d.join(FILE))
        .find(|f| f.is_file())
}

pub fn parse(bytes: &[u8]) -> Result<Binding, String> {
    toml::from_str(std::str::from_utf8(bytes).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

/// 1-based line of the first line a stored secret appears on (0: only across lines).
pub fn secret_line(bytes: &[u8], r: &Redactor) -> Option<usize> {
    if r.is_empty() || r.redact_all(bytes) == bytes {
        return None;
    }
    Some(
        bytes
            .split_inclusive(|b| *b == b'\n')
            .position(|l| r.redact_all(l) != l)
            .map_or(0, |i| i + 1),
    )
}

pub fn load(path: &Path) -> Result<(Binding, Vec<u8>), Fail> {
    let bytes = std::fs::read(path).map_err(|e| {
        Fail(
            ExitCode::Failure,
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    let b = parse(&bytes)
        .map_err(|e| Fail(ExitCode::Usage, format!("invalid {}: {e}", path.display())))?;
    Ok((b, bytes))
}

/// `smith init --binding-only`: writes a binding for `dir` using the vault's default project.
pub fn init(dir: &Path) -> Result<PathBuf, Fail> {
    let f = dir.join(FILE);
    let body = "# Names only. Never put secret values in this file.\n\
                project = \"default\"\nenv = \"development\"\nkeys = []\n";
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&f)
        .map_err(|e| {
            Fail(
                ExitCode::Failure,
                format!("cannot create {}: {e}", f.display()),
            )
        })?;
    std::io::Write::write_all(&mut file, body.as_bytes())
        .map_err(|e| Fail(ExitCode::Failure, e.to_string()))?;
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ls_redact::Secret;

    #[test]
    fn parses_fields() {
        let b =
            parse(b"project=\"p\"\nenv=\"e\"\nkeys=[\"A\",\"B\"]\n[commands]\nx=\"y\"\n").unwrap();
        assert_eq!(b.project.as_deref(), Some("p"));
        assert_eq!(b.keys, ["A", "B"]);
        assert!(parse(b"keys = 3").is_err());
    }

    #[test]
    fn finds_up_to_git_root_only() {
        let t = std::env::temp_dir().join(format!("smith-bind-{}", std::process::id()));
        let sub = t.join("repo/a/b");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(t.join(FILE), "").unwrap(); // above the git root: must be ignored
        assert_eq!(find(&sub), None);
        std::fs::create_dir_all(t.join("repo/.git")).unwrap();
        assert_eq!(find(&sub), None);
        std::fs::write(t.join("repo").join(FILE), "").unwrap();
        assert_eq!(find(&sub), Some(t.join("repo").join(FILE)));
        std::fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn detects_value_and_line_without_leaking() {
        let r = Redactor::new(&[Secret::new("K", b"fake_live_abcdef123456")]);
        assert_eq!(
            secret_line(b"a=1\nb=\"fake_live_abcdef123456\"\n", &r),
            Some(2)
        );
        assert_eq!(secret_line(b"project=\"x\"\nkeys=[\"K\"]\n", &r), None);
    }
}
