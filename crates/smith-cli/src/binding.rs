//! `.locksmith.toml`: names the project, default environment and allowed keys. Never holds values.

use crate::Fail;
use ls_core::ExitCode;
use std::path::{Path, PathBuf};

pub use ls_redact::binding::{Binding, FILE, parse, secret_line};

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
}
