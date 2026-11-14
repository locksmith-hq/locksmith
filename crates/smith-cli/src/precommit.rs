//! Pre-commit scanner installer (M4 task 3.2): adds `smith scan --staged` to the repo's hook
//! manager (husky, lefthook, pre-commit framework) or to `.git/hooks/pre-commit`, never
//! replacing what is there. Our lines carry `MARKER`, so a second run changes nothing.

use std::path::{Path, PathBuf};
use std::process::Command;

pub const MARKER: &str = "locksmith:pre-commit";
const ID: &str = "locksmith-scan";
const CHAINED: &str = "pre-commit.pre-locksmith";

/// Fails the hook visibly when `smith` is missing, and blocks the commit on findings.
const SH_STEP: &str = "command -v smith >/dev/null 2>&1 || { echo \"locksmith: 'smith' not found on PATH; the secret scan cannot run (install Locksmith or remove this hook step)\" >&2; exit 1; }\nsmith scan --staged || exit 1\n";

/// One file to create or rewrite, shown in the init preview before it is applied.
pub struct Change {
    /// Relative to the repo root (or absolute when outside it, e.g. a custom hooks dir).
    pub path: PathBuf,
    pub before: Option<String>,
    pub after: String,
    pub exec: bool,
}

pub fn apply(root: &Path, c: &Change) -> std::io::Result<()> {
    let f = root.join(&c.path);
    if let Some(d) = f.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(&f, &c.after)?;
    if c.exec {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn read(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

fn ensure_nl(mut s: String) -> String {
    if !s.is_empty() && !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// Which manager the repo uses, and the change that adds our step (`None`: already there).
pub fn plan(root: &Path) -> Result<Option<(&'static str, Vec<Change>)>, String> {
    let (name, changes) = if root.join(".husky").is_dir() {
        ("husky", husky(root))
    } else if let Some(f) = ["lefthook.yml", "lefthook.yaml"]
        .iter()
        .find(|f| root.join(f).is_file())
    {
        ("lefthook", lefthook(root, f)?)
    } else if root.join(".pre-commit-config.yaml").is_file() {
        ("pre-commit", pre_commit_framework(root)?)
    } else {
        ("git hook", git_hook(root)?)
    };
    Ok((!changes.is_empty()).then_some((name, changes)))
}

/// True when our step is installed (for `smith doctor`).
pub fn installed(root: &Path) -> bool {
    matches!(plan(root), Ok(None))
}

fn husky(root: &Path) -> Vec<Change> {
    let path = PathBuf::from(".husky/pre-commit");
    let before = read(&root.join(&path));
    if before.as_deref().is_some_and(|b| b.contains(MARKER)) {
        return vec![];
    }
    let mut after = ensure_nl(before.clone().unwrap_or_default());
    after.push_str(&format!("# {MARKER}\n{SH_STEP}"));
    vec![Change {
        path,
        before,
        after,
        exec: true,
    }]
}

fn git_hook(root: &Path) -> Result<Vec<Change>, String> {
    let out = Command::new("git")
        .args(["rev-parse", "--git-path", "hooks/pre-commit"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if !out.status.success() {
        return Err("not a git repository".into());
    }
    let hook = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    let rel = if hook.is_absolute() {
        hook
    } else {
        root.join(hook)
    };
    let rel = rel.strip_prefix(root).map(Path::to_path_buf).unwrap_or(rel);
    let existing = read(&root.join(&rel));
    if existing.as_deref().is_some_and(|b| b.contains(MARKER)) {
        return Ok(vec![]);
    }
    let mut ours = format!("#!/bin/sh\n# {MARKER} (managed by `smith init`)\n{SH_STEP}");
    let mut changes = vec![];
    if let Some(old) = &existing {
        // Keep the user's hook: it moves aside and runs after the scan.
        changes.push(Change {
            path: rel.with_file_name(CHAINED),
            before: None,
            after: old.clone(),
            exec: true,
        });
        ours.push_str(&format!("exec \"$(dirname \"$0\")/{CHAINED}\" \"$@\"\n"));
    }
    changes.push(Change {
        path: rel,
        before: existing,
        after: ours,
        exec: true,
    });
    Ok(changes)
}

fn indent(l: &str) -> usize {
    l.len() - l.trim_start().len()
}

/// Inserts `block` lines (already relative to a 0 indent) after line `at`, indented by `by`.
fn insert(lines: &mut Vec<String>, at: usize, by: usize, block: &[String]) {
    let pad = " ".repeat(by);
    for (i, b) in block.iter().enumerate() {
        lines.insert(at + 1 + i, format!("{pad}{b}"));
    }
}

fn lefthook(root: &Path, file: &str) -> Result<Vec<Change>, String> {
    let before = read(&root.join(file)).unwrap_or_default();
    if before.contains(MARKER) {
        return Ok(vec![]);
    }
    let mut lines: Vec<String> = before.lines().map(String::from).collect();
    let cmd = [
        format!("# {MARKER}"),
        format!("{ID}:"),
        "  run: smith scan --staged".into(),
    ];
    let job = [
        format!("# {MARKER}"),
        format!("- name: {ID}"),
        "  run: smith scan --staged".into(),
    ];
    let hook = lines.iter().position(|l| l.trim_end() == "pre-commit:");
    match hook {
        None => {
            let mut s = ensure_nl(before.clone());
            s.push_str(&format!(
                "# {MARKER}\npre-commit:\n  commands:\n    {ID}:\n      run: smith scan --staged\n"
            ));
            return Ok(vec![Change {
                path: file.into(),
                before: Some(before),
                after: s,
                exec: false,
            }]);
        }
        Some(h) => {
            let end = lines[h + 1..]
                .iter()
                .position(|l| !l.trim().is_empty() && indent(l) == 0)
                .map_or(lines.len(), |i| h + 1 + i);
            let find = |key: &str| {
                (h + 1..end).find(|&i| {
                    lines[i].trim_end().ends_with(key) && lines[i].trim_start().starts_with(key)
                })
            };
            if let Some(c) = find("commands:") {
                let child = lines.get(c + 1).filter(|l| indent(l) > indent(&lines[c]));
                let by = child.map_or(indent(&lines[c]) + 2, |l| indent(l));
                insert(&mut lines, c, by, &cmd);
            } else if let Some(j) = find("jobs:") {
                let by = lines
                    .get(j + 1)
                    .filter(|l| indent(l) >= indent(&lines[j]))
                    .map_or(indent(&lines[j]) + 2, |l| indent(l));
                insert(&mut lines, j, by, &job);
            } else if lines[h + 1..end]
                .iter()
                .all(|l| l.trim().is_empty() || indent(l) > 0)
            {
                let by = lines.get(h + 1).map_or(2, |l| indent(l).max(2));
                let mut b = vec!["commands:".to_string()];
                b.extend(cmd.iter().map(|l| format!("  {l}")));
                insert(&mut lines, h, by, &b);
            }
        }
    }
    let after = ensure_nl(lines.join("\n"));
    Ok(vec![Change {
        path: file.into(),
        before: Some(before),
        after,
        exec: false,
    }])
}

fn pre_commit_framework(root: &Path) -> Result<Vec<Change>, String> {
    let file = ".pre-commit-config.yaml";
    let before = read(&root.join(file)).unwrap_or_default();
    if before.contains(MARKER) {
        return Ok(vec![]);
    }
    if !before.lines().any(|l| l.trim_end() == "repos:") {
        return Err(format!(
            "{file} has no top-level `repos:` list; add the step by hand: entry `smith scan --staged`"
        ));
    }
    // Same indent as the existing `- repo:` items.
    let by = before
        .lines()
        .find(|l| l.trim_start().starts_with("- repo:"))
        .map_or(0, indent);
    let pad = " ".repeat(by);
    let mut after = ensure_nl(before.clone());
    // shortcut: appended at the end of the file, so `repos:` must be its last top-level key.
    after.push_str(&format!(
        "{pad}# {MARKER}\n{pad}- repo: local\n{pad}  hooks:\n{pad}    - id: {ID}\n{pad}      name: locksmith scan\n{pad}      entry: smith scan --staged\n{pad}      language: system\n{pad}      pass_filenames: false\n{pad}      always_run: true\n"
    ));
    Ok(vec![Change {
        path: file.into(),
        before: Some(before),
        after,
        exec: false,
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("smith-pc-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn lefthook_after(src: &str) -> String {
        let d = tmp(&format!("lh{}", src.len()));
        std::fs::write(d.join("lefthook.yml"), src).unwrap();
        let c = lefthook(&d, "lefthook.yml").unwrap().remove(0).after;
        std::fs::remove_dir_all(&d).unwrap();
        c
    }

    #[test]
    fn lefthook_merges_into_existing_shapes() {
        let a = lefthook_after("pre-commit:\n  commands:\n    lint:\n      run: eslint .\n");
        assert!(
            a.contains("    locksmith-scan:\n      run: smith scan --staged\n    lint:"),
            "{a}"
        );
        let b = lefthook_after("pre-commit:\n  parallel: true\n");
        assert!(
            b.contains("  commands:\n    # locksmith:pre-commit\n    locksmith-scan:"),
            "{b}"
        );
        let c = lefthook_after("pre-push:\n  commands:\n    t:\n      run: x\n");
        assert!(c.ends_with(
            "pre-commit:\n  commands:\n    locksmith-scan:\n      run: smith scan --staged\n"
        ));
        let j = lefthook_after("pre-commit:\n  jobs:\n    - name: lint\n      run: x\n");
        assert!(
            j.contains(
                "    - name: locksmith-scan\n      run: smith scan --staged\n    - name: lint"
            ),
            "{j}"
        );
    }
}
