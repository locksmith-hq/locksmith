//! Lint for design decision 5: tenant context must be transaction-local.
//!
//! Flags, in non-test Rust code, a session-level SQL `SET` of an `app.*` setting (plain or
//! `SESSION`; `SET LOCAL` is allowed) and any `set_config(...)` call whose last argument is the
//! literal `false`. Test code is skipped: files under a crate's `tests/`, `benches/` or
//! `examples/` directory, and items annotated `#[cfg(test)]`. Line comments are skipped.
//!
//! Limits (it is a text lint, not a parser): an `is_local` flag passed as a bind parameter is
//! not seen, and braces inside string literals can confuse `#[cfg(test)]` item matching.

use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub path: PathBuf,
    pub line: usize,
    pub rule: &'static str,
}

pub const RULE_SESSION_SET: &str = "session-level SET of an app.* setting";
pub const RULE_SET_CONFIG_FALSE: &str = "set_config with is_local = false (session-level)";

fn rules() -> &'static [(Regex, &'static str)] {
    static RULES: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            (
                Regex::new(r#"(?i)\bSET\s+(?:SESSION\s+)?"?app\."#).expect("valid regex"),
                RULE_SESSION_SET,
            ),
            (
                // One level of nested parentheses inside the call is allowed.
                Regex::new(r"(?is)\bset_config\s*\((?:[^()]|\([^()]*\))*?,\s*false\s*\)")
                    .expect("valid regex"),
                RULE_SET_CONFIG_FALSE,
            ),
        ]
    })
}

/// Blank out (keeping newlines, so line numbers hold) every `#[cfg(test)]` item and every
/// whole-line `//` comment.
fn strip_test_and_comments(src: &str) -> String {
    let mut out: Vec<u8> = src.as_bytes().to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for b in &mut out[from..to] {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    };

    static CFG_TEST: OnceLock<Regex> = OnceLock::new();
    let cfg_test = CFG_TEST.get_or_init(|| Regex::new(r"#\[cfg\(test\)\]").expect("valid regex"));
    for m in cfg_test.find_iter(src) {
        let rest = &src.as_bytes()[m.end()..];
        let Some(stop) = rest.iter().position(|&b| b == b'{' || b == b';') else {
            blank(&mut out, m.start(), src.len());
            continue;
        };
        let mut end = m.end() + stop + 1;
        if rest[stop] == b'{' {
            let mut depth = 1usize;
            while end < src.len() && depth > 0 {
                match src.as_bytes()[end] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                end += 1;
            }
        }
        blank(&mut out, m.start(), end);
    }

    let mut offset = 0;
    for line in src.split_inclusive('\n') {
        if line.trim_start().starts_with("//") {
            blank(&mut out, offset, offset + line.len());
        }
        offset += line.len();
    }
    String::from_utf8(out).expect("only ASCII bytes were replaced")
}

/// Scan one source file's text. Returns (1-based line, rule).
pub fn scan_source(src: &str) -> Vec<(usize, &'static str)> {
    let code = strip_test_and_comments(src);
    let mut hits = Vec::new();
    for (re, rule) in rules() {
        for m in re.find_iter(&code) {
            let line = code[..m.start()].bytes().filter(|&b| b == b'\n').count() + 1;
            hits.push((line, *rule));
        }
    }
    hits.sort();
    hits
}

/// True when `file` is under `tests/`, `benches/` or `examples/` of its nearest crate.
fn is_test_file(file: &Path) -> bool {
    let mut dir = file.parent();
    while let Some(d) = dir {
        if d.join("Cargo.toml").is_file() {
            let rel = file.strip_prefix(d).unwrap_or(file);
            return matches!(
                rel.components().next().and_then(|c| c.as_os_str().to_str()),
                Some("tests" | "benches" | "examples")
            );
        }
        dir = d.parent();
    }
    false
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry.file_type()?.is_dir() {
            if name.starts_with('.') || name == "target" || name == "node_modules" {
                continue;
            }
            walk(&path, files)?;
        } else if name.ends_with(".rs") {
            files.push(path);
        }
    }
    Ok(())
}

/// Scan every non-test `.rs` file under `root`.
pub fn scan_tree(root: &Path) -> std::io::Result<Vec<Finding>> {
    let mut files = Vec::new();
    walk(root, &mut files)?;
    files.sort();
    let mut findings = Vec::new();
    for file in files.into_iter().filter(|f| !is_test_file(f)) {
        let src = std::fs::read_to_string(&file)?;
        for (line, rule) in scan_source(&src) {
            findings.push(Finding {
                path: file.strip_prefix(root).unwrap_or(&file).to_path_buf(),
                line,
                rule,
            });
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_session_level_settings() {
        let src = "fn a() {\n  q(\"SET app.org_id = '1'\");\n  q(\"set session app.x = 1\");\n  q(\"SELECT set_config('app.org_id', $1, false)\");\n  q(\"SELECT set_config(\n 'app.org_id',\n format('%s', $1),\n FALSE)\");\n}\n";
        assert_eq!(
            scan_source(src),
            vec![
                (2, RULE_SESSION_SET),
                (3, RULE_SESSION_SET),
                (4, RULE_SET_CONFIG_FALSE),
                (5, RULE_SET_CONFIG_FALSE),
            ]
        );
    }

    #[test]
    fn allows_transaction_local_settings() {
        let src = "fn a() {\n  q(\"SET LOCAL app.org_id = '1'\");\n  q(\"SELECT set_config('app.org_id', $1, true)\");\n  q(\"RESET app.org_id\");\n  q(\"SET search_path = public\");\n}\n";
        assert!(scan_source(src).is_empty());
    }

    #[test]
    fn skips_cfg_test_items_and_comments() {
        let src = "fn a() {}\n// never: SET app.org_id = 1\n#[cfg(test)]\nmod t {\n  fn b() { q(\"SET app.org_id = 1\"); { } }\n}\n#[cfg(test)]\nuse x::y;\nfn c() { q(\"SET app.org_id = 1\"); }\n";
        assert_eq!(scan_source(src), vec![(9, RULE_SESSION_SET)]);
    }

    #[test]
    fn integration_test_dirs_are_test_code() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(is_test_file(&root.join("tests/rls.rs")));
        assert!(!is_test_file(&root.join("src/tenant.rs")));
    }
}
