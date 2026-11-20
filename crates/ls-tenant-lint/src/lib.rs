//! Lint for A0-5: tenant context must be transaction-local.
//!
//! Moved here from `a0-spikes` (S1 design decision 5) so every crate and service shares one
//! copy: `a0-spikes` re-exports it, and its repository-wide test plus the control-plane's
//! `services/` test both run it.
//!
//! Flags, in non-test Rust code, a session-level SQL `SET` of an `app.*` setting (plain or
//! `SESSION`; `SET LOCAL` is allowed) and any `set_config(...)` call whose last argument is the
//! literal `false`. Test code is skipped: files under a crate's `tests/`, `benches/` or
//! `examples/` directory, and items annotated `#[cfg(test)]`. Line comments are skipped.
//!
//! A second check covers migrations (T1 task 3.1, A0-4): every table a migration creates must have
//! row-level security enabled and forced and at least one policy, so a new table cannot ship
//! readable by the app role. See [`scan_migrations`].
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

/// Every non-test `.rs` file under `root`, sorted.
pub fn scanned_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    walk(root, &mut files)?;
    files.sort();
    files.retain(|f| !is_test_file(f));
    Ok(files)
}

/// Scan every non-test `.rs` file under `root`. Finding paths are relative to `root`.
pub fn scan_tree(root: &Path) -> std::io::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for file in scanned_files(root)? {
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

pub const RULE_NO_RLS: &str = "table created without ENABLE ROW LEVEL SECURITY";
pub const RULE_NO_FORCE_RLS: &str = "table created without FORCE ROW LEVEL SECURITY";
pub const RULE_NO_POLICY: &str = "table created without a CREATE POLICY";

/// A table whose migrations lack a row-level-security rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableFinding {
    pub table: String,
    pub rule: &'static str,
}

/// Check the concatenated text of a migration set: every `CREATE TABLE` needs `ENABLE`, `FORCE`
/// and a `CREATE POLICY` for that table somewhere in the set (policies may live in a later file).
/// `--` comments are ignored. Tables created `TEMP` are skipped. A table dropped later is still
/// checked at its creation, which is the conservative reading.
pub fn scan_migration_sql(sql: &str) -> Vec<TableFinding> {
    static CREATE: OnceLock<Regex> = OnceLock::new();
    let create = CREATE.get_or_init(|| {
        Regex::new(r#"(?i)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?"?([a-z_][a-z0-9_]*)"?"#)
            .expect("valid regex")
    });
    let code: String = sql
        .lines()
        .map(|l| l.split("--").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let has = |kind: &str, table: &str| {
        Regex::new(&format!(
            r#"(?i){kind}\s+(?:public\.)?"?{}"?\b"#,
            regex::escape(table)
        ))
        .expect("valid regex")
        .is_match(&code)
    };
    let mut findings = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for cap in create.captures_iter(&code) {
        let table = cap[1].to_lowercase();
        if !seen.insert(table.clone()) {
            continue;
        }
        let checks = [
            (r"ALTER\s+TABLE", "ENABLE", RULE_NO_RLS),
            (r"ALTER\s+TABLE", "FORCE", RULE_NO_FORCE_RLS),
            (r"CREATE\s+POLICY\s+\S+\s+ON", "", RULE_NO_POLICY),
        ];
        for (kind, word, rule) in checks {
            let ok = if word.is_empty() {
                has(kind, &table)
            } else {
                Regex::new(&format!(
                    r#"(?i){kind}\s+(?:ONLY\s+)?(?:public\.)?"?{}"?\s+{word}\s+ROW\s+LEVEL\s+SECURITY"#,
                    regex::escape(&table)
                ))
                .expect("valid regex")
                .is_match(&code)
            };
            if !ok {
                findings.push(TableFinding {
                    table: table.clone(),
                    rule,
                });
            }
        }
    }
    findings
}

/// Run [`scan_migration_sql`] over every `*.sql` file in `dir`, in file-name order.
pub fn scan_migrations(dir: &Path) -> std::io::Result<Vec<TableFinding>> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();
    let mut all = String::new();
    for f in files {
        all.push_str(&std::fs::read_to_string(f)?);
        all.push('\n');
    }
    Ok(scan_migration_sql(&all))
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
        assert!(is_test_file(&root.join("tests/any.rs")));
        assert!(!is_test_file(&root.join("src/lib.rs")));
    }

    #[test]
    fn migration_lint_requires_enable_force_and_a_policy() {
        let ok = "CREATE TABLE a (id int);\nALTER TABLE a ENABLE ROW LEVEL SECURITY;\nALTER TABLE a FORCE ROW LEVEL SECURITY;\nCREATE POLICY p ON a USING (true);\n";
        assert!(scan_migration_sql(ok).is_empty());

        let none = "CREATE TABLE b (id int);\n-- ALTER TABLE b ENABLE ROW LEVEL SECURITY;\n";
        let rules: Vec<_> = scan_migration_sql(none)
            .into_iter()
            .map(|f| f.rule)
            .collect();
        assert_eq!(rules, vec![RULE_NO_RLS, RULE_NO_FORCE_RLS, RULE_NO_POLICY]);

        let no_force = "CREATE TABLE c (id int);\nALTER TABLE c ENABLE ROW LEVEL SECURITY;\nCREATE POLICY p ON c USING (true);\n";
        let f = scan_migration_sql(no_force);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].table.as_str(), f[0].rule), ("c", RULE_NO_FORCE_RLS));

        // A table name that only prefixes another's does not satisfy it.
        let prefix = "CREATE TABLE d (id int);\nCREATE TABLE d2 (id int);\nALTER TABLE d2 ENABLE ROW LEVEL SECURITY;\nALTER TABLE d2 FORCE ROW LEVEL SECURITY;\nCREATE POLICY p ON d2 USING (true);\n";
        let f = scan_migration_sql(prefix);
        assert_eq!(f.len(), 3);
        assert!(f.iter().all(|x| x.table == "d"));
    }
}
