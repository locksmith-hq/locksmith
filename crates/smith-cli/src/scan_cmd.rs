//! `smith scan [--staged | PATH]` (M4 task 3.1). Findings are `path:line: NAME`; values are
//! never printed.

use crate::input::Opts;
use crate::{Fail, vault_cmds};
use clap::Args;
use ls_core::ExitCode;
use ls_ipc::{Client, Request, Response};
use ls_redact::{Redactor, Secret};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Larger files are skipped (same bound as the daemon's `scan_path`).
const MAX_FILE: usize = 2 << 20;
/// Vault values shorter than this match ordinary text (same bound as the daemon).
const MIN_LEN: usize = 8;
/// Largest text sent to the daemon in one request (frames are capped at 1 MiB, JSON-escaped).
const CHUNK: usize = 128 << 10;

#[derive(Args)]
pub struct ScanArgs {
    /// Scan the files staged for commit (the pre-commit hook uses this).
    #[arg(long, conflicts_with = "path")]
    pub staged: bool,
    /// Use only the built-in key-format rules; do not open the vault.
    #[arg(long)]
    pub no_vault: bool,
    /// File or directory to scan (default: the current directory).
    pub path: Option<PathBuf>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Finding {
    pub path: String,
    /// 1-based; 0 when a value spans lines and could not be placed.
    pub line: usize,
    pub name: String,
    pub vault: bool,
}

pub(crate) enum Source {
    Redactor(Redactor),
    Daemon(Client),
    None,
}

fn fail(msg: String) -> Fail {
    Fail(ExitCode::Failure, msg)
}

/// Daemon when it is running and unlocked, else the vault opened directly (prompts unless
/// `--passphrase-stdin`), else nothing when there is no vault.
fn source(o: &Opts, no_vault: bool) -> Result<Source, Fail> {
    if no_vault {
        return Ok(Source::None);
    }
    if let Ok(mut c) = Client::connect_default()
        && matches!(
            c.call(&Request::ScanText {
                text: String::new()
            }),
            Ok(Response::Keys { .. })
        )
    {
        return Ok(Source::Daemon(c));
    }
    if !ls_vault::exists(&vault_cmds::dir()) {
        return Ok(Source::None);
    }
    let _ = ls_platform::disable_core_dumps();
    let v = vault_cmds::unlock(o)?;
    let mut all = Vec::new();
    for m in v.list_secrets(None, None).map_err(vault_cmds::fail)? {
        let val = v
            .get_secret(&m.project, &m.environment, &m.name)
            .map_err(vault_cmds::fail)?;
        if val.expose().len() >= MIN_LEN {
            all.push(Secret::new(m.name, val.expose()));
        }
    }
    Ok(Source::Redactor(Redactor::new(&all)))
}

fn line_of(data: &[u8], off: usize) -> usize {
    data[..off.min(data.len())]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

impl Source {
    /// Vault key names found in `data`, with their 1-based line.
    fn vault_hits(&mut self, data: &[u8]) -> Vec<(usize, String)> {
        match self {
            Source::None => vec![],
            Source::Redactor(r) => r
                .find(data)
                .into_iter()
                .map(|(n, off)| (line_of(data, off), n.to_string()))
                .collect(),
            Source::Daemon(c) => {
                let mut ask = |bytes: &[u8]| -> Vec<String> {
                    let text = String::from_utf8_lossy(bytes).into_owned();
                    match c.call(&Request::ScanText { text }) {
                        Ok(Response::Keys { keys }) => keys,
                        _ => vec![],
                    }
                };
                let mut out = Vec::new();
                // Chunks of whole lines; a chunk with a hit is re-asked line by line to place
                // it. shortcut: a value split over lines (or over a chunk edge) is reported at
                // the chunk's first line, and a single line over 128 KiB is sent as is.
                let (mut start, mut line) = (0, 1);
                while start < data.len() {
                    let mut end = start;
                    while end < data.len() && (end == start || end - start < CHUNK) {
                        end = data[end..]
                            .iter()
                            .position(|b| *b == b'\n')
                            .map_or(data.len(), |i| end + i + 1);
                    }
                    let chunk = &data[start..end];
                    let keys = ask(chunk);
                    if !keys.is_empty() {
                        let mut placed = false;
                        for (i, l) in chunk.split_inclusive(|b| *b == b'\n').enumerate() {
                            for k in ask(l) {
                                out.push((line + i, k));
                                placed = true;
                            }
                        }
                        if !placed {
                            out.extend(keys.into_iter().map(|k| (line, k)));
                        }
                    }
                    line += chunk.iter().filter(|b| **b == b'\n').count();
                    start = end;
                }
                out
            }
        }
    }
}

/// Binary (NUL in the first 8 KiB) or oversized content is not scanned.
fn scannable(data: &[u8]) -> bool {
    data.len() <= MAX_FILE && !data[..data.len().min(8192)].contains(&0)
}

/// Documentation-style tokens (`AKIAXXXX...`, `xoxb-your-token`) in `.env.example` and READMEs.
/// shortcut: a word list on the matched token, so a real key containing one is missed
/// (random keys essentially never do); tighten the rules in ls-hooks if this proves too loose.
fn placeholder(rest: &str) -> bool {
    let tok: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .collect::<String>()
        .to_ascii_lowercase();
    [
        "xxxx",
        "example",
        "your",
        "placeholder",
        "changeme",
        "redacted",
    ]
    .iter()
    .any(|w| tok.contains(w))
}

fn scan_bytes(src: &mut Source, path: &str, data: &[u8], out: &mut Vec<Finding>) {
    if !scannable(data) {
        return;
    }
    for (line, name) in src.vault_hits(data) {
        out.push(Finding {
            path: path.into(),
            line,
            name,
            vault: true,
        });
    }
    let text = String::from_utf8_lossy(data);
    for (rule, off) in ls_hooks::generic::find(&text) {
        if rule != "private-key" && placeholder(&text[off..]) {
            continue;
        }
        out.push(Finding {
            path: path.into(),
            line: line_of(text.as_bytes(), off),
            name: rule.into(),
            vault: false,
        });
    }
}

fn git(dir: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let o = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    o.status.success().then_some(o.stdout)
}

fn nul_list(b: &[u8]) -> Vec<String> {
    b.split(|c| *c == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

fn walk(dir: &Path, rel: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        if name == ".git" {
            continue;
        }
        match e.file_type() {
            Ok(t) if t.is_dir() => walk(&e.path(), &rel.join(&name), out),
            Ok(t) if t.is_file() => out.push(rel.join(&name)),
            _ => {}
        }
    }
}

pub fn run(o: &Opts, a: ScanArgs) -> Result<ExitCode, Fail> {
    let mut src = source(o, a.no_vault)?;
    let mut found = Vec::new();
    if a.staged {
        let cwd = std::env::current_dir().map_err(|e| fail(e.to_string()))?;
        let names = git(
            &cwd,
            &[
                "diff",
                "--cached",
                "--name-only",
                "-z",
                "--diff-filter=ACMR",
            ],
        )
        .ok_or_else(|| fail("cannot list staged files (not a git repository?)".into()))?;
        for n in nul_list(&names) {
            if let Some(data) = git(&cwd, &["show", &format!(":{n}")]) {
                scan_bytes(&mut src, &n, &data, &mut found);
            }
        }
    } else {
        let root = a.path.unwrap_or_else(|| PathBuf::from("."));
        let meta = std::fs::symlink_metadata(&root)
            .map_err(|e| Fail(ExitCode::NotFound, format!("{}: {e}", root.display())))?;
        let mut files: Vec<PathBuf> = Vec::new();
        if meta.is_file() {
            files.push(PathBuf::new());
        } else if let Some(l) = git(&root, &["ls-files", "-co", "--exclude-standard", "-z"]) {
            files = nul_list(&l).into_iter().map(PathBuf::from).collect();
        } else {
            walk(&root, Path::new(""), &mut files);
        }
        for rel in files {
            let full = root.join(&rel);
            // Regular files only: no symlinks, FIFOs or devices.
            if !std::fs::symlink_metadata(&full).is_ok_and(|m| m.is_file()) {
                continue;
            }
            let Ok(data) = std::fs::read(&full) else {
                continue;
            };
            let shown = if root == Path::new(".") { rel } else { full };
            scan_bytes(&mut src, &shown.to_string_lossy(), &data, &mut found);
        }
    }
    found.sort();
    found.dedup();
    if o.json {
        let rows: Vec<_> = found
            .iter()
            .map(|f| {
                let k = if f.vault { "key" } else { "rule" };
                json!({ "path": f.path, "line": f.line, k: f.name })
            })
            .collect();
        println!("{}", json!({ "clean": found.is_empty(), "findings": rows }));
    } else {
        for f in &found {
            println!("{}:{}: {}", f.path, f.line, f.name);
        }
        if !found.is_empty() {
            eprintln!(
                "smith: {} finding(s); values are not shown. Remove them or move them into the vault.",
                found.len()
            );
        }
    }
    Ok(if found.is_empty() {
        ExitCode::Ok
    } else {
        ExitCode::Failure
    })
}
