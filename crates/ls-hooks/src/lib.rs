//! Agent hook decision engine.
//!
//! `decide(Event) -> Decision` is the single engine; agent adapters only translate JSON.
//! Protection level, stated honestly: friction plus detection. A determined agent can always
//! obfuscate (`python -c "open('.e'+'nv')"`); real prevention is keeping secrets out of reach
//! (M2 import, M5+ delegation). The engine aims at zero false positives on normal dev work.

pub mod adapters;
pub mod generic;
pub mod shell;

use std::path::{Path, PathBuf};

/// What the agent is about to do.
#[derive(Debug, Clone)]
pub enum Event {
    Shell {
        command: String,
        cwd: PathBuf,
    },
    /// A file-reading tool (Claude `Read`, Cursor `beforeReadFile`).
    Read {
        path: PathBuf,
        cwd: PathBuf,
    },
    /// An editing tool that shows file content back (Claude `Edit`/`MultiEdit`).
    Edit {
        path: PathBuf,
        cwd: PathBuf,
    },
    /// A search tool (Claude `Grep`/`Glob`) rooted at `path`.
    Search {
        path: Option<PathBuf>,
        glob: Option<String>,
        cwd: PathBuf,
    },
    Prompt {
        text: String,
    },
    /// Any other string in a tool's input that may name a file or a glob (decision P3-2: a path
    /// under a misnamed key must still meet the protected-path policy).
    Arg {
        arg: String,
        cwd: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny {
        rule: &'static str,
        reason: String,
        alternative: String,
    },
    /// Cannot be analysed reliably: let the human decide (design D2).
    Ask {
        rule: &'static str,
        reason: String,
    },
}

impl Decision {
    /// Text shown to the agent or user. A denial always starts with "Blocked by Locksmith"
    /// (spec "Honest blocking": never success with fabricated output).
    pub fn message(&self) -> String {
        match self {
            Decision::Allow => String::new(),
            Decision::Deny {
                reason,
                alternative,
                ..
            } => format!("Blocked by Locksmith: {reason}. Instead: {alternative}"),
            Decision::Ask { reason, .. } => format!(
                "Locksmith cannot verify this command ({reason}); approve only if you trust it"
            ),
        }
    }

    pub fn rule(&self) -> Option<&'static str> {
        match self {
            Decision::Allow => None,
            Decision::Deny { rule, .. } | Decision::Ask { rule, .. } => Some(rule),
        }
    }
}

/// Vault lookups (design D3, D4), answered by the daemon with key names only.
/// `None` means the vault is unavailable (daemon down or locked).
pub trait Vault {
    fn keys_in_text(&self, text: &str) -> Option<Vec<String>>;
    fn keys_in_file(&self, path: &Path) -> Option<Vec<String>>;
}

/// No vault: generic patterns and filename rules only.
pub struct NoVault;
impl Vault for NoVault {
    fn keys_in_text(&self, _: &str) -> Option<Vec<String>> {
        None
    }
    fn keys_in_file(&self, _: &Path) -> Option<Vec<String>> {
        None
    }
}

const ALT_FILES: &str =
    "use `smith ls` to see key names, or `smith run -- <command>` to give a command the values";
const ALT_ENV: &str =
    "use `smith env-template` to see key names, or `printenv NAME` for a non-secret variable";

fn deny(rule: &'static str, reason: impl Into<String>, alternative: &str) -> Decision {
    Decision::Deny {
        rule,
        reason: reason.into(),
        alternative: alternative.into(),
    }
}

fn ask(rule: &'static str, reason: impl Into<String>) -> Decision {
    Decision::Ask {
        rule,
        reason: reason.into(),
    }
}

pub fn decide(ev: &Event, v: &dyn Vault) -> Decision {
    match ev {
        Event::Shell { command, cwd } => shell_decision(command, cwd, 0),
        Event::Read { path, cwd } | Event::Edit { path, cwd } => {
            file_decision(&resolve(cwd, path), v)
        }
        Event::Search { path, glob, cwd } => {
            if let Some(p) = path.as_ref().map(|p| resolve(cwd, p))
                && p.is_file()
            {
                return file_decision(&p, v);
            }
            match glob {
                Some(g) if glob_may_hit_secret(g) => deny(
                    "secret-file",
                    format!("the search pattern `{g}` targets secret-bearing files"),
                    ALT_FILES,
                ),
                _ => Decision::Allow,
            }
        }
        Event::Prompt { text } => prompt_decision(text, v),
        Event::Arg { arg, cwd } => {
            // A secret file by name (a glob is judged as a search pattern below, so `*` alone
            // stays allowed), then the file's content and secret-naming globs.
            if !arg.contains(['*', '?'])
                && let Some(t) = secret_targets(cwd, arg).first()
            {
                return deny(
                    "secret-file",
                    format!("{} holds secrets", display(Path::new(t))),
                    ALT_FILES,
                );
            }
            decide(
                &Event::Search {
                    path: Some(PathBuf::from(arg)),
                    glob: Some(arg.clone()),
                    cwd: cwd.clone(),
                },
                v,
            )
        }
    }
}

fn resolve(cwd: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

fn file_decision(p: &Path, v: &dyn Vault) -> Decision {
    if is_secret_path(p) {
        return deny(
            "secret-file",
            format!("{} holds secrets", display(p)),
            ALT_FILES,
        );
    }
    match v.keys_in_file(p) {
        Some(keys) if !keys.is_empty() => deny(
            "secret-content",
            format!("{} contains the value of {}", display(p), keys.join(", ")),
            "remove the value from the file and reference it with `smith run`",
        ),
        _ => Decision::Allow,
    }
}

fn display(p: &Path) -> String {
    p.file_name().map_or_else(
        || p.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

fn prompt_decision(text: &str, v: &dyn Vault) -> Decision {
    let mut keys = v.keys_in_text(text).unwrap_or_default();
    keys.extend(
        generic::find(text)
            .into_iter()
            .map(|(id, _)| id.to_string()),
    );
    keys.sort();
    keys.dedup();
    if keys.is_empty() {
        return Decision::Allow;
    }
    deny(
        "prompt-secret",
        format!(
            "your prompt contains the value of {}; it was not sent",
            keys.join(", ")
        ),
        "describe the problem without the value; the agent can use it through `smith run`",
    )
}

// ---------- file names ----------

const ENV_SAFE_SUFFIXES: &[&str] = &[
    "example", "sample", "template", "dist", "defaults", "schema",
];

/// Secret-bearing by name (design D3 adds content checks on top).
pub fn is_secret_path(p: &Path) -> bool {
    let s = p.to_string_lossy().replace('\\', "/");
    let name = s.rsplit('/').next().unwrap_or(&s);
    if let Some(rest) = name.strip_prefix(".env.") {
        return !ENV_SAFE_SUFFIXES
            .iter()
            .any(|x| rest == *x || rest.ends_with(&format!(".{x}")));
    }
    if name == ".env" || name.ends_with(".env") {
        return true;
    }
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    if matches!(
        ext.as_deref(),
        Some("pem" | "key" | "p12" | "pfx" | "jks" | "keystore")
    ) {
        return true;
    }
    if ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]
        .iter()
        .any(|k| name.starts_with(k) && !name.ends_with(".pub"))
    {
        return true;
    }
    const PATHS: &[&str] = &[
        ".aws/credentials",
        ".netrc",
        ".git-credentials",
        ".pgpass",
        ".docker/config.json",
        ".kube/config",
        ".pypirc",
    ];
    if PATHS
        .iter()
        .any(|t| s == *t || s.ends_with(&format!("/{t}")))
    {
        return true;
    }
    name == ".npmrc" && npmrc_has_token(p)
}

fn npmrc_has_token(p: &Path) -> bool {
    std::fs::read_to_string(p)
        .is_ok_and(|c| c.contains("_authToken") || c.contains("_auth=") || c.contains("_password"))
}

/// Paths an agent must never stage, beyond secret-bearing files.
fn is_local_only(p: &str) -> bool {
    let p = p.trim_start_matches("./");
    p == ".claude/settings.local.json"
        || p.ends_with("/.claude/settings.local.json")
        || p == ".locksmith"
        || p.starts_with(".locksmith/")
}

/// Could a glob (last segment) select a secret-bearing file?
fn glob_may_hit_secret(g: &str) -> bool {
    let seg = g.rsplit('/').next().unwrap_or(g);
    // Only globs that name secret files on purpose; `*` alone never reaches hidden `.env`
    // through ripgrep-based search tools.
    if !["env", "pem", "key", "id_"].iter().any(|k| seg.contains(k)) {
        return false;
    }
    [
        ".env",
        "a.env",
        ".env.local",
        "k.pem",
        "k.key",
        "id_rsa",
        "id_ed25519",
    ]
    .iter()
    .any(|probe| glob_match(seg, probe))
}

/// `*` and `?` glob match of one path segment.
fn glob_match(pat: &str, s: &str) -> bool {
    fn go(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], s) || (!s.is_empty() && go(p, &s[1..])),
            (Some(b'?'), Some(_)) => go(&p[1..], &s[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &s[1..]),
            _ => false,
        }
    }
    go(pat.as_bytes(), s.as_bytes())
}

/// The secret-bearing paths `arg` names: itself, or what a glob in its last segment matches.
fn secret_targets(cwd: &Path, arg: &str) -> Vec<String> {
    let arg = arg.strip_prefix("file://").unwrap_or(arg);
    if !arg.contains(['*', '?']) {
        let p = resolve(cwd, Path::new(arg));
        let name = arg.rsplit('/').next().unwrap_or(arg);
        // `app.env` only counts when it exists: `process.env` is usually a search pattern.
        let loose = name.ends_with(".env") && !name.starts_with(".env");
        return if is_secret_path(&p) && (!loose || p.is_file()) {
            vec![arg.to_string()]
        } else {
            vec![]
        };
    }
    let (dir, pat) = arg.rsplit_once('/').unwrap_or(("", arg));
    let base = resolve(cwd, Path::new(if dir.is_empty() { "." } else { dir }));
    let Ok(rd) = std::fs::read_dir(&base) else {
        // Nothing to expand against: judge the pattern itself.
        return if glob_may_hit_secret(pat) {
            vec![arg.to_string()]
        } else {
            vec![]
        };
    };
    rd.flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| glob_match(pat, n) && is_secret_path(&base.join(n)))
        .collect()
}

// ---------- shell ----------

const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish"];
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "perl", "ruby", "node",
];
/// Commands that take file arguments without printing their content.
const NON_READING: &[&str] = &[
    "ls", "rm", "mv", "ln", "touch", "chmod", "chown", "chgrp", "stat", "test", "[", "file",
    "echo", "printf", "mkdir", "rmdir", "realpath", "readlink", "basename", "dirname", "which",
    "find", "du", "wc", "shred", "trash", "code", "vim", "vi", "nvim", "nano", "emacs", "open",
    "true", ":",
];
const SECRETISH: &[&str] = &[
    "KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "AUTH",
];

fn base(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

fn shell_decision(src: &str, cwd: &Path, depth: u8) -> Decision {
    if depth > 3 {
        return ask(
            "opaque-command",
            "shell commands nested more than three levels deep",
        );
    }
    let script = shell::parse(src);
    for r in &script.reads {
        if is_proc_environ(r) {
            return deny(
                "env-dump",
                format!("{r} exposes a process environment"),
                ALT_ENV,
            );
        }
        if !secret_targets(cwd, r).is_empty() {
            return deny(
                "secret-file",
                format!("`< {r}` reads a secret-bearing file"),
                ALT_FILES,
            );
        }
    }
    // A denial anywhere wins; otherwise the first ask.
    let mut verdict = Decision::Allow;
    for c in &script.cmds {
        match command_decision(c, cwd, depth) {
            d @ Decision::Deny { .. } => return d,
            d @ Decision::Ask { .. } if verdict == Decision::Allow => verdict = d,
            _ => {}
        }
    }
    if verdict == Decision::Allow
        && let Some(r) = script.opaque.first()
    {
        verdict = ask("opaque-command", *r);
    }
    verdict
}

fn command_decision(c: &shell::Cmd, cwd: &Path, depth: u8) -> Decision {
    let Some(name) = c.name.as_deref() else {
        return Decision::Allow; // `$CMD args`: nothing static to judge
    };
    let name = base(name);
    let args: Vec<&str> = c.args.iter().filter_map(|a| a.as_deref()).collect();
    let mut positional = args.iter().copied().filter(|a| !a.starts_with('-'));

    // Dynamic code: the human decides (spec "Ambiguous commands go to the human").
    if name == "eval" {
        return ask(
            "opaque-command",
            "`eval` runs code that cannot be checked in advance",
        );
    }
    if c.piped_into && INTERPRETERS.contains(&name) && positional.next().is_none() {
        return ask(
            "opaque-command",
            format!("output is piped into `{name}` as a program"),
        );
    }

    // Wrappers: judge the wrapped command.
    if let Some(inner) = unwrap(name, &c.args) {
        return command_decision(&inner, cwd, depth);
    }

    // `sh -c SCRIPT`: parse the script itself (depth-limited).
    if SHELLS.contains(&name)
        && let Some(i) = c.args.iter().position(|a| {
            a.as_deref()
                .is_some_and(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('c'))
        })
    {
        return match c.args.get(i + 1) {
            Some(Some(script)) => shell_decision(script, cwd, depth + 1),
            Some(None) => ask(
                "opaque-command",
                format!("`{name} -c` runs a script built at run time"),
            ),
            None => Decision::Allow,
        };
    }
    if matches!(name, "source" | ".") {
        if c.args.first().is_some_and(Option::is_none) {
            return ask("opaque-command", "sourcing a script built at run time");
        }
        if let Some(f) = args.first()
            && !secret_targets(cwd, f).is_empty()
        {
            return deny(
                "secret-file",
                format!("`{name} {f}` loads secrets into the agent's shell"),
                "use `smith run -- <command>` so only that command gets the values",
            );
        }
    }

    if let Some(d) = env_dump(name, c, &args) {
        return d;
    }
    if let Some(a) = args.iter().find(|a| is_proc_environ(a)) {
        return deny(
            "env-dump",
            format!("{a} exposes a process environment"),
            ALT_ENV,
        );
    }
    match name {
        "smith" => return smith_decision(&args),
        "git" => return git_decision(&args, cwd),
        n if NON_READING.contains(&n) => return Decision::Allow,
        _ => {}
    }

    // Secret-bearing files as arguments of a command that reads them.
    let candidates: Vec<&str> = if name == "cp" {
        let pos: Vec<&str> = args
            .iter()
            .copied()
            .filter(|a| !a.starts_with('-'))
            .collect();
        pos[..pos.len().saturating_sub(1)].to_vec()
    } else {
        // `--data=@.env`, `-F file=@.env`, `if=.env`.
        args.iter()
            .map(|a| {
                a.rsplit_once('=')
                    .map_or(*a, |(_, v)| v)
                    .trim_start_matches('@')
            })
            .collect()
    };
    for a in candidates {
        if let Some(t) = secret_targets(cwd, a).first() {
            return deny(
                "secret-file",
                format!("`{name}` would read {t}, which holds secrets"),
                ALT_FILES,
            );
        }
    }
    Decision::Allow
}

/// `sudo X`, `env A=1 X`, `xargs X`, `timeout 5 X`, `nice -n 5 X`, `find ... -exec X {} ;`.
fn unwrap(name: &str, args: &[Option<String>]) -> Option<shell::Cmd> {
    let with_value: &[&str] = match name {
        "sudo" | "doas" => &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"],
        "xargs" => &[
            "-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "-J", "-R", "-S",
        ],
        "nice" => &["-n"],
        "timeout" => &["-s", "-k", "--signal", "--kill-after"],
        "env" => &["-u", "-C", "-S"],
        "nohup" | "time" | "exec" | "command" | "builtin" | "stdbuf" | "caffeinate" => &[],
        "find" => {
            let i = args.iter().position(|a| {
                matches!(a.as_deref(), Some("-exec" | "-execdir" | "-ok" | "-okdir"))
            })?;
            let rest: Vec<Option<String>> = args[i + 1..]
                .iter()
                .take_while(|a| !matches!(a.as_deref(), Some(";" | "+" | "\\;")))
                .cloned()
                .collect();
            return split(&rest);
        }
        _ => return None,
    };
    let mut i = 0;
    let mut duration_left = name == "timeout";
    while let Some(Some(a)) = args.get(i) {
        if with_value.contains(&a.as_str()) {
            i += 2;
        } else if a.starts_with('-') || (name == "env" && a.contains('=')) {
            i += 1;
        } else if duration_left {
            duration_left = false;
            i += 1;
        } else {
            break;
        }
    }
    split(args.get(i..).unwrap_or_default())
}

fn split(rest: &[Option<String>]) -> Option<shell::Cmd> {
    let (name, args) = rest.split_first()?;
    Some(shell::Cmd {
        name: name.clone(),
        args: args.to_vec(),
        declaration: false,
        declares_names: false,
        piped_into: false,
    })
}

fn is_proc_environ(a: &str) -> bool {
    a.starts_with("/proc/") && a.ends_with("/environ")
}

fn env_dump(name: &str, c: &shell::Cmd, args: &[&str]) -> Option<Decision> {
    let dump = |what: &str| {
        Some(deny(
            "env-dump",
            format!("`{what}` prints the whole environment"),
            ALT_ENV,
        ))
    };
    match name {
        "printenv" => {
            let names: Vec<&&str> = args.iter().filter(|a| !a.starts_with('-')).collect();
            if names.is_empty() {
                return dump("printenv");
            }
            names
                .iter()
                .find(|n| {
                    let up = n.to_ascii_uppercase();
                    SECRETISH.iter().any(|s| up.contains(s))
                })
                .map(|n| {
                    deny(
                        "env-dump",
                        format!("`printenv {n}` prints a secret variable"),
                        ALT_ENV,
                    )
                })
        }
        // `env` with nothing to run prints everything (`env A=1 cmd` is handled by unwrap).
        "env"
            if c.args.iter().all(|a| {
                a.as_deref()
                    .is_some_and(|a| a.starts_with('-') || a.contains('='))
            }) =>
        {
            dump("env")
        }
        "set" if c.args.is_empty() => dump("set"),
        "export" | "declare" | "typeset" | "readonly" if c.declaration && !c.declares_names => {
            let flags: String = args.iter().filter_map(|a| a.strip_prefix('-')).collect();
            (args.is_empty() || flags.contains('p') || flags.contains('x')).then(|| {
                deny(
                    "env-dump",
                    format!("`{name}` without names prints exported variables"),
                    ALT_ENV,
                )
            })
        }
        // BSD-style `ps eww` / `ps auxe` prints each process's environment.
        "ps" => args
            .first()
            .filter(|a| !a.starts_with('-') && a.contains('e'))
            .map(|a| {
                deny(
                    "env-dump",
                    format!("`ps {a}` prints process environments"),
                    "use `ps aux`",
                )
            }),
        _ => None,
    }
}

fn smith_decision(args: &[&str]) -> Decision {
    let sub: Vec<&str> = args
        .iter()
        .copied()
        .filter(|a| !a.starts_with('-'))
        .take(2)
        .collect();
    if sub.iter().any(|s| matches!(*s, "reveal" | "export")) {
        return deny(
            "smith-reveal",
            "agents may not reveal or export secret values",
            "use `smith run -- <command>`; reveal and export are for a human at a terminal",
        );
    }
    Decision::Allow
}

fn git_decision(args: &[&str], cwd: &Path) -> Decision {
    // Skip global options (`-C dir`, `-c k=v`, `--git-dir=...`).
    let mut i = 0;
    while let Some(a) = args.get(i) {
        match *a {
            "-C" | "-c" => i += 2,
            a if a.starts_with('-') => i += 1,
            _ => break,
        }
    }
    let Some(sub) = args.get(i) else {
        return Decision::Allow;
    };
    let rest = &args[(i + 1).min(args.len())..];
    let paths: Vec<&str> = rest
        .iter()
        .copied()
        .filter(|a| !a.starts_with('-'))
        .collect();
    match *sub {
        "add" | "stage" => {
            for p in &paths {
                if is_local_only(p) || !secret_targets(cwd, p).is_empty() {
                    return deny(
                        "stage-sensitive",
                        format!("`{p}` must not be committed"),
                        "keep it out of git (`smith init` adds it to .gitignore)",
                    );
                }
            }
            let all = rest
                .iter()
                .any(|a| matches!(*a, "-A" | "--all" | "-u" | "--update"))
                || paths.iter().any(|p| matches!(*p, "." | ":/" | "*"));
            if all && let Some(f) = unignored_sensitive(cwd) {
                return deny(
                    "stage-sensitive",
                    format!("this would stage {f}, which git does not ignore"),
                    "add it to .gitignore (or run `smith init`), then stage files explicitly",
                );
            }
            Decision::Allow
        }
        "show" | "diff" | "log" | "blame" | "cat-file" | "grep" => {
            for p in paths {
                let p = p.rsplit_once(':').map_or(p, |(_, f)| f);
                if !p.is_empty() && !secret_targets(cwd, p).is_empty() {
                    return deny(
                        "secret-file",
                        format!("`git {sub}` would print {p}, which holds secrets"),
                        ALT_FILES,
                    );
                }
            }
            Decision::Allow
        }
        _ => Decision::Allow,
    }
}

/// A sensitive file in the working directory that git does not ignore.
fn unignored_sensitive(cwd: &Path) -> Option<String> {
    let mut cands: Vec<String> = std::fs::read_dir(cwd)
        .ok()?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| is_secret_path(&cwd.join(n)))
        .collect();
    if cwd.join(".claude/settings.local.json").is_file() {
        cands.push(".claude/settings.local.json".into());
    }
    cands.into_iter().find(|f| {
        std::process::Command::new("git")
            .args(["check-ignore", "-q", "--", f])
            .current_dir(cwd)
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.code() == Some(1)) // 1 = not ignored; 128 = not a repo
    })
}

#[cfg(test)]
mod tests;
