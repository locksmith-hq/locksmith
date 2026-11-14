//! `smith vault|project|env|add|ls|rm|history|reveal|export|import`.
//! Secret values appear only in `reveal --print` output and in files the user asks `export` to write.

use crate::input::{self, Opts};
use crate::{Fail, audit_cmds, dotenv};
use clap::{Args, Subcommand};
use ls_core::ExitCode;
use ls_crypto::recovery::RecoveryPhrase;
use ls_crypto::{SecretBytes, SecretKey32};
use ls_vault::{Error as VErr, Vault};
use serde_json::json;
use std::io::{IsTerminal, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

#[derive(Subcommand)]
pub enum VaultCmds {
    /// Create, unlock-manage and recover the vault.
    Vault {
        #[command(subcommand)]
        cmd: VaultCmd,
    },
    /// Manage projects.
    Project {
        #[command(subcommand)]
        cmd: ProjectCmd,
    },
    /// Manage environments.
    Env {
        #[command(subcommand)]
        cmd: EnvCmd,
    },
    /// Store a secret (value from a no-echo prompt, --stdin or --from-file; never an argument).
    Add(AddArgs),
    /// List secrets (names and metadata only).
    Ls(Scope),
    /// Remove a secret and all its versions.
    Rm(NameArgs),
    /// List the versions of a secret (no values).
    History(NameArgs),
    /// Copy a secret to the clipboard (humans only: needs a terminal, fresh passphrase).
    Reveal(RevealArgs),
    /// Write secrets to a 0600 file.
    Export(ExportArgs),
    /// Import secrets from another format.
    Import {
        #[command(subcommand)]
        cmd: ImportCmd,
    },
}

#[derive(Subcommand)]
pub enum VaultCmd {
    /// Create the vault and show the recovery phrase once.
    Init,
    /// Change the passphrase (with --passphrase-stdin: current, then new, one per line).
    Passwd,
    /// Regain access with the recovery phrase (with --passphrase-stdin: phrase, then new passphrase).
    Recover,
    /// Manage the recovery phrase.
    Recovery {
        #[command(subcommand)]
        cmd: RecoveryCmd,
    },
}

#[derive(Subcommand)]
pub enum RecoveryCmd {
    /// Replace the recovery phrase with a new one.
    Rotate,
}

#[derive(Subcommand)]
pub enum ProjectCmd {
    Add {
        name: String,
    },
    Ls,
    Rm {
        name: String,
        /// Skip the confirmation question.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum EnvCmd {
    Add {
        name: String,
        #[arg(short, long, default_value = "default")]
        project: String,
    },
    Ls {
        #[arg(short, long, default_value = "default")]
        project: String,
    },
}

#[derive(Subcommand)]
pub enum ImportCmd {
    /// Move the values of a .env file into the vault, then offer to delete the file.
    Dotenv {
        file: PathBuf,
        #[command(flatten)]
        t: Target,
        /// Delete the file without asking.
        #[arg(long, conflicts_with = "keep")]
        yes: bool,
        /// Keep the file without asking.
        #[arg(long)]
        keep: bool,
    },
}

#[derive(Args)]
pub struct Target {
    #[arg(short, long, default_value = "default")]
    pub(crate) project: String,
    #[arg(short, long, default_value = "development")]
    pub(crate) env: String,
}

#[derive(Args)]
pub struct Scope {
    #[arg(short, long)]
    project: Option<String>,
    #[arg(short, long)]
    env: Option<String>,
}

#[derive(Args)]
pub struct NameArgs {
    name: String,
    #[command(flatten)]
    t: Target,
}

#[derive(Args)]
pub struct AddArgs {
    name: String,
    /// Rejected: values must not be passed as arguments (shell history and `ps` would leak them).
    #[arg(hide = true)]
    extra: Vec<String>,
    /// Read the value from stdin (after the passphrase line when --passphrase-stdin is set).
    #[arg(long)]
    stdin: bool,
    #[arg(long, value_name = "FILE", conflicts_with = "stdin")]
    from_file: Option<PathBuf>,
    #[command(flatten)]
    t: Target,
}

#[derive(Args)]
pub struct RevealArgs {
    name: String,
    /// Print the value on the terminal instead of copying it to the clipboard.
    #[arg(long)]
    print: bool,
    #[command(flatten)]
    t: Target,
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Format {
    Env,
    Json,
}

#[derive(Args)]
pub struct ExportArgs {
    #[arg(long, value_enum, default_value = "env")]
    format: Format,
    /// Output file (mode 0600). Without it, stdout is used only when it is a terminal.
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
    #[arg(short, long, default_value = "default")]
    project: String,
    /// One environment; all environments of the project when omitted.
    #[arg(short, long)]
    env: Option<String>,
}

pub(crate) fn dir() -> PathBuf {
    ls_core::config_dir().join("vault")
}

pub(crate) fn fail(e: VErr) -> Fail {
    let code = match e {
        VErr::NotFound(_) => ExitCode::NotFound,
        VErr::Invalid(_) | VErr::AlreadyExists(_) => ExitCode::Usage,
        _ => ExitCode::Failure,
    };
    Fail(code, e.to_string())
}

fn out(o: &Opts, msg: &str, j: serde_json::Value) {
    if o.json {
        println!("{j}");
    } else {
        println!("{msg}");
    }
}

/// Perms and existence are checked before any passphrase prompt.
pub(crate) fn precheck(d: &Path) -> Result<(), Fail> {
    ls_vault::check_perms(d).map_err(fail)?;
    if !ls_vault::exists(d) {
        return Err(fail(VErr::NotInitialized));
    }
    Ok(())
}

/// Every command that touches secrets unlocks with a fresh passphrase entry (nothing is cached).
pub(crate) fn unlock(o: &Opts) -> Result<Vault, Fail> {
    let d = dir();
    precheck(&d)?;
    let (_, weak) = input::kdf();
    let pw = input::passphrase(o, "Passphrase: ")?;
    Vault::open_passphrase(&d, pw.as_bytes(), weak).map_err(fail)
}

pub fn run(cmd: VaultCmds, o: &Opts) -> Result<ExitCode, Fail> {
    let _ = ls_platform::disable_core_dumps();
    match cmd {
        VaultCmds::Vault { cmd } => match cmd {
            VaultCmd::Init => init(o)?,
            VaultCmd::Passwd => passwd(o)?,
            VaultCmd::Recover => recover(o)?,
            VaultCmd::Recovery {
                cmd: RecoveryCmd::Rotate,
            } => rotate(o)?,
        },
        VaultCmds::Project { cmd } => project(o, cmd)?,
        VaultCmds::Env { cmd } => env(o, cmd)?,
        VaultCmds::Add(a) => add(o, a)?,
        VaultCmds::Ls(s) => ls(o, s)?,
        VaultCmds::Rm(a) => {
            unlock(o)?
                .remove_secret(&a.t.project, &a.t.env, &a.name)
                .map_err(fail)?;
            out(
                o,
                &format!("removed {}", a.name),
                json!({ "removed": a.name }),
            );
        }
        VaultCmds::History(a) => history(o, a)?,
        VaultCmds::Reveal(a) => reveal(o, a)?,
        VaultCmds::Export(a) => export(o, a)?,
        VaultCmds::Import {
            cmd: ImportCmd::Dotenv { file, t, yes, keep },
        } => import_dotenv(o, &file, &t, yes, keep)?,
    }
    Ok(ExitCode::Ok)
}

// ---- vault lifecycle ----

/// Shows the 24 words once on stderr, then requires 3 randomly chosen words (by position).
fn show_and_confirm(o: &Opts, phrase: &RecoveryPhrase) -> Result<(), Fail> {
    let words = phrase.words();
    eprintln!(
        "Recovery phrase. Write these 24 words down and keep them offline; they are shown only once.\n\
         Without the passphrase AND this phrase, the vault cannot be recovered."
    );
    for (i, w) in words.iter().enumerate() {
        eprintln!("{:>3}. {w}", i + 1);
    }
    loop {
        let rnd = SecretKey32::random().map_err(|e| Fail(ExitCode::Failure, e.to_string()))?;
        let mut pos: Vec<usize> = Vec::new();
        for b in rnd.expose() {
            let i = *b as usize % 24;
            if !pos.contains(&i) {
                pos.push(i);
            }
            if pos.len() == 3 {
                break;
            }
        }
        pos.sort_unstable();
        let answers: Vec<String> = if o.test_confirm {
            eprintln!(
                "Confirm words #{} #{} #{} (space-separated):",
                pos[0] + 1,
                pos[1] + 1,
                pos[2] + 1
            );
            input::read_line_stdin()?
                .split_whitespace()
                .map(str::to_lowercase)
                .collect()
        } else {
            let mut v = Vec::new();
            for p in &pos {
                v.push(
                    input::prompt_secret(&format!("Re-type word #{}: ", p + 1))?
                        .trim()
                        .to_lowercase(),
                );
            }
            v
        };
        if answers.len() == 3 && pos.iter().zip(&answers).all(|(p, a)| words[*p] == a) {
            return Ok(());
        }
        eprintln!("Those words do not match. Try again.");
    }
}

fn init(o: &Opts) -> Result<(), Fail> {
    let d = dir();
    if ls_vault::exists(&d) {
        return Err(Fail(
            ExitCode::Failure,
            "a vault already exists here".into(),
        ));
    }
    let pw = input::new_passphrase(o)?;
    let phrase = RecoveryPhrase::generate().map_err(|e| Fail(ExitCode::Failure, e.to_string()))?;
    show_and_confirm(o, &phrase)?;
    let (params, weak) = input::kdf();
    let mut v = Vault::create(&d, pw.as_bytes(), params, weak, &phrase).map_err(fail)?;
    v.add_project("default").map_err(fail)?;
    out(o, "vault created", json!({ "status": "created" }));
    Ok(())
}

fn passwd(o: &Opts) -> Result<(), Fail> {
    let mut v = unlock(o)?;
    let new = input::new_passphrase(o)?;
    let (params, weak) = input::kdf();
    v.change_passphrase(new.as_bytes(), params, weak)
        .map_err(fail)?;
    out(
        o,
        "passphrase changed",
        json!({ "status": "passphrase_changed" }),
    );
    Ok(())
}

fn recover(o: &Opts) -> Result<(), Fail> {
    let d = dir();
    precheck(&d)?;
    let typed = input::passphrase(o, "Recovery phrase (24 words): ")?;
    let phrase = RecoveryPhrase::parse(&typed).map_err(|e| Fail(ExitCode::Usage, e.to_string()))?;
    let mut v = Vault::open_recovery(&d, &phrase).map_err(fail)?; // wrong phrase: nothing modified
    let new = input::new_passphrase(o)?;
    let (params, weak) = input::kdf();
    v.change_passphrase(new.as_bytes(), params, weak)
        .map_err(fail)?;
    out(
        o,
        "vault recovered; passphrase replaced",
        json!({ "status": "recovered" }),
    );
    Ok(())
}

fn rotate(o: &Opts) -> Result<(), Fail> {
    let mut v = unlock(o)?;
    let phrase = RecoveryPhrase::generate().map_err(|e| Fail(ExitCode::Failure, e.to_string()))?;
    show_and_confirm(o, &phrase)?;
    v.rotate_recovery(&phrase).map_err(fail)?;
    out(
        o,
        "recovery phrase rotated",
        json!({ "status": "recovery_rotated" }),
    );
    Ok(())
}

// ---- projects, environments ----

fn project(o: &Opts, cmd: ProjectCmd) -> Result<(), Fail> {
    match cmd {
        ProjectCmd::Add { name } => {
            unlock(o)?.add_project(&name).map_err(fail)?;
            out(
                o,
                &format!("project {name} created (environment: development)"),
                json!({ "project": name }),
            );
        }
        ProjectCmd::Ls => {
            let v = unlock(o)?;
            let mut rows = Vec::new();
            for p in v.list_projects().map_err(fail)? {
                let envs = v.list_envs(&p).map_err(fail)?;
                if !o.json {
                    println!("{p}  [{}]", envs.join(", "));
                }
                rows.push(json!({ "name": p, "environments": envs }));
            }
            if o.json {
                println!("{}", json!({ "projects": rows }));
            }
        }
        ProjectCmd::Rm { name, yes } => {
            let mut v = unlock(o)?;
            if !yes {
                let q = format!(
                    "Delete project '{name}' and all its secrets? Type its name to confirm: "
                );
                if input::tty_line(&q).as_deref() != Some(name.as_str()) {
                    return Err(Fail(
                        ExitCode::Failure,
                        "not confirmed; nothing deleted (use --yes in scripts)".into(),
                    ));
                }
            }
            v.remove_project(&name).map_err(fail)?;
            out(
                o,
                &format!("project {name} removed"),
                json!({ "removed": name }),
            );
        }
    }
    Ok(())
}

fn env(o: &Opts, cmd: EnvCmd) -> Result<(), Fail> {
    match cmd {
        EnvCmd::Add { name, project } => {
            unlock(o)?.add_env(&project, &name).map_err(fail)?;
            out(
                o,
                &format!("environment {name} added to {project}"),
                json!({ "project": project, "environment": name }),
            );
        }
        EnvCmd::Ls { project } => {
            let envs = unlock(o)?.list_envs(&project).map_err(fail)?;
            if o.json {
                println!("{}", json!({ "project": project, "environments": envs }));
            } else {
                for e in envs {
                    println!("{e}");
                }
            }
        }
    }
    Ok(())
}

// ---- secrets ----

fn add(o: &Opts, a: AddArgs) -> Result<(), Fail> {
    if !a.extra.is_empty() {
        // Deliberately does not echo the offending argument.
        return Err(Fail(
            ExitCode::Usage,
            "a secret value must not be passed as an argument; supply it via the interactive \
             no-echo prompt, --stdin, or --from-file FILE"
                .into(),
        ));
    }
    let mut v = unlock(o)?;
    let value = if a.stdin {
        SecretBytes::new(input::read_value_stdin()?)
    } else if let Some(f) = &a.from_file {
        SecretBytes::new(std::fs::read(f).map_err(|e| {
            Fail(
                ExitCode::Failure,
                format!("cannot read {}: {e}", f.display()),
            )
        })?)
    } else {
        SecretBytes::new(
            input::prompt_secret(&format!("Value for {}: ", a.name))?
                .as_bytes()
                .to_vec(),
        )
    };
    let ver = v
        .put_secret(&a.t.project, &a.t.env, &a.name, value.expose())
        .map_err(fail)?;
    audit_write(&v, &a.t, &a.name, ver)?;
    out(
        o,
        &format!(
            "stored {} (version {ver}) in {}/{}",
            a.name, a.t.project, a.t.env
        ),
        json!({ "name": a.name, "project": a.t.project, "environment": a.t.env, "version": ver }),
    );
    Ok(())
}

/// Version 1 is a new secret (CREATE); later versions replace it (ROTATE).
fn audit_write(v: &Vault, t: &Target, name: &str, ver: u32) -> Result<(), Fail> {
    let action = if ver == 1 { "CREATE" } else { "ROTATE" };
    audit_cmds::record(v, action, format!("{}/{}/{name}", t.project, t.env), "cli")
}

fn ls(o: &Opts, s: Scope) -> Result<(), Fail> {
    let items = unlock(o)?
        .list_secrets(s.project.as_deref(), s.env.as_deref())
        .map_err(fail)?;
    if o.json {
        let rows: Vec<_> = items
            .iter()
            .map(|m| {
                json!({ "project": m.project, "environment": m.environment, "name": m.name,
                        "version": m.version, "created_at": m.created_at, "updated_at": m.updated_at })
            })
            .collect();
        println!("{}", json!({ "secrets": rows }));
    } else {
        for m in items {
            println!(
                "{}/{}  {}  v{}  updated {}",
                m.project, m.environment, m.name, m.version, m.updated_at
            );
        }
    }
    Ok(())
}

fn history(o: &Opts, a: NameArgs) -> Result<(), Fail> {
    let h = unlock(o)?
        .history(&a.t.project, &a.t.env, &a.name)
        .map_err(fail)?;
    if o.json {
        let rows: Vec<_> = h
            .iter()
            .map(|x| json!({ "version": x.version, "created_at": x.created_at, "current": x.current }))
            .collect();
        println!("{}", json!({ "name": a.name, "versions": rows }));
    } else {
        for x in h {
            println!(
                "v{}  {}{}",
                x.version,
                x.created_at,
                if x.current { "  (current)" } else { "" }
            );
        }
    }
    Ok(())
}

fn blocked(msg: &str) -> Fail {
    Fail(ExitCode::Blocked, msg.into())
}

fn reveal(o: &Opts, a: RevealArgs) -> Result<(), Fail> {
    if let Some(k) = input::agent_detected() {
        return Err(blocked(&format!(
            "refusing to reveal a secret: an AI agent environment was detected ({k}). \
             Run `smith reveal` in your own terminal."
        )));
    }
    if o.passphrase_stdin {
        return Err(Fail(
            ExitCode::Usage,
            "reveal needs interactive passphrase entry; --passphrase-stdin is not allowed".into(),
        ));
    }
    if o.json {
        return Err(Fail(ExitCode::Usage, "reveal has no --json output".into()));
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(blocked(
            "reveal requires an interactive terminal on both stdin and stdout",
        ));
    }
    let v = unlock(o)?;
    let val = v
        .get_secret(&a.t.project, &a.t.env, &a.name)
        .map_err(fail)?;
    if a.print {
        let mut so = std::io::stdout().lock();
        let _ = so.write_all(val.expose());
        let _ = so.write_all(b"\n");
    } else {
        copy_to_clipboard(val.expose())?;
        eprintln!(
            "copied {} to the clipboard; it will be cleared in 30 seconds",
            a.name
        );
    }
    Ok(())
}

fn copy_to_clipboard(value: &[u8]) -> Result<(), Fail> {
    let cmdline = if cfg!(target_os = "macos") {
        "pbcopy"
    } else if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        "wl-copy"
    } else {
        "xclip -selection clipboard"
    };
    let mut parts = cmdline.split_whitespace();
    let tool = parts.next().unwrap_or("pbcopy");
    let no_tool = |e: std::io::Error| {
        Fail(
            ExitCode::Failure,
            format!("cannot run {tool} ({e}); use `smith reveal --print` instead"),
        )
    };
    let mut c = Command::new(tool)
        .args(parts)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(no_tool)?;
    c.stdin
        .take()
        .ok_or_else(|| Fail(ExitCode::Failure, "clipboard tool has no stdin".into()))?
        .write_all(value)
        .map_err(no_tool)?;
    if !c.wait().map_err(no_tool)?.success() {
        return Err(Fail(ExitCode::Failure, format!("{tool} failed")));
    }
    // Detached (own process group) so it outlives smith and a Ctrl-C in the terminal.
    Command::new("sh")
        .arg("-c")
        .arg(format!("sleep 30; printf \"\" | {cmdline}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(no_tool)?;
    Ok(())
}

fn utf8(name: &str, v: &SecretBytes) -> Result<Zeroizing<String>, Fail> {
    String::from_utf8(v.expose().to_vec())
        .map(Zeroizing::new)
        .map_err(|_| {
            Fail(
                ExitCode::Failure,
                format!("secret {name} is not valid UTF-8; cannot export as text"),
            )
        })
}

fn env_line(out: &mut String, k: &str, v: &str) {
    if v.chars()
        .all(|c| c.is_ascii_alphanumeric() || "_./:@%+=,-".contains(c))
    {
        out.push_str(&format!("{k}={v}\n"));
        return;
    }
    out.push_str(k);
    out.push_str("=\"");
    for c in v.chars() {
        match c {
            '\\' | '"' | '$' | '`' => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push_str("\"\n");
}

fn export(o: &Opts, a: ExportArgs) -> Result<(), Fail> {
    if a.out.is_none() && !std::io::stdout().is_terminal() {
        return Err(blocked(
            "refusing to write secrets to a non-terminal stdout; use --out FILE",
        ));
    }
    let v = unlock(o)?;
    let items = v.get_all(&a.project, a.env.as_deref()).map_err(fail)?;
    let mut body = Zeroizing::new(String::new());
    match a.format {
        Format::Env => {
            let mut last = None;
            for (e, n, val) in &items {
                if a.env.is_none() && last != Some(e) {
                    body.push_str(&format!("# environment: {e}\n"));
                    last = Some(e);
                }
                env_line(&mut body, n, &utf8(n, val)?);
            }
        }
        Format::Json => {
            let mut nested = serde_json::Map::new();
            for (e, n, val) in &items {
                let s = utf8(n, val)?;
                let m = nested.entry(e.clone()).or_insert_with(|| json!({}));
                m[n.as_str()] = json!(s.as_str());
            }
            let doc = match &a.env {
                Some(e) => nested.remove(e).unwrap_or_else(|| json!({})),
                None => serde_json::Value::Object(nested),
            };
            *body = serde_json::to_string_pretty(&doc).expect("JSON value serializes") + "\n";
        }
    }
    match &a.out {
        Some(p) => {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(p)
                .map_err(|e| {
                    Fail(
                        ExitCode::Failure,
                        format!("cannot create {} (it must not exist yet): {e}", p.display()),
                    )
                })?;
            f.write_all(body.as_bytes()).map_err(|e| {
                Fail(
                    ExitCode::Failure,
                    format!("cannot write {}: {e}", p.display()),
                )
            })?;
            eprintln!(
                "wrote {} secret(s) to {} (mode 0600)",
                items.len(),
                p.display()
            );
        }
        None => print!("{}", body.as_str()),
    }
    Ok(())
}

pub(crate) fn import_dotenv(
    o: &Opts,
    file: &Path,
    t: &Target,
    yes: bool,
    keep: bool,
) -> Result<(), Fail> {
    let src = Zeroizing::new(std::fs::read_to_string(file).map_err(|e| {
        Fail(
            ExitCode::Failure,
            format!("cannot read {}: {e}", file.display()),
        )
    })?);
    let items = dotenv::parse(&src)
        .map_err(|m| Fail(ExitCode::Usage, format!("{}: {m}", file.display())))?;
    if items.is_empty() {
        return Err(Fail(
            ExitCode::Usage,
            format!("{} contains no entries", file.display()),
        ));
    }
    let mut v = unlock(o)?;
    let vers = v.put_secrets(&t.project, &t.env, &items).map_err(fail)?;
    for ((k, _), ver) in items.iter().zip(vers) {
        audit_write(&v, t, k, ver)?;
    }
    let names: Vec<&String> = items.iter().map(|(k, _)| k).collect();
    let delete = if keep {
        false
    } else if yes {
        true
    } else if std::io::stdin().is_terminal() {
        input::tty_line(&format!(
            "Imported {} secret(s). Delete {}? [y/N] ",
            names.len(),
            file.display()
        ))
        .is_some_and(|a| a.eq_ignore_ascii_case("y"))
    } else {
        eprintln!(
            "not deleting {} (non-interactive; pass --yes to delete)",
            file.display()
        );
        false
    };
    if delete {
        std::fs::remove_file(file).map_err(|e| {
            Fail(
                ExitCode::Failure,
                format!("imported, but cannot delete {}: {e}", file.display()),
            )
        })?;
    }
    out(
        o,
        &format!(
            "imported {} secret(s) into {}/{}{}",
            names.len(),
            t.project,
            t.env,
            if delete { "; file deleted" } else { "" }
        ),
        json!({ "imported": names.len(), "project": t.project, "environment": t.env, "names": names, "file_deleted": delete }),
    );
    Ok(())
}
