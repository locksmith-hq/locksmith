//! `smith honey plant <name> --into <path>` (t5-honey-tokens task 2.4, design decision 7).
//!
//! A person plants a honey token's decoy value into a file (typically an agent workspace's
//! `.env`), so any later use of it through Locksmith raises an alarm. The value comes from the
//! gateway's owner-only `GET /v1/honey-tokens/{id}/value`, called with the person's own access
//! token (`smith login --user`); agent credentials are refused there. The CLI:
//!
//! - resolves `<name>` to an id through `GET /v1/honey-tokens?name=` (a UUID is taken as the id);
//! - writes the value, followed by a newline, to a new file with mode 0600, refusing to replace an
//!   existing file unless `--force` (then it writes a 0600 temporary file next to it and renames
//!   it over the target, so a symlink at the target is replaced rather than followed);
//! - never prints the value: the output names the token, its id and the path only.
//!
//! The value is held only in zeroizing buffers.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use ls_core::ExitCode;
use secrecy::SecretString;
use serde_json::json;
use zeroize::Zeroizing;

use crate::Fail;
use crate::user_login;

#[derive(Subcommand)]
pub enum HoneyCmd {
    /// Write a honey token's decoy value into a file (mode 0600). Needs `smith login --user` as
    /// the org's owner; the value is never printed.
    Plant(PlantArgs),
}

#[derive(Args)]
pub struct PlantArgs {
    /// Honey token name (as shown in the console), or its id.
    pub name: String,
    /// File to create with the decoy value, e.g. an agent workspace's `.env`.
    #[arg(long, value_name = "PATH")]
    pub into: PathBuf,
    /// Replace the file if it already exists.
    #[arg(long)]
    pub force: bool,
    /// Gateway base URL (`https`, or `http` on loopback only).
    #[arg(long, env = ls_connector::GATEWAY_ENV)]
    pub gateway_url: Option<String>,
}

fn fail(msg: impl Into<String>) -> Fail {
    Fail(ExitCode::Failure, msg.into())
}

pub fn run(json: bool, cmd: HoneyCmd) -> Result<ExitCode, Fail> {
    match cmd {
        HoneyCmd::Plant(a) => plant(json, a),
    }
}

/// The gateway endpoint: the flag or environment, else the one `smith login --agent` saved.
fn gateway(flag: Option<&str>) -> Result<String, Fail> {
    match flag {
        Some(raw) => Ok(ls_connector::parse_endpoint(raw)?),
        None => ls_connector::State::load()
            .map(|s| s.gateway_url().to_owned())
            .map_err(|_| {
                Fail(
                    ExitCode::Usage,
                    format!(
                        "no gateway URL: pass --gateway-url or set {}",
                        ls_connector::GATEWAY_ENV
                    ),
                )
            }),
    }
}

/// The id of the one honey token `name` names.
fn resolve(gateway: &str, user: &SecretString, name: &str) -> Result<(String, String), Fail> {
    if let Ok(id) = ls_connector::uuid_like(name) {
        return Ok((id, name.to_owned()));
    }
    let found = ls_connector::honey_find(gateway, user, name)?;
    match found.as_slice() {
        [] => Err(fail(format!("no honey token named `{name}`"))),
        [t] if t.disabled => Err(fail(format!(
            "honey token `{name}` is disabled; enable or recreate it first"
        ))),
        [t] => Ok((t.id.clone(), t.name.clone())),
        many => Err(fail(format!(
            "{} honey tokens are named `{name}` (one per environment); pass the id instead: {}",
            many.len(),
            many.iter()
                .map(|t| t.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

fn plant(json: bool, a: PlantArgs) -> Result<ExitCode, Fail> {
    if !a.force && std::fs::symlink_metadata(&a.into).is_ok() {
        return Err(fail(format!(
            "{} already exists; pass --force to replace it",
            a.into.display()
        )));
    }
    let gateway = gateway(a.gateway_url.as_deref())?;
    let user = user_login::access_token()?;
    let (id, name) = resolve(&gateway, &user, &a.name)?;
    let value = ls_connector::honey_value(&gateway, &user, &id)?;
    let mut content = Zeroizing::new(Vec::with_capacity(value.len() + 1));
    content.extend_from_slice(&value);
    drop(value);
    content.push(b'\n');
    write_0600(&a.into, &content, a.force)?;
    if json {
        println!(
            "{}",
            json!({ "status": "planted", "name": name, "id": id, "path": a.into })
        );
    } else {
        println!(
            "planted honey token `{name}` ({id}) into {} (mode 0600); any use of it through Locksmith raises an alert",
            a.into.display()
        );
    }
    Ok(ExitCode::Ok)
}

/// Create `path` with mode 0600 holding `content`. Without `force` an existing path (file or
/// symlink) is refused atomically (`O_EXCL`); with `force` a 0600 temporary file in the same
/// directory is renamed over it.
fn write_0600(path: &Path, content: &[u8], force: bool) -> Result<(), Fail> {
    let io = |e: std::io::Error| fail(format!("cannot write {}: {e}", path.display()));
    if !force {
        return match create_new_0600(path) {
            Ok(mut f) => {
                let r = f.write_all(content).and_then(|()| f.sync_all());
                if let Err(e) = r {
                    let _ = std::fs::remove_file(path);
                    return Err(io(e));
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(fail(format!(
                "{} already exists; pass --force to replace it",
                path.display()
            ))),
            Err(e) => Err(io(e)),
        };
    }
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let file_name = path
        .file_name()
        .ok_or_else(|| fail(format!("{} is not a file path", path.display())))?;
    let tmp = dir.join(format!(
        ".{}.smith-{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let written = create_new_0600(&tmp).and_then(|mut f| {
        f.write_all(content)?;
        f.sync_all()
    });
    if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io(e));
    }
    Ok(())
}

fn create_new_0600(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}
