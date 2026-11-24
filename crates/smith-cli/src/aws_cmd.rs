//! `smith aws creds --contained [--profile P] -- <cmd>` (M7 2.1): the fallback for tools that
//! ignore `AWS_ENDPOINT_URL`. The child gets real 15-minute STS credentials limited by the
//! project policy. They are visible to that process: contained, not delegated.
//!
//! D2 task 4.1: `credential-process`, `setup` and `teardown` for the hosted gateway. The AWS CLI
//! and SDKs run `smith aws credential-process` (a keyless profile's `credential_process`), which
//! asks `POST /v1/aws/credentials` for short-lived, grant-scoped STS credentials and prints the
//! documented JSON on stdout. Nothing is cached on disk by smith; the AWS tooling holds the
//! credentials in memory for their lifetime. Vending is off unless the gateway binding sets
//! `vend = true`. The credentials are visible to the agent for their lifetime (contained by the
//! session policy and expiry, not hidden). A denial is one fixed message.

use crate::{Fail, run_cmd};
use clap::{Args, Subcommand};
use ls_connector::State;
use ls_core::ExitCode;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum AwsCmd {
    /// Run a command with short-lived STS credentials (see `--contained`).
    Creds(CredsArgs),
    /// Print short-lived AWS credentials as AWS CLI `credential_process` JSON, from the gateway
    /// (needs `smith login --agent`, a `delegate` grant and a binding with `vend = true`).
    /// Caches nothing on disk. The credentials are visible to the caller for their lifetime.
    CredentialProcess(CredentialProcessArgs),
    /// Add a keyless profile to the AWS config (`$AWS_CONFIG_FILE` or `~/.aws/config`) whose
    /// `credential_process` is `smith aws credential-process`. Writes no key.
    Setup(SetupArgs),
    /// Remove the profile `smith aws setup` added; other config content is left as it is.
    Teardown(TeardownArgs),
}

#[derive(Args)]
pub struct CredentialProcessArgs {
    /// Requested lifetime in seconds (900-3600; the gateway clamps it to the grant).
    #[arg(long)]
    duration_secs: Option<u32>,
    /// Gateway the profile was set up for; refused when it is not the logged-in gateway.
    #[arg(long)]
    gateway: Option<String>,
}

#[derive(Args)]
pub struct SetupArgs {
    /// Gateway base URL (`https`, or `http` on loopback only) recorded in the profile.
    #[arg(long, env = ls_connector::GATEWAY_ENV)]
    gateway: Option<String>,
    /// Profile name.
    #[arg(long, default_value = DEFAULT_PROFILE)]
    profile: String,
    /// Default region for the profile.
    #[arg(long)]
    region: Option<String>,
}

#[derive(Args)]
pub struct TeardownArgs {
    /// Profile name.
    #[arg(long, default_value = DEFAULT_PROFILE)]
    profile: String,
}

pub const DEFAULT_PROFILE: &str = "locksmith";
const BEGIN: &str = "# >>> locksmith aws profile (managed by `smith aws setup`; do not edit) >>>";
const END: &str = "# <<< locksmith aws profile <<<";

#[derive(Args)]
pub struct CredsArgs {
    /// Required acknowledgement: the credentials are visible to the command.
    #[arg(long, required = true)]
    contained: bool,
    /// `[aws.profiles.<name>]` to use (default: the only or first profile).
    #[arg(long)]
    profile: Option<String>,
    /// Command to run, after `--`.
    #[arg(last = true, required = true)]
    cmd: Vec<String>,
}

pub fn run(o: &crate::input::Opts, c: AwsCmd) -> Result<ExitCode, Fail> {
    let a = match c {
        AwsCmd::Creds(a) => a,
        AwsCmd::CredentialProcess(a) => return credential_process(a),
        AwsCmd::Setup(a) => return setup(a),
        AwsCmd::Teardown(a) => return teardown(a),
    };
    let _ = a.contained; // clap enforces it
    let profile = match a.profile {
        Some(p) => p,
        None => run_cmd::bound()?
            .and_then(|(b, _)| b.aws.profiles.keys().next().cloned())
            .ok_or_else(|| {
                Fail(
                    ExitCode::Usage,
                    "no [aws.profiles.<name>] in .locksmith.toml".into(),
                )
            })?,
    };
    eprintln!("{}", ls_proxy::aws::sts::CONTAINED_NOTICE);
    let aws = Some((profile, true));
    if crate::session::in_session() {
        return crate::session::run_via_daemon(None, None, vec![], false, a.cmd, aws);
    }
    crate::session::run_leased(o, None, None, vec![], false, a.cmd, aws)
}

fn fail(msg: &str) -> Fail {
    Fail(ExitCode::Failure, msg.to_owned())
}

fn credential_process(a: CredentialProcessArgs) -> Result<ExitCode, Fail> {
    let st = State::load_fresh()?;
    if let Some(g) = &a.gateway {
        let want = ls_connector::parse_endpoint(g)?;
        if want != st.gateway_url() {
            return Err(fail("the profile was set up for a different gateway"));
        }
    }
    let doc = ls_connector::aws_credentials(&st, a.duration_secs)?;
    // stdout only; the AWS tooling keeps the document in memory.
    let mut so = std::io::stdout().lock();
    so.write_all(doc.as_bytes())
        .and_then(|()| so.write_all(b"\n"))
        .and_then(|()| so.flush())
        .map_err(|_| fail("cannot write the credentials to stdout"))?;
    Ok(ExitCode::Ok)
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

fn env_path(var: &str, default: &str) -> Option<PathBuf> {
    match std::env::var_os(var).filter(|v| !v.is_empty()) {
        Some(p) => Some(PathBuf::from(p)),
        None => home().map(|h| h.join(".aws").join(default)),
    }
}

/// `$AWS_CONFIG_FILE` or `~/.aws/config`.
pub fn config_path() -> Option<PathBuf> {
    env_path("AWS_CONFIG_FILE", "config")
}

/// `$AWS_SHARED_CREDENTIALS_FILE` or `~/.aws/credentials`.
pub fn credentials_path() -> Option<PathBuf> {
    env_path("AWS_SHARED_CREDENTIALS_FILE", "credentials")
}

/// Profile names go into an INI section header and a marker: keep them boring.
fn valid_profile(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 64
        && p.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}

fn section_name(profile: &str) -> String {
    if profile == "default" {
        "default".into()
    } else {
        format!("profile {profile}")
    }
}

/// The `credential_process` command: this binary (quoted) when its path is plain, else `smith`.
fn command_line(gateway: Option<&str>) -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned))
        .filter(|p| !p.contains(['"', '\\', '\n', '\r']))
        .unwrap_or_else(|| "smith".into());
    let mut c = format!("\"{exe}\" aws credential-process");
    if let Some(g) = gateway {
        c.push_str(&format!(" --gateway {g}"));
    }
    c
}

/// The managed block for `profile` (starts with a blank separator line).
pub fn profile_block(profile: &str, region: Option<&str>, gateway: Option<&str>) -> String {
    let mut b = format!("\n{BEGIN}\n[{}]\n", section_name(profile));
    if let Some(r) = region {
        b.push_str(&format!("region = {r}\n"));
    }
    b.push_str(&format!(
        "credential_process = {}\n{END}\n",
        command_line(gateway)
    ));
    b
}

/// Whether `config` has a section for `profile` outside any managed block.
fn has_unmanaged(config: &str, profile: &str) -> bool {
    let header = format!("[{}]", section_name(profile));
    let mut inside = false;
    for l in config.lines() {
        let t = l.trim();
        if t == BEGIN {
            inside = true;
        } else if t == END {
            inside = false;
        } else if !inside && t == header {
            return true;
        }
    }
    false
}

/// `config` without the managed block (and its blank separator line), if present.
fn without_block(config: &str) -> Option<String> {
    let start = config.find(BEGIN)?;
    let end_rel = config[start..].find(END)?;
    let mut end = start + end_rel + END.len();
    if config[end..].starts_with("\r\n") {
        end += 2;
    } else if config[end..].starts_with('\n') {
        end += 1;
    }
    let mut head = &config[..start];
    // The blank separator `setup` added.
    if let Some(h) = head.strip_suffix("\n\n") {
        head = &config[..h.len() + 1];
    }
    Some(format!("{head}{}", &config[end..]))
}

/// `config` with the managed block set to `block` (replacing an earlier one).
fn with_block(config: &str, block: &str) -> String {
    let mut base = without_block(config).unwrap_or_else(|| config.to_owned());
    if !base.is_empty() && !base.ends_with('\n') {
        base.push('\n');
    }
    if base.is_empty() {
        // No separator needed in an empty file.
        return block.trim_start_matches('\n').to_owned();
    }
    base.push_str(block);
    base
}

fn read_config(path: &Path) -> Result<String, Fail> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(_) => Err(fail("cannot read the AWS config file")),
    }
}

fn write_config(path: &Path, text: &str) -> Result<(), Fail> {
    let err = || fail("cannot write the AWS config file");
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|_| err())?;
    }
    std::fs::write(path, text).map_err(|_| err())
}

fn setup(a: SetupArgs) -> Result<ExitCode, Fail> {
    if !valid_profile(&a.profile) {
        return Err(Fail(
            ExitCode::Usage,
            "profile names use letters, digits, `_`, `-` and `.` (max 64)".into(),
        ));
    }
    if let Some(r) = &a.region
        && !(!r.is_empty()
            && r.len() <= 32
            && r.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
    {
        return Err(Fail(ExitCode::Usage, "invalid region".into()));
    }
    let gateway = a
        .gateway
        .as_deref()
        .map(ls_connector::parse_endpoint)
        .transpose()?;
    let path = config_path().ok_or_else(|| fail("cannot find the AWS config file (set HOME)"))?;
    let config = read_config(&path)?;
    if has_unmanaged(&config, &a.profile) {
        return Err(fail(
            "the AWS config already has that profile; choose another with --profile",
        ));
    }
    let block = profile_block(&a.profile, a.region.as_deref(), gateway.as_deref());
    write_config(&path, &with_block(&config, &block))?;
    println!(
        "profile {} added to {}: AWS credentials come from `smith aws credential-process` (short-lived, visible to the agent)",
        a.profile,
        path.display()
    );
    Ok(ExitCode::Ok)
}

fn teardown(a: TeardownArgs) -> Result<ExitCode, Fail> {
    let path = config_path().ok_or_else(|| fail("cannot find the AWS config file (set HOME)"))?;
    let config = read_config(&path)?;
    let header = format!("[{}]", section_name(&a.profile));
    let managed = config
        .find(BEGIN)
        .zip(config.find(END))
        .is_some_and(|(b, e)| b < e && config[b..e].contains(&header));
    if !managed {
        println!("no managed profile {} in {}", a.profile, path.display());
        return Ok(ExitCode::Ok);
    }
    let Some(rest) = without_block(&config) else {
        return Err(fail("cannot find the managed profile block"));
    };
    write_config(&path, &rest)?;
    println!("profile {} removed from {}", a.profile, path.display());
    Ok(ExitCode::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_round_trips_and_preserves_content() {
        let orig = "[default]\nregion = us-east-1\n\n[profile dev]\nsso_session = x\n";
        let block = profile_block("locksmith", Some("eu-west-1"), None);
        let with = with_block(orig, &block);
        assert!(with.starts_with(orig));
        assert!(with.contains("credential_process = "));
        assert!(!with.contains("aws_access_key_id"));
        assert_eq!(without_block(&with).unwrap(), orig);
        // Idempotent: a second setup replaces the block.
        assert_eq!(with_block(&with, &block), with);
        // Empty file round trip.
        let only = with_block("", &block);
        assert!(only.starts_with(BEGIN));
        assert_eq!(without_block(&only).unwrap(), "");
    }

    #[test]
    fn unmanaged_profile_detected() {
        assert!(has_unmanaged(
            "[profile locksmith]\nregion=x\n",
            "locksmith"
        ));
        let block = profile_block("locksmith", None, None);
        assert!(!has_unmanaged(&with_block("", &block), "locksmith"));
    }

    #[test]
    fn profile_names_are_checked() {
        assert!(valid_profile("locksmith"));
        assert!(!valid_profile("a b"));
        assert!(!valid_profile("a]\n[b"));
        assert!(!valid_profile(""));
    }
}
