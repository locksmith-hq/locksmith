//! `smith aws creds --contained [--profile P] -- <cmd>` (M7 2.1): the fallback for tools that
//! ignore `AWS_ENDPOINT_URL`. The child gets real 15-minute STS credentials limited by the
//! project policy. They are visible to that process: contained, not delegated.

use crate::{Fail, run_cmd};
use clap::{Args, Subcommand};
use ls_core::ExitCode;

#[derive(Subcommand)]
pub enum AwsCmd {
    /// Run a command with short-lived STS credentials (see `--contained`).
    Creds(CredsArgs),
}

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
    let AwsCmd::Creds(a) = c;
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
    if std::env::var_os("LOCKSMITH_SESSION").is_some() {
        return crate::session::run_via_daemon(None, None, vec![], false, a.cmd, aws);
    }
    crate::session::run_leased(o, None, None, vec![], false, a.cmd, aws)
}
