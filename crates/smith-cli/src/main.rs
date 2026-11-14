//! `smith`: the Locksmith command-line interface.

use clap::{CommandFactory, Parser, Subcommand};
use ls_core::ExitCode;
use serde_json::json;
use std::process;

mod audit_cmds;
mod binding;
mod dotenv;
mod input;
mod run_cmd;
mod session;
mod vault_cmds;

// Keep the diagnostics crates linked so their `inventory` checks register.
use ls_broker as _; // daemon/platform/audit doctor checks
use ls_diag as _;
use ls_redact as _;
use ls_update as _;
use ls_vault as _;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMIT: &str = env!("SMITH_COMMIT");
const TARGET: &str = env!("SMITH_TARGET");
const CHANNEL: &str = env!("SMITH_CHANNEL");

#[derive(Parser)]
#[command(
    name = "smith",
    about = "Locksmith: credentials for AI agents without exposure",
    disable_version_flag = true
)]
struct Cli {
    /// Print exactly one JSON document on stdout.
    #[arg(long, global = true)]
    json: bool,
    /// Print version information.
    #[arg(long, short = 'V')]
    version: bool,
    /// Read the passphrase from the first line of stdin instead of prompting (not allowed for `reveal`).
    #[arg(long, global = true)]
    passphrase_stdin: bool,
    /// Test hook (debug builds only): read the init confirmation words from stdin.
    #[cfg(debug_assertions)]
    #[arg(long, global = true, hide = true)]
    test_confirm_words_from_stdin: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check that Locksmith is healthy on this machine.
    Doctor,
    #[command(flatten)]
    Vault(vault_cmds::VaultCmds),
    /// Run a command with project secrets injected into its environment (output is redacted).
    Run(run_cmd::RunArgs),
    /// Print KEY= lines (names only) for the bound or selected keys.
    EnvTemplate(run_cmd::TemplateArgs),
    /// Create a project file (only `--binding-only` for now).
    Init {
        /// Write `.locksmith.toml` in the current directory.
        #[arg(long)]
        binding_only: bool,
    },
    /// Manage the background daemon.
    Daemon {
        #[command(subcommand)]
        cmd: session::DaemonCmd,
    },
    /// Authorize an agent for a bounded time.
    Session {
        #[command(subcommand)]
        cmd: session::SessionCmd,
    },
    /// Show the daemon's lock state and active sessions.
    Status,
    /// Revoke a session (or all of them); effective immediately.
    Revoke {
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        id: Option<String>,
        #[arg(long)]
        all: bool,
    },
    /// Lock the vault now.
    Lock,
    /// Inspect the tamper-evident audit ledger.
    Audit {
        #[command(subcommand)]
        cmd: audit_cmds::AuditCmd,
    },
    /// Print a shell completion script.
    Completions { shell: clap_complete::Shell },
    /// Manage the Locksmith installation itself.
    #[command(name = "self")]
    Smith {
        #[command(subcommand)]
        cmd: SelfCmd,
    },
}

#[derive(Subcommand)]
enum SelfCmd {
    /// Install the latest verified release (or only check with --check).
    Update {
        #[arg(long)]
        check: bool,
    },
}

/// Error carrying the exit code it maps to.
struct Fail(ExitCode, String);

fn main() {
    let cli = Cli::parse(); // clap exits 2 on usage errors
    let json = cli.json;
    let code = match run(cli) {
        Ok(code) => code,
        Err(Fail(code, msg)) => {
            if json {
                println!("{}", json!({ "error": msg, "code": code as u8 }));
            } else {
                eprintln!("smith: {msg}");
            }
            code
        }
    };
    process::exit(code as i32);
}

fn run(cli: Cli) -> Result<ExitCode, Fail> {
    if cli.version {
        if cli.json {
            println!(
                "{}",
                json!({ "version": VERSION, "commit": COMMIT, "target": TARGET, "channel": CHANNEL })
            );
        } else {
            println!("smith {VERSION} ({COMMIT} {TARGET} {CHANNEL})");
        }
        return Ok(ExitCode::Ok);
    }
    let ro = opts(&cli);
    match cli.cmd {
        None => {
            Cli::command().print_help().ok();
            Ok(ExitCode::Usage)
        }
        Some(Cmd::Doctor) => {
            let report = ls_diag::run_all(VERSION);
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("report serializes")
                );
            } else {
                print!("{}", report.render_human());
            }
            Ok(if report.failed() {
                ExitCode::Failure
            } else {
                ExitCode::Ok
            })
        }
        Some(Cmd::Init { binding_only }) => run_cmd::init(binding_only),
        Some(Cmd::Run(a)) => run_cmd::run(&ro, a),
        Some(Cmd::Daemon { cmd }) => session::daemon(cmd),
        Some(Cmd::Session { cmd }) => session::session(&ro, cmd),
        Some(Cmd::Status) => session::status(cli.json),
        Some(Cmd::Revoke { id, .. }) => session::revoke(id),
        Some(Cmd::Lock) => session::lock(),
        Some(Cmd::Audit { cmd }) => audit_cmds::run(&ro, cmd),
        Some(Cmd::EnvTemplate(a)) => run_cmd::env_template(&ro, a),
        Some(Cmd::Vault(c)) => {
            let o = input::Opts {
                json: cli.json,
                passphrase_stdin: cli.passphrase_stdin,
                #[cfg(debug_assertions)]
                test_confirm: cli.test_confirm_words_from_stdin,
                #[cfg(not(debug_assertions))]
                test_confirm: false,
            };
            vault_cmds::run(c, &o)
        }
        Some(Cmd::Completions { shell }) => {
            clap_complete::generate(shell, &mut Cli::command(), "smith", &mut std::io::stdout());
            Ok(ExitCode::Ok)
        }
        Some(Cmd::Smith {
            cmd: SelfCmd::Update { check },
        }) => self_update(check, cli.json),
    }
}

fn opts(cli: &Cli) -> input::Opts {
    input::Opts {
        json: cli.json,
        passphrase_stdin: cli.passphrase_stdin,
        test_confirm: false,
    }
}

fn self_update(check: bool, json: bool) -> Result<ExitCode, Fail> {
    let fail = |e: ls_update::Error| Fail(ExitCode::Failure, e.to_string());
    let src =
        std::env::var("LOCKSMITH_UPDATE_URL").unwrap_or_else(|_| ls_update::DEFAULT_SOURCE.into());
    let updater = ls_update::Updater {
        source: ls_update::Source::parse(&src),
        pubkey_b64: ls_update::EMBEDDED_PUBKEY.into(),
        target: TARGET.into(),
        current: semver::Version::parse(VERSION).expect("crate version is semver"),
    };
    let outcome = if check {
        updater.check().map_err(fail)?
    } else {
        let exe = std::env::current_exe()
            .and_then(|p| p.canonicalize())
            .map_err(|e| Fail(ExitCode::Failure, format!("cannot locate own binary: {e}")))?;
        updater.install(&exe).map_err(fail)?
    };
    use ls_update::Outcome::*;
    let (status, msg, current, latest) = match &outcome {
        UpToDate { current, latest } => (
            "up_to_date",
            format!("smith {current} is up to date"),
            current,
            latest,
        ),
        Available { current, latest } => (
            "available",
            format!("update available: {current} -> {latest} (run `smith self update`)"),
            current,
            latest,
        ),
        Installed { from, to } => (
            "installed",
            format!("updated smith {from} -> {to}"),
            from,
            to,
        ),
    };
    if json {
        println!(
            "{}",
            json!({ "status": status, "current": current, "latest": latest })
        );
    } else {
        println!("{msg}");
    }
    Ok(ExitCode::Ok)
}
