//! `smith`: the Locksmith command-line interface.

use clap::{CommandFactory, Parser, Subcommand};
use ls_core::ExitCode;
use serde_json::json;
use std::process;

mod agents;
mod audit_cmds;
mod aws_cmd;
mod binding;
mod connector;
mod daemon_vault;
mod db_cmd;
mod doctor_d2;
mod doctor_d3_db;
mod doctor_m4;
mod doctor_m5;
mod doctor_m6;
mod doctor_m6_db;
mod doctor_m7;
mod doctor_mcp;
mod doctor_workload;
mod dotenv;
mod git_cmd;
mod honey_cmd;
mod hook_cmd;
mod http_cmd;
mod init_cmd;
mod input;
mod mcp_bridge;
mod precommit;
mod run_cmd;
mod scan_cmd;
mod session;
mod user_login;
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
    /// Set up this project: binding, .env import, .gitignore, pre-commit scanner, agent hooks.
    Init {
        /// Only write `.locksmith.toml` in the current directory.
        #[arg(long)]
        binding_only: bool,
        /// Apply every change without asking (CI).
        #[arg(long)]
        yes: bool,
        /// Also add the remote Hub MCP server (`<URL>/mcp`, OAuth) for agents that support it.
        #[arg(long, value_name = "URL")]
        hub: Option<String>,
        /// Replace the repo's MCP entries for upstreams the gateway serves this agent (needs
        /// `smith login --agent`) with `smith mcp bridge <name>`, which holds no credential.
        #[arg(long)]
        mcp_gateway: bool,
        /// Print the planned changes and exit without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Agent hook entry point: `smith hook <agent> <event>` reads the hook JSON on stdin.
    Hook { agent: String, event: String },
    /// Scan files for vault secrets and well-known key formats (names only, never values).
    Scan(scan_cmd::ScanArgs),
    /// Route Git for private hosts through Locksmith, so agents never hold a Git token.
    Git {
        #[command(subcommand)]
        cmd: git_cmd::GitCmd,
    },
    /// Password-less local endpoints for the project's databases (inside a session), or the
    /// hosted gateway's Postgres listener with `--gateway`.
    Db {
        #[command(subcommand)]
        cmd: db_cmd::DbCmd,
    },
    /// Opaque tokens for the HTTP relay: the app holds `lsk_…`, Locksmith attaches the key.
    Token {
        #[command(subcommand)]
        cmd: http_cmd::TokenCmd,
    },
    /// HTTP relay status, provider catalog and the opt-in local CA (explicit-proxy mode).
    Http {
        #[command(subcommand)]
        cmd: http_cmd::HttpCmd,
    },
    /// AWS helpers: short-lived STS credentials. `creds --contained -- <cmd>` runs a command with them;
    /// `setup`, `credential-process` and `teardown` give the AWS CLI keyless gateway-issued credentials
    /// (off unless the gateway binding allows it; the credentials are visible to the agent).
    Aws {
        #[command(subcommand)]
        cmd: aws_cmd::AwsCmd,
    },
    /// Honey tokens (decoys that alert on any use): `plant <name> --into <path>` writes one into a
    /// file for the org's owner (needs `smith login --user`); the value is never printed.
    Honey {
        #[command(subcommand)]
        cmd: honey_cmd::HoneyCmd,
    },
    /// Run the GitHub CLI with a token injected (contained: visible to `gh` only, output redacted).
    Gh(git_cmd::GhArgs),
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
    /// Log in as an agent (`--agent`, short-lived gateway token), as a CI or cluster workload with no stored secret (`--workload github|kubernetes`, OIDC token exchange), or as a human (`--user`, device grant, token in the OS keystore).
    Login(connector::LoginArgs),
    /// List the secrets this agent may use through the gateway (names and hosts, never values).
    Grants,
    /// MCP gateway helpers: `smith mcp bridge <name>` serves an upstream MCP server that the
    /// gateway holds the credential for, over stdio, with no credential in the agent's MCP file.
    Mcp {
        #[command(subcommand)]
        cmd: McpCmd,
    },
    /// Call an upstream through the gateway, which injects the granted secret; output is redacted.
    Relay(connector::RelayArgs),
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
enum McpCmd {
    /// Serve the gateway's upstream MCP server `<name>` over stdio (a stdio MCP server entry).
    Bridge {
        /// Upstream name (see `smith init --mcp-gateway`).
        name: String,
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
        Some(Cmd::Init {
            binding_only,
            yes,
            hub,
            mcp_gateway,
            dry_run,
        }) => init_cmd::run(&ro, binding_only, yes, hub.as_deref(), mcp_gateway, dry_run),
        Some(Cmd::Login(a)) => connector::login(cli.json, a),
        Some(Cmd::Grants) => connector::grants(cli.json),
        Some(Cmd::Relay(a)) => connector::relay(cli.json, a),
        Some(Cmd::Mcp {
            cmd: McpCmd::Bridge { name },
        }) => mcp_bridge::run(&name),
        Some(Cmd::Hook { agent, event }) => hook_cmd::run(&agent, &event),
        Some(Cmd::Scan(a)) => scan_cmd::run(&ro, a),
        Some(Cmd::Git { cmd }) => git_cmd::run(cli.json, cmd),
        Some(Cmd::Gh(a)) => git_cmd::gh(a),
        Some(Cmd::Honey { cmd }) => honey_cmd::run(cli.json, cmd),
        Some(Cmd::Aws { cmd }) => aws_cmd::run(&ro, cmd),
        Some(Cmd::Db { cmd }) => db_cmd::run(cli.json, cmd),
        Some(Cmd::Token { cmd }) => http_cmd::token(cli.json, cmd),
        Some(Cmd::Http { cmd }) => http_cmd::http(&ro, cmd),
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
