//! `locksmith-audit verify --db | --dir <export> [--json]` (S5 task 5.1) and
//! `locksmith-audit export --dir <export> [--json]` (task 5.2).
//!
//! Verify exit status: 0 when every org verifies, 1 when any org fails (stderr names each org
//! and its first broken `seq`), 2 when verify could not run (bad arguments, config, directory or
//! database). Export exit status: 0 when every org is exported, 1 when an org's ledger no longer
//! extends its export (stderr names the org and `seq`; the other orgs are still exported), 2
//! when export could not run.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgGroup, Args, Parser, Subcommand};
use locksmith_audit::export::{
    DEFAULT_BATCH_SIZE, ExportOutcome, export_db, export_json, export_text,
};
use locksmith_audit::sink::FileSink;
use locksmith_audit::{Outcome, load_keys, to_json, to_text, verify_db, verify_dir};

#[derive(Parser)]
#[command(
    name = "locksmith-audit",
    version,
    about = "Verify and export the Locksmith audit ledger (hash chain and signed checkpoints)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify every org's chain and checkpoints; exit 1 naming the org and first broken seq.
    Verify(VerifyArgs),
    /// Export each org's new events and checkpoints to a file sink directory (incremental:
    /// resumes from each org's cursor and never writes an event twice).
    Export(ExportArgs),
}

#[derive(Args)]
struct ExportArgs {
    /// The export directory (`<org_id>/events-<first_seq>.jsonl`, `checkpoints.jsonl`,
    /// `cursor.json`); created if missing.
    #[arg(long, value_name = "DIR")]
    dir: PathBuf,
    /// Postgres URL, logging in as `audit_verifier`. Never printed. Prefer the env var: a flag
    /// value shows in the process list.
    #[arg(
        long,
        env = "LOCKSMITH_AUDIT_DATABASE_URL",
        hide_env_values = true,
        value_name = "URL"
    )]
    database_url: String,
    /// Events per batch and per event file.
    #[arg(long, default_value_t = DEFAULT_BATCH_SIZE, value_name = "N")]
    batch_size: u64,
    /// Print one JSON object instead of text.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
#[command(group(ArgGroup::new("source").required(true).args(["db", "dir"])))]
struct VerifyArgs {
    /// Verify the database as the `audit_verifier` role and record each org's result in
    /// `audit_verify_runs`.
    #[arg(long)]
    db: bool,
    /// Verify an export directory offline (public keys only, no database or KMS).
    #[arg(long, value_name = "DIR")]
    dir: Option<PathBuf>,
    /// Postgres URL for `--db`, logging in as `audit_verifier`. Never printed.
    #[arg(
        long,
        env = "LOCKSMITH_AUDIT_DATABASE_URL",
        hide_env_values = true,
        value_name = "URL"
    )]
    database_url: Option<String>,
    /// Verifier config with the checkpoint public keys (written by `just up`).
    #[arg(
        long,
        env = "LOCKSMITH_AUDIT_VERIFIER_CONFIG",
        default_value = "infra/compose/.audit-verifier.json",
        value_name = "PATH"
    )]
    config: PathBuf,
    /// Print one JSON object instead of text.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let args = match Cli::parse().cmd {
        Cmd::Verify(args) => args,
        Cmd::Export(args) => return export(&args),
    };
    if args.db && args.database_url.is_none() {
        eprintln!("locksmith-audit: --db needs --database-url or LOCKSMITH_AUDIT_DATABASE_URL");
        return ExitCode::from(2);
    }
    let result = load_keys(&args.config).and_then(|keys| match &args.dir {
        Some(dir) => verify_dir(dir, &keys),
        None => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| locksmith_audit::Error::Db(format!("runtime: {e}")))
            .and_then(|rt| {
                rt.block_on(verify_db(
                    args.database_url.as_deref().unwrap_or_default(),
                    &keys,
                ))
            }),
    });
    match result {
        Ok(outcome) => report(&outcome, args.json),
        Err(e) => {
            eprintln!("locksmith-audit: {e}");
            ExitCode::from(2)
        }
    }
}

fn report(o: &Outcome, json: bool) -> ExitCode {
    if json {
        println!("{}", to_json(o));
    } else {
        print!("{}", to_text(o));
    }
    if o.ok() {
        return ExitCode::SUCCESS;
    }
    for r in o.failed() {
        match r.first_broken_seq() {
            Some(seq) => eprintln!(
                "locksmith-audit: org {}: first broken seq {seq}",
                r.report.org_id.hyphenated()
            ),
            None => eprintln!(
                "locksmith-audit: org {}: malformed export lines",
                r.report.org_id.hyphenated()
            ),
        }
    }
    ExitCode::from(1)
}

fn export(args: &ExportArgs) -> ExitCode {
    let result = FileSink::open(&args.dir).and_then(|mut sink| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| locksmith_audit::Error::Db(format!("runtime: {e}")))
            .and_then(|rt| rt.block_on(export_db(&args.database_url, &mut sink, args.batch_size)))
    });
    match result {
        Ok(outcome) => report_export(&outcome, args.json),
        Err(e) => {
            eprintln!("locksmith-audit: {e}");
            ExitCode::from(2)
        }
    }
}

fn report_export(o: &ExportOutcome, json: bool) -> ExitCode {
    if json {
        println!("{}", export_json(o));
    } else {
        print!("{}", export_text(o));
    }
    if o.ok() {
        return ExitCode::SUCCESS;
    }
    for r in o.orgs.iter() {
        if let Some(p) = r.refused {
            eprintln!(
                "locksmith-audit: org {}: the ledger does not extend the export at seq {} ({})",
                r.org_id.hyphenated(),
                p.seq(),
                p.as_str()
            );
        }
    }
    ExitCode::from(1)
}
