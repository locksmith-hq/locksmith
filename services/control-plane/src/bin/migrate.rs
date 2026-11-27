//! `locksmith-migrate`: apply the embedded schema migrations once and exit.
//!
//! The Rust migrator stays the only thing that applies migrations (B1 design: `apps/api` only reads
//! the schema). This binary lets tooling, such as `just api-types`, migrate a throwaway database
//! without starting the API. It logs no connection details.

use std::process::ExitCode;

use ls_control_plane::{config, db, migrate};
use secrecy::SecretString;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let Ok(url) = std::env::var(config::ENV_DATABASE_OWNER_URL) else {
        eprintln!(
            "environment variable {} is not set",
            config::ENV_DATABASE_OWNER_URL
        );
        return ExitCode::FAILURE;
    };
    let Ok(options) = db::connect_options(&SecretString::from(url)) else {
        eprintln!(
            "environment variable {} has an invalid value",
            config::ENV_DATABASE_OWNER_URL
        );
        return ExitCode::FAILURE;
    };
    match migrate::run(options).await {
        Ok(()) => {
            println!("migrations applied");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("migrations failed: {e}");
            ExitCode::FAILURE
        }
    }
}
