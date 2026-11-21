//! Schema migrations, run at startup through the owner pool (design decision 4, A0-4).
//!
//! The owner pool (`DATABASE_OWNER_URL`) exists only for the duration of [`run`] and is closed
//! before it returns; the request path never sees it. Migrations are embedded in the binary.
//! sqlx's migrator takes a Postgres advisory lock, so replicas starting together do not race.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use sqlx_core::migrate::{MigrateError, Migration, MigrationType, Migrator};
use sqlx_core::sql_str::SqlSafeStr;
use sqlx_postgres::{PgConnectOptions, PgPoolOptions};

use crate::db::DbReadiness;

/// The embedded migrations, in `migrations/`. A test checks this list matches the directory.
const MIGRATIONS: &[(i64, &str, &str)] = &[
    (1, "roles", include_str!("../migrations/0001_roles.sql")),
    (
        2,
        "tenancy schema",
        include_str!("../migrations/0002_tenancy_schema.sql"),
    ),
    (
        3,
        "secret versions",
        include_str!("../migrations/0003_secret_versions.sql"),
    ),
    (
        4,
        "gateway audit",
        include_str!("../migrations/0004_gateway_audit.sql"),
    ),
    (
        5,
        "gateway audit version and caller",
        include_str!("../migrations/0005_gateway_audit_version_caller.sql"),
    ),
    (6, "agents", include_str!("../migrations/0006_agents.sql")),
    (
        7,
        "gateway audit agent id",
        include_str!("../migrations/0007_gateway_audit_agent.sql"),
    ),
    (
        8,
        "audit ledger",
        include_str!("../migrations/0008_audit_ledger.sql"),
    ),
    (
        9,
        "gateway audit read only",
        include_str!("../migrations/0009_gateway_audit_read_only.sql"),
    ),
    (
        10,
        "audit checkpoint jobs",
        include_str!("../migrations/0010_audit_checkpoint_jobs.sql"),
    ),
    (11, "users", include_str!("../migrations/0011_users.sql")),
    (12, "mcp", include_str!("../migrations/0012_mcp.sql")),
    (
        13,
        "grant delegate",
        include_str!("../migrations/0013_grant_delegate.sql"),
    ),
];

/// The migrator over the embedded migrations.
pub fn migrator() -> Migrator {
    Migrator::with_migrations(
        MIGRATIONS
            .iter()
            .map(|&(version, description, sql)| {
                Migration::new(
                    version,
                    Cow::Borrowed(description),
                    MigrationType::Simple,
                    sql.into_sql_str(),
                    false,
                )
            })
            .collect(),
    )
}

/// Apply every pending migration as the owner role, then close the owner pool.
pub async fn run(owner: PgConnectOptions) -> Result<(), MigrateError> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(owner)
        .await?;
    let result = migrator().run(&pool).await;
    pool.close().await;
    result
}

/// Retry [`run`] with backoff (1 s doubling to 30 s) until it succeeds, then mark `readiness`
/// migrated. Errors are logged without connection details.
pub async fn run_until_done(owner: PgConnectOptions, readiness: Arc<DbReadiness>) {
    let mut delay = Duration::from_secs(1);
    loop {
        match run(owner.clone()).await {
            Ok(()) => {
                readiness.set_migrated();
                tracing::info!("database migrations applied; owner pool closed");
                return;
            }
            Err(e) => {
                tracing::warn!(error = %e, retry_in_s = delay.as_secs(), "database migrations failed");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_migrations_match_the_directory() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut on_disk: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".sql"))
            .collect();
        on_disk.sort();
        assert_eq!(
            on_disk.len(),
            MIGRATIONS.len(),
            "embed every migration file"
        );
        for (name, &(version, _, sql)) in on_disk.iter().zip(MIGRATIONS) {
            assert!(name.starts_with(&format!("{version:04}_")), "{name}");
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("migrations")
                .join(name);
            assert_eq!(std::fs::read_to_string(path).unwrap(), sql, "{name}");
        }
    }

    /// No plaintext column anywhere. Only `secret_versions` (S2, decision 6) may hold
    /// ciphertext, and only as `ciphertext` / `wrapped_dek` bytea.
    #[test]
    fn no_value_column_anywhere() {
        for &(version, _, sql) in MIGRATIONS {
            let code: String = sql
                .lines()
                .filter(|l| !l.trim_start().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n")
                .to_lowercase();
            for banned in ["value ", "plaintext"] {
                assert!(!code.contains(banned), "migration defines `{banned}`");
            }
            if version != 3 {
                assert!(!code.contains("ciphertext"), "migration {version}");
            }
        }
    }
}
