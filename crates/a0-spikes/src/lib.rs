//! A0 spikes: throwaway proofs for the data and cloud foundations.
//!
//! - [`tenant`]: per-transaction tenant context (`set_config('app.org_id', $1, true)`).
//! - [`tenant_lint`]: rejects session-level tenant settings in non-test Rust code
//!   (moved to the shared `ls-tenant-lint` crate; re-exported here).
//! - [`header`]: the versioned ciphertext header (design decision 7).
//!
//! The RLS tests in `tests/rls.rs` need the local stack (`just up`).

pub mod header;
pub mod tenant;
/// The tenant-context lint, now shared in `ls-tenant-lint` (re-exported for the A0 test).
pub use ls_tenant_lint as tenant_lint;

/// The sqlx API this crate uses, from `sqlx-core` + `sqlx-postgres` (see Cargo.toml for why
/// not the `sqlx` facade).
pub mod db {
    pub use sqlx_core::acquire::Acquire;
    pub use sqlx_core::connection::Connection;
    pub use sqlx_core::error::{Error, Result};
    pub use sqlx_core::migrate::Migrator;
    pub use sqlx_core::query::query;
    pub use sqlx_core::query_as::query_as;
    pub use sqlx_core::query_scalar::query_scalar;
    pub use sqlx_core::raw_sql::raw_sql;
    pub use sqlx_core::row::Row;
    pub use sqlx_core::sql_str::AssertSqlSafe;
    pub use sqlx_core::transaction::Transaction;
    pub use sqlx_postgres::{
        PgConnectOptions, PgConnection, PgPool, PgPoolOptions, PgTransaction, Postgres,
    };
}

/// Migrations: owner and app roles, then the RLS tenant table (`migrations/`).
pub async fn migrator() -> Result<db::Migrator, sqlx_core::migrate::MigrateError> {
    db::Migrator::new(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations"
    )))
    .await
}
