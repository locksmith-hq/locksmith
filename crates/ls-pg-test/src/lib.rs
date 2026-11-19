//! Test support: one throwaway `postgres:18` container per test (testcontainers; needs a Docker
//! daemon), with the dev role passwords from `services/control-plane/migrations/0001_roles.sql`
//! and `0008_audit_ledger.sql`.
//!
//! Shared by the control-plane, gateway and `ls-audit` integration tests so the container setup
//! exists once. Only ever a dev-dependency.

use std::path::{Path, PathBuf};
use std::time::Duration;

use sqlx_core::connection::Connection;
use sqlx_core::migrate::{MigrateError, Migrator};
use sqlx_postgres::{PgConnectOptions, PgConnection, PgPoolOptions};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

// Test-only values; the container is local and discarded after the test.
pub const BOOTSTRAP_USER: &str = "postgres";
pub const BOOTSTRAP_PASSWORD: &str = "bootstrap-test-only";
// Dev-only role passwords from the control plane's migrations (listed in
// infra/compose/.env.example).
pub const OWNER_PASSWORD: &str = "locksmith-owner-dev-only";
pub const APP_PASSWORD: &str = "locksmith-app-dev-only";
pub const VERIFIER_PASSWORD: &str = "locksmith-audit-verifier-dev-only";

/// The control plane's migration directory (the schema every service shares).
pub fn control_plane_migrations() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../services/control-plane/migrations")
}

/// A throwaway `postgres:18` container.
pub struct Pg {
    pub container: ContainerAsync<GenericImage>,
    pub port: u16,
}

impl Pg {
    /// Start the container and wait until TCP logins work. Not migrated.
    pub async fn start() -> Self {
        let container = GenericImage::new("postgres", "18")
            .with_exposed_port(5432.tcp())
            .with_wait_for(WaitFor::message_on_stderr(
                "database system is ready to accept connections",
            ))
            .with_env_var("POSTGRES_PASSWORD", BOOTSTRAP_PASSWORD)
            .with_startup_timeout(Duration::from_secs(120))
            .start()
            .await
            .expect("start postgres:18 (is Docker running?)");
        let port = container.get_host_port_ipv4(5432.tcp()).await.unwrap();
        let pg = Self { container, port };
        // The image restarts the server once after init; wait until TCP logins work.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            match PgConnection::connect_with(&pg.bootstrap()).await {
                Ok(c) => {
                    c.close().await.unwrap();
                    break;
                }
                Err(e) if tokio::time::Instant::now() > deadline => panic!("postgres: {e}"),
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
        pg
    }

    /// Start a container and apply the control plane's migrations from their directory as the
    /// bootstrap superuser, as on a first `just up`. The control plane's own tests use its
    /// embedded migrator instead; a unit test there keeps the two identical.
    pub async fn migrated() -> Self {
        let pg = Self::start().await;
        pg.migrate_dir(&control_plane_migrations())
            .await
            .expect("migrations apply");
        pg
    }

    /// Apply the migrations in `dir` as the bootstrap superuser.
    pub async fn migrate_dir(&self, dir: &Path) -> Result<(), MigrateError> {
        let migrator = Migrator::new(dir.to_path_buf()).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(self.bootstrap())
            .await?;
        let result = migrator.run(&pool).await;
        pool.close().await;
        result
    }

    pub fn options(&self, user: &str, password: &str) -> PgConnectOptions {
        PgConnectOptions::new()
            .host("127.0.0.1")
            .port(self.port)
            .database("postgres")
            .username(user)
            .password(password)
    }

    pub fn bootstrap(&self) -> PgConnectOptions {
        self.options(BOOTSTRAP_USER, BOOTSTRAP_PASSWORD)
    }

    /// `locksmith_owner`: owns the schema (and can rewrite rows, which the tamper tests need).
    pub fn owner(&self) -> PgConnectOptions {
        self.options("locksmith_owner", OWNER_PASSWORD)
    }

    /// `locksmith_app`: the request role (RLS applies).
    pub fn app(&self) -> PgConnectOptions {
        self.options("locksmith_app", APP_PASSWORD)
    }

    /// `audit_verifier`: SELECT plus BYPASSRLS, used only by the audit CLI.
    pub fn verifier(&self) -> PgConnectOptions {
        self.options("audit_verifier", VERIFIER_PASSWORD)
    }

    /// A single connection as the bootstrap superuser.
    pub async fn admin(&self) -> PgConnection {
        PgConnection::connect_with(&self.bootstrap()).await.unwrap()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn migration_dir_exists() {
        let dir = super::control_plane_migrations();
        assert!(dir.join("0001_roles.sql").is_file(), "{}", dir.display());
    }
}
