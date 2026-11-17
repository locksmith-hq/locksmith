//! Helpers shared by the integration tests. Each test file declares `mod common;` and builds
//! its own binary (some install a global tracing subscriber), so not every binary uses every
//! helper.
#![allow(dead_code)]

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ls_control_plane::app::{self, AppState};
use ls_control_plane::db::{Database, PoolSettings, connect_options};
use ls_control_plane::migrate;
use ls_control_plane::readiness::ReadyFlag;
use sqlx_core::connection::Connection;
use sqlx_postgres::{PgConnectOptions, PgConnection};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tracing_subscriber::fmt::MakeWriter;

// Test-only values; the container is local and discarded after the test.
pub const BOOTSTRAP_USER: &str = "postgres";
pub const BOOTSTRAP_PASSWORD: &str = "bootstrap-test-only";
// Dev-only role passwords from migrations/0001_roles.sql (listed in infra/compose/.env.example).
pub const OWNER_PASSWORD: &str = "locksmith-owner-dev-only";
pub const APP_PASSWORD: &str = "locksmith-app-dev-only";

/// A throwaway `postgres:18` container (testcontainers; needs a Docker daemon).
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

    pub async fn admin(&self) -> PgConnection {
        PgConnection::connect_with(&self.bootstrap()).await.unwrap()
    }

    /// Fresh database: migrate as the bootstrap superuser, as on a first `just up`.
    pub async fn migrated() -> Self {
        let pg = Self::start().await;
        migrate::run(pg.bootstrap())
            .await
            .expect("migrations apply");
        pg
    }

    /// Lazy pool as the `locksmith_app` role.
    pub fn app_db(&self, pool: PoolSettings) -> Database {
        Database::connect_lazy(self.options("locksmith_app", APP_PASSWORD), pool)
    }
}

/// A lazy pool that never connects, for tests that touch no tenant data.
pub fn unreachable_db() -> Database {
    unreachable_db_with(PoolSettings::default())
}

pub fn unreachable_db_with(pool: PoolSettings) -> Database {
    let url = "postgres://nobody@127.0.0.1:1/none".to_owned().into();
    Database::connect_lazy(connect_options(&url).unwrap(), pool)
}

/// App with dev auth off and readiness on, backed by [`unreachable_db`].
pub fn unreachable_app() -> axum::Router {
    app::build(AppState::new(
        false,
        Arc::new(ReadyFlag::new(true)),
        unreachable_db(),
    ))
}

/// Console capture: a `MakeWriter` collecting everything the tracing subscriber prints.
#[derive(Clone, Default)]
pub struct Capture(pub Arc<Mutex<Vec<u8>>>);

pub struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Capture {
    pub fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = CaptureWriter;
    fn make_writer(&'a self) -> CaptureWriter {
        CaptureWriter(self.0.clone())
    }
}
