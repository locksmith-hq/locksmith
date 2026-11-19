//! Helpers shared by the integration tests. Each test file declares `mod common;` and builds
//! its own binary (some install a global tracing subscriber), so not every binary uses every
//! helper.
#![allow(dead_code)]

use std::io;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use ls_control_plane::app::{self, AppState};
use ls_control_plane::db::{Database, PoolSettings, connect_options};
use ls_control_plane::migrate;
use ls_control_plane::readiness::ReadyFlag;
use tracing_subscriber::fmt::MakeWriter;

/// The shared throwaway `postgres:18` container (`ls-pg-test`), migrated here with the control
/// plane's own embedded migrator.
pub struct Pg(ls_pg_test::Pg);

impl Deref for Pg {
    type Target = ls_pg_test::Pg;
    fn deref(&self) -> &ls_pg_test::Pg {
        &self.0
    }
}

impl Pg {
    /// Start the container and wait until TCP logins work. Not migrated.
    pub async fn start() -> Self {
        Self(ls_pg_test::Pg::start().await)
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
        Database::connect_lazy(self.app(), pool)
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
