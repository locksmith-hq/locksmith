//! The tenant transaction helper (design decision 5, A0-5): the only way request code reaches
//! Postgres.
//!
//! The app-role pool is private to this module. Callers hand [`Database::with_org`] a closure;
//! it runs `BEGIN`, `set_config('app.org_id', $1, true)`, the closure, then `COMMIT` (or
//! `ROLLBACK` on error), inside one `db.transaction` tracing span that is a child of the
//! caller's span. The setting is transaction-local, so it resets at the end of the transaction
//! and cannot leak to the next checkout of a pooled connection. The `ls-tenant-lint` lint keeps
//! session-level settings out of `services/`.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use sqlx_postgres::{PgConnectOptions, PgConnection, PgPool, PgPoolOptions};
use tracing::Instrument;
use uuid::Uuid;

use crate::readiness::Readiness;

/// The query API request code uses inside a transaction (from `sqlx-core` and `sqlx-postgres`;
/// the `sqlx` facade is not used, see Cargo.toml). Deliberately no pool or connect types.
pub mod sql {
    pub use sqlx_core::error::{Error, Result};
    pub use sqlx_core::from_row::FromRow;
    pub use sqlx_core::query::query;
    pub use sqlx_core::query_as::query_as;
    pub use sqlx_core::query_scalar::{QueryScalar, query_scalar};
    pub use sqlx_core::row::Row;
    pub use sqlx_postgres::{PgArguments, PgConnection, PgRow, Postgres};
}

/// The future a transaction closure returns. It borrows the connection for `'c`.
pub type TxFuture<'c, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'c>>;

/// A database URL that does not parse. Never carries the URL (it holds a password).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidDatabaseUrl;

impl fmt::Display for InvalidDatabaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid database URL")
    }
}

impl std::error::Error for InvalidDatabaseUrl {}

/// Parse a secret database URL into connect options without echoing it on failure.
pub fn connect_options(url: &SecretString) -> Result<PgConnectOptions, InvalidDatabaseUrl> {
    url.expose_secret().parse().map_err(|_| InvalidDatabaseUrl)
}

/// App-pool sizing.
#[derive(Debug, Clone, Copy)]
pub struct PoolSettings {
    pub max_connections: u32,
    pub acquire_timeout: Duration,
}

impl Default for PoolSettings {
    fn default() -> Self {
        Self {
            max_connections: 10,
            acquire_timeout: Duration::from_secs(3),
        }
    }
}

/// The app-role (`locksmith_app`) connection pool, reachable only through tenant transactions.
/// No `Debug`: the pool's connect options hold the password.
#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// Build the pool without connecting; connections open on first use, so the service can
    /// start (and report not ready) while Postgres is still down.
    pub fn connect_lazy(options: PgConnectOptions, settings: PoolSettings) -> Self {
        let pool = PgPoolOptions::new()
            .max_connections(settings.max_connections)
            .acquire_timeout(settings.acquire_timeout)
            .connect_lazy_with(options);
        Self { pool }
    }

    /// Run `f` in one transaction bound to `org_id`. Row-level security then limits every
    /// statement to that org's rows. Commits when `f` returns `Ok`, rolls back otherwise.
    ///
    /// ```ignore
    /// let names: Vec<String> = db
    ///     .with_org(org.org_id, |c| Box::pin(async move {
    ///         sql::query_scalar("SELECT name FROM projects ORDER BY id").fetch_all(c).await
    ///     }))
    ///     .await?;
    /// ```
    pub async fn with_org<T, E, F>(&self, org_id: Uuid, f: F) -> Result<T, E>
    where
        T: Send,
        E: From<sql::Error> + Send,
        F: for<'c> FnOnce(&'c mut PgConnection) -> TxFuture<'c, T, E> + Send,
    {
        let span = tracing::info_span!(
            "db.transaction",
            otel.kind = "client",
            db.system.name = "postgresql",
            org_id = %org_id,
            error = tracing::field::Empty,
        );
        self.transaction(Some(org_id), f).instrument(span).await
    }

    /// Run `f` in a transaction with no org bound. Under `FORCE ROW LEVEL SECURITY` every
    /// tenant table then reads as empty and rejects writes, so this cannot reach tenant data.
    /// It exists for probes and for tests that check exactly that.
    pub async fn without_org<T, E, F>(&self, f: F) -> Result<T, E>
    where
        T: Send,
        E: From<sql::Error> + Send,
        F: for<'c> FnOnce(&'c mut PgConnection) -> TxFuture<'c, T, E> + Send,
    {
        let span = tracing::info_span!(
            "db.transaction",
            otel.kind = "client",
            db.system.name = "postgresql",
            error = tracing::field::Empty,
        );
        self.transaction(None, f).instrument(span).await
    }

    /// Run `f` in one transaction for a sign-in (T1 design decision 6): no org is bound yet, but
    /// the verified identity is, so the `users` policy shows the rows for exactly that
    /// `(issuer, subject)` and, when `verified_email` is given, rows with that same verified
    /// email (identity linking). `f` binds an org itself with [`bind_org`] once it knows which.
    /// Everything is transaction-local, like [`Self::with_org`].
    pub async fn with_login<T, E, F>(
        &self,
        issuer: &str,
        subject: &str,
        verified_email: Option<&str>,
        f: F,
    ) -> Result<T, E>
    where
        T: Send,
        E: From<sql::Error> + Send,
        F: for<'c> FnOnce(&'c mut PgConnection) -> TxFuture<'c, T, E> + Send,
    {
        let span = tracing::info_span!(
            "db.transaction",
            otel.kind = "client",
            db.system.name = "postgresql",
            error = tracing::field::Empty,
        );
        let login = Login {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
            email: verified_email.map(str::to_lowercase),
        };
        self.run(None, Some(login), f).instrument(span).await
    }

    async fn transaction<T, E, F>(&self, org_id: Option<Uuid>, f: F) -> Result<T, E>
    where
        E: From<sql::Error>,
        F: for<'c> FnOnce(&'c mut PgConnection) -> TxFuture<'c, T, E>,
    {
        self.run(org_id, None, f).await
    }

    async fn run<T, E, F>(&self, org_id: Option<Uuid>, login: Option<Login>, f: F) -> Result<T, E>
    where
        E: From<sql::Error>,
        F: for<'c> FnOnce(&'c mut PgConnection) -> TxFuture<'c, T, E>,
    {
        let mut tx = self.pool.begin().await.inspect_err(|_| mark_error())?;
        if let Some(org_id) = org_id {
            bind_org(&mut tx, org_id)
                .await
                .inspect_err(|_| mark_error())?;
        }
        if let Some(login) = login {
            sql::query(
                "SELECT set_config('app.login_issuer', $1, true), \
                        set_config('app.login_subject', $2, true), \
                        set_config('app.login_email', $3, true)",
            )
            .bind(login.issuer)
            .bind(login.subject)
            .bind(login.email.unwrap_or_default())
            .execute(&mut *tx)
            .await
            .inspect_err(|_| mark_error())?;
        }
        match f(&mut tx).await {
            Ok(value) => {
                tx.commit().await.inspect_err(|_| mark_error())?;
                Ok(value)
            }
            Err(e) => {
                mark_error();
                // A failed rollback leaves the connection to be reset by the pool.
                let _ = tx.rollback().await;
                Err(e)
            }
        }
    }

    /// Start a background task that checks every `every` whether Postgres answers, and feeds
    /// the result into `readiness`. The task ends when the returned handle is aborted.
    pub fn spawn_readiness_probe(
        &self,
        readiness: Arc<DbReadiness>,
        every: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let pool = self.pool.clone();
        tokio::spawn(async move {
            loop {
                let ok = tokio::time::timeout(PROBE_TIMEOUT, sql::query("SELECT 1").execute(&pool))
                    .await
                    .is_ok_and(|r| r.is_ok());
                readiness.reachable.store(ok, Ordering::Release);
                tokio::time::sleep(every).await;
            }
        })
    }

    /// Close the pool, waiting for checked-out connections to return.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// The identity a sign-in transaction acts for; see [`Database::with_login`].
struct Login {
    issuer: String,
    subject: String,
    email: Option<String>,
}

/// Bind `org_id` as the tenant for the rest of the current transaction (transaction-local, so it
/// resets at commit or rollback). [`Database::with_org`] does this first; a sign-in transaction
/// calls it once the personal org is known.
pub async fn bind_org(conn: &mut PgConnection, org_id: Uuid) -> sql::Result<()> {
    sql::query("SELECT set_config('app.org_id', $1, true)")
        .bind(org_id.to_string())
        .execute(conn)
        .await
        .map(|_| ())
}

fn mark_error() {
    tracing::Span::current().record("error", true);
}

/// How long one readiness probe may take before Postgres counts as unreachable.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// How often the readiness probe runs. With [`PROBE_TIMEOUT`], an outage shows within 5 s.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// Readiness backed by the database: ready once migrations are applied and while the last
/// probe reached Postgres.
#[derive(Debug, Default)]
pub struct DbReadiness {
    migrated: AtomicBool,
    reachable: AtomicBool,
}

impl DbReadiness {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that every migration has been applied.
    pub fn set_migrated(&self) {
        self.migrated.store(true, Ordering::Release);
    }

    pub fn is_migrated(&self) -> bool {
        self.migrated.load(Ordering::Acquire)
    }

    pub fn is_reachable(&self) -> bool {
        self.reachable.load(Ordering::Acquire)
    }
}

impl Readiness for DbReadiness {
    fn is_ready(&self) -> bool {
        self.is_migrated() && self.is_reachable()
    }
}
