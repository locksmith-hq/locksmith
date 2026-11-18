//! Postgres helpers for the live tests (`db.rs`, `export.rs`, `tamper.rs`).

use ls_audit::SignedCheckpoint;
use ls_audit::pg;
use ls_pg_test::{APP_PASSWORD, OWNER_PASSWORD, Pg, VERIFIER_PASSWORD, control_plane_migrations};
use sqlx_core::connection::Connection;
use sqlx_core::migrate::Migrator;
use sqlx_core::query::query;
use sqlx_core::sql_str::AssertSqlSafe;
use sqlx_postgres::{PgConnectOptions, PgConnection, PgPool, PgPoolOptions};
use uuid::Uuid;

pub async fn create_org(app: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    let mut tx = app.begin().await.unwrap();
    pg::bind_org(&mut tx, id).await.unwrap();
    query("INSERT INTO orgs (id, name) VALUES ($1, 'audit verify test')")
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    id
}

/// Store a signed checkpoint as the owner role (bound to the org: RLS is forced on owners too).
pub async fn store_checkpoint(owner: &PgConnectOptions, cp: &SignedCheckpoint) {
    let mut c = PgConnection::connect_with(owner).await.unwrap();
    let mut tx = c.begin().await.unwrap();
    pg::bind_org(&mut tx, cp.body.org_id).await.unwrap();
    query(
        "INSERT INTO audit_checkpoints (org_id, seq, hash, at, key_id, signature)
         VALUES ($1, $2, $3, 'epoch'::timestamptz + $4 * interval '1 microsecond', $5, $6)",
    )
    .bind(cp.body.org_id)
    .bind(i64::try_from(cp.body.seq).unwrap())
    .bind(&cp.body.hash[..])
    .bind(cp.body.at_micros)
    .bind(&cp.key_id)
    .bind(&cp.signature[..])
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// Run `stmt` as the database owner bound to `org` (the tamper path).
pub async fn owner_exec(owner: &PgConnectOptions, org: Uuid, stmt: &str) {
    let mut c = PgConnection::connect_with(owner).await.unwrap();
    let mut tx = c.begin().await.unwrap();
    pg::bind_org(&mut tx, org).await.unwrap();
    query(AssertSqlSafe(stmt.to_owned()))
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// Set to a superuser URL of a running Postgres (as `just audit-tamper-test` does with the
/// compose stack) to run [`Ledger`] tests in a scratch database there instead of a container.
pub const ADMIN_URL_ENV: &str = "LOCKSMITH_AUDIT_TEST_ADMIN_URL";

/// A migrated ledger database: a throwaway `postgres:18` container by default, or a scratch
/// database (`ls_audit_test_<uuid>`, dropped again when this is dropped) on the server named by
/// [`ADMIN_URL_ENV`]. The role passwords are the dev-only ones from the migrations.
pub struct Ledger {
    host: String,
    port: u16,
    database: String,
    _pg: Option<Pg>,
    /// The admin login of a scratch database, to drop it.
    scratch_admin: Option<PgConnectOptions>,
}

impl Ledger {
    pub async fn new() -> Self {
        let Ok(url) = std::env::var(ADMIN_URL_ENV) else {
            let pg = Pg::migrated().await;
            return Self {
                host: "127.0.0.1".into(),
                port: pg.port,
                database: "postgres".into(),
                _pg: Some(pg),
                scratch_admin: None,
            };
        };
        let admin: PgConnectOptions = url
            .parse()
            .unwrap_or_else(|_| panic!("{ADMIN_URL_ENV} does not parse"));
        let database = format!("ls_audit_test_{}", Uuid::now_v7().simple());
        let mut c = PgConnection::connect_with(&admin)
            .await
            .unwrap_or_else(|e| panic!("connect with {ADMIN_URL_ENV}: {e}"));
        query(AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(&mut c)
            .await
            .unwrap();
        c.close().await.unwrap();
        let on_scratch = admin.clone().database(&database);
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(on_scratch)
            .await
            .unwrap();
        Migrator::new(control_plane_migrations())
            .await
            .unwrap()
            .run(&pool)
            .await
            .expect("migrations apply");
        pool.close().await;
        Self {
            host: admin.get_host().to_owned(),
            port: admin.get_port(),
            database,
            _pg: None,
            scratch_admin: Some(admin),
        }
    }

    fn options(&self, user: &str, password: &str) -> PgConnectOptions {
        PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .database(&self.database)
            .username(user)
            .password(password)
    }

    /// `locksmith_owner`: can rewrite and delete ledger rows (the tamper path).
    pub fn owner(&self) -> PgConnectOptions {
        self.options("locksmith_owner", OWNER_PASSWORD)
    }

    /// `locksmith_app`: the appending role.
    pub fn app(&self) -> PgConnectOptions {
        self.options("locksmith_app", APP_PASSWORD)
    }

    /// The `audit_verifier` URL the binary logs in with.
    pub fn verifier_url(&self) -> String {
        format!(
            "postgres://audit_verifier:{VERIFIER_PASSWORD}@{}:{}/{}",
            self.host, self.port, self.database
        )
    }
}

impl Drop for Ledger {
    fn drop(&mut self) {
        let Some(admin) = self.scratch_admin.take() else {
            return;
        };
        let stmt = format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.database);
        // Drop runs inside the test's runtime, so the async cleanup gets its own thread.
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                if let Ok(mut c) = PgConnection::connect_with(&admin).await {
                    let _ = query(AssertSqlSafe(stmt)).execute(&mut c).await;
                    let _ = c.close().await;
                }
            });
        })
        .join();
    }
}
