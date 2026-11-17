//! Task 2.2: RLS tenancy on Postgres 18 with sqlx (spec: data-foundations).
//! Requires `just up`. Each test migrates its own fresh database, then drops it.
//! Dev-only credentials come from infra/compose/.env.example (override with A0_PG_URL).

use a0_spikes::db::{
    self as sqlx, AssertSqlSafe, Connection, PgConnectOptions, PgConnection, PgPool, PgPoolOptions,
    Row,
};
use a0_spikes::header::{self, Binding, KeyId, Keyring, Purpose};
use a0_spikes::tenant::begin_for_org;
use ls_crypto::{SecretBytes, SecretKey32};
use uuid::Uuid;

const APP_ROLE: &str = "a0_app";
const APP_PASSWORD: &str = "a0-app-dev-only";

fn admin_options() -> PgConnectOptions {
    let url = std::env::var("A0_PG_URL").unwrap_or_else(|_| {
        "postgres://locksmith:locksmith-dev-only@127.0.0.1:5432/locksmith".into()
    });
    url.parse().expect("A0_PG_URL is a Postgres URL")
}

struct Db {
    name: String,
    app: PgPool,
    /// Keep the database after the test (for `just leak-scan`).
    keep: bool,
}

async fn drop_database(name: &str) {
    let mut admin = admin_conn().await;
    sqlx::raw_sql(AssertSqlSafe(format!(
        "DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"
    )))
    .execute(&mut admin)
    .await
    .unwrap();
}

/// Drops the database even when the test panics, on a separate thread and runtime.
impl Drop for Db {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        let name = std::mem::take(&mut self.name);
        let _ = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(drop_database(&name));
        })
        .join();
    }
}

async fn admin_conn() -> PgConnection {
    PgConnection::connect_with(&admin_options())
        .await
        .expect("connect to local Postgres as the bootstrap user (is `just up` running?)")
}

/// Create (or recreate) `name`, run the migrations as the bootstrap user (DDL runs under
/// `SET LOCAL ROLE a0_owner`), and return a pool of size 1 logged in as the app role.
async fn create_db(name: &str) -> Db {
    let mut admin = admin_conn().await;
    sqlx::raw_sql(AssertSqlSafe(format!(
        "DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"
    )))
    .execute(&mut admin)
    .await
    .unwrap();
    sqlx::raw_sql(AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
        .execute(&mut admin)
        .await
        .unwrap();
    admin.close().await.unwrap();

    let mut migrator_conn = PgConnection::connect_with(&admin_options().database(name))
        .await
        .unwrap();
    a0_spikes::migrator()
        .await
        .expect("load migrations")
        .run(&mut migrator_conn)
        .await
        .expect("migrations apply");
    migrator_conn.close().await.unwrap();

    let app = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            admin_options()
                .database(name)
                .username(APP_ROLE)
                .password(APP_PASSWORD),
        )
        .await
        .expect("connect as the app role");
    Db {
        name: name.to_owned(),
        app,
        keep: false,
    }
}

async fn fresh_db() -> Db {
    create_db(&format!("a0_spike_{}", Uuid::new_v4().simple())).await
}

impl Db {
    /// Close the pool; `Drop` then removes the database.
    async fn drop_db(self) {
        self.app.close().await;
    }

    async fn insert(&self, ctx_org: Uuid, row_org: Uuid, name: &str) -> sqlx::Result<Uuid> {
        let mut tx = begin_for_org(&self.app, ctx_org).await?;
        let id: Uuid =
            sqlx::query_scalar("INSERT INTO secrets (org_id, name) VALUES ($1, $2) RETURNING id")
                .bind(row_org)
                .bind(name)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(id)
    }
}

#[tokio::test]
async fn roles_table_and_policy_are_as_designed() {
    let db = fresh_db().await;
    let mut admin = PgConnection::connect_with(&admin_options().database(&db.name))
        .await
        .unwrap();
    let row = sqlx::query(
        "SELECT pg_get_userbyid(c.relowner) AS owner, c.relrowsecurity, c.relforcerowsecurity
         FROM pg_class c WHERE c.oid = 'public.secrets'::regclass",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("owner"), "a0_owner");
    assert!(row.get::<bool, _>("relrowsecurity"));
    assert!(row.get::<bool, _>("relforcerowsecurity"));

    let (sup, bypass): (bool, bool) =
        sqlx::query_as("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1")
            .bind(APP_ROLE)
            .fetch_one(&mut admin)
            .await
            .unwrap();
    assert!(
        !sup && !bypass,
        "app role must be neither superuser nor BYPASSRLS"
    );

    let policies: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_policies WHERE tablename = 'secrets' AND policyname = 'tenant_isolation'",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert_eq!(policies, 1);

    let server: String = sqlx::query_scalar("SHOW server_version")
        .fetch_one(&mut admin)
        .await
        .unwrap();
    assert!(
        server.starts_with("18."),
        "expected Postgres 18, got {server}"
    );
    admin.close().await.unwrap();
    db.drop_db().await;
}

/// Scenario: cross-tenant read returns nothing.
#[tokio::test]
async fn cross_tenant_read_returns_nothing() {
    let db = fresh_db().await;
    let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
    db.insert(a, a, "a-1").await.unwrap();
    db.insert(b, b, "b-1").await.unwrap();
    db.insert(b, b, "b-2").await.unwrap();

    let mut tx = begin_for_org(&db.app, a).await.unwrap();
    let b_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets WHERE org_id = $1")
        .bind(b)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(b_rows, 0, "org A must not see org B's rows");
    let visible: Vec<Uuid> = sqlx::query_scalar("SELECT org_id FROM secrets")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert_eq!(visible, vec![a]);
    // Updates and deletes across tenants touch nothing either.
    let touched = sqlx::query("UPDATE secrets SET name = 'x' WHERE org_id = $1")
        .bind(b)
        .execute(&mut *tx)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(touched, 0);
    tx.commit().await.unwrap();
    db.drop_db().await;
}

/// Scenario: cross-tenant insert fails with an RLS violation.
#[tokio::test]
async fn cross_tenant_insert_fails() {
    let db = fresh_db().await;
    let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
    let err = db
        .insert(a, b, "planted")
        .await
        .expect_err("insert into org B as org A");
    let db_err = err.as_database_error().expect("database error");
    assert_eq!(db_err.code().as_deref(), Some("42501"));
    assert!(
        db_err.message().contains("row-level security"),
        "unexpected error: {}",
        db_err.message()
    );

    // Updating a row's org_id to another tenant is rejected by WITH CHECK as well.
    db.insert(a, a, "mine").await.unwrap();
    let mut tx = begin_for_org(&db.app, a).await.unwrap();
    let err = sqlx::query("UPDATE secrets SET org_id = $1")
        .bind(b)
        .execute(&mut *tx)
        .await
        .expect_err("move row to org B");
    assert_eq!(
        err.as_database_error().unwrap().code().as_deref(),
        Some("42501")
    );
    drop(tx);
    db.drop_db().await;
}

/// Scenario: tenant context does not leak across pooled connections (pool size 1).
#[tokio::test]
async fn tenant_context_does_not_leak_across_pooled_connections() {
    let db = fresh_db().await;
    let a = Uuid::now_v7();

    let mut tx = begin_for_org(&db.app, a).await.unwrap();
    let pid_1: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO secrets (org_id, name) VALUES ($1, 'a-1')")
        .bind(a)
        .execute(&mut *tx)
        .await
        .unwrap();
    let seen: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(seen, 1);
    tx.commit().await.unwrap();

    // Same physical connection (pool of one), no org set.
    let mut conn = db.app.acquire().await.unwrap();
    let pid_2: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(pid_1, pid_2, "pool of one must reuse the connection");
    let setting: Option<String> = sqlx::query_scalar("SELECT current_setting('app.org_id', true)")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    // After COMMIT the placeholder GUC survives with '' (hence NULLIF in the policy).
    assert_eq!(setting.as_deref(), Some(""));
    let leaked: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(leaked, 0, "tenant context leaked to the next checkout");
    let err = sqlx::query("INSERT INTO secrets (org_id, name) VALUES ($1, 'no-ctx')")
        .bind(a)
        .execute(&mut *conn)
        .await
        .expect_err("insert without tenant context");
    assert_eq!(
        err.as_database_error().unwrap().code().as_deref(),
        Some("42501")
    );

    // Negative control: a session-level set_config (banned by the 2.3 lint) does leak, which
    // shows this test can see a leak.
    sqlx::query("SELECT set_config('app.org_id', $1, false)")
        .bind(a.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    let mut conn = db.app.acquire().await.unwrap();
    let leaked: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(leaked, 1, "control: session-level setting should leak");
    drop(conn);
    db.drop_db().await;
}

/// Spec: time-ordered UUID primary keys.
#[tokio::test]
async fn uuidv7_ids_sort_by_creation_time() {
    let db = fresh_db().await;
    let a = Uuid::now_v7();
    let first = db.insert(a, a, "first").await.unwrap();
    let second = db.insert(a, a, "second").await.unwrap();
    assert_eq!(first.get_version_num(), 7);
    assert!(second > first, "second id must sort after the first");

    // App-generated v7 ids are accepted and order by time with server ones. Server ids carry
    // sub-millisecond precision and app ids only milliseconds, so step past the millisecond.
    std::thread::sleep(std::time::Duration::from_millis(2));
    let app_id = Uuid::now_v7();
    let mut tx = begin_for_org(&db.app, a).await.unwrap();
    sqlx::query("INSERT INTO secrets (id, org_id, name) VALUES ($1, $2, 'app')")
        .bind(app_id)
        .bind(a)
        .execute(&mut *tx)
        .await
        .unwrap();
    let ordered: Vec<String> = sqlx::query_scalar("SELECT name FROM secrets ORDER BY id")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(ordered, ["first", "second", "app"]);
    db.drop_db().await;
}

/// First canary from the leak-scan canary file, if any (`just canary new`).
fn canary() -> Option<SecretBytes> {
    let path = std::env::var("LOCKSMITH_CANARIES").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../infra/compose/.canaries").into()
    });
    let text = SecretBytes::new(std::fs::read(path).ok()?);
    let text = std::str::from_utf8(text.expose()).ok()?;
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .find_map(|l| l.split_whitespace().last())
        .map(|v| SecretBytes::new(v.as_bytes().to_vec()))
}

/// Stores a sealed canary in a database that is kept after the test, so `just leak-scan`
/// can confirm only ciphertext reaches Postgres. The blob opens again for its own org only.
#[tokio::test]
async fn sealed_value_at_rest_is_ciphertext_and_bound_to_its_org() {
    let mut db = create_db("a0_spikes_evidence").await;
    db.keep = true;
    let plaintext =
        canary().unwrap_or_else(|| SecretBytes::new(Uuid::new_v4().as_bytes().to_vec()));
    let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
    let key_id = KeyId(*Uuid::now_v7().as_bytes());
    let key = SecretKey32::random().unwrap();

    let mut tx = begin_for_org(&db.app, a).await.unwrap();
    let id: Uuid =
        sqlx::query_scalar("INSERT INTO secrets (org_id, name) VALUES ($1, 'canary') RETURNING id")
            .bind(a)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    let binding = Binding {
        org_id: *a.as_bytes(),
        secret_id: *id.as_bytes(),
        version: 1,
        purpose: Purpose::SecretPayload,
    };
    let blob = header::seal(key_id, &key, &binding, plaintext.expose()).unwrap();
    sqlx::query("UPDATE secrets SET ciphertext = $1 WHERE id = $2")
        .bind(&blob)
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut keys = Keyring::new();
    keys.insert(key_id, key);

    let mut tx = begin_for_org(&db.app, a).await.unwrap();
    let stored: Vec<u8> = sqlx::query_scalar("SELECT ciphertext FROM secrets WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let opened = header::open(&keys, &binding, &stored).expect("opens for its own org");
    assert!(
        opened.expose() == plaintext.expose(),
        "stored value does not round trip"
    );
    let as_b = Binding {
        org_id: *b.as_bytes(),
        ..binding
    };
    assert_eq!(
        header::open(&keys, &as_b, &stored).err(),
        Some(header::HeaderError::Integrity)
    );

    // Org B cannot even read the row.
    let mut tx = begin_for_org(&db.app, b).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(n, 0);
    tx.commit().await.unwrap();
    db.app.close().await; // keep the database for `just leak-scan`
}
