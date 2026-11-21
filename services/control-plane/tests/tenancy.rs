//! Tasks 2.1-2.4: schema, roles and tenant isolation on a throwaway `postgres:18` container
//! (testcontainers; needs a Docker daemon). Each test starts its own container.

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::Pg;
use ls_control_plane::app::{self, AppState};
use ls_control_plane::db::{Database, DbReadiness, PoolSettings, sql};
use ls_control_plane::migrate;
use ls_control_plane::readiness::Readiness;
use ls_pg_test::OWNER_PASSWORD;
use sqlx_core::connection::Connection;
use tower::ServiceExt;
use uuid::Uuid;

/// Design decision 7: generate a v7 id, bind it as the org, and insert through RLS.
async fn create_org(db: &Database, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    let name = name.to_owned();
    db.with_org(id, move |c| {
        Box::pin(async move {
            sql::query("INSERT INTO orgs (id, name) VALUES ($1, $2)")
                .bind(id)
                .bind(name)
                .execute(c)
                .await
                .map(|_| ())
        })
    })
    .await
    .expect("create org");
    id
}

async fn create_project(db: &Database, org: Uuid, name: &str) -> Uuid {
    let name = name.to_owned();
    db.with_org(org, move |c| {
        Box::pin(async move {
            sql::query_scalar::<_, Uuid>(
                "INSERT INTO projects (org_id, name) VALUES ($1, $2) RETURNING id",
            )
            .bind(org)
            .bind(name)
            .fetch_one(c)
            .await
        })
    })
    .await
    .expect("create project")
}

async fn create_env(db: &Database, org: Uuid, project: Uuid, name: &str) -> sql::Result<Uuid> {
    let name = name.to_owned();
    db.with_org(org, move |c| {
        Box::pin(async move {
            sql::query_scalar::<_, Uuid>(
                "INSERT INTO environments (org_id, project_id, name) VALUES ($1, $2, $3) RETURNING id",
            )
            .bind(org)
            .bind(project)
            .bind(name)
            .fetch_one(c)
            .await
        })
    })
    .await
}

fn sqlstate(e: &sql::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
}

/// Scenario: fresh database, then restart (applies nothing). Tables are owned by
/// locksmith_owner with FORCE RLS, and there is no value column anywhere.
#[tokio::test]
async fn migrations_apply_once_and_restart_as_owner_applies_nothing() {
    let pg = Pg::migrated().await;
    let mut admin = pg.admin().await;
    let applied: Vec<i64> =
        sql::query_scalar("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version")
            .fetch_all(&mut admin)
            .await
            .unwrap();
    assert_eq!(applied, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);

    // Restart: once the roles exist, locksmith_owner itself can run the (no-op) migrations.
    migrate::run(pg.options("locksmith_owner", OWNER_PASSWORD))
        .await
        .expect("restart applies nothing");
    let count: i64 = sql::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&mut admin)
        .await
        .unwrap();
    assert_eq!(count, 13);

    let tables: Vec<(String, String, bool, bool)> = sql::query_as(
        "SELECT c.relname::text, pg_get_userbyid(c.relowner)::text, c.relrowsecurity, c.relforcerowsecurity
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname <> '_sqlx_migrations'
         ORDER BY 1",
    )
    .fetch_all(&mut admin)
    .await
    .unwrap();
    let names: Vec<&str> = tables.iter().map(|t| t.0.as_str()).collect();
    assert_eq!(
        names,
        [
            "agent_grants",
            "agents",
            "audit_checkpoint_jobs",
            "audit_checkpoints",
            "audit_events",
            "audit_heads",
            "audit_verify_runs",
            "environments",
            "gateway_audit",
            "mcp_clients",
            "mcp_tool_settings",
            "orgs",
            "projects",
            "secret_versions",
            "secrets",
            "users",
            "workload_identities"
        ]
    );
    for (name, owner, rls, force) in tables.iter().cloned() {
        assert_eq!(owner, "locksmith_owner", "{name}");
        assert!(rls && force, "{name} must FORCE ROW LEVEL SECURITY");
    }
    let policies: i64 = sql::query_scalar(
        "SELECT count(*) FROM pg_policies WHERE schemaname = 'public' AND policyname = 'tenant_isolation'",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert_eq!(policies, 17);

    let value_like: Vec<String> = sql::query_scalar(
        "SELECT table_name || '.' || column_name FROM information_schema.columns
         WHERE table_schema = 'public'
           AND (column_name ILIKE '%value%' OR column_name ILIKE '%cipher%' OR column_name ILIKE '%plain%')",
    )
    .fetch_all(&mut admin)
    .await
    .unwrap();
    // Only S2's envelope ciphertext (design decision 6) is allowed; never a plaintext column.
    assert_eq!(
        value_like,
        ["secret_versions.ciphertext"],
        "value-like columns: {value_like:?}"
    );
    let version_cols: Vec<(String, String)> = sql::query_as(
        "SELECT column_name::text, data_type::text FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'secret_versions' ORDER BY ordinal_position",
    )
    .fetch_all(&mut admin)
    .await
    .unwrap();
    let version_cols: Vec<(&str, &str)> = version_cols
        .iter()
        .map(|(c, t)| (c.as_str(), t.as_str()))
        .collect();
    assert_eq!(
        version_cols,
        [
            ("org_id", "uuid"),
            ("secret_id", "uuid"),
            ("version", "integer"),
            ("ciphertext", "bytea"),
            ("wrapped_dek", "bytea"),
            ("key_id", "text"),
            ("created_at", "timestamp with time zone"),
        ]
    );

    let server: String = sql::query_scalar("SHOW server_version")
        .fetch_one(&mut admin)
        .await
        .unwrap();
    assert!(
        server.starts_with("18."),
        "expected Postgres 18, got {server}"
    );
    admin.close().await.unwrap();
}

/// Scenario: the app role cannot bypass isolation.
#[tokio::test]
async fn app_role_is_not_superuser_not_bypassrls_and_owns_nothing() {
    let pg = Pg::migrated().await;
    let mut admin = pg.admin().await;
    let (sup, bypass, createrole, createdb): (bool, bool, bool, bool) = sql::query_as(
        "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = 'locksmith_app'",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert!(!sup, "locksmith_app must not be superuser");
    assert!(!bypass, "locksmith_app must not have BYPASSRLS");
    assert!(!createrole && !createdb);

    let owned: Vec<String> = sql::query_scalar(
        "SELECT relname::text FROM pg_class WHERE relowner = 'locksmith_app'::regrole
         UNION ALL SELECT nspname::text FROM pg_namespace WHERE nspowner = 'locksmith_app'::regrole
         UNION ALL SELECT proname::text FROM pg_proc WHERE proowner = 'locksmith_app'::regrole",
    )
    .fetch_all(&mut admin)
    .await
    .unwrap();
    assert!(owned.is_empty(), "locksmith_app owns {owned:?}");

    // Not a member of any role that could lend it ownership or bypass.
    let member_of: i64 = sql::query_scalar(
        "SELECT count(*) FROM pg_auth_members WHERE member = 'locksmith_app'::regrole",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert_eq!(member_of, 0);
    admin.close().await.unwrap();

    // The request pool really logs in as locksmith_app.
    let db = pg.app_db(PoolSettings {
        max_connections: 1,
        ..PoolSettings::default()
    });
    let who: String = db
        .without_org(|c| {
            Box::pin(async move {
                sql::query_scalar("SELECT current_user::text")
                    .fetch_one(c)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(who, "locksmith_app");
    db.close().await;
}

/// Scenarios: cross-org read and cross-org list return nothing; cross-org writes touch nothing.
#[tokio::test]
async fn cross_org_read_and_list_return_nothing() {
    let pg = Pg::migrated().await;
    let db = pg.app_db(PoolSettings {
        max_connections: 4,
        ..PoolSettings::default()
    });
    let a = create_org(&db, "org-a").await;
    let b = create_org(&db, "org-b").await;
    let pa = create_project(&db, a, "shared-name").await;
    let pb = create_project(&db, b, "shared-name").await;
    create_env(&db, b, pb, "dev").await.unwrap();

    let (by_id, listed, orgs, envs, updated, deleted) = db
        .with_org(a, move |c| {
            Box::pin(async move {
                let by_id: Option<Uuid> =
                    sql::query_scalar("SELECT id FROM projects WHERE id = $1")
                        .bind(pb)
                        .fetch_optional(&mut *c)
                        .await?;
                let listed: Vec<Uuid> = sql::query_scalar("SELECT id FROM projects ORDER BY id")
                    .fetch_all(&mut *c)
                    .await?;
                let orgs: Vec<Uuid> = sql::query_scalar("SELECT id FROM orgs")
                    .fetch_all(&mut *c)
                    .await?;
                let envs: i64 = sql::query_scalar("SELECT count(*) FROM environments")
                    .fetch_one(&mut *c)
                    .await?;
                let updated = sql::query("UPDATE projects SET name = 'stolen' WHERE id = $1")
                    .bind(pb)
                    .execute(&mut *c)
                    .await?
                    .rows_affected();
                let deleted = sql::query("DELETE FROM projects WHERE id = $1")
                    .bind(pb)
                    .execute(&mut *c)
                    .await?
                    .rows_affected();
                Ok::<_, sql::Error>((by_id, listed, orgs, envs, updated, deleted))
            })
        })
        .await
        .unwrap();
    assert_eq!(by_id, None, "org A read org B's project");
    assert_eq!(listed, [pa], "org A's list must hold only its own project");
    assert_eq!(orgs, [a]);
    assert_eq!(envs, 0);
    assert_eq!((updated, deleted), (0, 0));

    // Org B's data is intact.
    let b_name: String = db
        .with_org(b, move |c| {
            Box::pin(async move {
                sql::query_scalar("SELECT name FROM projects WHERE id = $1")
                    .bind(pb)
                    .fetch_one(c)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(b_name, "shared-name");

    // A child under another org's parent fails the composite FK; a row carrying another org's
    // id fails RLS.
    let err = create_env(&db, a, pb, "planted")
        .await
        .expect_err("org A attached a row to org B's project");
    assert_eq!(sqlstate(&err).as_deref(), Some("23503"), "{err}");
    let err = db
        .with_org(a, move |c| {
            Box::pin(async move {
                sql::query("INSERT INTO projects (org_id, name) VALUES ($1, 'planted')")
                    .bind(b)
                    .execute(c)
                    .await
            })
        })
        .await
        .expect_err("insert with another org's org_id");
    assert_eq!(sqlstate(&err).as_deref(), Some("42501"));
    db.close().await;
}

/// Scenario: a child cannot point at another org's parent (composite FK on org_id), even
/// though foreign-key checks ignore RLS.
#[tokio::test]
async fn cross_org_parent_fk_fails() {
    let pg = Pg::migrated().await;
    let db = pg.app_db(PoolSettings {
        max_connections: 2,
        ..PoolSettings::default()
    });
    let a = create_org(&db, "org-a").await;
    let b = create_org(&db, "org-b").await;
    let pa = create_project(&db, a, "a-proj").await;
    let pb = create_project(&db, b, "b-proj").await;
    let ea = create_env(&db, a, pa, "dev").await.unwrap();
    let eb = create_env(&db, b, pb, "dev").await.unwrap();

    // Environment in org A under org B's project, reusing a name B already has there: the FK
    // fails (not a duplicate key, which would reveal that B has that name).
    let err = create_env(&db, a, pb, "dev")
        .await
        .expect_err("env under another org's project");
    assert_eq!(sqlstate(&err).as_deref(), Some("23503"), "{err}");

    // Secret in org A pointing at org B's environment, or at an environment of another project.
    let pa2 = create_project(&db, a, "a-proj-2").await;
    for (project, env) in [(pa, eb), (pb, eb), (pa2, ea)] {
        let err = db
            .with_org(a, move |c| {
                Box::pin(async move {
                    sql::query(
                        "INSERT INTO secrets (org_id, project_id, environment_id, name)
                         VALUES ($1, $2, $3, 'STRIPE_KEY')",
                    )
                    .bind(a)
                    .bind(project)
                    .bind(env)
                    .execute(c)
                    .await
                })
            })
            .await
            .expect_err("secret under a foreign parent");
        assert_eq!(sqlstate(&err).as_deref(), Some("23503"), "{err}");
    }

    // The valid tree works, and names are unique per parent.
    let ok = db
        .with_org(a, move |c| {
            Box::pin(async move {
                sql::query(
                    "INSERT INTO secrets (org_id, project_id, environment_id, name)
                     VALUES ($1, $2, $3, 'STRIPE_KEY')",
                )
                .bind(a)
                .bind(pa)
                .bind(ea)
                .execute(c)
                .await
            })
        })
        .await
        .unwrap();
    assert_eq!(ok.rows_affected(), 1);
    let dup = create_env(&db, a, pa, "dev")
        .await
        .expect_err("duplicate env name");
    assert_eq!(sqlstate(&dup).as_deref(), Some("23505"));
    db.close().await;
}

/// Scenario: pooled-connection reuse (pool size 1) sees no org.
#[tokio::test]
async fn pooled_connection_reuse_with_pool_size_1_sees_no_org() {
    let pg = Pg::migrated().await;
    let db = pg.app_db(PoolSettings {
        max_connections: 1,
        ..PoolSettings::default()
    });
    let a = create_org(&db, "org-a").await;
    let pid_1: i32 = db
        .with_org(a, move |c| {
            Box::pin(async move {
                sql::query("INSERT INTO projects (org_id, name) VALUES ($1, 'p')")
                    .bind(a)
                    .execute(&mut *c)
                    .await?;
                let seen: i64 = sql::query_scalar("SELECT count(*) FROM projects")
                    .fetch_one(&mut *c)
                    .await?;
                assert_eq!(seen, 1);
                sql::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *c)
                    .await
            })
        })
        .await
        .unwrap();

    let (pid_2, setting, visible, insert_err) = db
        .without_org(move |c| {
            Box::pin(async move {
                let pid: i32 = sql::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *c)
                    .await?;
                let setting: Option<String> =
                    sql::query_scalar("SELECT current_setting('app.org_id', true)")
                        .fetch_one(&mut *c)
                        .await?;
                let visible: i64 = sql::query_scalar(
                    "SELECT (SELECT count(*) FROM orgs) + (SELECT count(*) FROM projects)
                          + (SELECT count(*) FROM environments) + (SELECT count(*) FROM secrets)",
                )
                .fetch_one(&mut *c)
                .await?;
                // Savepoint so the failed insert does not abort the transaction.
                sql::query("SAVEPOINT s").execute(&mut *c).await?;
                let insert_err = sql::query("INSERT INTO projects (org_id, name) VALUES ($1, 'x')")
                    .bind(a)
                    .execute(&mut *c)
                    .await
                    .err()
                    .and_then(|e| sqlstate(&e));
                sql::query("ROLLBACK TO SAVEPOINT s")
                    .execute(&mut *c)
                    .await?;
                Ok::<_, sql::Error>((pid, setting, visible, insert_err))
            })
        })
        .await
        .unwrap();
    assert_eq!(pid_1, pid_2, "a pool of one must reuse the connection");
    assert_eq!(setting.as_deref().unwrap_or(""), "", "org context leaked");
    assert_eq!(visible, 0, "tenant rows visible without an org");
    assert_eq!(insert_err.as_deref(), Some("42501"));
    db.close().await;
}

/// A closure error rolls the whole transaction back.
#[tokio::test]
async fn closure_error_rolls_back() {
    let pg = Pg::migrated().await;
    let db = pg.app_db(PoolSettings {
        max_connections: 1,
        ..PoolSettings::default()
    });
    let a = create_org(&db, "org-a").await;
    let err = db
        .with_org(a, move |c| {
            Box::pin(async move {
                sql::query("INSERT INTO projects (org_id, name) VALUES ($1, 'rolled-back')")
                    .bind(a)
                    .execute(&mut *c)
                    .await?;
                Err::<(), _>(sql::Error::RowNotFound)
            })
        })
        .await;
    assert!(matches!(err, Err(sql::Error::RowNotFound)));
    let n: i64 = db
        .with_org(a, |c| {
            Box::pin(async move {
                sql::query_scalar("SELECT count(*) FROM projects")
                    .fetch_one(c)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(n, 0);
    db.close().await;
}

async fn readyz(state: &AppState) -> StatusCode {
    app::build(state.clone())
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn wait_for(cond: impl Fn() -> bool, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    cond()
}

/// `/readyz` is 503 until migrated, 200 after, and 503 within 5 s of Postgres stopping.
#[tokio::test]
async fn readyz_follows_migrations_and_database() {
    let pg = Pg::start().await;
    let readiness = Arc::new(DbReadiness::new());
    let db = pg.app_db(PoolSettings {
        max_connections: 2,
        ..PoolSettings::default()
    });
    let probe = db.spawn_readiness_probe(readiness.clone(), Duration::from_millis(200));
    let state = AppState::new(false, readiness.clone(), db.clone());

    // Not migrated: the app role does not even exist yet.
    assert_eq!(readyz(&state).await, StatusCode::SERVICE_UNAVAILABLE);

    migrate::run_until_done(pg.bootstrap(), readiness.clone()).await;
    let r = readiness.clone();
    assert!(wait_for(move || r.is_ready(), Duration::from_secs(10)).await);
    assert_eq!(readyz(&state).await, StatusCode::OK);

    pg.container.stop().await.unwrap();
    let r = readiness.clone();
    assert!(
        wait_for(move || !r.is_ready(), Duration::from_secs(5)).await,
        "readiness must drop within 5 s of Postgres stopping"
    );
    assert_eq!(readyz(&state).await, StatusCode::SERVICE_UNAVAILABLE);
    probe.abort();
}

/// Task 3.1 (design decision 6): `secret_versions` is tenant-isolated, can only name a secret
/// of its own org, and is append-only for the app role. Deleting the secret cascades.
#[tokio::test]
async fn secret_versions_are_isolated_append_only_and_cascade() {
    let pg = Pg::migrated().await;
    let db = pg.app_db(PoolSettings {
        max_connections: 2,
        ..PoolSettings::default()
    });
    let a = create_org(&db, "org-a").await;
    let b = create_org(&db, "org-b").await;
    let pa = create_project(&db, a, "p").await;
    let pb = create_project(&db, b, "p").await;
    let ea = create_env(&db, a, pa, "dev").await.unwrap();
    let eb = create_env(&db, b, pb, "dev").await.unwrap();
    let secret = |org: Uuid, project: Uuid, env: Uuid| {
        let db = db.clone();
        async move {
            db.with_org(org, move |c| {
                Box::pin(async move {
                    sql::query_scalar::<_, Uuid>(
                        "INSERT INTO secrets (org_id, project_id, environment_id, name)
                         VALUES ($1, $2, $3, 'K') RETURNING id",
                    )
                    .bind(org)
                    .bind(project)
                    .bind(env)
                    .fetch_one(c)
                    .await
                })
            })
            .await
            .unwrap()
        }
    };
    let sa = secret(a, pa, ea).await;
    let sb = secret(b, pb, eb).await;

    // Shaped like real blobs; contents are irrelevant to the schema.
    let insert = |org: Uuid, secret_id: Uuid, version: i32| {
        let db = db.clone();
        async move {
            db.with_org(org, move |c| {
                Box::pin(async move {
                    sql::query(
                        "INSERT INTO secret_versions
                         (org_id, secret_id, version, ciphertext, wrapped_dek, key_id)
                         VALUES ($1, $2, $3, $4, $5, 'gateway:v1')",
                    )
                    .bind(org)
                    .bind(secret_id)
                    .bind(version)
                    .bind(vec![0u8; 50])
                    .bind(vec![0u8; 80])
                    .execute(c)
                    .await
                    .map(|_| ())
                })
            })
            .await
        }
    };
    insert(a, sa, 1).await.unwrap();
    insert(a, sa, 2).await.unwrap();
    // Version unique per secret.
    let err = insert(a, sa, 2).await.expect_err("duplicate version");
    assert_eq!(sqlstate(&err).as_deref(), Some("23505"));
    // A version in org A naming org B's secret: composite FK fails.
    let err = insert(a, sb, 1)
        .await
        .expect_err("version under a foreign secret");
    assert_eq!(sqlstate(&err).as_deref(), Some("23503"), "{err}");
    // A row claiming org B while bound to org A: RLS WITH CHECK refuses.
    let err = db
        .with_org(a, move |c| {
            Box::pin(async move {
                sql::query(
                    "INSERT INTO secret_versions
                     (org_id, secret_id, version, ciphertext, wrapped_dek, key_id)
                     VALUES ($1, $2, 1, $3, $4, 'gateway:v1')",
                )
                .bind(b)
                .bind(sb)
                .bind(vec![0u8; 50])
                .bind(vec![0u8; 80])
                .execute(c)
                .await
            })
        })
        .await
        .expect_err("cross-org insert");
    assert_eq!(sqlstate(&err).as_deref(), Some("42501"), "{err}");

    // Org B sees none of org A's versions.
    let seen_by_b: i64 = db
        .with_org(b, |c| {
            Box::pin(async move {
                sql::query_scalar("SELECT count(*) FROM secret_versions")
                    .fetch_one(c)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(seen_by_b, 0);

    // Append-only: the app role may not UPDATE or DELETE versions.
    for stmt in [
        "UPDATE secret_versions SET key_id = 'x' WHERE secret_id = $1",
        "DELETE FROM secret_versions WHERE secret_id = $1",
    ] {
        let err = db
            .with_org(a, move |c| {
                Box::pin(async move { sql::query(stmt).bind(sa).execute(c).await })
            })
            .await
            .expect_err(stmt);
        assert_eq!(sqlstate(&err).as_deref(), Some("42501"), "{stmt}: {err}");
    }

    // Deleting the secret removes its versions (referential action, not an app-role DELETE).
    let left: i64 = db
        .with_org(a, move |c| {
            Box::pin(async move {
                sql::query("DELETE FROM secrets WHERE id = $1")
                    .bind(sa)
                    .execute(&mut *c)
                    .await?;
                sql::query_scalar("SELECT count(*) FROM secret_versions")
                    .fetch_one(&mut *c)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(left, 0);
    db.close().await;
}

/// S3 task 2.1 (design decision 8), S5 task 3.1 (design decision 6): `gateway_audit` is
/// read-only legacy. Rows written before S5 stay tenant-isolated for the app role, which may no
/// longer INSERT (migration 0009), UPDATE or DELETE.
#[tokio::test]
async fn gateway_audit_is_isolated_and_read_only() {
    let pg = Pg::migrated().await;
    let db = pg.app_db(PoolSettings {
        max_connections: 2,
        ..PoolSettings::default()
    });
    let a = create_org(&db, "org-a").await;
    let b = create_org(&db, "org-b").await;
    let secret = Uuid::now_v7();
    // A legacy row, written as the bootstrap superuser (as the pre-S5 gateway would have).
    let mut admin = pg.admin().await;
    sql::query(
        "INSERT INTO gateway_audit (org_id, secret_id, method, scheme, host, path, outcome, status)
         VALUES ($1, $2, 'GET', 'https', 'api.example.com', '/v1/x', 'ok', 200)",
    )
    .bind(a)
    .bind(secret)
    .execute(&mut admin)
    .await
    .unwrap();

    let count = |org: Uuid| {
        let db = db.clone();
        async move {
            db.with_org(org, |c| {
                Box::pin(async move {
                    sql::query_scalar::<_, i64>("SELECT count(*) FROM gateway_audit")
                        .fetch_one(c)
                        .await
                })
            })
            .await
            .unwrap()
        }
    };
    assert_eq!(count(a).await, 1, "legacy rows stay readable");
    assert_eq!(count(b).await, 0, "and tenant-isolated");

    for stmt in [
        "INSERT INTO gateway_audit (org_id, secret_id, method, scheme, host, path, outcome, status)
         VALUES (current_org_id(), gen_random_uuid(), 'GET', 'https', 'h', '/', 'ok', 200)",
        "UPDATE gateway_audit SET outcome = 'x'",
        "DELETE FROM gateway_audit",
    ] {
        let err = db
            .with_org(a, move |c| {
                Box::pin(async move { sql::query(stmt).execute(c).await })
            })
            .await
            .expect_err(stmt);
        assert_eq!(sqlstate(&err).as_deref(), Some("42501"), "{stmt}: {err}");
    }
    assert_eq!(count(a).await, 1);
    db.close().await;
}
