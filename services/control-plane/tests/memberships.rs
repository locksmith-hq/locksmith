//! T6 task 2.1 and 2.2: migration 0014 (`memberships`, `invites`), its backfill and its row-level
//! security. Needs a Docker daemon (throwaway `postgres:18`).

mod common;

use common::Pg;
use ls_control_plane::db::sql;
use ls_control_plane::migrate;
use sqlx_core::connection::Connection;
use uuid::Uuid;

/// Two users in two orgs, inserted as the bootstrap superuser (RLS bypassed), before 0014 runs.
#[tokio::test]
async fn migration_backfills_one_owner_membership_per_existing_user() {
    let pg = Pg::start().await;
    let mut admin = pg.admin().await;
    // Apply 0001..=0013, add users, then apply 0014 on top.
    let mut c = pg.admin().await;
    migrate::migrator()
        .run_to(14, &mut c)
        .await
        .expect("migrations to 0013");
    let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
    for (org, sub) in [(a, "s1"), (b, "s2")] {
        sql::query("INSERT INTO orgs (id, name) VALUES ($1, 'o')")
            .bind(org)
            .execute(&mut admin)
            .await
            .unwrap();
        sql::query(
            "INSERT INTO users (issuer, subject, email, email_verified, personal_org_id) \
             VALUES ('https://i.test', $1, $1 || '@e.test', true, $2)",
        )
        .bind(sub)
        .bind(org)
        .execute(&mut admin)
        .await
        .unwrap();
    }
    migrate::run(pg.bootstrap()).await.expect("0014 applies");

    let rows: Vec<(Uuid, String)> =
        sql::query_as("SELECT org_id, role FROM memberships ORDER BY created_at, org_id")
            .fetch_all(&mut admin)
            .await
            .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|(_, r)| r == "owner"));
    assert!(rows.iter().any(|(o, _)| *o == a) && rows.iter().any(|(o, _)| *o == b));
    // FORCE was restored on `users` after the backfill.
    let forced: bool =
        sql::query_scalar("SELECT relforcerowsecurity FROM pg_class WHERE relname = 'users'")
            .fetch_one(&mut admin)
            .await
            .unwrap();
    assert!(forced);
}

async fn seed(pg: &Pg) -> (Uuid, Uuid, Uuid, Uuid) {
    let mut admin = pg.admin().await;
    let (org_a, org_b) = (Uuid::now_v7(), Uuid::now_v7());
    let mut users = Vec::new();
    for (org, sub) in [(org_a, "ua"), (org_b, "ub")] {
        sql::query("INSERT INTO orgs (id, name) VALUES ($1, 'o')")
            .bind(org)
            .execute(&mut admin)
            .await
            .unwrap();
        let u: Uuid = sql::query_scalar(
            "INSERT INTO users (issuer, subject, personal_org_id) \
             VALUES ('https://i.test', $1, $2) RETURNING id",
        )
        .bind(sub)
        .bind(org)
        .fetch_one(&mut admin)
        .await
        .unwrap();
        sql::query("INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, 'owner')")
            .bind(org)
            .bind(u)
            .execute(&mut admin)
            .await
            .unwrap();
        users.push(u);
    }
    (org_a, org_b, users[0], users[1])
}

#[tokio::test]
async fn memberships_and_invites_are_isolated_by_org_and_login_user() {
    let pg = Pg::migrated().await;
    let (org_a, org_b, user_a, user_b) = seed(&pg).await;
    let db = pg.app_db(Default::default());

    // Bound to org A: only org A's membership is visible.
    let seen: Vec<Uuid> = db
        .with_org(org_a, |c| {
            Box::pin(async move {
                sql::query_scalar("SELECT user_id FROM memberships")
                    .fetch_all(c)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(seen, vec![user_a]);

    // Another org's row cannot be inserted from org A's context.
    let cross = db
        .with_org(org_a, move |c| {
            Box::pin(async move {
                sql::query(
                    "INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, 'member')",
                )
                .bind(org_b)
                .bind(user_a)
                .execute(c)
                .await
                .map(|_| ())
            })
        })
        .await;
    assert!(cross.is_err(), "cross-org insert must be refused by RLS");

    // Invites: org B's invite is invisible from org A, and a raw hash alone does not leak it
    // unless `app.invite_hash` is bound.
    let hash = [7u8; 32];
    db.with_org(org_b, move |c| {
        Box::pin(async move {
            sql::query(
                "INSERT INTO invites (org_id, email, role, token_hash, invited_by, expires_at) \
                 VALUES ($1, 'x@e.test', 'member', $2, $3, now() + interval '7 days')",
            )
            .bind(org_b)
            .bind(hash.to_vec())
            .bind(user_b)
            .execute(c)
            .await
            .map(|_| ())
        })
    })
    .await
    .expect("invite insert in its own org");
    let from_a: i64 = db
        .with_org(org_a, |c| {
            Box::pin(async move {
                sql::query_scalar("SELECT count(*) FROM invites")
                    .fetch_one(c)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(from_a, 0);

    // With the hash bound (and no org), exactly that invite is visible, and the accepting user
    // can join with the invited role only.
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    let mut c = sql::PgConnection::connect_with(&pg.app()).await.unwrap();
    let mut tx = c.begin().await.unwrap();
    sql::query(
        "SELECT set_config('app.invite_hash', $1, true), set_config('app.login_user', $2, true)",
    )
    .bind(hex)
    .bind(user_a.to_string())
    .execute(&mut *tx)
    .await
    .unwrap();
    let visible: i64 = sql::query_scalar("SELECT count(*) FROM invites")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(visible, 1);
    let own: i64 = sql::query_scalar("SELECT count(*) FROM memberships")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(own, 1, "login_user sees its own membership across orgs");
    sql::query("SAVEPOINT s").execute(&mut *tx).await.unwrap();
    let wrong_role =
        sql::query("INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, 'owner')")
            .bind(org_b)
            .bind(user_a)
            .execute(&mut *tx)
            .await;
    assert!(
        wrong_role.is_err(),
        "a role other than the invited one is refused"
    );
    sql::query("ROLLBACK TO SAVEPOINT s")
        .execute(&mut *tx)
        .await
        .unwrap();
    sql::query("INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, 'member')")
        .bind(org_b)
        .bind(user_a)
        .execute(&mut *tx)
        .await
        .expect("join with the invited role");
    tx.commit().await.unwrap();
}
