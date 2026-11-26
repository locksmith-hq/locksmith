//! N1 task 2.3: the notification tables on a throwaway `postgres:18` container: defaults seeded
//! on org creation, and two orgs never see each other's rows.

mod common;

use common::Pg;
use ls_control_plane::db::{Database, sql};
use sqlx_core::connection::Connection;
use sqlx_postgres::PgConnection;
use uuid::Uuid;

async fn create_org(db: &Database) -> Uuid {
    let id = Uuid::now_v7();
    db.with_org(id, move |c| {
        Box::pin(async move {
            sql::query("INSERT INTO orgs (id, name) VALUES ($1, 'n1-org')")
                .bind(id)
                .execute(c)
                .await
                .map(|_| ())
        })
    })
    .await
    .expect("create org");
    id
}

/// A user in `org` (its personal org), the recipient of an inbox item.
async fn create_user(db: &Database, org: Uuid) -> Uuid {
    db.with_org(org, move |c| {
        Box::pin(async move {
            let subject = Uuid::now_v7().to_string();
            // The sign-in transaction binds the identity it creates (migration 0011).
            sql::query(
                "SELECT set_config('app.login_issuer', 'https://issuer.test', true), set_config('app.login_subject', $1, true)",
            )
            .bind(&subject)
            .execute(&mut *c)
            .await?;
            sql::query_scalar::<_, Uuid>(
                "INSERT INTO users (issuer, subject, personal_org_id) VALUES ('https://issuer.test', $1, $2) RETURNING id",
            )
            .bind(subject)
            .bind(org)
            .fetch_one(c)
            .await
        })
    })
    .await
    .expect("create user")
}

async fn count(db: &Database, org: Uuid, table: &'static str) -> i64 {
    let query = match table {
        "notification_rules" => "SELECT count(*) FROM notification_rules",
        "notification_cursors" => "SELECT count(*) FROM notification_cursors",
        "notifications" => "SELECT count(*) FROM notifications",
        "notification_deliveries" => "SELECT count(*) FROM notification_deliveries",
        other => panic!("unknown table {other}"),
    };
    db.with_org(org, move |c| {
        Box::pin(async move { sql::query_scalar::<_, i64>(query).fetch_one(c).await })
    })
    .await
    .expect("count")
}

#[tokio::test]
async fn new_org_gets_default_rules_and_a_cursor() {
    let pg = Pg::migrated().await;
    let db = pg.app_db(Default::default());
    let org = create_org(&db).await;

    // Four notifiable kinds on three channels; only the inbox starts enabled, all to the owner.
    assert_eq!(count(&db, org, "notification_rules").await, 12);
    let enabled: Vec<(String, String, bool)> = db
        .with_org(org, |c| {
            Box::pin(async move {
                sql::query_as(
                    "SELECT channel, audience, enabled FROM notification_rules WHERE enabled",
                )
                .fetch_all(c)
                .await
            })
        })
        .await
        .unwrap();
    assert_eq!(enabled.len(), 4);
    assert!(
        enabled
            .iter()
            .all(|(ch, aud, _)| ch == "inbox" && aud == "owner")
    );
    assert_eq!(count(&db, org, "notification_cursors").await, 1);
}

#[tokio::test]
async fn two_orgs_never_see_each_others_notification_rows() {
    let pg = Pg::migrated().await;
    let db = pg.app_db(Default::default());
    let a = create_org(&db).await;
    let b = create_org(&db).await;
    let user_a = create_user(&db, a).await;

    let note: Uuid = db
        .with_org(a, move |c| {
            Box::pin(async move {
                let id: Uuid = sql::query_scalar(
                    "INSERT INTO notifications (org_id, user_id, kind, payload) \
                     VALUES ($1, $2, 'relay.denied', '{\"kind\":\"relay.denied\"}') RETURNING id",
                )
                .bind(a)
                .bind(user_a)
                .fetch_one(&mut *c)
                .await?;
                sql::query(
                    "INSERT INTO notification_deliveries (org_id, notification_id, channel) VALUES ($1, $2, 'inbox')",
                )
                .bind(a)
                .bind(id)
                .execute(&mut *c)
                .await?;
                Ok::<_, sql::Error>(id)
            })
        })
        .await
        .unwrap();

    for table in ["notifications", "notification_deliveries"] {
        assert_eq!(count(&db, a, table).await, 1, "{table} own org");
        assert_eq!(count(&db, b, table).await, 0, "{table} other org");
    }
    assert_eq!(count(&db, b, "notification_rules").await, 12);

    // Marking read from the other org changes nothing; from its own org it works.
    let touched = |org: Uuid| {
        let db = &db;
        async move {
            db.with_org(org, move |c| {
                Box::pin(async move {
                    sql::query("UPDATE notifications SET read_at = now() WHERE id = $1")
                        .bind(note)
                        .execute(c)
                        .await
                        .map(|r| r.rows_affected())
                })
            })
            .await
            .unwrap()
        }
    };
    assert_eq!(touched(b).await, 0);
    assert_eq!(touched(a).await, 1);

    // A row for org A cannot be written under org B's binding.
    let cross = db
        .with_org(b, move |c| {
            Box::pin(async move {
                sql::query("INSERT INTO notification_cursors (org_id) VALUES ($1)")
                    .bind(a)
                    .execute(c)
                    .await
                    .map(|_| ())
            })
        })
        .await;
    assert!(cross.is_err(), "cross-org insert must be refused");
}

/// The fan-out job lists every cursor with no org bound, but sees no inbox or rule rows then.
#[tokio::test]
async fn cursors_are_listable_unbound_other_tables_are_not() {
    let pg = Pg::migrated().await;
    let db = pg.app_db(Default::default());
    let a = create_org(&db).await;
    let b = create_org(&db).await;
    let mut app = PgConnection::connect_with(&pg.app()).await.unwrap();
    let cursors: Vec<Uuid> = sql::query_scalar("SELECT org_id FROM notification_cursors")
        .fetch_all(&mut app)
        .await
        .unwrap();
    assert!(cursors.contains(&a) && cursors.contains(&b));
    let rules: i64 = sql::query_scalar("SELECT count(*) FROM notification_rules")
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert_eq!(rules, 0);
}
