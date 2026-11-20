//! T1 tasks 3.1 to 3.3: the users table and its RLS, the first-login transaction (user plus
//! personal org, idempotent and race-free), the email-verified gate and verified-email-only
//! identity linking. Needs a Docker daemon (throwaway `postgres:18`).

mod common;

use common::Pg;
use ls_control_plane::auth::human::HumanIdentity;
use ls_control_plane::db::{Database, sql};
use ls_control_plane::problem::Kind;
use ls_control_plane::users::{self, PERSONAL_ORG_NAME};
use uuid::Uuid;

const ISSUER: &str = "https://idp.test/realms/locksmith";

fn identity(subject: &str, email: Option<&str>, verified: bool) -> HumanIdentity {
    HumanIdentity {
        issuer: ISSUER.to_owned(),
        subject: subject.to_owned(),
        email: email.map(str::to_owned),
        email_verified: verified,
        client_id: None,
        auth_time: None,
    }
}

async fn count(pg: &Pg, table: &str) -> i64 {
    // The bootstrap superuser bypasses RLS: this sees every row.
    let mut c = pg.admin().await;
    let q = match table {
        "users" => "SELECT count(*) FROM users",
        "orgs" => "SELECT count(*) FROM orgs",
        other => panic!("unknown table {other}"),
    };
    sql::query_scalar::<_, i64>(q)
        .fetch_one(&mut c)
        .await
        .unwrap()
}

fn db(pg: &Pg) -> Database {
    pg.app_db(Default::default())
}

#[tokio::test]
async fn users_first_login_creates_the_user_and_a_personal_org_once() {
    let pg = Pg::migrated().await;
    let db = db(&pg);
    let id = identity("sub-1", Some("ada@example.com"), true);

    let first = users::resolve(&db, &id).await.unwrap();
    assert!(first.created && first.org_created);
    let again = users::resolve(&db, &id).await.unwrap();
    assert!(!again.created && !again.org_created);
    assert_eq!((again.user_id, again.org_id), (first.user_id, first.org_id));
    assert_eq!(count(&pg, "users").await, 1);
    assert_eq!(count(&pg, "orgs").await, 1);

    // The org exists under that id, is reachable through RLS with it bound, and is named.
    let name: String = db
        .with_org(first.org_id, |c| {
            Box::pin(async move {
                sql::query_scalar("SELECT name FROM orgs")
                    .fetch_one(c)
                    .await
            })
        })
        .await
        .map_err(|e: sql::Error| e)
        .unwrap();
    assert_eq!(name, PERSONAL_ORG_NAME);

    // A different person gets a different org.
    let other = users::resolve(&db, &identity("sub-2", Some("bob@example.com"), true))
        .await
        .unwrap();
    assert_ne!(other.org_id, first.org_id);
    assert_eq!(
        (count(&pg, "users").await, count(&pg, "orgs").await),
        (2, 2)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn users_concurrent_first_logins_create_exactly_one_user_and_org() {
    let pg = Pg::migrated().await;
    let db = db(&pg);
    let id = identity("racer", Some("racer@example.com"), true);

    let tasks: Vec<_> = (0..16)
        .map(|_| {
            let (db, id) = (db.clone(), id.clone());
            tokio::spawn(async move { users::resolve(&db, &id).await })
        })
        .collect();
    let mut results = Vec::new();
    for t in tasks {
        results.push(t.await.unwrap().expect("every concurrent request succeeds"));
    }

    let org = results[0].org_id;
    assert!(results.iter().all(|r| r.org_id == org), "one org for all");
    assert!(results.iter().all(|r| r.user_id == results[0].user_id));
    assert_eq!(
        results.iter().filter(|r| r.created).count(),
        1,
        "one creator"
    );
    assert_eq!(count(&pg, "users").await, 1);
    assert_eq!(count(&pg, "orgs").await, 1);
}

#[tokio::test]
async fn users_unverified_email_gets_403_and_leaves_no_rows() {
    let pg = Pg::migrated().await;
    let db = db(&pg);
    for id in [
        identity("u1", Some("mallory@example.com"), false),
        identity("u2", None, false),
    ] {
        let err = users::resolve(&db, &id).await.unwrap_err();
        assert_eq!(err.kind, Kind::EmailVerificationRequired);
        assert_eq!(err.kind.status(), 403);
        assert_eq!(
            err.kind.type_uri(),
            "urn:locksmith:problem:email-verification-required"
        );
    }
    assert_eq!(
        (count(&pg, "users").await, count(&pg, "orgs").await),
        (0, 0)
    );
}

#[tokio::test]
async fn users_identities_link_by_verified_email_only() {
    let pg = Pg::migrated().await;
    let db = db(&pg);

    let google = users::resolve(&db, &identity("google-1", Some("Ada@Example.com"), true))
        .await
        .unwrap();
    // Same address (case-insensitive), verified, different subject: joins the same personal org.
    let github = users::resolve(&db, &identity("github-1", Some("ada@example.com"), true))
        .await
        .unwrap();
    assert!(github.created && !github.org_created);
    assert_eq!(github.org_id, google.org_id);
    assert_ne!(github.user_id, google.user_id);
    assert_eq!(
        (count(&pg, "users").await, count(&pg, "orgs").await),
        (2, 1)
    );

    // An unverified claim to that address is refused and links nothing.
    let attacker = identity("evil-1", Some("ada@example.com"), false);
    assert_eq!(
        users::resolve(&db, &attacker).await.unwrap_err().kind,
        Kind::EmailVerificationRequired
    );
    assert_eq!(
        (count(&pg, "users").await, count(&pg, "orgs").await),
        (2, 1)
    );

    // A verified, different address is a separate user and org.
    let bob = users::resolve(&db, &identity("google-2", Some("bob@example.com"), true))
        .await
        .unwrap();
    assert_ne!(bob.org_id, google.org_id);
    assert_eq!(
        (count(&pg, "users").await, count(&pg, "orgs").await),
        (3, 2)
    );

    // A verified identity with no email claim cannot link: it gets its own org.
    let none = users::resolve(&db, &identity("noemail", None, true))
        .await
        .unwrap();
    assert!(none.org_created);
    assert_ne!(none.org_id, google.org_id);
}

#[tokio::test]
async fn users_email_claim_is_refreshed_on_sign_in() {
    let pg = Pg::migrated().await;
    let db = db(&pg);
    let first = users::resolve(&db, &identity("s", Some("old@example.com"), true))
        .await
        .unwrap();
    let again = users::resolve(&db, &identity("s", Some("new@example.com"), true))
        .await
        .unwrap();
    assert_eq!(again.user_id, first.user_id);
    let mut c = pg.admin().await;
    let email: Option<String> = sql::query_scalar("SELECT email FROM users")
        .fetch_one(&mut c)
        .await
        .unwrap();
    assert_eq!(email.as_deref(), Some("new@example.com"));
}

fn sqlstate(e: &sql::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
}

#[tokio::test]
async fn users_rls_isolates_users_between_orgs() {
    let pg = Pg::migrated().await;
    let db = db(&pg);
    let a = users::resolve(&db, &identity("a", Some("a@example.com"), true))
        .await
        .unwrap();
    let b = users::resolve(&db, &identity("b", Some("b@example.com"), true))
        .await
        .unwrap();

    async fn visible(db: &Database, org: Option<Uuid>) -> Vec<String> {
        macro_rules! read {
            () => {
                |c| {
                    Box::pin(async move {
                        sql::query_scalar("SELECT subject FROM users ORDER BY subject")
                            .fetch_all(c)
                            .await
                    })
                }
            };
        }
        let rows: Result<Vec<String>, sql::Error> = match org {
            Some(o) => db.with_org(o, read!()).await,
            None => db.without_org(read!()).await,
        };
        rows.unwrap()
    }
    assert_eq!(visible(&db, Some(a.org_id)).await, vec!["a"]);
    assert_eq!(visible(&db, Some(b.org_id)).await, vec!["b"]);
    assert!(
        visible(&db, None).await.is_empty(),
        "no org bound reads nothing"
    );

    // A request bound to org A cannot create a user (the identity is not bound), nor re-point
    // or edit B's row.
    let err = db
        .with_org(a.org_id, move |c| {
            Box::pin(async move {
                sql::query(
                    "INSERT INTO users (issuer, subject, email_verified, personal_org_id) \
                     VALUES ('i', 'forged', true, $1)",
                )
                .bind(a.org_id)
                .execute(c)
                .await
                .map(|_| ())
            })
        })
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&err).as_deref(), Some("42501"), "{err}");
    let hit = db
        .with_org(a.org_id, move |c| {
            Box::pin(async move {
                sql::query("UPDATE users SET email = 'x@example.com' WHERE id = $1")
                    .bind(b.user_id)
                    .execute(c)
                    .await
                    .map(|r| r.rows_affected())
            })
        })
        .await
        .map_err(|e: sql::Error| e)
        .unwrap();
    assert_eq!(hit, 0);
    // The app role cannot delete users or change who they belong to.
    let err = db
        .with_org(a.org_id, move |c| {
            Box::pin(async move { sql::query("DELETE FROM users").execute(c).await.map(|_| ()) })
        })
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&err).as_deref(), Some("42501"), "{err}");
}

#[tokio::test]
async fn users_identity_is_unique_per_issuer_and_subject() {
    let pg = Pg::migrated().await;
    let db = db(&pg);
    users::resolve(&db, &identity("same", Some("a@example.com"), true))
        .await
        .unwrap();
    // The owner role (no RLS in the way for a superuser) cannot add a second row either.
    let mut c = pg.admin().await;
    let org: Uuid = sql::query_scalar("SELECT personal_org_id FROM users")
        .fetch_one(&mut c)
        .await
        .unwrap();
    let err = sql::query(
        "INSERT INTO users (issuer, subject, email_verified, personal_org_id) VALUES ($1, 'same', true, $2)",
    )
    .bind(ISSUER)
    .bind(org)
    .execute(&mut c)
    .await
    .unwrap_err();
    assert_eq!(sqlstate(&err).as_deref(), Some("23505"), "{err}");
}
