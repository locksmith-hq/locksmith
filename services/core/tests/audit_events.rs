//! `POST /v1/audit/events` against a real Postgres (task 3.1; needs Docker).

use axum::body::Body;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use ls_audit::pg::PgLedger;
use ls_core_service::app::{AppState, router};
use ls_core_service::auth::ServiceToken;
use ls_pg_test::Pg;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx_postgres::PgPoolOptions;
use tower::ServiceExt;

const ORG: &str = "11111111-1111-4111-8111-111111111111";
const ATTEMPT: &str = "44444444-4444-4444-8444-444444444444";

fn token() -> ServiceToken {
    ServiceToken::new(SecretString::from("test-token".to_owned()))
}

async fn post(app: &axum::Router, auth: Option<&str>, body: Value) -> (StatusCode, Value) {
    let mut req =
        Request::post("/v1/audit/events").header(header::CONTENT_TYPE, "application/json");
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn created() -> Value {
    json!({
        "org_id": ORG, "kind": "agent.created", "outcome": "ok",
        "actor": {"type": "service", "code": "control_plane"},
        "target": {"type": "agent", "id": "22222222-2222-4222-8222-222222222222"},
        "attrs": {},
    })
}

fn outcome(target: &str) -> Value {
    json!({
        "org_id": ORG, "kind": "relay.outcome", "outcome": "ok",
        "actor": {"type": "service", "code": "gateway"},
        "target": {"type": "agent", "id": target},
        "attrs": {"attempt_id": ATTEMPT},
        "idempotency_key": ATTEMPT,
    })
}

const BEARER: Option<&str> = Some("Bearer test-token");

#[tokio::test]
async fn without_credentials_nothing_is_appended() {
    let app = router(AppState::new(token()));
    let (s, _) = post(&app, None, created()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = post(&app, Some("Bearer nope"), created()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bad_input_is_400_and_missing_database_is_503() {
    let app = router(AppState::new(token()));
    for body in [
        json!({"nope": 1}),
        json!({"org_id": ORG, "kind": "made.up", "outcome": "ok", "actor": {"type": "service", "code": "gateway"}, "attrs": {}}),
        json!({"org_id": ORG, "kind": "agent.created", "outcome": "ok", "actor": {"type": "service", "code": "gateway"}, "attrs": {"free_text": "x"}}),
        // A key on a non-outcome event is refused.
        json!({"org_id": ORG, "kind": "agent.created", "outcome": "ok", "actor": {"type": "service", "code": "gateway"}, "attrs": {}, "idempotency_key": ATTEMPT}),
    ] {
        let (s, p) = post(&app, BEARER, body).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{p}");
        assert_eq!(p["status"], 400);
    }
    let (s, _) = post(&app, BEARER, created()).await;
    assert_eq!(
        s,
        StatusCode::SERVICE_UNAVAILABLE,
        "valid input, no database"
    );
}

#[tokio::test]
async fn appends_chain_and_retries_are_idempotent() {
    let pg = Pg::migrated().await;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(pg.app())
        .await
        .unwrap();
    {
        let org: uuid::Uuid = ORG.parse().unwrap();
        let mut tx = pool.begin().await.unwrap();
        ls_audit::pg::bind_org(&mut tx, org).await.unwrap();
        sqlx_core::query::query("INSERT INTO orgs (id, name) VALUES ($1, 'core-test')")
            .bind(org)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let app = router(AppState::new(token()).with_pool(pool.clone()));

    let (s, a) = post(&app, BEARER, created()).await;
    assert_eq!(s, StatusCode::OK, "{a}");
    assert_eq!(a["seq"], 1);
    assert_eq!(a["deduplicated"], false);
    assert_eq!(a["hash"].as_str().unwrap().len(), 64);
    let (_, b) = post(&app, BEARER, created()).await;
    assert_eq!(b["seq"], 2);

    let target = "55555555-5555-4555-8555-555555555555";
    let (s, first) = post(&app, BEARER, outcome(target)).await;
    assert_eq!(
        (s, first["seq"].as_i64(), first["deduplicated"].as_bool()),
        (StatusCode::OK, Some(3), Some(false))
    );
    let (s, again) = post(&app, BEARER, outcome(target)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(again["deduplicated"], true);
    assert_eq!(
        (&again["id"], &again["hash"]),
        (&first["id"], &first["hash"])
    );
    // The same key with a different event is refused and appends nothing.
    let (s, _) = post(
        &app,
        BEARER,
        outcome("66666666-6666-4666-8666-666666666666"),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let rows = PgLedger::new(pool)
        .records(ORG.parse().unwrap())
        .await
        .unwrap();
    assert_eq!(rows.len(), 3);
}
