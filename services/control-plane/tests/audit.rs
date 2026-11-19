//! S5 tasks 2.3 and 2.4: the control plane's audit ledger appends. S4 agent and grant admin
//! requests append their events in the same transaction, and the gateway appends relay events
//! through `POST /internal/v1/audit/events` behind the service token. Auth refusals need no
//! database; the rest use a throwaway `postgres:18` container (testcontainers; needs Docker).

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use ls_audit::{GENESIS, Record, verify};
use ls_control_plane::app::{self, AppState};
use ls_control_plane::auth::ServiceToken;
use ls_control_plane::db::{Database, PoolSettings};
use ls_control_plane::readiness::ReadyFlag;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use sqlx_core::query_scalar::query_scalar;
use sqlx_postgres::PgConnection;
use tower::ServiceExt;
use uuid::Uuid;

// Test-only values.
const TOKEN: &str = "test-only-gateway-service-token-0123456789";
const WRONG: &str = "test-only-gateway-service-token-0123456780";
// Underscores, like real API keys: a value made only of letters, digits, dots and hyphens is a
// valid host name, which the `host` attribute accepts by design.
const CANARY: &str = "CANARY_5e1d0c77_audit_do_not_store";
const EVENTS: &str = "/internal/v1/audit/events";

struct Reply {
    status: StatusCode,
    body: Value,
    raw: String,
}

fn state(db: Database, token: Option<&str>) -> AppState {
    let s = AppState::new(true, Arc::new(ReadyFlag::new(true)), db);
    match token {
        Some(t) => s.with_service_token(ServiceToken::new(SecretString::from(t))),
        None => s,
    }
}

fn bearer(t: &str) -> String {
    format!("Bearer {t}")
}

async fn send(app: &Router, req: Request<Body>) -> Reply {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        raw: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

/// `POST /internal/v1/audit/events` with optional `Authorization` and `X-Locksmith-Org`.
async fn post_event(app: &Router, auth: Option<&str>, org: Option<Uuid>, body: &Value) -> Reply {
    let mut b = Request::builder()
        .method("POST")
        .uri(EVENTS)
        .header("content-type", "application/json");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    if let Some(o) = org {
        b = b.header("x-locksmith-org", o.to_string());
    }
    send(app, b.body(Body::from(body.to_string())).unwrap()).await
}

/// A dev-auth request as `org`.
async fn dev(app: &Router, method: &str, uri: &str, org: Uuid, body: Option<Value>) -> Reply {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-locksmith-dev-org", org.to_string());
    let body = match body {
        Some(v) => {
            b = b.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    send(app, b.body(body).unwrap()).await
}

fn assert_problem(r: &Reply, status: StatusCode, slug: &str) {
    assert_eq!(r.status, status, "{}", r.raw);
    assert_eq!(r.body["type"], format!("urn:locksmith:problem:{slug}"));
    for s in [TOKEN, WRONG, CANARY] {
        assert!(!r.raw.contains(s), "problem echoes request data: {}", r.raw);
    }
}

fn attempt(agent: Uuid, secret: Uuid) -> Value {
    json!({
        "kind": "relay.attempt", "outcome": "pending",
        "agent_id": agent, "secret_id": secret, "version": 1,
        "method": "GET", "host": "api.example.com",
    })
}

/// No token, a wrong token, a token without an org, and no configured token are all `401`
/// before any database access (the pool here never connects).
#[tokio::test]
async fn missing_or_wrong_service_token_is_401() {
    let app = app::build(state(common::unreachable_db(), Some(TOKEN)));
    let org = Some(Uuid::now_v7());
    let body = attempt(Uuid::now_v7(), Uuid::now_v7());

    for auth in [
        None,
        Some(bearer(WRONG)),
        Some(TOKEN.to_owned()),
        Some(format!("Basic {TOKEN}")),
        Some("Bearer ".to_owned()),
    ] {
        let r = post_event(&app, auth.as_deref(), org, &body).await;
        assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    }
    let r = post_event(&app, Some(&bearer(TOKEN)), None, &body).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    // The dev org header does not open the internal route.
    let r = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(EVENTS)
            .header("content-type", "application/json")
            .header("x-locksmith-dev-org", Uuid::now_v7().to_string())
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");

    // Fail closed: with no token configured, every token is refused.
    let closed = app::build(state(common::unreachable_db(), None));
    for auth in [None, Some(bearer(TOKEN))] {
        let r = post_event(&closed, auth.as_deref(), org, &body).await;
        assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    }
}

/// Bodies outside the allow-list are `400` before any database access, and the problem never
/// echoes the value: free-form strings, a host with a port, path or query, unknown kinds,
/// outcomes or methods, and an outcome that does not fit the kind.
#[tokio::test]
async fn non_allow_listed_bodies_are_400() {
    let app = app::build(state(common::unreachable_db(), Some(TOKEN)));
    let auth = bearer(TOKEN);
    let org = Some(Uuid::now_v7());
    let base = attempt(Uuid::now_v7(), Uuid::now_v7());
    let with = |k: &str, v: Value| {
        let mut b = base.clone();
        b[k] = v;
        b
    };
    for bad in [
        with("url", json!(format!("https://api.example.com/?k={CANARY}"))),
        with("path", json!(format!("/v1/{CANARY}"))),
        with("header", json!(CANARY)),
        with("request_id", json!(CANARY)),
        with("host", json!(CANARY)),
        with("host", json!("api.example.com:443")),
        with("host", json!("api.example.com/v1")),
        with("host", json!(format!("api.example.com?token={CANARY}"))),
        with("kind", json!(CANARY)),
        with("kind", json!("agent.created")),
        with("outcome", json!(CANARY)),
        with("outcome", json!("ok")),
        with("method", json!(CANARY)),
        with("method", json!("CONNECT")),
        with("agent_id", json!(CANARY)),
        with("version", json!(0)),
        with("status", json!(42)),
        json!({"kind": "relay.outcome", "outcome": "pending", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        json!({"kind": "relay.denied", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        json!({"kind": "relay.attempt", "outcome": "pending", "agent_id": Uuid::now_v7()}),
        // Git events: one per call, never pending, and a denial only as `git.denied`.
        json!({"kind": "git.fetch", "outcome": "pending", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        json!({"kind": "git.push", "outcome": "denied", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        json!({"kind": "git.denied", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        // An outcome must name its attempt (the idempotency key).
        json!({"kind": "relay.outcome", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
    ] {
        let r = post_event(&app, Some(&auth), org, &bad).await;
        assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    }
}

/// Git events (D1): `git.fetch`, `git.push` and `git.denied` append to the chain with their own
/// kinds, and carry the host, port and status but no attempt.
#[tokio::test]
async fn git_events_append_to_the_chain() {
    let f = Fixture::start().await;
    let org = f.org("git").await;
    let auth = bearer(TOKEN);
    let (agent, secret) = (Uuid::now_v7(), Uuid::now_v7());
    let base = |kind: &str, outcome: &str| {
        json!({
            "kind": kind, "outcome": outcome, "agent_id": agent, "secret_id": secret,
            "version": 1, "method": "POST", "host": "github.com", "status": 200,
        })
    };
    for (n, (kind, outcome)) in [
        ("git.fetch", "ok"),
        ("git.push", "upstream_timeout"),
        ("git.denied", "denied"),
    ]
    .into_iter()
    .enumerate()
    {
        let r = post_event(&f.app, Some(&auth), Some(org), &base(kind, outcome)).await;
        assert_eq!(
            (r.status, r.body["seq"].as_u64()),
            (StatusCode::CREATED, Some(n as u64 + 1))
        );
    }
    let rows = f.records(org).await;
    assert_intact(&rows);
    let seen: Vec<_> = rows
        .iter()
        .map(|r| (r.kind.as_str(), r.outcome.as_str()))
        .collect();
    assert_eq!(
        seen,
        [
            ("git.fetch", "ok"),
            ("git.push", "upstream_timeout"),
            ("git.denied", "denied")
        ]
    );
}

/// A migrated database and the app as `locksmith_app`.
struct Fixture {
    app: Router,
    pg: common::Pg,
}

impl Fixture {
    async fn start() -> Self {
        let pg = common::Pg::migrated().await;
        let pool = PoolSettings {
            max_connections: 20,
            ..PoolSettings::default()
        };
        let app = app::build(state(pg.app_db(pool), Some(TOKEN)));
        Self { app, pg }
    }

    async fn org(&self, name: &str) -> Uuid {
        let r = send(
            &self.app,
            Request::builder()
                .method("POST")
                .uri("/v1/orgs")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "name": name }).to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
        id(&r)
    }

    /// `org`'s events as the app role bound to `org` (RLS applies).
    async fn records(&self, org: Uuid) -> Vec<Record> {
        let mut c = PgConnection::connect_with(&self.pg.app()).await.unwrap();
        let mut tx = c.begin().await.unwrap();
        ls_audit::pg::bind_org(&mut tx, org).await.unwrap();
        let rows = ls_audit::pg::records_in_tx(&mut tx, org).await.unwrap();
        tx.rollback().await.unwrap();
        rows
    }

    /// Every stored ledger row, all orgs, as text (bootstrap superuser, no RLS).
    async fn ledger_text(&self) -> String {
        let mut c = self.pg.admin().await;
        let text: Option<String> =
            query_scalar("SELECT string_agg(t::text, E'\\n') FROM audit_events t")
                .fetch_one(&mut c)
                .await
                .unwrap();
        c.close().await.unwrap();
        text.unwrap_or_default()
    }
}

fn id(r: &Reply) -> Uuid {
    r.body["id"].as_str().unwrap().parse().unwrap()
}

/// The chain read back from Postgres is seq 1..n, linked from GENESIS, with every recomputed
/// hash equal to the stored one.
fn assert_intact(rows: &[Record]) {
    assert_eq!(
        rows.iter().map(|r| r.seq).collect::<Vec<_>>(),
        (1..=rows.len() as u64).collect::<Vec<_>>()
    );
    let mut prev = GENESIS;
    for r in rows {
        assert_eq!(r.prev_hash, prev, "seq {} link", r.seq);
        assert_eq!(r.compute_hash(), r.hash, "seq {} hash", r.seq);
        prev = r.hash;
    }
    let walk = verify(rows.iter().map(Record::link), &[]);
    assert!(walk.ok(), "{walk:?}");
}

/// Scenario: concurrent appends stay linear, through the endpoint. 50 requests race on one org;
/// the responses carry seq 1..50 exactly once each and the stored chain is intact.
#[tokio::test]
async fn fifty_concurrent_endpoint_appends_give_seq_1_to_50() {
    let f = Fixture::start().await;
    let org = f.org("org-concurrent").await;
    let (agent, secret) = (Uuid::now_v7(), Uuid::now_v7());
    let auth = bearer(TOKEN);

    let mut tasks = Vec::new();
    for n in 0..50u16 {
        let app = f.app.clone();
        let auth = auth.clone();
        let body = json!({
            "kind": "relay.outcome", "outcome": "ok", "agent_id": agent, "secret_id": secret,
            "version": 1, "method": "POST", "host": "api.example.com", "status": 200 + n,
            "attempt_id": Uuid::now_v7(),
        });
        tasks.push(tokio::spawn(async move {
            post_event(&app, Some(&auth), Some(org), &body).await
        }));
    }
    let mut seqs = BTreeSet::new();
    for t in tasks {
        let r = t.await.unwrap();
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
        assert!(seqs.insert(r.body["seq"].as_u64().unwrap()));
    }
    assert_eq!(seqs, (1..=50).collect::<BTreeSet<u64>>());

    let rows = f.records(org).await;
    assert_eq!(rows.len(), 50);
    assert_intact(&rows);
    let r = &rows[0];
    assert_eq!(r.kind, "relay.outcome");
    assert_eq!(r.outcome, "ok");
    assert_eq!(r.actor, format!("agent:{agent}"));
    assert_eq!(r.target.as_deref(), Some(&*format!("secret:{secret}")));
}

/// Scenario: cross-org isolation through the endpoint. Each org's events go to its own chain
/// (both start at seq 1), and an org's binding sees none of the other org's events.
#[tokio::test]
async fn endpoint_appends_are_isolated_per_org() {
    let f = Fixture::start().await;
    let (a, b) = (f.org("a").await, f.org("b").await);
    let auth = bearer(TOKEN);
    let (agent_a, agent_b, secret) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());

    for n in 1..=3u64 {
        let r = post_event(&f.app, Some(&auth), Some(a), &attempt(agent_a, secret)).await;
        assert_eq!(
            (r.status, r.body["seq"].as_u64()),
            (StatusCode::CREATED, Some(n))
        );
    }
    let denied = json!({
        "kind": "relay.denied", "outcome": "no_grant", "agent_id": agent_b, "secret_id": secret,
    });
    let r = post_event(&f.app, Some(&auth), Some(b), &denied).await;
    assert_eq!(
        (r.status, r.body["seq"].as_u64()),
        (StatusCode::CREATED, Some(1))
    );

    let rows_a = f.records(a).await;
    let rows_b = f.records(b).await;
    assert_eq!(rows_a.len(), 3);
    assert_eq!(rows_b.len(), 1);
    assert_intact(&rows_a);
    assert_intact(&rows_b);
    assert!(
        rows_a
            .iter()
            .all(|r| r.org_id == a && r.actor.contains(&agent_a.to_string()))
    );
    assert_eq!(rows_b[0].org_id, b);
    assert_eq!(rows_b[0].kind, "relay.denied");
    assert_eq!(rows_b[0].outcome, "no_grant");

    // RLS: bound to B, reading A's chain by its id returns nothing.
    let mut c = PgConnection::connect_with(&f.pg.app()).await.unwrap();
    let mut tx = c.begin().await.unwrap();
    ls_audit::pg::bind_org(&mut tx, b).await.unwrap();
    assert!(
        ls_audit::pg::records_in_tx(&mut tx, a)
            .await
            .unwrap()
            .is_empty()
    );
    let all: i64 = query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(all, 1);
    tx.rollback().await.unwrap();
}

/// S5 task 3.1 (design decision 5): `relay.outcome` is idempotent on `attempt_id`. A resend
/// with the same fields returns the stored event (`200`, same id and seq) and appends nothing; a
/// different outcome for the same attempt is a `409`; concurrent resends append once. The partial
/// unique index from migration 0009 refuses a second outcome even past the endpoint.
#[tokio::test]
async fn relay_outcome_is_idempotent_on_attempt_id() {
    let f = Fixture::start().await;
    let org = f.org("org-idempotent").await;
    let auth = bearer(TOKEN);
    let (agent, secret) = (Uuid::now_v7(), Uuid::now_v7());
    let a = post_event(&f.app, Some(&auth), Some(org), &attempt(agent, secret)).await;
    assert_eq!(a.status, StatusCode::CREATED, "{}", a.raw);
    let outcome = json!({
        "kind": "relay.outcome", "outcome": "ok", "agent_id": agent, "secret_id": secret,
        "version": 1, "method": "GET", "host": "api.example.com", "status": 200,
        "attempt_id": id(&a),
    });
    let first = post_event(&f.app, Some(&auth), Some(org), &outcome).await;
    assert_eq!(first.status, StatusCode::CREATED, "{}", first.raw);
    let again = post_event(&f.app, Some(&auth), Some(org), &outcome).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.raw);
    assert_eq!(again.body, first.body, "the stored event, not a new one");

    let mut other = outcome.clone();
    other["status"] = json!(502);
    other["outcome"] = json!("upstream_error");
    let r = post_event(&f.app, Some(&auth), Some(org), &other).await;
    assert_problem(&r, StatusCode::CONFLICT, "conflict");

    // Concurrent resends of a second attempt's outcome: one append, every answer the same event.
    let b = post_event(&f.app, Some(&auth), Some(org), &attempt(agent, secret)).await;
    let mut second = outcome.clone();
    second["attempt_id"] = json!(id(&b));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (app, auth, body) = (f.app.clone(), auth.clone(), second.clone());
        tasks.push(tokio::spawn(async move {
            post_event(&app, Some(&auth), Some(org), &body).await
        }));
    }
    let mut ids = BTreeSet::new();
    let mut created = 0;
    for t in tasks {
        let r = t.await.unwrap();
        assert!(
            matches!(r.status, StatusCode::CREATED | StatusCode::OK),
            "{}",
            r.raw
        );
        created += usize::from(r.status == StatusCode::CREATED);
        ids.insert(id(&r));
    }
    assert_eq!((created, ids.len()), (1, 1));

    let rows = f.records(org).await;
    assert_eq!(
        rows.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>(),
        [
            "relay.attempt",
            "relay.outcome",
            "relay.attempt",
            "relay.outcome"
        ]
    );
    assert_intact(&rows);

    // Backstop: a direct append of a second outcome for the first attempt is refused by the
    // unique index (unique_violation), and the chain is unchanged.
    let event = ls_audit::Event {
        kind: ls_audit::kind::RELAY_OUTCOME,
        actor: ls_audit::Actor::Agent(agent),
        target: Some(ls_audit::Target::Secret(secret)),
        outcome: ls_audit::outcome::OK,
        attrs: ls_audit::Attrs::new().id(ls_audit::attr::ATTEMPT_ID, id(&a)),
    };
    let mut c = PgConnection::connect_with(&f.pg.app()).await.unwrap();
    let mut tx = c.begin().await.unwrap();
    ls_audit::pg::bind_org(&mut tx, org).await.unwrap();
    let err = ls_audit::pg::append_in_tx(&mut tx, org, &event)
        .await
        .expect_err("second outcome for one attempt");
    assert_eq!(
        err.as_database_error().and_then(|d| d.code()).as_deref(),
        Some("23505")
    );
    tx.rollback().await.unwrap();
    assert_eq!(f.records(org).await.len(), 4);
}

/// S4 admin requests append `agent.created`, `grant.created`, `agent.rotated`,
/// `grant.revoked`, `grant.created` and `agent.deleted` in order, with ids and codes only. Failed
/// requests (404, 409) append nothing, because the event shares the change's transaction. No
/// stored event contains the canary (used as names and descriptions, and sent to the endpoint
/// in refused bodies) or the enrollment secret.
#[tokio::test]
async fn admin_events_are_chained_and_hold_no_canary() {
    let f = Fixture::start().await;
    let org = f.org("org-admin").await;

    let p = id(&dev(
        &f.app,
        "POST",
        "/v1/projects",
        org,
        Some(json!({"name": CANARY})),
    )
    .await);
    let e = id(&dev(
        &f.app,
        "POST",
        &format!("/v1/projects/{p}/environments"),
        org,
        Some(json!({"name": "dev", "description": CANARY})),
    )
    .await);
    let secret = id(&dev(
        &f.app,
        "POST",
        &format!("/v1/projects/{p}/environments/{e}/secrets"),
        org,
        Some(json!({"name": CANARY, "description": CANARY})),
    )
    .await);

    let r = dev(
        &f.app,
        "POST",
        "/v1/agents",
        org,
        Some(json!({"name": CANARY, "description": CANARY})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    let agent: Uuid = r.body["agent"]["id"].as_str().unwrap().parse().unwrap();
    let mut enrollment = vec![r.body["enrollment_secret"].as_str().unwrap().to_owned()];

    let grants = format!("/v1/agents/{agent}/grants");
    let r = dev(
        &f.app,
        "POST",
        &grants,
        org,
        Some(json!({"secret_id": secret})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    let grant1 = id(&r);
    // A duplicate grant (409) and a grant on a missing secret (404) append nothing.
    let r = dev(
        &f.app,
        "POST",
        &grants,
        org,
        Some(json!({"secret_id": secret})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.raw);
    let r = dev(
        &f.app,
        "POST",
        &grants,
        org,
        Some(json!({"secret_id": Uuid::now_v7()})),
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.raw);

    let r = dev(
        &f.app,
        "POST",
        &format!("/v1/agents/{agent}/enrollment-secret"),
        org,
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    enrollment.push(r.body["enrollment_secret"].as_str().unwrap().to_owned());

    let r = dev(&f.app, "DELETE", &format!("{grants}/{grant1}"), org, None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.raw);
    // Revoking it again, and deleting a missing agent, are 404 and append nothing.
    let r = dev(&f.app, "DELETE", &format!("{grants}/{grant1}"), org, None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = dev(
        &f.app,
        "DELETE",
        &format!("/v1/agents/{}", Uuid::now_v7()),
        org,
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    let expires = "2099-01-01T00:00:00Z";
    let r = dev(
        &f.app,
        "POST",
        &grants,
        org,
        Some(json!({"secret_id": secret, "expires_at": expires})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    let grant2 = id(&r);

    let r = dev(&f.app, "DELETE", &format!("/v1/agents/{agent}"), org, None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.raw);

    // Refused relay bodies carrying the canary store nothing.
    let auth = bearer(TOKEN);
    for bad in [
        json!({"kind": "relay.attempt", "outcome": "pending", "agent_id": agent,
               "secret_id": secret, "host": CANARY}),
        json!({"kind": "relay.attempt", "outcome": "pending", "agent_id": agent,
               "secret_id": secret, "query": CANARY}),
    ] {
        let r = post_event(&f.app, Some(&auth), Some(org), &bad).await;
        assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    }

    let rows = f.records(org).await;
    assert_intact(&rows);
    let actor = "service:dev_auth";
    let summary: Vec<(&str, &str, Option<&str>, &str)> = rows
        .iter()
        .map(|r| (&*r.kind, &*r.actor, r.target.as_deref(), &*r.outcome))
        .collect();
    let (ag, g1, g2) = (
        format!("agent:{agent}"),
        format!("grant:{grant1}"),
        format!("grant:{grant2}"),
    );
    assert_eq!(
        summary,
        [
            ("agent.created", actor, Some(&*ag), "ok"),
            ("grant.created", actor, Some(&*g1), "ok"),
            ("agent.rotated", actor, Some(&*ag), "ok"),
            ("grant.revoked", actor, Some(&*g1), "ok"),
            ("grant.created", actor, Some(&*g2), "ok"),
            ("agent.deleted", actor, Some(&*ag), "ok"),
        ]
    );
    let attrs = |i: usize| rows[i].attrs.as_ref().unwrap().to_json();
    assert_eq!(
        attrs(1),
        json!({"agent_id": {"id": agent}, "mode": {"code": "relay"}, "secret_id": {"id": secret}})
    );
    assert_eq!(attrs(3), json!({"agent_id": {"id": agent}}));
    assert_eq!(attrs(4)["expires_at"], json!({"int": 4_070_908_800_i64}));
    assert_eq!(attrs(5), json!({"grants_revoked": {"int": 1}}));

    // Canary and enrollment secrets appear in no stored event, of any org.
    let text = f.ledger_text().await;
    assert_eq!(text.lines().count(), 6, "{text}");
    assert!(!text.contains(CANARY));
    for s in &enrollment {
        assert!(!text.contains(s.as_str()));
    }
}

/// S5 task 6.1: `GET /v1/audit/events` pages the bound org's events newest first and never shows
/// another org's; `GET /v1/audit/status` reports the head, the latest checkpoint and the latest
/// verify run.
#[tokio::test]
async fn audit_read_api_pages_newest_first_and_is_org_scoped() {
    let f = Fixture::start().await;
    let (a, b) = (f.org("a").await, f.org("b").await);
    let auth = bearer(TOKEN);
    let (agent, secret) = (Uuid::now_v7(), Uuid::now_v7());
    for _ in 0..5 {
        let r = post_event(&f.app, Some(&auth), Some(a), &attempt(agent, secret)).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    }
    let denied = json!({
        "kind": "relay.denied", "outcome": "no_grant", "agent_id": agent, "secret_id": secret,
    });
    assert_eq!(
        post_event(&f.app, Some(&auth), Some(b), &denied)
            .await
            .status,
        StatusCode::CREATED
    );

    // Pages of 2: seq 5,4 then 3,2 then 1; `next` only while more remain.
    let mut seen = Vec::new();
    let mut uri = "/v1/audit/events?limit=2".to_owned();
    loop {
        let r = dev(&f.app, "GET", &uri, a, None).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
        let items = r.body["items"].as_array().unwrap();
        assert!(items.len() <= 2);
        seen.extend(items.iter().map(|e| e["seq"].as_i64().unwrap()));
        match r.body["next"].as_str() {
            Some(n) => uri = format!("/v1/audit/events?limit=2&cursor={n}"),
            None => break,
        }
    }
    assert_eq!(seen, [5, 4, 3, 2, 1]);

    let r = dev(&f.app, "GET", "/v1/audit/events", a, None).await;
    let first = &r.body["items"][0];
    assert_eq!(first["kind"], "relay.attempt");
    assert_eq!(first["outcome"], "pending");
    assert_eq!(first["actor"], format!("agent:{agent}"));
    assert_eq!(first["target"], format!("secret:{secret}"));
    assert_eq!(first["attrs"]["host"]["host"], "api.example.com");
    let recs = f.records(a).await;
    assert_eq!(first["digest"], hex::encode(recs[4].hash));
    assert_eq!(first["prev_digest"], hex::encode(recs[3].hash));
    assert!(r.body.get("next").is_none());

    // Org B sees only its own event.
    let r = dev(&f.app, "GET", "/v1/audit/events", b, None).await;
    assert_eq!(r.body["items"].as_array().unwrap().len(), 1);
    assert_eq!(r.body["items"][0]["kind"], "relay.denied");

    for bad in [
        "/v1/audit/events?limit=0",
        "/v1/audit/events?limit=101",
        "/v1/audit/events?cursor=not-a-cursor",
        "/v1/audit/events?unknown=1",
    ] {
        let r = dev(&f.app, "GET", bad, a, None).await;
        assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    }
    // No org binding: 401.
    let r = send(
        &f.app,
        Request::builder()
            .uri("/v1/audit/events")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");

    // Status: no checkpoint and no verify run yet.
    let r = dev(&f.app, "GET", "/v1/audit/status", a, None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(r.body, json!({"head_seq": 5}));
    let r = dev(&f.app, "GET", "/v1/audit/status", Uuid::now_v7(), None).await;
    assert_eq!(r.body, json!({"head_seq": 0}));

    // Seed a checkpoint (app role) and two verify runs (owner); the newest run wins, and org B
    // sees neither.
    let mut c = PgConnection::connect_with(&f.pg.app()).await.unwrap();
    let mut tx = c.begin().await.unwrap();
    ls_audit::pg::bind_org(&mut tx, a).await.unwrap();
    sqlx_core::query::query(
        "INSERT INTO audit_checkpoints (org_id, seq, hash, at, key_id, signature) \
         VALUES ($1, 5, $2, now(), 'audit-checkpoint:1', $3)",
    )
    .bind(a)
    .bind(recs[4].hash.as_slice())
    .bind([7u8; 64].as_slice())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let mut o = PgConnection::connect_with(&f.pg.owner()).await.unwrap();
    for (ok, finished, broken) in [
        (false, "2026-01-01T00:00:00Z", Some(3i64)),
        (true, "2026-01-02T00:00:00Z", None),
    ] {
        let mut tx = o.begin().await.unwrap();
        ls_audit::pg::bind_org(&mut tx, a).await.unwrap();
        sqlx_core::query::query(
            "INSERT INTO audit_verify_runs (org_id, mode, started_at, finished_at, ok, events, \
             checkpoints, broken_seq, break_kind) \
             VALUES ($1, 'db', $2::timestamptz, $2::timestamptz, $3, 5, 1, $4, \
             CASE WHEN $4::bigint IS NULL THEN NULL ELSE 'hash' END)",
        )
        .bind(a)
        .bind(finished)
        .bind(ok)
        .bind(broken)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let r = dev(&f.app, "GET", "/v1/audit/status", a, None).await;
    assert_eq!(r.body["head_seq"], 5);
    assert_eq!(r.body["latest_checkpoint"]["seq"], 5);
    assert_eq!(
        r.body["latest_checkpoint"]["digest"],
        hex::encode(recs[4].hash)
    );
    assert_eq!(r.body["latest_checkpoint"]["key_id"], "audit-checkpoint:1");
    assert!(r.body["latest_checkpoint"].get("signature").is_none());
    let v = &r.body["latest_verify"];
    assert_eq!(
        (v["ok"].clone(), v["mode"].clone()),
        (json!(true), json!("db"))
    );
    assert_eq!(
        (v["events"].clone(), v["checkpoints"].clone()),
        (json!(5), json!(1))
    );
    assert_eq!(v["finished_at"], "2026-01-02T00:00:00Z");
    assert!(v.get("broken_seq").is_none());
    let r = dev(&f.app, "GET", "/v1/audit/status", b, None).await;
    assert_eq!(r.body, json!({"head_seq": 1}));
}
