//! T8 task 2.2: revoke-one, revoke-all, pause and resume (authorization, ledger events,
//! idempotency, the grant-set fields the gateway reads, jti canaries, org isolation). Postgres
//! backed (testcontainers; needs Docker) except where noted.

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ls_control_plane::app::{self, AppState};
use ls_control_plane::auth::ServiceToken;
use ls_control_plane::auth::human::{HumanAuth, HumanAuthConfig};
use ls_control_plane::db::PoolSettings;
use ls_control_plane::readiness::ReadyFlag;
use p256::pkcs8::EncodePrivateKey as _;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// Test-only token value.
const TOKEN: &str = "test-only-gateway-service-token-0123456789";
const ISSUER: &str = "https://idp.test/realms/locksmith";
const AUDIENCE: &str = "locksmith-api";

struct Reply {
    status: StatusCode,
    body: Value,
    raw: String,
}

async fn call(app: &Router, req: Request<Body>) -> Reply {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        raw: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

/// An org member's request (dev auth), `POST` with no body unless `body` is given.
async fn member(app: &Router, org: Uuid, method: &str, uri: &str, body: Option<Value>) -> Reply {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-locksmith-dev-org", org.to_string())
        .header("content-type", "application/json")
        .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
        .unwrap();
    call(app, req).await
}

async fn report(app: &Router, org: Uuid, body: Value) -> Reply {
    let req = Request::builder()
        .method("POST")
        .uri("/internal/v1/sessions")
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("x-locksmith-org", org.to_string())
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    call(app, req).await
}

/// The grant set as the gateway fetches it.
async fn grant_set(app: &Router, org: Uuid, agent: Uuid) -> Reply {
    let req = Request::builder()
        .uri(format!("/internal/v1/agents/{agent}/grants"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("x-locksmith-org", org.to_string())
        .body(Body::empty())
        .unwrap();
    call(app, req).await
}

fn id_of(r: &Reply) -> Uuid {
    let v = if r.body["agent"].is_object() {
        &r.body["agent"]["id"]
    } else {
        &r.body["id"]
    };
    v.as_str().unwrap().parse().unwrap()
}

async fn open(f: &Fixture, org: Uuid, agent: Uuid, jti: Uuid, slug: &str) -> Uuid {
    let r = report(
        &f.app,
        org,
        json!({"event": "open", "agent_id": agent, "token_jti": jti, "kind": "http", "slug": slug}),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    id_of(&r)
}

struct TestKey(p256::ecdsa::SigningKey);

impl TestKey {
    fn jwks(&self) -> Value {
        let point = self.0.verifying_key().to_sec1_point(false);
        json!({"keys": [{
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }]})
    }

    fn mint(&self, sub: &str, email_verified: bool) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": sub, "exp": now + 600,
            "email": format!("{sub}@example.com"), "email_verified": email_verified,
        });
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("k1".to_owned());
        let der = self.0.to_pkcs8_der().unwrap();
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ec_der(der.as_bytes())).unwrap()
    }
}

struct Fixture {
    app: Router,
    pg: common::Pg,
    // Keeps the mock issuer alive.
    _issuer: MockServer,
    key: TestKey,
    org_a: Uuid,
    org_b: Uuid,
    agent_a: Uuid,
    agent_b: Uuid,
}

impl Fixture {
    async fn start() -> Self {
        let pg = common::Pg::migrated().await;
        let key = TestKey(p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap());
        let issuer = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(key.jwks()))
            .mount(&issuer)
            .await;
        let human = HumanAuth::with_refresh(
            &HumanAuthConfig {
                issuer: ISSUER.to_owned(),
                audience: AUDIENCE.to_owned(),
                jwks_url: format!("{}/jwks", issuer.uri()),
            },
            Duration::from_secs(1),
            Duration::from_secs(3600),
        )
        .unwrap();
        let state = AppState::new(
            true,
            Arc::new(ReadyFlag::new(true)),
            pg.app_db(PoolSettings::default()),
        )
        .with_service_token(ServiceToken::new(SecretString::from(TOKEN)))
        .with_human_auth(human);
        let app = app::build(state);
        let mut f = Self {
            app,
            pg,
            _issuer: issuer,
            key,
            org_a: Uuid::nil(),
            org_b: Uuid::nil(),
            agent_a: Uuid::nil(),
            agent_b: Uuid::nil(),
        };
        f.org_a = f.create("/v1/orgs", None, json!({"name": "a"})).await;
        f.org_b = f.create("/v1/orgs", None, json!({"name": "b"})).await;
        f.agent_a = f
            .create("/v1/agents", Some(f.org_a), json!({"name": "agent-a"}))
            .await;
        f.agent_b = f
            .create("/v1/agents", Some(f.org_b), json!({"name": "agent-b"}))
            .await;
        f
    }

    async fn create(&self, uri: &str, org: Option<Uuid>, body: Value) -> Uuid {
        let mut b = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(o) = org {
            b = b.header("x-locksmith-dev-org", o.to_string());
        }
        let r = call(&self.app, b.body(Body::from(body.to_string())).unwrap()).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
        id_of(&r)
    }

    /// Ledger event kinds of an org, oldest first (owner connection, tests only).
    async fn ledger_kinds(&self, org: Uuid) -> Vec<String> {
        let mut c = self.pg.admin().await;
        let rows: Vec<(String,)> = sqlx_core::query_as::query_as(
            "SELECT kind FROM audit_events WHERE org_id = $1 ORDER BY seq",
        )
        .bind(org)
        .fetch_all(&mut c)
        .await
        .unwrap();
        c.close().await.unwrap();
        rows.into_iter().map(|r| r.0).collect()
    }

    async fn count(&self, org: Uuid, kind: &str) -> usize {
        self.ledger_kinds(org)
            .await
            .iter()
            .filter(|k| *k == kind)
            .count()
    }
}

#[tokio::test]
async fn sessions_admin_unverified_human_gets_403_and_nothing_changes() {
    let f = Fixture::start().await;
    let jti = Uuid::now_v7();
    let sid = open(&f, f.org_a, f.agent_a, jti, "x").await;
    let routes = [
        format!("/v1/sessions/{sid}/revoke"),
        "/v1/sessions/revoke-all".to_owned(),
        "/v1/orgs/current/agents/pause".to_owned(),
        "/v1/orgs/current/agents/resume".to_owned(),
    ];
    // A person the issuer has not verified is no member: 403 from the org binding.
    let bearer = format!("Bearer {}", f.key.mint("not-a-member", false));
    for uri in &routes {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("authorization", &bearer)
            .body(Body::empty())
            .unwrap();
        let r = call(&f.app, req).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{uri}: {}", r.raw);
        // No credentials at all: 401.
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        assert_eq!(call(&f.app, req).await.status, StatusCode::UNAUTHORIZED);
    }
    // Nothing changed: not revoked, not paused, no events beyond org setup.
    let gs = grant_set(&f.app, f.org_a, f.agent_a).await;
    assert_eq!(gs.body["revoked_jtis"], json!([]), "{}", gs.raw);
    assert_eq!(gs.body["agents_paused"], false);
    for k in ["session.revoked", "agents.paused", "agents.resumed"] {
        assert_eq!(f.count(f.org_a, k).await, 0, "{k}");
    }
}

#[tokio::test]
async fn sessions_admin_verified_human_can_pause_in_their_own_org() {
    let f = Fixture::start().await;
    let bearer = format!("Bearer {}", f.key.mint("member-1", true));
    let req = Request::builder()
        .method("POST")
        .uri("/v1/orgs/current/agents/pause")
        .header("authorization", bearer)
        .body(Body::empty())
        .unwrap();
    let r = call(&f.app, req).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(r.body["agents_paused"], true);
    // Their personal org only; the fixture's orgs are untouched.
    assert_eq!(f.count(f.org_a, "agents.paused").await, 0);
}

#[tokio::test]
async fn sessions_admin_revoke_one_ledger_grant_set_and_canary() {
    let f = Fixture::start().await;
    let jti = Uuid::now_v7();
    let other_jti = Uuid::now_v7();
    let sid = open(&f, f.org_a, f.agent_a, jti, "github-api").await;
    let _other = open(&f, f.org_a, f.agent_a, other_jti, "pg").await;

    // Before: nothing revoked, not paused.
    let gs = grant_set(&f.app, f.org_a, f.agent_a).await;
    assert_eq!(gs.status, StatusCode::OK, "{}", gs.raw);
    assert_eq!(gs.body["revoked_jtis"], json!([]));
    assert_eq!(gs.body["agents_paused"], false);

    let r = member(
        &f.app,
        f.org_a,
        "POST",
        &format!("/v1/sessions/{sid}/revoke"),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(r.body["id"], sid.to_string());
    assert_eq!(r.body["agent_id"], f.agent_a.to_string());
    assert_eq!(r.body["live"], false);
    assert!(!r.raw.contains("jti"));

    // After: exactly that jti is listed for the gateway.
    let gs = grant_set(&f.app, f.org_a, f.agent_a).await;
    assert_eq!(
        gs.body["revoked_jtis"],
        json!([jti.to_string()]),
        "{}",
        gs.raw
    );

    // One ledger event; revoking again is a no-op with no second event.
    assert_eq!(f.count(f.org_a, "session.revoked").await, 1);
    let again = member(
        &f.app,
        f.org_a,
        "POST",
        &format!("/v1/sessions/{sid}/revoke"),
        None,
    )
    .await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.raw);
    assert_eq!(f.count(f.org_a, "session.revoked").await, 1);

    // Canary: no human-API response carries either jti.
    let list = member(&f.app, f.org_a, "GET", "/v1/sessions", None).await;
    let audit = member(&f.app, f.org_a, "GET", "/v1/audit/events", None).await;
    for resp in [&r, &again, &list, &audit] {
        for j in [jti, other_jti] {
            assert!(
                !resp.raw.contains(&j.to_string()),
                "leaked a jti: {}",
                resp.raw
            );
        }
    }
    let item = list.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == sid.to_string())
        .unwrap();
    assert_eq!(item["live"], false);

    // Unknown session: 404.
    let r = member(
        &f.app,
        f.org_a,
        "POST",
        &format!("/v1/sessions/{}/revoke", Uuid::now_v7()),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.raw);
}

#[tokio::test]
async fn sessions_admin_revoke_all_counts_and_records() {
    let f = Fixture::start().await;
    let j1 = Uuid::now_v7();
    let j2 = Uuid::now_v7();
    let s1 = open(&f, f.org_a, f.agent_a, j1, "a").await;
    open(&f, f.org_a, f.agent_a, j2, "b").await;
    // Already revoked sessions are not counted again.
    member(
        &f.app,
        f.org_a,
        "POST",
        &format!("/v1/sessions/{s1}/revoke"),
        None,
    )
    .await;

    let r = member(&f.app, f.org_a, "POST", "/v1/sessions/revoke-all", None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(r.body, json!({"revoked": 1}));
    assert_eq!(f.count(f.org_a, "session.revoked").await, 2);

    let gs = grant_set(&f.app, f.org_a, f.agent_a).await;
    let mut got: Vec<String> = serde_json::from_value(gs.body["revoked_jtis"].clone()).unwrap();
    got.sort();
    let mut want = vec![j1.to_string(), j2.to_string()];
    want.sort();
    assert_eq!(got, want, "{}", gs.raw);

    let list = member(&f.app, f.org_a, "GET", "/v1/sessions", None).await;
    assert!(
        list.body["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["live"] == false)
    );
    assert!(!r.raw.contains(&j1.to_string()) && !list.raw.contains(&j2.to_string()));

    // Nothing left to revoke: zero, still recorded.
    let r = member(&f.app, f.org_a, "POST", "/v1/sessions/revoke-all", None).await;
    assert_eq!(r.body, json!({"revoked": 0}));
    assert_eq!(f.count(f.org_a, "session.revoked").await, 3);
}

#[tokio::test]
async fn sessions_admin_pause_resume_idempotent_with_events() {
    let f = Fixture::start().await;
    let pause = "/v1/orgs/current/agents/pause";
    let resume = "/v1/orgs/current/agents/resume";

    // Resume while not paused: ok, no event.
    let r = member(&f.app, f.org_a, "POST", resume, None).await;
    assert_eq!(r.body, json!({"agents_paused": false}), "{}", r.raw);
    assert_eq!(f.count(f.org_a, "agents.resumed").await, 0);

    for _ in 0..2 {
        let r = member(&f.app, f.org_a, "POST", pause, None).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
        assert_eq!(r.body, json!({"agents_paused": true}));
    }
    assert_eq!(f.count(f.org_a, "agents.paused").await, 1);
    let gs = grant_set(&f.app, f.org_a, f.agent_a).await;
    assert_eq!(gs.body["agents_paused"], true, "{}", gs.raw);

    for _ in 0..2 {
        let r = member(&f.app, f.org_a, "POST", resume, None).await;
        assert_eq!(r.body, json!({"agents_paused": false}));
    }
    assert_eq!(f.count(f.org_a, "agents.resumed").await, 1);
    let gs = grant_set(&f.app, f.org_a, f.agent_a).await;
    assert_eq!(gs.body["agents_paused"], false);
}

#[tokio::test]
async fn sessions_admin_is_isolated_between_orgs() {
    let f = Fixture::start().await;
    let jti_b = Uuid::now_v7();
    let sid_b = open(&f, f.org_b, f.agent_b, jti_b, "b-only").await;
    let jti_a = Uuid::now_v7();
    open(&f, f.org_a, f.agent_a, jti_a, "a-only").await;

    // Org A cannot revoke org B's session.
    let r = member(
        &f.app,
        f.org_a,
        "POST",
        &format!("/v1/sessions/{sid_b}/revoke"),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.raw);

    // Org A's revoke-all and pause leave org B alone.
    let r = member(&f.app, f.org_a, "POST", "/v1/sessions/revoke-all", None).await;
    assert_eq!(r.body, json!({"revoked": 1}));
    member(
        &f.app,
        f.org_a,
        "POST",
        "/v1/orgs/current/agents/pause",
        None,
    )
    .await;

    let gs_b = grant_set(&f.app, f.org_b, f.agent_b).await;
    assert_eq!(gs_b.body["revoked_jtis"], json!([]), "{}", gs_b.raw);
    assert_eq!(gs_b.body["agents_paused"], false);
    assert!(!gs_b.raw.contains(&jti_a.to_string()));
    let list_b = member(&f.app, f.org_b, "GET", "/v1/sessions", None).await;
    assert_eq!(list_b.body["items"][0]["live"], true, "{}", list_b.raw);
    for k in ["session.revoked", "agents.paused"] {
        assert_eq!(f.count(f.org_b, k).await, 0, "{k}");
    }
    // And org A's grant set carries its own state only.
    let gs_a = grant_set(&f.app, f.org_a, f.agent_a).await;
    assert_eq!(gs_a.body["revoked_jtis"], json!([jti_a.to_string()]));
    assert!(!gs_a.raw.contains(&jti_b.to_string()));
}
