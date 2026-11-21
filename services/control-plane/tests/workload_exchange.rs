//! D4 task 3.3: `POST /v1/workload-tokens` against a wiremock stub issuer and a throwaway
//! `postgres:18` container (testcontainers; needs Docker). The minted token verifies with the
//! gateway verifier and carries only the agent claims; policy delete and grant revoke cut access;
//! every failure body is identical; the external token appears in no log line or ledger row.

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ls_control_plane::agent_token::{AUDIENCE, AgentTokenSigner, JwkSet, verify};
use ls_control_plane::app::{self, AppState};
use ls_control_plane::auth::ServiceToken;
use ls_control_plane::auth::external::{DEFAULT_MAX_LIFETIME, ExternalVerifier};
use ls_control_plane::auth::issuers::{IssuerAccess, IssuerRegistry};
use ls_control_plane::db::{PoolSettings, sql};
use ls_control_plane::readiness::ReadyFlag;
use ls_control_plane::workload::encode_handle;
use p256::pkcs8::EncodePrivateKey as _;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zeroize::Zeroizing;

// Test-only values.
const SERVICE_TOKEN: &str = "test-only-gateway-service-token-0123456789";
const AUD: &str = "https://locksmith.example";
const DEV: IssuerAccess = IssuerAccess {
    allow_private_hosts: true,
};

struct TestKey {
    kid: String,
    signing: p256::ecdsa::SigningKey,
}

impl TestKey {
    fn new(kid: &str, seed: u8) -> Self {
        Self {
            kid: kid.to_owned(),
            signing: p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap(),
        }
    }

    fn jwk(&self) -> Value {
        let point = self.signing.verifying_key().to_sec1_point(false);
        json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": self.kid,
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        })
    }

    fn mint(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        let der = self.signing.to_pkcs8_der().unwrap();
        jsonwebtoken::encode(&header, claims, &EncodingKey::from_ec_der(der.as_bytes())).unwrap()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A stub OpenID issuer: discovery plus one JWKS.
async fn stub_issuer(key: &TestKey) -> MockServer {
    let server = MockServer::start().await;
    let url = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": url, "jwks_uri": format!("{url}/jwks"),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [key.jwk()] })))
        .mount(&server)
        .await;
    server
}

/// GitHub-shaped claims for `issuer`. `canary` rides in `actor`, a claim no policy names.
fn claims(issuer: &str, git_ref: &str) -> Value {
    let t = now();
    json!({
        "iss": issuer, "aud": AUD, "sub": format!("repo:acme/api:ref:{git_ref}"),
        "repository": "acme/api", "ref": git_ref, "actor": "canary-actor-name",
        "jti": format!("jti-{t}"), "iat": t, "nbf": t, "exp": t + 600,
    })
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
    raw: String,
}

async fn send(app: &Router, req: Request<Body>) -> Reply {
    let resp = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        raw: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    org: Option<Uuid>,
    body: Option<Value>,
) -> Reply {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(o) = org {
        b = b.header("x-locksmith-dev-org", o.to_string());
    }
    let req = match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(v.to_string())),
        None => b.body(Body::empty()),
    }
    .unwrap();
    send(app, req).await
}

async fn exchange(app: &Router, policy: &str, token: &str) -> Reply {
    call(
        app,
        "POST",
        "/v1/workload-tokens",
        None,
        Some(json!({ "policy": policy, "token": token })),
    )
    .await
}

fn signer() -> AgentTokenSigner {
    AgentTokenSigner::from_seed(Zeroizing::new([0x5a; 32])).unwrap()
}

fn state(db: ls_control_plane::db::Database, access: IssuerAccess) -> AppState {
    AppState::new(true, Arc::new(ReadyFlag::new(true)), db)
        .with_service_token(ServiceToken::new(SecretString::from(SERVICE_TOKEN)))
        .with_agent_signer(signer())
        .with_workload_verifier(ExternalVerifier::new(
            IssuerRegistry::new(access).unwrap(),
            DEFAULT_MAX_LIFETIME,
        ))
}

struct Fixture {
    pg: common::Pg,
    app: Router,
    org: Uuid,
    agent: Uuid,
    grant: Uuid,
    key: TestKey,
    issuer: MockServer,
    policy: Uuid,
}

impl Fixture {
    async fn start() -> Self {
        let pg = common::Pg::migrated().await;
        let app = app::build(state(pg.app_db(PoolSettings::default()), DEV));
        let org = id(call(&app, "POST", "/v1/orgs", None, Some(json!({"name": "a"}))).await);
        let p = id(call(
            &app,
            "POST",
            "/v1/projects",
            Some(org),
            Some(json!({"name": "p"})),
        )
        .await);
        let e = id(call(
            &app,
            "POST",
            &format!("/v1/projects/{p}/environments"),
            Some(org),
            Some(json!({"name": "dev"})),
        )
        .await);
        let secret = id(call(
            &app,
            "POST",
            &format!("/v1/projects/{p}/environments/{e}/secrets"),
            Some(org),
            Some(json!({"name": "UPSTREAM_KEY"})),
        )
        .await);
        let r = call(
            &app,
            "POST",
            "/v1/agents",
            Some(org),
            Some(json!({"name": "ci"})),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
        let agent: Uuid = r.body["agent"]["id"].as_str().unwrap().parse().unwrap();
        let g = call(
            &app,
            "POST",
            &format!("/v1/agents/{agent}/grants"),
            Some(org),
            Some(json!({ "secret_id": secret })),
        )
        .await;
        assert_eq!(g.status, StatusCode::CREATED, "{}", g.raw);
        let key = TestKey::new("k1", 7);
        let issuer = stub_issuer(&key).await;
        let policy = insert_policy(&pg, org, agent, &issuer.uri(), "ci").await;
        Self {
            pg,
            app,
            org,
            agent,
            grant: g.body["id"].as_str().unwrap().parse().unwrap(),
            key,
            issuer,
            policy,
        }
    }

    fn handle(&self) -> String {
        encode_handle(self.org, self.policy)
    }

    fn token(&self, git_ref: &str) -> String {
        self.key.mint(&claims(&self.issuer.uri(), git_ref))
    }

    /// The agent's grants as the gateway would look them up.
    async fn grants(&self) -> Value {
        let req = Request::builder()
            .uri(format!("/internal/v1/agents/{}/grants", self.agent))
            .header("x-locksmith-org", self.org.to_string())
            .header("authorization", format!("Bearer {SERVICE_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        send(&self.app, req).await.body["items"].clone()
    }

    /// `(kind, outcome, actor, attrs)` of the org's ledger, read as the superuser.
    async fn ledger(&self) -> Vec<(String, String, String, String)> {
        let mut c = self.pg.admin().await;
        let rows = sql::query_as(
            "SELECT kind, outcome, actor, attrs::text FROM audit_events \
             WHERE org_id = $1 ORDER BY seq",
        )
        .bind(self.org)
        .fetch_all(&mut c)
        .await
        .unwrap();
        c.close().await.unwrap();
        rows
    }

    async fn dump_text(&self) -> String {
        let mut c = self.pg.admin().await;
        let tables: Vec<String> = sql::query_scalar(
            "SELECT tablename::text FROM pg_tables WHERE schemaname = 'public' ORDER BY 1",
        )
        .fetch_all(&mut c)
        .await
        .unwrap();
        let mut out = String::new();
        for table in tables {
            let rows: Vec<String> = sql::query_scalar(sqlx_core::sql_str::AssertSqlSafe(format!(
                "SELECT t::text FROM {table} t"
            )))
            .fetch_all(&mut c)
            .await
            .unwrap();
            out.push_str(&rows.join("\n"));
            out.push('\n');
        }
        c.close().await.unwrap();
        out
    }
}

fn id(r: Reply) -> Uuid {
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    r.body["id"].as_str().unwrap().parse().unwrap()
}

/// A policy on the (plain http, loopback) stub issuer, written as the superuser: the create API
/// requires an https issuer.
async fn insert_policy(pg: &common::Pg, org: Uuid, agent: Uuid, issuer: &str, name: &str) -> Uuid {
    let policy = Uuid::now_v7();
    let mut c = pg.admin().await;
    // The table only stores https issuers; the stub is plain http on loopback (test only).
    sql::query("ALTER TABLE workload_identities DROP CONSTRAINT IF EXISTS workload_identities_issuer_check")
        .execute(&mut c)
        .await
        .unwrap();
    sql::query(
        "INSERT INTO workload_identities \
         (id, org_id, name, issuer_kind, issuer, audience, agent_id, conditions) \
         VALUES ($1, $2, $3, 'oidc', $4, $5, $6, $7::jsonb)",
    )
    .bind(policy)
    .bind(org)
    .bind(name)
    .bind(issuer)
    .bind(AUD)
    .bind(agent)
    .bind(
        json!([
            {"claim": "repository", "op": "eq", "value": "acme/api"},
            {"claim": "ref", "op": "eq", "value": "refs/heads/main"},
        ])
        .to_string(),
    )
    .execute(&mut c)
    .await
    .unwrap();
    c.close().await.unwrap();
    policy
}

fn payload(token: &str) -> Value {
    let part = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
}

fn keys(v: &Value) -> Vec<&str> {
    let mut k: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    k.sort_unstable();
    k
}

#[tokio::test]
async fn workload_exchange_mints_a_gateway_verifiable_agent_token() {
    let capture = common::Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let f = Fixture::start().await;
    let external = f.token("refs/heads/main");
    let r = exchange(&f.app, &f.handle(), &external).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(r.headers["cache-control"], "no-store");
    assert_eq!(
        keys(&r.body),
        ["access_token", "expires_at", "expires_in", "token_type"]
    );
    assert_eq!(r.body["expires_in"], 900);
    let token = r.body["access_token"].as_str().unwrap();

    // Verifies with the gateway's verifier and the served JWKS; only the agent claims.
    let jwks = call(&f.app, "GET", "/.well-known/jwks.json", None, None).await;
    let set: JwkSet = serde_json::from_value(jwks.body).unwrap();
    let claims = verify(token, &set.keys[0].decoding_key().unwrap()).unwrap();
    assert_eq!((claims.sub, claims.org), (f.agent, f.org));
    assert_eq!(claims.aud, AUDIENCE);
    assert_eq!(claims.exp - claims.iat, 15 * 60);
    assert_eq!(keys(&payload(token)), ["aud", "exp", "iat", "org", "sub"]);
    assert!(!r.raw.contains("canary-actor-name"));

    // The agent's grants (not the token) decide what it can do: unchanged.
    assert_eq!(f.grants().await.as_array().unwrap().len(), 1);

    // last_used_at is set, and only once within the throttle window.
    let got = call(
        &f.app,
        "GET",
        &format!("/v1/workload-identities/{}", f.policy),
        Some(f.org),
        None,
    )
    .await;
    let first = got.body["last_used_at"].as_str().unwrap().to_owned();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        exchange(&f.app, &f.handle(), &f.token("refs/heads/main"))
            .await
            .status,
        StatusCode::OK
    );
    let got = call(
        &f.app,
        "GET",
        &format!("/v1/workload-identities/{}", f.policy),
        Some(f.org),
        None,
    )
    .await;
    assert_eq!(got.body["last_used_at"], first.as_str());

    // Ledger: two `exchanged` events with ids and the issuer host only.
    let events: Vec<_> = f
        .ledger()
        .await
        .into_iter()
        .filter(|e| e.0 == "workload_identity.exchanged")
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].1, "ok");
    assert_eq!(events[0].2, format!("agent:{}", f.agent));
    assert!(events[0].3.contains(&f.agent.to_string()));

    // The external token is in no log line and no stored row; the claims logged are the ones
    // the policy names.
    let logs = capture.contents();
    let ledger_and_rows = f.dump_text().await;
    for haystack in [&logs, &ledger_and_rows] {
        assert!(!haystack.contains(&external), "external token leaked");
        assert!(!haystack.contains(external.split('.').nth(2).unwrap()));
        assert!(!haystack.contains("canary-actor-name"));
    }
    assert!(logs.contains("exchange_workload_token"));
    assert!(logs.contains("repository=acme/api ref=refs/heads/main"));
}

#[tokio::test]
async fn workload_exchange_every_failure_is_the_same_401() {
    let capture = common::Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let f = Fixture::start().await;
    let url = f.issuer.uri();
    let good_handle = f.handle();
    let other_key = TestKey::new("k1", 9);

    // A policy whose issuer is unreachable (nothing listens on port 9).
    let down = insert_policy(&f.pg, f.org, f.agent, "http://127.0.0.1:9", "down").await;
    // The policy handle of another org.
    let other_org = id(call(&f.app, "POST", "/v1/orgs", None, Some(json!({"name": "b"}))).await);

    let mut wrong_aud = claims(&url, "refs/heads/main");
    wrong_aud["aud"] = json!("https://other.example");
    let mut expired = claims(&url, "refs/heads/main");
    let t = now() - 3000;
    expired["iat"] = json!(t);
    expired["nbf"] = json!(t);
    expired["exp"] = json!(t + 600);
    let wrong_iss = claims("https://attacker.example", "refs/heads/main");

    let cases: Vec<(&str, String, String)> = vec![
        (
            "wrong ref",
            good_handle.clone(),
            f.token("refs/heads/feature"),
        ),
        ("wrong aud", good_handle.clone(), f.key.mint(&wrong_aud)),
        ("expired", good_handle.clone(), f.key.mint(&expired)),
        ("wrong iss", good_handle.clone(), f.key.mint(&wrong_iss)),
        (
            "forged signature",
            good_handle.clone(),
            other_key.mint(&claims(&url, "refs/heads/main")),
        ),
        ("garbage token", good_handle.clone(), "not-a-jwt".into()),
        ("empty token", good_handle.clone(), String::new()),
        (
            "issuer down",
            encode_handle(f.org, down),
            f.key.mint(&claims("http://127.0.0.1:9", "refs/heads/main")),
        ),
        (
            "unknown policy",
            encode_handle(f.org, Uuid::now_v7()),
            f.token("refs/heads/main"),
        ),
        (
            "policy of another org",
            encode_handle(other_org, f.policy),
            f.token("refs/heads/main"),
        ),
        (
            "malformed handle",
            "lsw_nope".into(),
            f.token("refs/heads/main"),
        ),
        ("no handle", String::new(), f.token("refs/heads/main")),
    ];
    let mut first: Option<(String, Value)> = None;
    for (name, handle, token) in &cases {
        let r = exchange(&f.app, handle, token).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{name}: {}", r.raw);
        assert_eq!(
            r.body["type"], "urn:locksmith:problem:unauthenticated",
            "{name}"
        );
        let shape = (r.raw.clone(), r.body.clone());
        match &first {
            None => first = Some(shape),
            Some(f0) => assert_eq!(f0, &shape, "{name}: body differs"),
        }
        if token.len() > 20 {
            assert!(!r.raw.contains(token.as_str()));
        }
    }

    // Policy-known refusals are on the ledger with a static reason; unknown handles are not.
    let denied: Vec<_> = f
        .ledger()
        .await
        .into_iter()
        .filter(|e| e.0 == "workload_identity.denied")
        .collect();
    assert_eq!(denied.len(), 8, "{denied:?}");
    for e in &denied {
        assert_eq!(e.1, "denied");
        assert_eq!(e.2, "service:control_plane");
        assert!(e.3.contains("reason"));
    }
    assert!(denied.iter().any(|e| e.3.contains("claims")));

    // No external token text anywhere.
    let logs = capture.contents();
    let rows = f.dump_text().await;
    for (_, _, token) in &cases {
        if token.len() > 20 {
            assert!(!logs.contains(token.as_str()) && !rows.contains(token.as_str()));
        }
    }
    assert!(!logs.contains("canary-actor-name") && !rows.contains("canary-actor-name"));
    assert!(logs.contains("reason=\"claims\"") || logs.contains("reason=claims"));

    // Malformed bodies are rejected before any credential check, without echoing the token.
    let r = call(
        &f.app,
        "POST",
        "/v1/workload-tokens",
        None,
        Some(json!({ "policy": good_handle, "token": "canary-extra", "x": 1 })),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(!r.raw.contains("canary-extra"));
}

#[tokio::test]
async fn workload_exchange_policy_delete_and_grant_revoke_cut_access() {
    let f = Fixture::start().await;
    let ok = exchange(&f.app, &f.handle(), &f.token("refs/heads/main")).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.raw);
    assert_eq!(f.grants().await.as_array().unwrap().len(), 1);

    // Revoking the grant leaves nothing for the minted (or any later) token to use.
    let d = call(
        &f.app,
        "DELETE",
        &format!("/v1/agents/{}/grants/{}", f.agent, f.grant),
        Some(f.org),
        None,
    )
    .await;
    assert_eq!(d.status, StatusCode::NO_CONTENT);
    assert_eq!(f.grants().await, json!([]));

    // Deleting the policy stops further exchanges.
    let d = call(
        &f.app,
        "DELETE",
        &format!("/v1/workload-identities/{}", f.policy),
        Some(f.org),
        None,
    )
    .await;
    assert_eq!(d.status, StatusCode::NO_CONTENT);
    let r = exchange(&f.app, &f.handle(), &f.token("refs/heads/main")).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.raw);
}

#[tokio::test]
async fn workload_exchange_unconfigured_is_503_and_private_issuers_are_refused_at_create() {
    // No verifier: the exchange answers 503 before touching the database.
    let app = app::build(
        AppState::new(
            true,
            Arc::new(ReadyFlag::new(true)),
            common::unreachable_db(),
        )
        .with_agent_signer(signer()),
    );
    let r = exchange(
        &app,
        &encode_handle(Uuid::now_v7(), Uuid::now_v7()),
        "x.y.z",
    )
    .await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{}", r.raw);

    // Create-time issuer check (default access: public https only).
    let pg = common::Pg::migrated().await;
    let app = app::build(state(
        pg.app_db(PoolSettings::default()),
        IssuerAccess::default(),
    ));
    let org = id(call(&app, "POST", "/v1/orgs", None, Some(json!({"name": "a"}))).await);
    let agent = {
        let r = call(
            &app,
            "POST",
            "/v1/agents",
            Some(org),
            Some(json!({"name": "ci"})),
        )
        .await;
        r.body["agent"]["id"].as_str().unwrap().to_owned()
    };
    for issuer in [
        "https://127.0.0.1",
        "https://169.254.169.254",
        "https://10.0.0.5/realm",
        "https://[::1]",
    ] {
        let r = call(
            &app,
            "POST",
            "/v1/workload-identities",
            Some(org),
            Some(json!({
                "name": "k8s", "issuer_kind": "oidc", "issuer": issuer, "audience": AUD,
                "agent_id": agent,
                "conditions": [{"claim": "sub", "pattern": "system:serviceaccount:prod:deployer"}],
            })),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{issuer}: {}", r.raw);
    }
}
