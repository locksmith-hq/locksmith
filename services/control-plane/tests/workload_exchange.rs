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
use ls_control_plane::auth::abuse::AbuseLimits;
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
        "jti": format!("jti-{}", Uuid::new_v4()), "iat": t, "nbf": t, "exp": t + 600,
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

fn state(
    db: ls_control_plane::db::Database,
    access: IssuerAccess,
    limits: AbuseLimits,
) -> AppState {
    AppState::new(true, Arc::new(ReadyFlag::new(true)), db)
        .with_workload_limits(limits)
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
        Self::start_with(AbuseLimits::default()).await
    }

    async fn start_with(limits: AbuseLimits) -> Self {
        let pg = common::Pg::migrated().await;
        let app = app::build(state(pg.app_db(PoolSettings::default()), DEV, limits));
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
    insert_policy_ref(pg, org, agent, issuer, name, "refs/heads/main").await
}

/// [`insert_policy`] pinned to `git_ref`.
async fn insert_policy_ref(
    pg: &common::Pg,
    org: Uuid,
    agent: Uuid,
    issuer: &str,
    name: &str,
    git_ref: &str,
) -> Uuid {
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
            {"claim": "ref", "op": "eq", "value": git_ref},
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
        AbuseLimits::default(),
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

/// An exchange request as if it came from `ip` (what `axum::serve` with connect info adds).
async fn exchange_from(app: &Router, ip: &str, policy: &str, token: &str) -> Reply {
    let mut req = Request::builder()
        .method("POST")
        .uri("/v1/workload-tokens")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "policy": policy, "token": token }).to_string(),
        ))
        .unwrap();
    let addr: std::net::SocketAddr = format!("{ip}:40000").parse().unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(addr));
    send(app, req).await
}

#[tokio::test]
async fn workload_abuse_replayed_jti_is_refused_with_the_same_401() {
    let f = Fixture::start().await;
    let token = f.token("refs/heads/main");
    let first = exchange(&f.app, &f.handle(), &token).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.raw);
    let replay = exchange(&f.app, &f.handle(), &token).await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    // Identical to any other credential failure.
    let other = exchange(&f.app, &f.handle(), "not-a-jwt").await;
    assert_eq!(replay.raw, other.raw);
    assert!(!replay.raw.contains("jti") && !replay.raw.contains("replay"));
    // A fresh token (new jti) still works.
    let fresh = exchange(&f.app, &f.handle(), &f.token("refs/heads/main")).await;
    assert_eq!(fresh.status, StatusCode::OK, "{}", fresh.raw);
    // The denial is on the ledger with a reason code and no token content.
    let ledger = f.ledger().await;
    let denied: Vec<_> = ledger
        .iter()
        .filter(|(k, ..)| k == "workload_identity.denied")
        .collect();
    assert!(
        denied.iter().any(|(.., attrs)| attrs.contains("replay")),
        "{denied:?}"
    );
    assert!(!f.dump_text().await.contains(&token));
}

#[tokio::test]
async fn workload_abuse_token_without_jti_is_accepted() {
    let f = Fixture::start().await;
    let mut c = claims(&f.issuer.uri(), "refs/heads/main");
    c.as_object_mut().unwrap().remove("jti");
    let token = f.key.mint(&c);
    for _ in 0..2 {
        let r = exchange(&f.app, &f.handle(), &token).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    }
}

#[tokio::test]
async fn workload_abuse_a_policy_mismatch_does_not_burn_the_jti() {
    let f = Fixture::start().await;
    // A second policy on the same issuer that accepts the feature branch.
    let feature = insert_policy_ref(
        &f.pg,
        f.org,
        f.agent,
        &f.issuer.uri(),
        "feat",
        "refs/heads/feature",
    )
    .await;
    let feature_handle = encode_handle(f.org, feature);
    let token = f.key.mint(&claims(&f.issuer.uri(), "refs/heads/feature"));

    // The main-only policy refuses it, and the ledger says why (claims, not replay).
    let r = exchange(&f.app, &f.handle(), &token).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let last = f.ledger().await.pop().unwrap();
    assert_eq!(last.0, "workload_identity.denied");
    assert!(
        last.3.contains("claims") && !last.3.contains("replay"),
        "{last:?}"
    );

    // The refusal did not consume the jti: the same token still works on the matching policy.
    let ok = exchange(&f.app, &feature_handle, &token).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.raw);
    // And the success did consume it.
    let again = exchange(&f.app, &feature_handle, &token).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    assert!(f.ledger().await.pop().unwrap().3.contains("replay"));
}

#[tokio::test]
async fn workload_abuse_per_policy_rate_limit_is_the_same_401() {
    let f = Fixture::start_with(AbuseLimits {
        per_policy: 3,
        per_source: 0,
        jti_entries: 1000,
    })
    .await;
    for _ in 0..3 {
        let r = exchange(&f.app, &f.handle(), &f.token("refs/heads/main")).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    }
    let over = exchange(&f.app, &f.handle(), &f.token("refs/heads/main")).await;
    assert_eq!(over.status, StatusCode::UNAUTHORIZED);
    let other = exchange(&f.app, &f.handle(), "not-a-jwt").await;
    // `not-a-jwt` is also over the limit; compare against another policy's failure instead.
    assert_eq!(over.raw, other.raw);
    let down = insert_policy(&f.pg, f.org, f.agent, "http://127.0.0.1:9", "down").await;
    let unrelated = exchange(&f.app, &encode_handle(f.org, down), "not-a-jwt").await;
    assert_eq!(unrelated.status, StatusCode::UNAUTHORIZED);
    assert_eq!(over.raw, unrelated.raw);
}

#[tokio::test]
async fn workload_abuse_per_source_rate_limit_counts_each_address_separately() {
    let f = Fixture::start_with(AbuseLimits {
        per_policy: 0,
        per_source: 2,
        jti_entries: 1000,
    })
    .await;
    for _ in 0..2 {
        let r = exchange_from(
            &f.app,
            "192.0.2.7",
            &f.handle(),
            &f.token("refs/heads/main"),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    }
    let over = exchange_from(
        &f.app,
        "192.0.2.7",
        &f.handle(),
        &f.token("refs/heads/main"),
    )
    .await;
    assert_eq!(over.status, StatusCode::UNAUTHORIZED);
    let bad = exchange(&f.app, &f.handle(), "not-a-jwt").await;
    assert_eq!(over.raw, bad.raw);
    // Another source is unaffected, and so is a request with no known peer.
    let ok = exchange_from(
        &f.app,
        "192.0.2.8",
        &f.handle(),
        &f.token("refs/heads/main"),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.raw);
    let ok = exchange(&f.app, &f.handle(), &f.token("refs/heads/main")).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.raw);
}

// ---- Task 4.2: abuse cases for the exchange ------------------------------------------------

/// Log capture with span open and close events, so the span fields are in it too.
fn capture_logs() -> (common::Capture, tracing::subscriber::DefaultGuard) {
    let capture = common::Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    // Tests share one process under `cargo test`: a callsite first hit by a test with no
    // subscriber caches "never", so re-evaluate every callsite against this subscriber.
    tracing::callsite::rebuild_interest_cache();
    (capture, guard)
}

/// When `WORKLOAD_ABUSE_ARTIFACT_DIR` is set (tests/adversarial/cases/D4.sh), write what an
/// attacker could read after the run (logs, the org ledger, a dump of every table) there, for
/// the shared leak oracle. Never contains the canary unless the code under test leaks it.
fn write_artifacts(name: &str, logs: &str, ledger: &str, rows: &str) {
    let Ok(dir) = std::env::var("WORKLOAD_ABUSE_ARTIFACT_DIR") else {
        return;
    };
    for (suffix, text) in [("logs", logs), ("ledger", ledger), ("rows", rows)] {
        std::fs::write(
            std::path::Path::new(&dir).join(format!("{name}.{suffix}")),
            text,
        )
        .unwrap();
    }
}

/// An attacker-controlled OpenID issuer that records every request it receives.
async fn attacker_issuer(key: &TestKey) -> MockServer {
    stub_issuer(key).await
}

async fn received(server: &MockServer) -> usize {
    server.received_requests().await.map_or(0, |r| r.len())
}

#[tokio::test]
async fn workload_abuse_forged_iss_at_an_attacker_host_makes_no_outbound_call() {
    let f = Fixture::start().await;
    let attacker_key = TestKey::new("k1", 11);
    let attacker = attacker_issuer(&attacker_key).await;
    let evil = attacker.uri();

    // The attacker signs with its own key and names itself as the issuer.
    let forged = attacker_key.mint(&claims(&evil, "refs/heads/main"));
    let r = exchange(&f.app, &f.handle(), &forged).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.raw);
    assert_eq!(
        received(&attacker).await,
        0,
        "the stored issuer is the only one fetched"
    );

    // Same, claiming the policy's real issuer but pointing discovery-ish claims at the attacker.
    let mut c = claims(&f.issuer.uri(), "refs/heads/main");
    c["jwks_uri"] = json!(format!("{evil}/jwks"));
    c["discovery"] = json!(format!("{evil}/.well-known/openid-configuration"));
    let r = exchange(&f.app, &f.handle(), &attacker_key.mint(&c)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.raw);

    // A policy handle cannot select an issuer either: an unknown policy id never reaches out.
    let r = exchange(&f.app, &encode_handle(f.org, Uuid::now_v7()), &forged).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(received(&attacker).await, 0);

    // Nothing was minted for any of it.
    assert!(
        f.ledger()
            .await
            .iter()
            .all(|e| e.0 != "workload_identity.exchanged")
    );
}

#[tokio::test]
async fn workload_abuse_jku_x5u_and_embedded_jwk_headers_are_ignored() {
    let f = Fixture::start().await;
    let attacker_key = TestKey::new("k1", 11);
    let attacker = attacker_issuer(&attacker_key).await;
    let evil = attacker.uri();

    // Attacker-signed token whose header offers the attacker's key set: refused.
    let mut h = Header::new(Algorithm::ES256);
    h.kid = Some("k1".into());
    h.jku = Some(format!("{evil}/jwks"));
    h.x5u = Some(format!("{evil}/cert"));
    let der = attacker_key.signing.to_pkcs8_der().unwrap();
    let forged = jsonwebtoken::encode(
        &h,
        &claims(&f.issuer.uri(), "refs/heads/main"),
        &EncodingKey::from_ec_der(der.as_bytes()),
    )
    .unwrap();
    let r = exchange(&f.app, &f.handle(), &forged).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.raw);

    // Header with an embedded `jwk` of the attacker's key, hand-assembled.
    let header = json!({
        "alg": "ES256", "typ": "JWT", "kid": "k1", "jwk": attacker_key.jwk(),
        "jku": format!("{evil}/jwks"),
    });
    let payload = claims(&f.issuer.uri(), "refs/heads/main");
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string())
    );
    let real = f.key.mint(&payload);
    let sig = real.rsplit('.').next().unwrap();
    let r = exchange(&f.app, &f.handle(), &format!("{signing_input}.{sig}")).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.raw);

    // A genuine token that carries a `jku` header is still judged by the stored issuer's keys.
    let mut h = Header::new(Algorithm::ES256);
    h.kid = Some(f.key.kid.clone());
    h.jku = Some(format!("{evil}/jwks"));
    let der = f.key.signing.to_pkcs8_der().unwrap();
    let genuine = jsonwebtoken::encode(
        &h,
        &claims(&f.issuer.uri(), "refs/heads/main"),
        &EncodingKey::from_ec_der(der.as_bytes()),
    )
    .unwrap();
    let r = exchange(&f.app, &f.handle(), &genuine).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);

    assert_eq!(
        received(&attacker).await,
        0,
        "the jku host was never contacted"
    );
}

#[tokio::test]
async fn workload_abuse_token_for_another_audience_is_refused() {
    let f = Fixture::start().await;
    let url = f.issuer.uri();
    for (name, aud) in [
        ("other string", json!("https://other.example")),
        (
            "array without ours",
            json!(["https://other.example", "https://third.example"]),
        ),
        ("prefix of ours", json!("https://locksmith.exampl")),
        ("ours with a suffix", json!(format!("{AUD}/"))),
        ("empty", json!("")),
        ("number", json!(7)),
    ] {
        let mut c = claims(&url, "refs/heads/main");
        c["aud"] = aud;
        let r = exchange(&f.app, &f.handle(), &f.key.mint(&c)).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{name}: {}", r.raw);
    }
    let mut c = claims(&url, "refs/heads/main");
    c.as_object_mut().unwrap().remove("aud");
    let r = exchange(&f.app, &f.handle(), &f.key.mint(&c)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "no aud: {}", r.raw);

    // The right audience (alone, or in an array) works, so the refusals above were about aud.
    let ok = exchange(&f.app, &f.handle(), &f.token("refs/heads/main")).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.raw);
    let mut c = claims(&url, "refs/heads/main");
    c["aud"] = json!(["https://other.example", AUD]);
    let ok = exchange(&f.app, &f.handle(), &f.key.mint(&c)).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.raw);
}

#[tokio::test]
async fn workload_abuse_replayed_jti_is_accepted_at_most_once_under_a_race() {
    let f = Fixture::start().await;
    let token = f.token("refs/heads/main");
    let handle = f.handle();
    let replies = [
        exchange(&f.app, &handle, &token),
        exchange(&f.app, &handle, &token),
        exchange(&f.app, &handle, &token),
        exchange(&f.app, &handle, &token),
        exchange(&f.app, &handle, &token),
    ];
    let replies = futures_join(replies).await;
    let ok = replies
        .iter()
        .filter(|r| r.status == StatusCode::OK)
        .count();
    assert_eq!(ok, 1, "exactly one concurrent use of a jti wins");
    assert!(
        replies
            .iter()
            .filter(|r| r.status != StatusCode::OK)
            .all(|r| r.status == StatusCode::UNAUTHORIZED)
    );
}

async fn futures_join<const N: usize>(
    futs: [impl std::future::Future<Output = Reply>; N],
) -> Vec<Reply> {
    let mut out = Vec::with_capacity(N);
    // Polled together on one task so the requests interleave.
    let mut pinned: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = Reply> + '_>>> =
        futs.into_iter().map(|f| Box::pin(f) as _).collect();
    let mut done: Vec<Option<Reply>> = (0..N).map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (i, p) in pinned.iter_mut().enumerate() {
            if done[i].is_none() {
                match p.as_mut().poll(cx) {
                    std::task::Poll::Ready(r) => done[i] = Some(r),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    out.extend(done.into_iter().map(Option::unwrap));
    out
}

#[tokio::test]
async fn workload_abuse_policy_handle_of_another_org_is_refused() {
    let f = Fixture::start().await;
    let other_org = id(call(&f.app, "POST", "/v1/orgs", None, Some(json!({"name": "b"}))).await);
    let other_agent = {
        let r = call(
            &f.app,
            "POST",
            "/v1/agents",
            Some(other_org),
            Some(json!({"name": "theirs"})),
        )
        .await;
        r.body["agent"]["id"]
            .as_str()
            .unwrap()
            .parse::<Uuid>()
            .unwrap()
    };
    let theirs = insert_policy(&f.pg, other_org, other_agent, &f.issuer.uri(), "theirs").await;

    // Org A's policy id under org B's handle, and the reverse: a valid token for either policy
    // must not mint across the org boundary.
    let token_a = f.token("refs/heads/main");
    let crossed_a = exchange(&f.app, &encode_handle(other_org, f.policy), &token_a).await;
    let token_b = f.token("refs/heads/main");
    let crossed_b = exchange(&f.app, &encode_handle(f.org, theirs), &token_b).await;
    let bogus = exchange(&f.app, "lsw_nope", &f.token("refs/heads/main")).await;
    for r in [&crossed_a, &crossed_b] {
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.raw);
        assert_eq!(r.raw, bogus.raw, "indistinguishable from any other failure");
    }
    // Neither refusal burned a jti: both tokens still work on their own org's policy.
    let a = exchange(&f.app, &f.handle(), &token_a).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.raw);
    let b = exchange(&f.app, &encode_handle(other_org, theirs), &token_b).await;
    assert_eq!(b.status, StatusCode::OK, "{}", b.raw);
    // The minted token names the agent of the handle's own org only.
    for (r, agent) in [(&a, f.agent), (&b, other_agent)] {
        let minted = r.body["access_token"].as_str().unwrap();
        assert_eq!(payload(minted)["sub"].as_str().unwrap(), agent.to_string());
    }
}

#[tokio::test]
async fn workload_abuse_canary_external_token_is_in_no_log_span_or_ledger() {
    let (capture, _guard) = capture_logs();
    let f = Fixture::start().await;
    let canary = std::env::var("ADVERSARIAL_CANARY_FILE")
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map_or_else(
            || format!("canary-{}", Uuid::new_v4().simple()),
            |s| s.trim().to_owned(),
        );

    // The canary rides in an unnamed claim and in the `kid`-less signature path of every token.
    let mut tokens = Vec::new();
    let mut ok_claims = claims(&f.issuer.uri(), "refs/heads/main");
    ok_claims["actor"] = json!(canary);
    tokens.push(f.key.mint(&ok_claims));
    let mut bad_ref = claims(&f.issuer.uri(), "refs/heads/feature");
    bad_ref["actor"] = json!(canary);
    tokens.push(f.key.mint(&bad_ref));
    let mut bad_aud = claims(&f.issuer.uri(), "refs/heads/main");
    bad_aud["actor"] = json!(canary);
    bad_aud["aud"] = json!("https://other.example");
    tokens.push(f.key.mint(&bad_aud));
    let mut forged = claims("https://attacker.example", "refs/heads/main");
    forged["actor"] = json!(canary);
    tokens.push(TestKey::new("k1", 9).mint(&forged));
    tokens.push(tokens[0].clone()); // replay
    // The canary as the bare token, as a handle and inside a malformed body.
    tokens.push(canary.clone());

    let mut minted = Vec::new();
    for t in &tokens {
        let r = exchange(&f.app, &f.handle(), t).await;
        if r.status == StatusCode::OK {
            minted.push(r.body["access_token"].as_str().unwrap().to_owned());
        }
        assert!(!r.raw.contains(&canary));
    }
    let r = exchange(&f.app, &canary, &tokens[0]).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(!r.raw.contains(&canary));
    assert_eq!(
        minted.len(),
        1,
        "only the first, well-formed token was exchanged"
    );

    let logs = capture.contents();
    let ledger = format!("{:?}", f.ledger().await);
    let rows = f.dump_text().await;
    assert!(
        logs.contains("exchange_workload_token"),
        "the span is in the capture (captured {} bytes: {})",
        logs.len(),
        logs.chars().take(600).collect::<String>()
    );
    for t in &tokens {
        let parts: Vec<&str> = t.split('.').collect();
        // The whole token, and each of its segments, must be absent.
        for needle in
            std::iter::once(t.as_str()).chain(parts.iter().copied().filter(|p| p.len() > 16))
        {
            for (where_, hay) in [("logs", &logs), ("ledger", &ledger), ("rows", &rows)] {
                assert!(!hay.contains(needle), "token material in {where_}");
            }
        }
    }
    for (where_, hay) in [("logs", &logs), ("ledger", &ledger), ("rows", &rows)] {
        assert!(!hay.contains(&canary), "canary in {where_}");
    }
    // The minted agent token is Locksmith's own and does not embed the external one.
    for m in &minted {
        for t in &tokens {
            assert!(!m.contains(t.as_str()));
        }
        assert!(
            !URL_SAFE_NO_PAD
                .decode(m.split('.').nth(1).unwrap())
                .map(|b| String::from_utf8_lossy(&b).contains(&canary))
                .unwrap_or(false)
        );
    }
    write_artifacts("canary", &logs, &ledger, &rows);
}
