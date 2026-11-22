//! S4 tasks 1.1-1.3: agents, grants, enrollment secrets, agent tokens, the JWKS and the
//! internal grants lookup. Tests without a database use a pool that never connects; the rest use
//! a throwaway `postgres:18` container (testcontainers; needs Docker). Each test starts its own.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use ls_control_plane::agent_token::{
    AUDIENCE, AgentClaims, AgentTokenSigner, JwkSet, VerifyError, verify,
};
use ls_control_plane::app::{self, AppState};
use ls_control_plane::auth::ServiceToken;
use ls_control_plane::db::{Database, PoolSettings, sql};
use ls_control_plane::readiness::ReadyFlag;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;
use zeroize::Zeroizing;

// Test-only values.
const SERVICE_TOKEN: &str = "test-only-gateway-service-token-0123456789";
const SEED: [u8; 32] = [0x5a; 32];

fn signer() -> AgentTokenSigner {
    AgentTokenSigner::from_seed(Zeroizing::new(SEED)).unwrap()
}

fn state(db: Database, with_signer: bool) -> AppState {
    let s = AppState::new(true, Arc::new(ReadyFlag::new(true)), db)
        .with_service_token(ServiceToken::new(SecretString::from(SERVICE_TOKEN)));
    if with_signer {
        s.with_agent_signer(signer())
    } else {
        s
    }
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

/// A request as `org` through dev auth (or no org binding when `None`).
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

/// `GET` an internal route with the service token, acting for `org`.
async fn internal(app: &Router, uri: &str, org: Uuid, token: Option<&str>) -> Reply {
    let mut b = Request::builder()
        .uri(uri)
        .header("x-locksmith-org", org.to_string());
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    send(app, b.body(Body::empty()).unwrap()).await
}

async fn mint(app: &Router, secret: &str) -> Reply {
    call(
        app,
        "POST",
        "/v1/agent-tokens",
        None,
        Some(json!({ "enrollment_secret": secret })),
    )
    .await
}

fn assert_problem(r: &Reply, status: StatusCode, slug: &str) {
    assert_eq!(r.status, status, "{}", r.raw);
    assert_eq!(r.body["type"], format!("urn:locksmith:problem:{slug}"));
}

fn keys(v: &Value) -> Vec<&str> {
    let mut k: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    k.sort_unstable();
    k
}

/// One org with a project, an environment and a secret.
struct Tenant {
    org: Uuid,
    secret: Uuid,
    secret_uri: String,
}

struct Fixture {
    app: Router,
    pg: common::Pg,
    a: Tenant,
    b: Tenant,
}

impl Fixture {
    async fn start() -> Self {
        let pg = common::Pg::migrated().await;
        let app = app::build(state(pg.app_db(PoolSettings::default()), true));
        let a = Self::tenant(&app, "org-a").await;
        let b = Self::tenant(&app, "org-b").await;
        Self { app, pg, a, b }
    }

    async fn tenant(app: &Router, name: &str) -> Tenant {
        let r = call(app, "POST", "/v1/orgs", None, Some(json!({ "name": name }))).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
        let org: Uuid = r.body["id"].as_str().unwrap().parse().unwrap();
        let id = |r: Reply| {
            assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
            r.body["id"].as_str().unwrap().to_owned()
        };
        let p = id(call(
            app,
            "POST",
            "/v1/projects",
            Some(org),
            Some(json!({"name": "p"})),
        )
        .await);
        let e = id(call(
            app,
            "POST",
            &format!("/v1/projects/{p}/environments"),
            Some(org),
            Some(json!({"name": "dev"})),
        )
        .await);
        let secret_uri = format!("/v1/projects/{p}/environments/{e}/secrets");
        let s = id(call(
            app,
            "POST",
            &secret_uri,
            Some(org),
            Some(json!({"name": "UPSTREAM_KEY"})),
        )
        .await);
        Tenant {
            org,
            secret: s.parse().unwrap(),
            secret_uri: format!("{secret_uri}/{s}"),
        }
    }

    /// Register an agent; returns its id and enrollment secret.
    async fn agent(&self, org: Uuid, name: &str) -> (Uuid, String) {
        let r = call(
            &self.app,
            "POST",
            "/v1/agents",
            Some(org),
            Some(json!({ "name": name })),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
        (
            r.body["agent"]["id"].as_str().unwrap().parse().unwrap(),
            r.body["enrollment_secret"].as_str().unwrap().to_owned(),
        )
    }

    async fn grant(&self, org: Uuid, agent: Uuid, body: Value) -> Reply {
        call(
            &self.app,
            "POST",
            &format!("/v1/agents/{agent}/grants"),
            Some(org),
            Some(body),
        )
        .await
    }

    /// Every row of every table as text, read as the superuser (bypasses RLS).
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

/// Decode a JWT payload without verifying it (to inspect the claim names).
fn payload(token: &str) -> Value {
    let part = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
}

/// Scenario "one-time enrollment secret": registration shows it once (no-store), no read path
/// returns it, the database holds only an Argon2id hash, and rotation replaces it. Nothing logs
/// the secret or a minted token.
#[tokio::test]
async fn enrollment_secret_is_shown_once_and_stored_only_as_a_hash() {
    let capture = common::Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let f = Fixture::start().await;
    let r = call(
        &f.app,
        "POST",
        "/v1/agents",
        Some(f.a.org),
        Some(json!({ "name": "claude-code", "description": "laptop" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    assert_eq!(r.headers["cache-control"], "no-store");
    assert_eq!(keys(&r.body), ["agent", "enrollment_secret"]);
    assert_eq!(
        keys(&r.body["agent"]),
        ["created_at", "description", "id", "name", "updated_at"]
    );
    let agent: Uuid = r.body["agent"]["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(agent.get_version_num(), 7);
    assert_eq!(
        r.headers["location"].to_str().unwrap(),
        format!("/v1/agents/{agent}")
    );
    let secret = r.body["enrollment_secret"].as_str().unwrap().to_owned();
    assert!(secret.starts_with("lse_") && secret.len() > 80);
    let secret_body = &secret["lse_".len()..];

    // No read path returns it, nor the hash.
    let got = call(
        &f.app,
        "GET",
        &format!("/v1/agents/{agent}"),
        Some(f.a.org),
        None,
    )
    .await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(
        keys(&got.body),
        ["created_at", "description", "id", "name", "updated_at"]
    );
    let listed = call(&f.app, "GET", "/v1/agents", Some(f.a.org), None).await;
    assert_eq!(listed.body["items"].as_array().unwrap().len(), 1);
    for raw in [&got.raw, &listed.raw] {
        assert!(
            !raw.contains(secret_body) && !raw.contains("argon2"),
            "{raw}"
        );
    }

    // The database holds an Argon2id hash and no copy of the secret.
    let dump = f.dump_text().await;
    assert!(!dump.contains(secret_body));
    let mut c = f.pg.admin().await;
    let hash: String = sql::query_scalar("SELECT enrollment_hash FROM agents WHERE id = $1")
        .bind(agent)
        .fetch_one(&mut c)
        .await
        .unwrap();
    c.close().await.unwrap();
    assert!(
        hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
        "{hash}"
    );

    // The secret exchanges for a token.
    let t = mint(&f.app, &secret).await;
    assert_eq!(t.status, StatusCode::OK, "{}", t.raw);
    let token = t.body["access_token"].as_str().unwrap().to_owned();

    // Rotation: a new secret, shown once; the old one stops working at once.
    let rotated = call(
        &f.app,
        "POST",
        &format!("/v1/agents/{agent}/enrollment-secret"),
        Some(f.a.org),
        None,
    )
    .await;
    assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.raw);
    assert_eq!(rotated.headers["cache-control"], "no-store");
    let new_secret = rotated.body["enrollment_secret"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(new_secret, secret);
    assert_problem(
        &mint(&f.app, &secret).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    assert_eq!(mint(&f.app, &new_secret).await.status, StatusCode::OK);

    // Unknown fields are refused: the secret cannot be chosen by the caller.
    let r = call(
        &f.app,
        "POST",
        "/v1/agents",
        Some(f.a.org),
        Some(json!({ "name": "x", "enrollment_secret": "lse_mine" })),
    )
    .await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");

    let logs = capture.contents();
    assert!(logs.contains("agent token minted"), "{logs}");
    for needle in [
        secret_body,
        &new_secret["lse_".len()..],
        token.as_str(),
        &hash,
    ] {
        assert!(!logs.contains(needle), "logs leak a credential");
    }
}

/// The exchange returns a 15-minute EdDSA JWT for audience `gateway` that verifies with the
/// served JWKS and carries only agent id, org id, audience and times.
#[tokio::test]
async fn token_exchange_mints_a_short_lived_gateway_token() {
    let f = Fixture::start().await;
    let (agent, secret) = f.agent(f.a.org, "ci").await;

    let r = mint(&f.app, &secret).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(r.headers["cache-control"], "no-store");
    assert_eq!(
        keys(&r.body),
        ["access_token", "expires_at", "expires_in", "token_type"]
    );
    assert_eq!(r.body["token_type"], "Bearer");
    assert_eq!(r.body["expires_in"], 900);
    let token = r.body["access_token"].as_str().unwrap();
    assert!(!token.contains(&secret["lse_".len()..]));

    let jwks = call(&f.app, "GET", "/.well-known/jwks.json", None, None).await;
    assert_eq!(jwks.status, StatusCode::OK);
    let set: JwkSet = serde_json::from_value(jwks.body.clone()).unwrap();
    assert_eq!(set.keys.len(), 1);
    let jwk = &set.keys[0];
    assert_eq!(
        (
            jwk.kty.as_str(),
            jwk.crv.as_str(),
            jwk.alg.as_str(),
            jwk.use_.as_str()
        ),
        ("OKP", "Ed25519", "EdDSA", "sig")
    );
    // Public half only: no private `d` member.
    assert_eq!(
        keys(&jwks.body["keys"][0]),
        ["alg", "crv", "kid", "kty", "use", "x"]
    );

    let header = jsonwebtoken::decode_header(token).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::EdDSA);
    assert_eq!(header.kid.as_deref(), Some(jwk.kid.as_str()));
    let claims = verify(token, &jwk.decoding_key().unwrap()).unwrap();
    assert_eq!(claims.sub, agent);
    assert_eq!(claims.org, f.a.org);
    assert_eq!(claims.aud, AUDIENCE);
    assert_eq!(claims.exp - claims.iat, 15 * 60);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    assert!((claims.iat - now).abs() < 60);
    assert_eq!(keys(&payload(token)), ["aud", "exp", "iat", "jti", "org", "sub"]);
}

/// Scenario "expired or forged token" (verifier side): an expired token, a wrong audience and a
/// token signed by another key all fail verification against the served JWKS.
#[tokio::test]
async fn expired_wrong_audience_and_forged_tokens_fail_verification() {
    let f = Fixture::start().await;
    let (agent, secret) = f.agent(f.a.org, "ci").await;
    assert_eq!(mint(&f.app, &secret).await.status, StatusCode::OK);

    let jwks = call(&f.app, "GET", "/.well-known/jwks.json", None, None).await;
    let set: JwkSet = serde_json::from_value(jwks.body).unwrap();
    let key = set.keys[0].decoding_key().unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = |aud: &str, exp: i64| AgentClaims {
        sub: agent,
        org: f.a.org,
        aud: aud.to_owned(),
        jti: Uuid::now_v7(),
        iat: exp - 900,
        exp,
    };

    // Signed with the control plane's own key, but expired (beyond the 30 s leeway).
    let expired = signer().sign(&claims(AUDIENCE, now - 31 - 60)).unwrap();
    assert_eq!(verify(&expired, &key), Err(VerifyError::Expired));
    // The right key, the wrong audience.
    for aud in ["control-plane", "Gateway", ""] {
        let t = signer().sign(&claims(aud, now + 600)).unwrap();
        assert_eq!(verify(&t, &key), Err(VerifyError::WrongAudience), "{aud}");
    }
    // Another key with a valid-looking token.
    let forged = AgentTokenSigner::from_seed(Zeroizing::new([0x11; 32]))
        .unwrap()
        .sign(&claims(AUDIENCE, now + 600))
        .unwrap();
    assert_eq!(verify(&forged, &key), Err(VerifyError::BadSignature));
    // Unsigned (`alg: none`) and HMAC-signed tokens are refused (no algorithm negotiation).
    let unsigned = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims(AUDIENCE, now + 600)).unwrap())
    );
    assert!(verify(&unsigned, &key).is_err());
    let hmac = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims(AUDIENCE, now + 600),
        &jsonwebtoken::EncodingKey::from_secret(set.keys[0].x.as_bytes()).unwrap(),
    )
    .unwrap();
    assert!(verify(&hmac, &key).is_err());
    // A token that is still valid verifies.
    let ok = signer().sign(&claims(AUDIENCE, now + 600)).unwrap();
    assert_eq!(verify(&ok, &key).unwrap().sub, agent);
}

/// Wrong, malformed, swapped-org and deleted-agent secrets are all the same `401`, which never
/// echoes the request.
#[tokio::test]
async fn bad_enrollment_secrets_are_401() {
    let f = Fixture::start().await;
    let (agent, secret) = f.agent(f.a.org, "ci").await;
    let raw = URL_SAFE_NO_PAD.decode(&secret["lse_".len()..]).unwrap();
    let encode = |raw: &[u8]| format!("lse_{}", URL_SAFE_NO_PAD.encode(raw));

    let mut wrong = raw.clone();
    wrong[40] ^= 1;
    let mut other_org = raw.clone();
    other_org[..16].copy_from_slice(f.b.org.as_bytes());
    let mut other_agent = raw.clone();
    other_agent[16..32].copy_from_slice(Uuid::now_v7().as_bytes());
    for bad in [
        encode(&wrong),
        encode(&other_org),
        encode(&other_agent),
        "lse_".to_owned(),
        "not-a-secret".to_owned(),
        secret[..secret.len() - 1].to_owned(),
    ] {
        let r = mint(&f.app, &bad).await;
        assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
        if bad.len() > "lse_".len() {
            assert!(!r.raw.contains(&bad), "{}", r.raw);
        }
    }
    // Shape errors are 400/415 and still never echo the value.
    let r = call(
        &f.app,
        "POST",
        "/v1/agent-tokens",
        None,
        Some(json!({ "enrollment_secret": secret, "agent_id": agent })),
    )
    .await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    assert!(!r.raw.contains(&secret));
    let r = call(
        &f.app,
        "POST",
        "/v1/agent-tokens",
        None,
        Some(json!({ "enrollment_secret": 7 })),
    )
    .await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    let req = Request::builder()
        .method("POST")
        .uri("/v1/agent-tokens")
        .header("content-type", "text/plain")
        .body(Body::from(secret.clone()))
        .unwrap();
    assert_problem(
        &send(&f.app, req).await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported-media-type",
    );

    // Deleting the agent makes its secret worthless.
    assert_eq!(mint(&f.app, &secret).await.status, StatusCode::OK);
    let d = call(
        &f.app,
        "DELETE",
        &format!("/v1/agents/{agent}"),
        Some(f.a.org),
        None,
    )
    .await;
    assert_eq!(d.status, StatusCode::NO_CONTENT);
    assert_problem(
        &mint(&f.app, &secret).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
}

/// Without a signing key the token endpoint is `503` (before any database access; this pool
/// never connects) and the JWKS is empty.
#[tokio::test]
async fn without_a_signing_key_tokens_are_503_and_jwks_is_empty() {
    let app = app::build(state(common::unreachable_db(), false));
    let r = mint(&app, "lse_anything").await;
    assert_problem(&r, StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    let jwks = call(&app, "GET", "/.well-known/jwks.json", None, None).await;
    assert_eq!(jwks.status, StatusCode::OK);
    assert_eq!(jwks.body, json!({ "keys": [] }));

    // Registration and grants need an org binding, like every /v1 resource.
    for (method, uri) in [
        ("POST", "/v1/agents".to_owned()),
        ("GET", "/v1/agents".to_owned()),
        ("GET", format!("/v1/agents/{}/grants", Uuid::now_v7())),
    ] {
        let r = call(&app, method, &uri, None, Some(json!({ "name": "x" }))).await;
        assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    }
}

/// Grants: create, list (with the secret name), validation, duplicates, revocation and
/// cascades; the internal lookup returns unexpired grants only and needs the service token.
#[tokio::test]
async fn grants_lifecycle_and_internal_lookup() {
    let f = Fixture::start().await;
    let (agent, _) = f.agent(f.a.org, "ci").await;
    let grants_uri = format!("/v1/agents/{agent}/grants");
    let lookup_uri = format!("/internal/v1/agents/{agent}/grants");

    // Validation.
    let past = (OffsetDateTime::now_utc() - time::Duration::minutes(1))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    for body in [
        json!({ "secret_id": f.a.secret, "expires_at": past }),
        json!({ "secret_id": f.a.secret, "mode": "inject" }),
        json!({ "secret_id": f.a.secret, "value": "x" }),
        json!({}),
    ] {
        let r = f.grant(f.a.org, agent, body).await;
        assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    }

    let future = (OffsetDateTime::now_utc() + time::Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let r = f
        .grant(
            f.a.org,
            agent,
            json!({ "secret_id": f.a.secret, "expires_at": future }),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    assert_eq!(
        keys(&r.body),
        [
            "agent_id",
            "created_at",
            "expires_at",
            "id",
            "mode",
            "secret_id",
            "secret_name"
        ]
    );
    assert_eq!(r.body["mode"], "relay");
    assert_eq!(r.body["secret_name"], "UPSTREAM_KEY");
    let grant: Uuid = r.body["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(grant.get_version_num(), 7);

    // One grant per agent, secret and mode.
    let dup = f
        .grant(f.a.org, agent, json!({ "secret_id": f.a.secret }))
        .await;
    assert_problem(&dup, StatusCode::CONFLICT, "conflict");

    let listed = call(&f.app, "GET", &grants_uri, Some(f.a.org), None).await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["items"][0]["id"], grant.to_string());

    // An expired grant (written directly: the API refuses a past expiry).
    let mut c = f.pg.admin().await;
    let second: Uuid = {
        let r = call(
            &f.app,
            "POST",
            f.a.secret_uri.rsplit_once('/').unwrap().0,
            Some(f.a.org),
            Some(json!({ "name": "OLD_KEY" })),
        )
        .await;
        r.body["id"].as_str().unwrap().parse().unwrap()
    };
    sql::query(
        "INSERT INTO agent_grants (org_id, agent_id, secret_id, expires_at)
         VALUES ($1, $2, $3, now() - interval '1 second')",
    )
    .bind(f.a.org)
    .bind(agent)
    .bind(second)
    .execute(&mut c)
    .await
    .unwrap();
    c.close().await.unwrap();

    // The internal lookup needs the service token.
    for token in [None, Some("test-only-gateway-service-token-0123456780")] {
        let r = internal(&f.app, &lookup_uri, f.a.org, token).await;
        assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    }
    let r = internal(&f.app, &lookup_uri, f.a.org, Some(SERVICE_TOKEN)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(keys(&r.body), ["agent_id", "items"]);
    let items = r.body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "expired grants are not served: {}", r.raw);
    assert_eq!(
        keys(&items[0]),
        ["expires_at", "grant_id", "mode", "secret_id", "secret_name"]
    );
    assert_eq!(items[0]["grant_id"], grant.to_string());
    assert_eq!(items[0]["secret_id"], f.a.secret.to_string());
    assert_eq!(items[0]["mode"], "relay");
    // The console list still shows the expired grant.
    let listed = call(&f.app, "GET", &grants_uri, Some(f.a.org), None).await;
    assert_eq!(listed.body["items"].as_array().unwrap().len(), 2);

    // Revocation removes it from the lookup.
    let d = call(
        &f.app,
        "DELETE",
        &format!("{grants_uri}/{grant}"),
        Some(f.a.org),
        None,
    )
    .await;
    assert_eq!(d.status, StatusCode::NO_CONTENT);
    let r = internal(&f.app, &lookup_uri, f.a.org, Some(SERVICE_TOKEN)).await;
    assert_eq!(r.body["items"], json!([]));
    let d = call(
        &f.app,
        "DELETE",
        &format!("{grants_uri}/{grant}"),
        Some(f.a.org),
        None,
    )
    .await;
    assert_problem(&d, StatusCode::NOT_FOUND, "not-found");

    // Deleting the secret removes its grants; deleting the agent makes the lookup 404.
    assert_eq!(
        f.grant(f.a.org, agent, json!({ "secret_id": f.a.secret }))
            .await
            .status,
        StatusCode::CREATED
    );
    let d = call(&f.app, "DELETE", &f.a.secret_uri, Some(f.a.org), None).await;
    assert_eq!(d.status, StatusCode::NO_CONTENT, "{}", d.raw);
    let r = internal(&f.app, &lookup_uri, f.a.org, Some(SERVICE_TOKEN)).await;
    assert_eq!(r.body["items"], json!([]));
    let d = call(
        &f.app,
        "DELETE",
        &format!("/v1/agents/{agent}"),
        Some(f.a.org),
        None,
    )
    .await;
    assert_eq!(d.status, StatusCode::NO_CONTENT);
    let r = internal(&f.app, &lookup_uri, f.a.org, Some(SERVICE_TOKEN)).await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not-found");
}

/// Scenario "cross-org isolation": org B sees none of org A's agents or grants through the API,
/// the internal lookup or the database, and cannot attach a grant across orgs.
#[tokio::test]
async fn cross_org_isolation() {
    let f = Fixture::start().await;
    let (agent_a, secret_a) = f.agent(f.a.org, "a-agent").await;
    let (agent_b, _) = f.agent(f.b.org, "b-agent").await;
    // Same agent name in another org is fine (names are unique per org).
    f.agent(f.b.org, "a-agent").await;
    let r = f
        .grant(f.a.org, agent_a, json!({ "secret_id": f.a.secret }))
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let grant_a: Uuid = r.body["id"].as_str().unwrap().parse().unwrap();

    // Lists.
    let listed = call(&f.app, "GET", "/v1/agents", Some(f.b.org), None).await;
    let ids: Vec<&str> = listed.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 2);
    assert!(!ids.contains(&agent_a.to_string().as_str()));

    // Reads and writes on A's agent from B are 404, the same as a missing agent.
    let missing = Uuid::now_v7();
    for id in [agent_a, missing] {
        for (method, uri, body) in [
            ("GET", format!("/v1/agents/{id}"), None),
            ("GET", format!("/v1/agents/{id}/grants"), None),
            (
                "POST",
                format!("/v1/agents/{id}/grants"),
                Some(json!({ "secret_id": f.b.secret })),
            ),
            ("POST", format!("/v1/agents/{id}/enrollment-secret"), None),
            ("DELETE", format!("/v1/agents/{id}/grants/{grant_a}"), None),
            ("DELETE", format!("/v1/agents/{id}"), None),
        ] {
            let r = call(&f.app, method, &uri, Some(f.b.org), body).await;
            assert_problem(&r, StatusCode::NOT_FOUND, "not-found");
        }
    }
    // B's agent cannot be granted A's secret.
    let r = f
        .grant(f.b.org, agent_b, json!({ "secret_id": f.a.secret }))
        .await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not-found");
    // The gateway acting for B cannot read A's agent's grants.
    let r = internal(
        &f.app,
        &format!("/internal/v1/agents/{agent_a}/grants"),
        f.b.org,
        Some(SERVICE_TOKEN),
    )
    .await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not-found");
    // A's enrollment secret with B's org swapped in is refused (covered in detail above), and
    // A's still works: nothing B did touched it.
    assert_eq!(mint(&f.app, &secret_a).await.status, StatusCode::OK);
    let r = call(
        &f.app,
        "GET",
        &format!("/v1/agents/{agent_a}/grants"),
        Some(f.a.org),
        None,
    )
    .await;
    assert_eq!(r.body["items"].as_array().unwrap().len(), 1);

    // Database level, as the app role bound to B: no rows of A's, and the composite foreign keys
    // refuse a grant that names A's agent or secret even with B's org id.
    let db = f.pg.app_db(PoolSettings::default());
    let (agents, grants) = db
        .with_org(f.b.org, move |c| {
            Box::pin(async move {
                let agents: Vec<Uuid> = sql::query_scalar("SELECT id FROM agents")
                    .fetch_all(&mut *c)
                    .await?;
                let grants: i64 = sql::query_scalar("SELECT count(*) FROM agent_grants")
                    .fetch_one(&mut *c)
                    .await?;
                Ok::<_, sql::Error>((agents, grants))
            })
        })
        .await
        .unwrap();
    assert_eq!(agents.len(), 2);
    assert!(!agents.contains(&agent_a));
    assert_eq!(grants, 0);
    let (org_b, secret_a_id) = (f.b.org, f.a.secret);
    for (agent, secret) in [(agent_a, f.b.secret), (agent_b, secret_a_id)] {
        let err = db
            .with_org(org_b, move |c| {
                Box::pin(async move {
                    sql::query(
                        "INSERT INTO agent_grants (org_id, agent_id, secret_id) VALUES ($1, $2, $3)",
                    )
                    .bind(org_b)
                    .bind(agent)
                    .bind(secret)
                    .execute(c)
                    .await
                })
            })
            .await
            .unwrap_err();
        let code = err.as_database_error().and_then(|d| d.code()).unwrap();
        assert_eq!(code, "23503", "foreign_key_violation");
    }
    // Writing a row for A while bound to B is refused by the policy.
    let org_a = f.a.org;
    let err = db
        .with_org(org_b, move |c| {
            Box::pin(async move {
                sql::query(
                    "INSERT INTO agents (org_id, name, enrollment_hash) VALUES ($1, 'x', '$argon2id$x')",
                )
                .bind(org_a)
                .execute(c)
                .await
            })
        })
        .await
        .unwrap_err();
    let code = err.as_database_error().and_then(|d| d.code()).unwrap();
    assert_eq!(code, "42501", "row-level security violation");
    db.close().await;
}
