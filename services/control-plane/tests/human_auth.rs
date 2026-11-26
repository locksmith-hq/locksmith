//! T1 tasks 1.3 and 1.4: human bearer tokens on `OrgBinding`, against a local mock issuer
//! (wiremock serving a JWKS). Forged, `none`, HS*, wrong audience, wrong issuer, expired and
//! rotated-key tokens must all get the same `401`.

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ls_control_plane::app::{self, AppState};
use ls_control_plane::auth::OrgBinding;
use ls_control_plane::auth::human::{HumanAuth, HumanAuthConfig};
use ls_control_plane::readiness::ReadyFlag;
use p256::pkcs8::EncodePrivateKey as _;
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ISSUER: &str = "https://idp.test/realms/locksmith";
const AUDIENCE: &str = "locksmith-api";
const DEV_ORG: &str = "0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
/// The refresh interval for tests that wait it out; kept well above the time a loaded CI runner
/// needs for the handful of requests made inside it.
const MIN_REFRESH: Duration = Duration::from_secs(1);
/// For tests that must see no second fetch at all, however slow the runner (issue #491).
const NO_REFRESH: Duration = Duration::from_secs(3600);

/// A deterministic throwaway P-256 key (test only; `seed` makes keys distinct).
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

    fn encoding_key(&self) -> EncodingKey {
        let der = self.signing.to_pkcs8_der().unwrap();
        EncodingKey::from_ec_der(der.as_bytes())
    }

    fn mint(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, claims, &self.encoding_key()).unwrap()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn claims(sub: &str) -> Value {
    json!({
        "iss": ISSUER, "aud": AUDIENCE, "sub": sub, "exp": now() + 600,
        "email": format!("{sub}@example.com"), "email_verified": true,
    })
}

/// An unsigned-or-garbage-signature token with a hand-written header.
fn raw_token(header: &Value, claims: &Value, signature: &[u8]) -> String {
    let enc = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
    format!(
        "{}.{}.{}",
        enc(header),
        enc(claims),
        URL_SAFE_NO_PAD.encode(signature)
    )
}

struct Issuer {
    server: MockServer,
    /// A migrated database, for tests whose valid tokens reach the users table (T1 task 3.2).
    pg: Option<common::Pg>,
}

impl Issuer {
    async fn start(keys: &[&TestKey]) -> Self {
        let issuer = Self {
            server: MockServer::start().await,
            pg: None,
        };
        issuer.publish(keys).await;
        issuer
    }

    /// As [`Self::start`], with a migrated Postgres behind the app.
    async fn start_db(keys: &[&TestKey]) -> Self {
        let mut issuer = Self::start(keys).await;
        issuer.pg = Some(common::Pg::migrated().await);
        issuer
    }

    async fn publish(&self, keys: &[&TestKey]) {
        self.server.reset().await;
        let jwks = json!({ "keys": keys.iter().map(|k| k.jwk()).collect::<Vec<_>>() });
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&self.server)
            .await;
    }

    async fn fetches(&self) -> usize {
        self.server.received_requests().await.unwrap().len()
    }

    fn app(&self, dev_auth: bool) -> Router {
        self.app_with_refresh(dev_auth, MIN_REFRESH)
    }

    fn app_with_refresh(&self, dev_auth: bool, min_refresh: Duration) -> Router {
        let human = HumanAuth::with_refresh(
            &HumanAuthConfig {
                issuer: ISSUER.to_owned(),
                audience: AUDIENCE.to_owned(),
                jwks_url: format!("{}/jwks", self.server.uri()),
            },
            min_refresh,
            Duration::from_secs(3600),
        )
        .unwrap();
        let state = AppState::new(
            dev_auth,
            Arc::new(ReadyFlag::new(true)),
            self.pg
                .as_ref()
                .map_or_else(common::unreachable_db, |pg| pg.app_db(Default::default())),
        )
        .with_human_auth(human);
        app::with_layers(app::routes().route("/whoami", get(whoami)), state)
    }
}

async fn whoami(org: OrgBinding) -> String {
    org.org_id.to_string()
}

async fn call(app: &Router, token: Option<&str>, dev_org: Option<&str>) -> (StatusCode, String) {
    let mut b = Request::builder().uri("/whoami");
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    if let Some(o) = dev_org {
        b = b.header("x-locksmith-dev-org", o);
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

/// Assert `token` is refused and return the response body for uniformity checks.
async fn refused(app: &Router, token: &str) -> String {
    let (status, body) = call(app, Some(token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(!body.contains(token), "token echoed back");
    body
}

#[tokio::test]
async fn auth_valid_token_binds_the_users_org() {
    let key = TestKey::new("k1", 1);
    let issuer = Issuer::start_db(&[&key]).await;
    let app = issuer.app(false);
    let (status, body) = call(&app, Some(&key.mint(&claims("user-1"))), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(uuid::Uuid::parse_str(&body).is_ok(), "{body}");
    // Same person, same org; a different person, a different org.
    let (_, again) = call(&app, Some(&key.mint(&claims("user-1"))), None).await;
    let (_, other) = call(&app, Some(&key.mint(&claims("user-2"))), None).await;
    assert_eq!(again, body);
    assert_ne!(other, body);
    assert_eq!(issuer.fetches().await, 1, "keys are cached");
}

#[tokio::test]
async fn auth_audience_may_be_one_of_several() {
    let key = TestKey::new("k1", 1);
    let issuer = Issuer::start_db(&[&key]).await;
    let mut c = claims("user-1");
    c["aud"] = json!(["other-api", AUDIENCE]);
    let (status, _) = call(&issuer.app(false), Some(&key.mint(&c)), None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn auth_rejections_are_uniform_and_say_nothing_about_why() {
    let key = TestKey::new("k1", 1);
    let attacker = TestKey::new("k1", 9); // same kid, different key
    let issuer = Issuer::start(&[&key]).await;
    let app = issuer.app(false);
    let good = claims("user-1");
    let with = |k: &str, v: Value| {
        let mut c = good.clone();
        c[k] = v;
        c
    };
    let header_es = json!({"alg": "ES256", "typ": "JWT", "kid": "k1"});

    let cases: Vec<(&str, String)> = vec![
        ("forged signature", attacker.mint(&good)),
        (
            "wrong audience",
            key.mint(&with("aud", json!("someone-else"))),
        ),
        (
            "wrong issuer",
            key.mint(&with("iss", json!("https://evil.test"))),
        ),
        ("expired", key.mint(&with("exp", json!(now() - 3600)))),
        ("not yet valid", key.mint(&with("nbf", json!(now() + 3600)))),
        ("no exp", {
            let mut c = good.clone();
            c.as_object_mut().unwrap().remove("exp");
            key.mint(&c)
        }),
        ("no sub", {
            let mut c = good.clone();
            c.as_object_mut().unwrap().remove("sub");
            key.mint(&c)
        }),
        ("unknown kid", TestKey::new("nope", 1).mint(&good)),
        (
            "alg none",
            raw_token(
                &json!({"alg": "none", "typ": "JWT", "kid": "k1"}),
                &good,
                b"",
            ),
        ),
        (
            "alg None, mixed case",
            raw_token(&json!({"alg": "None", "kid": "k1"}), &good, b""),
        ),
        (
            "none with a signature",
            raw_token(&json!({"alg": "none", "kid": "k1"}), &good, b"sig"),
        ),
        ("HS256 signed with the published key material", {
            let mut h = Header::new(Algorithm::HS256);
            h.kid = Some("k1".into());
            let x = key.jwk()["x"].as_str().unwrap().to_owned();
            jsonwebtoken::encode(&h, &good, &EncodingKey::from_secret(x.as_bytes()).unwrap())
                .unwrap()
        }),
        (
            "HS512 header, garbage signature",
            raw_token(&json!({"alg": "HS512", "kid": "k1"}), &good, b"x"),
        ),
        (
            "EdDSA header (not allow-listed)",
            raw_token(&json!({"alg": "EdDSA", "kid": "k1"}), &good, &[0u8; 64]),
        ),
        (
            "RS256 header against an EC key",
            raw_token(&json!({"alg": "RS256", "kid": "k1"}), &good, &[0u8; 256]),
        ),
        (
            "no kid",
            raw_token(&json!({"alg": "ES256"}), &good, &[0u8; 64]),
        ),
        (
            "unknown alg name",
            raw_token(&json!({"alg": "ES999", "kid": "k1"}), &good, &[0u8; 64]),
        ),
        ("tampered payload", {
            let t = key.mint(&good);
            let mut parts: Vec<_> = t.split('.').map(str::to_owned).collect();
            parts[1] =
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&with("sub", json!("admin"))).unwrap());
            parts.join(".")
        }),
        ("not a jwt", "abc".to_owned()),
        (
            "two segments",
            format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header_es.to_string()),
                "e30"
            ),
        ),
        ("oversized", "a".repeat(64 * 1024)),
    ];

    let mut bodies = Vec::new();
    for (name, token) in &cases {
        let body = refused(&app, token).await;
        bodies.push((name, body));
    }
    let first = &bodies[0].1;
    for (name, body) in &bodies {
        assert_eq!(body, first, "response for {name} differs");
    }
    let lowered = first.to_lowercase();
    for word in [
        "expired",
        "audience",
        "issuer",
        "signature",
        "algorithm",
        "kid",
        "key",
    ] {
        assert!(!lowered.contains(word), "body leaks `{word}`: {first}");
    }
}

#[tokio::test]
async fn auth_token_just_past_expiry_is_within_the_leeway_but_not_far_past() {
    let key = TestKey::new("k1", 1);
    let issuer = Issuer::start_db(&[&key]).await;
    let app = issuer.app(false);
    let mut c = claims("user-1");
    c["exp"] = json!(now() - 20);
    assert_eq!(
        call(&app, Some(&key.mint(&c)), None).await.0,
        StatusCode::OK
    );
    c["exp"] = json!(now() - 120);
    assert_eq!(
        call(&app, Some(&key.mint(&c)), None).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn auth_rotated_key_is_accepted_after_one_rate_limited_refresh() {
    let old = TestKey::new("old", 1);
    let new = TestKey::new("new", 2);
    let issuer = Issuer::start_db(&[&old]).await;
    let app = issuer.app(false);

    assert_eq!(
        call(&app, Some(&old.mint(&claims("u"))), None).await.0,
        StatusCode::OK
    );
    assert_eq!(issuer.fetches().await, 1);

    // The issuer rotates. Tokens under the new key inside the refresh interval are refused
    // (no fetch storm), however many arrive.
    issuer.publish(&[&new]).await;
    let fresh = new.mint(&claims("u"));
    for _ in 0..5 {
        assert_eq!(
            call(&app, Some(&fresh), None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(issuer.fetches().await, 0, "rate limited: no refetch yet");

    // After the interval the next request refreshes once and succeeds, and the retired key
    // no longer verifies.
    tokio::time::sleep(MIN_REFRESH + Duration::from_millis(100)).await;
    assert_eq!(call(&app, Some(&fresh), None).await.0, StatusCode::OK);
    assert_eq!(call(&app, Some(&fresh), None).await.0, StatusCode::OK);
    assert_eq!(issuer.fetches().await, 1);
    assert_eq!(
        call(&app, Some(&old.mint(&claims("u"))), None).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn auth_garbage_kids_cannot_turn_requests_into_a_fetch_storm() {
    let key = TestKey::new("k1", 1);
    let issuer = Issuer::start(&[&key]).await;
    // The interval itself is covered by the rotation test; here it must not elapse mid-loop.
    let app = issuer.app_with_refresh(false, NO_REFRESH);
    for i in 0..30 {
        let t = TestKey::new(&format!("random-{i}"), 3).mint(&claims("u"));
        assert_eq!(call(&app, Some(&t), None).await.0, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(issuer.fetches().await, 1);
}

#[tokio::test]
async fn auth_issuer_outage_refuses_tokens_without_a_distinct_answer() {
    let key = TestKey::new("k1", 1);
    let issuer = Issuer::start(&[&key]).await;
    let app = issuer.app(false);
    issuer.server.reset().await; // every request now 404s
    let body = refused(&app, &key.mint(&claims("u"))).await;
    assert!(body.contains("401"));
}

#[tokio::test]
async fn auth_dev_header_works_only_with_dev_auth_and_never_overrides_a_bearer_token() {
    let key = TestKey::new("k1", 1);
    let issuer = Issuer::start_db(&[&key]).await;

    // Off: the header alone is refused.
    assert_eq!(
        call(&issuer.app(false), None, Some(DEV_ORG)).await.0,
        StatusCode::UNAUTHORIZED
    );
    // On: the header alone binds.
    let (status, body) = call(&issuer.app(true), None, Some(DEV_ORG)).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, DEV_ORG));
    // On, with a bad bearer token: refused, not downgraded to the header.
    assert_eq!(
        call(&issuer.app(true), Some("not-a-jwt"), Some(DEV_ORG))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    // On, with a good bearer token: the token wins over the header.
    let (status, body) = call(
        &issuer.app(true),
        Some(&key.mint(&claims("user-1"))),
        Some(DEV_ORG),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The token's identity, not the header, picks the org: the user's own personal org.
    assert_ne!(body, DEV_ORG);
    assert!(uuid::Uuid::parse_str(&body).is_ok(), "{body}");
}

#[tokio::test]
async fn auth_bearer_token_is_refused_when_no_issuer_is_configured() {
    let key = TestKey::new("k1", 1);
    let state = AppState::new(
        true,
        Arc::new(ReadyFlag::new(true)),
        common::unreachable_db(),
    );
    let app = app::with_layers(app::routes().route("/whoami", get(whoami)), state);
    let (status, _) = call(&app, Some(&key.mint(&claims("u"))), Some(DEV_ORG)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_verify_span_has_no_token_content() {
    let capture = common::capture_logs();

    let key = TestKey::new("k1", 1);
    let issuer = Issuer::start_db(&[&key]).await;
    let app = issuer.app(false);
    let good = key.mint(&claims("secret-subject-xyz"));
    let bad = key.mint(&{
        let mut c = claims("secret-subject-xyz");
        c["aud"] = json!("nope");
        c
    });
    assert_eq!(call(&app, Some(&good), None).await.0, StatusCode::OK);
    assert_eq!(
        call(&app, Some(&bad), None).await.0,
        StatusCode::UNAUTHORIZED
    );

    let logs = capture.contents();
    let all_logs = capture.all_contents();
    assert!(logs.contains("verify_jwt"), "span missing: {logs}");
    assert!(
        logs.contains("outcome=\"ok\"") || logs.contains("outcome=ok"),
        "{logs}"
    );
    assert!(logs.contains("rejected"), "{logs}");
    for secret in [
        good.as_str(),
        bad.as_str(),
        good.split('.').nth(1).unwrap(),
        good.split('.').nth(2).unwrap(),
        "secret-subject-xyz",
        "secret-subject-xyz@example.com",
    ] {
        assert!(!all_logs.contains(secret), "trace leaked token content");
    }
}

#[tokio::test]
async fn users_unverified_email_gets_403_problem_over_http() {
    let key = TestKey::new("k1", 1);
    let issuer = Issuer::start_db(&[&key]).await;
    let app = issuer.app(false);
    for unverified in [json!(false), Value::Null] {
        let mut c = claims("unverified-1");
        if unverified.is_null() {
            c.as_object_mut().unwrap().remove("email_verified");
        } else {
            c["email_verified"] = unverified;
        }
        let (status, body) = call(&app, Some(&key.mint(&c)), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["type"],
            "urn:locksmith:problem:email-verification-required"
        );
        assert_eq!(v["status"], 403);
        assert!(!body.contains("unverified-1"), "no identity echoed");
    }
    // Once the issuer reports the email as verified, the same subject gets in.
    let (status, _) = call(&app, Some(&key.mint(&claims("unverified-1"))), None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn users_same_verified_email_from_two_subjects_share_one_org_over_http() {
    let key = TestKey::new("k1", 1);
    let issuer = Issuer::start_db(&[&key]).await;
    let app = issuer.app(false);
    let mut google = claims("google-1");
    google["email"] = json!("ada@example.com");
    let mut github = claims("github-1");
    github["email"] = json!("ada@example.com");
    let (_, a) = call(&app, Some(&key.mint(&google)), None).await;
    let (_, b) = call(&app, Some(&key.mint(&github)), None).await;
    assert!(uuid::Uuid::parse_str(&a).is_ok(), "{a}");
    assert_eq!(a, b);
}

// T1 task 5.1: auth events in the audit ledger, never with credentials.

async fn post(app: &Router, uri: &str, token: Option<&str>, dev_org: Option<&str>) -> StatusCode {
    let mut b = Request::builder().method("POST").uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    if let Some(o) = dev_org {
        b = b.header("x-locksmith-dev-org", o);
    }
    app.clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

/// Every ledger row as `(kind, actor, target, outcome, attrs)`, oldest first per org.
async fn ledger(pg: &common::Pg) -> Vec<(String, String, Option<String>, String, String)> {
    let mut c = pg.admin().await;
    ls_control_plane::db::sql::query_as(
        "SELECT kind, actor, target, outcome, attrs::text FROM audit_events ORDER BY at, seq",
    )
    .fetch_all(&mut c)
    .await
    .unwrap()
}

fn kinds(rows: &[(String, String, Option<String>, String, String)]) -> Vec<&str> {
    rows.iter().map(|r| r.0.as_str()).collect()
}

#[tokio::test]
async fn auth_events_sign_in_sign_out_and_personal_org_are_ledgered_without_tokens() {
    let key = TestKey::new("k1", 1);
    let issuer = Issuer::start_db(&[&key]).await;
    let app = issuer.app(false);
    let token = key.mint(&claims("user-audit"));
    let (_, org) = call(&app, Some(&token), None).await; // first sign-in creates the org
    assert_eq!(
        post(&app, "/v1/auth/sign-in", Some(&token), None).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post(&app, "/v1/auth/sign-out", Some(&token), None).await,
        StatusCode::NO_CONTENT
    );

    let rows = ledger(issuer.pg.as_ref().unwrap()).await;
    assert_eq!(
        kinds(&rows),
        ["org.personal_created", "auth.sign_in", "auth.sign_out"]
    );
    for (_, actor, target, outcome, attrs) in &rows {
        assert!(actor.starts_with("user:"), "{actor}");
        assert_eq!(target.as_deref(), Some(format!("org:{org}").as_str()));
        assert_eq!(outcome, "ok");
        assert!(attrs.contains("idp.test"), "issuer host recorded: {attrs}");
    }
    // Nothing credential-like or identity-claim-like reached any column.
    let dump = format!("{rows:?}");
    let parts: Vec<&str> = token.split('.').collect();
    assert!(!dump.contains(&token) && parts.iter().all(|p| !dump.contains(p)));
    for claim in ["user-audit", "example.com", "Bearer", "authorization"] {
        assert!(!dump.contains(claim), "{claim} leaked into the ledger");
    }
}

#[tokio::test]
async fn auth_sign_in_and_out_refuse_the_dev_header_and_bad_tokens() {
    let key = TestKey::new("k1", 1);
    let issuer = Issuer::start_db(&[&key]).await;
    let app = issuer.app(true);
    for uri in ["/v1/auth/sign-in", "/v1/auth/sign-out"] {
        assert_eq!(
            post(&app, uri, None, Some(DEV_ORG)).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(post(&app, uri, None, None).await, StatusCode::UNAUTHORIZED);
        let forged = TestKey::new("k1", 9).mint(&claims("user-1"));
        assert_eq!(
            post(&app, uri, Some(&forged), None).await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert!(ledger(issuer.pg.as_ref().unwrap()).await.is_empty());
}

#[tokio::test]
async fn auth_verify_failed_is_ledgered_for_a_known_user_only() {
    let key = TestKey::new("k1", 1);
    let issuer = Issuer::start_db(&[&key]).await;
    let app = issuer.app(false);

    // An unknown identity with an unverified email gets 403 and no ledger row anywhere.
    let mut stranger = claims("stranger");
    stranger["email_verified"] = json!(false);
    let (status, _) = call(&app, Some(&key.mint(&stranger)), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(ledger(issuer.pg.as_ref().unwrap()).await.is_empty());

    // A known user whose token now says "unverified" is refused and the refusal is recorded.
    let (status, _) = call(&app, Some(&key.mint(&claims("known"))), None).await;
    assert_eq!(status, StatusCode::OK);
    let mut now_unverified = claims("known");
    now_unverified["email_verified"] = json!(false);
    let token = key.mint(&now_unverified);
    let (status, _) = call(&app, Some(&token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let rows = ledger(issuer.pg.as_ref().unwrap()).await;
    assert_eq!(kinds(&rows), ["org.personal_created", "auth.verify_failed"]);
    let (_, actor, _, outcome, attrs) = &rows[1];
    assert!(actor.starts_with("user:"));
    assert_eq!(outcome, "denied");
    assert!(attrs.contains("email_unverified"), "{attrs}");
    let dump = format!("{rows:?}");
    assert!(!dump.contains(&token) && !dump.contains("known@"));
}

#[tokio::test]
async fn auth_linked_identity_does_not_create_a_second_personal_org_event() {
    let key = TestKey::new("k1", 1);
    let issuer = Issuer::start_db(&[&key]).await;
    let app = issuer.app(false);
    let mut a = claims("google-1");
    a["email"] = json!("ada@example.com");
    let mut b = claims("github-1");
    b["email"] = json!("ada@example.com");
    call(&app, Some(&key.mint(&a)), None).await;
    call(&app, Some(&key.mint(&b)), None).await;
    let rows = ledger(issuer.pg.as_ref().unwrap()).await;
    assert_eq!(kinds(&rows), ["org.personal_created"]);
}
