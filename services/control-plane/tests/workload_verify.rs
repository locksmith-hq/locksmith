//! D4 task 2.4: external workload token verification against a wiremock stub issuer (OpenID
//! discovery plus JWKS). Valid, expired, wrong audience, wrong issuer, `alg: none`, HS256
//! confusion, unknown `kid`, rotated key, issuer down and issuer at a private address.
//!
//! The stub runs on loopback over plain http, so most tests use the local-dev private-host flag;
//! the private-address tests turn it off and assert no request reaches the stub.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ls_control_plane::auth::external::{
    DEFAULT_MAX_LIFETIME, ExternalToken, ExternalVerifier, TrustAnchor,
};
use ls_control_plane::auth::human::Refused;
use ls_control_plane::auth::issuers::{IssuerAccess, IssuerRegistry};
use ls_control_plane::workload::{self, ConditionInput, IssuerKind};
use p256::pkcs8::EncodePrivateKey as _;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const AUDIENCE: &str = "https://locksmith.example";
const DISCOVERY: &str = "/.well-known/openid-configuration";
/// Long enough that no test sees a second fetch unless it waits for one.
const NO_REFRESH: Duration = Duration::from_secs(3600);
const SHORT_REFRESH: Duration = Duration::from_millis(500);

const DEV: IssuerAccess = IssuerAccess {
    allow_private_hosts: true,
};
const PUBLIC: IssuerAccess = IssuerAccess {
    allow_private_hosts: false,
};

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

    fn mint_with(&self, header: Header, claims: &Value) -> String {
        let der = self.signing.to_pkcs8_der().unwrap();
        jsonwebtoken::encode(&header, claims, &EncodingKey::from_ec_der(der.as_bytes())).unwrap()
    }

    fn mint(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        self.mint_with(header, claims)
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A token with a hand-written header and arbitrary signature bytes.
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
}

impl Issuer {
    async fn start(keys: &[&TestKey]) -> Self {
        let issuer = Self {
            server: MockServer::start().await,
        };
        issuer.publish(keys).await;
        issuer
    }

    fn url(&self) -> String {
        self.server.uri()
    }

    async fn publish(&self, keys: &[&TestKey]) {
        self.server.reset().await;
        Mock::given(method("GET"))
            .and(path(DISCOVERY))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": self.url(),
                "jwks_uri": format!("{}/jwks", self.url()),
                "id_token_signing_alg_values_supported": ["ES256", "RS256"],
            })))
            .mount(&self.server)
            .await;
        let jwks: Vec<Value> = keys.iter().map(|k| k.jwk()).collect();
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": jwks })))
            .mount(&self.server)
            .await;
    }

    async fn requests(&self, p: &str) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == p)
            .count()
    }

    async fn total_requests(&self) -> usize {
        self.server.received_requests().await.unwrap().len()
    }

    /// GitHub-shaped claims for this issuer.
    fn claims(&self, git_ref: &str) -> Value {
        let t = now();
        json!({
            "iss": self.url(), "aud": AUDIENCE,
            "sub": format!("repo:acme/api:ref:{git_ref}"),
            "repository": "acme/api", "repository_owner": "acme", "ref": git_ref,
            "jti": format!("jti-{t}"), "iat": t, "nbf": t, "exp": t + 600,
        })
    }
}

fn verifier(access: IssuerAccess, min_refresh: Duration) -> ExternalVerifier {
    let registry = IssuerRegistry::with_refresh(access, min_refresh, NO_REFRESH).unwrap();
    ExternalVerifier::new(registry, DEFAULT_MAX_LIFETIME)
}

fn anchor(issuer: &str) -> TrustAnchor<'_> {
    TrustAnchor {
        issuer,
        audience: AUDIENCE,
    }
}

async fn verify(v: &ExternalVerifier, token: String, issuer: &str) -> Result<Value, Refused> {
    v.verify_external(&ExternalToken::from(token), anchor(issuer))
        .await
        .map(|c| c.as_value())
}

fn ci(claim: &str, value: &str) -> ConditionInput {
    ConditionInput {
        claim: claim.into(),
        value: value.into(),
    }
}

#[tokio::test]
async fn workload_verify_valid_token_verifies_and_matches_the_policy() {
    let key = TestKey::new("k1", 7);
    let issuer = Issuer::start(&[&key]).await;
    let v = verifier(DEV, NO_REFRESH);

    let claims = verify(
        &v,
        key.mint(&issuer.claims("refs/heads/main")),
        &issuer.url(),
    )
    .await
    .unwrap();
    assert_eq!(claims["repository"], "acme/api");

    // The verified claims go through the policy's conditions (task 2.3).
    let policy = workload::validate(
        "ci",
        IssuerKind::Github,
        None,
        AUDIENCE,
        &[ci("repository", "acme/api"), ci("ref", "refs/heads/main")],
    )
    .unwrap();
    assert!(workload::matches(&policy.conditions, &claims));
    let feature = verify(
        &v,
        key.mint(&issuer.claims("refs/heads/feature")),
        &issuer.url(),
    )
    .await
    .unwrap();
    assert!(!workload::matches(&policy.conditions, &feature));

    // Discovery and JWKS were fetched once and are reused.
    assert_eq!(issuer.requests(DISCOVERY).await, 1);
    assert_eq!(issuer.requests("/jwks").await, 1);
}

#[tokio::test]
async fn workload_verify_kubernetes_token_with_array_audience() {
    let key = TestKey::new("k8s", 8);
    let issuer = Issuer::start(&[&key]).await;
    let v = verifier(DEV, NO_REFRESH);
    let t = now();
    let token = key.mint(&json!({
        "iss": issuer.url(), "aud": [AUDIENCE], "sub": "system:serviceaccount:prod:deployer",
        "kubernetes.io": {"namespace": "prod", "serviceaccount": {"name": "deployer"}},
        "iat": t, "nbf": t, "exp": t + 600,
    }));
    let claims = verify(&v, token, &issuer.url()).await.unwrap();
    let policy = workload::validate(
        "k",
        IssuerKind::Oidc,
        Some("https://k8s.example"),
        AUDIENCE,
        &[ci("sub", "system:serviceaccount:prod:deployer")],
    )
    .unwrap();
    assert!(workload::matches(&policy.conditions, &claims));
}

#[tokio::test]
async fn workload_verify_expired_token_is_refused() {
    let key = TestKey::new("k1", 7);
    let issuer = Issuer::start(&[&key]).await;
    let v = verifier(DEV, NO_REFRESH);
    let mut c = issuer.claims("refs/heads/main");
    let t = now() - 3000;
    c["iat"] = json!(t);
    c["nbf"] = json!(t);
    c["exp"] = json!(t + 600);
    assert_eq!(
        verify(&v, key.mint(&c), &issuer.url()).await,
        Err(Refused("invalid"))
    );
}

#[tokio::test]
async fn workload_verify_not_yet_valid_and_overlong_tokens_are_refused() {
    let key = TestKey::new("k1", 7);
    let issuer = Issuer::start(&[&key]).await;
    let v = verifier(DEV, NO_REFRESH);

    let mut c = issuer.claims("refs/heads/main");
    c["nbf"] = json!(now() + 600);
    assert_eq!(
        verify(&v, key.mint(&c), &issuer.url()).await,
        Err(Refused("invalid"))
    );

    let mut c = issuer.claims("refs/heads/main");
    c["exp"] = json!(now() + 2 * 3600);
    assert_eq!(
        verify(&v, key.mint(&c), &issuer.url()).await,
        Err(Refused("lifetime"))
    );

    let mut c = issuer.claims("refs/heads/main");
    c.as_object_mut().unwrap().remove("iat");
    assert_eq!(
        verify(&v, key.mint(&c), &issuer.url()).await,
        Err(Refused("invalid"))
    );
}

#[tokio::test]
async fn workload_verify_wrong_audience_is_refused() {
    let key = TestKey::new("k1", 7);
    let issuer = Issuer::start(&[&key]).await;
    let v = verifier(DEV, NO_REFRESH);
    for aud in [json!("https://other.example"), json!(["sts.amazonaws.com"])] {
        let mut c = issuer.claims("refs/heads/main");
        c["aud"] = aud;
        assert_eq!(
            verify(&v, key.mint(&c), &issuer.url()).await,
            Err(Refused("invalid"))
        );
    }
    let mut c = issuer.claims("refs/heads/main");
    c.as_object_mut().unwrap().remove("aud");
    assert_eq!(
        verify(&v, key.mint(&c), &issuer.url()).await,
        Err(Refused("invalid"))
    );
}

#[tokio::test]
async fn workload_verify_wrong_issuer_is_refused_without_an_outbound_request() {
    let key = TestKey::new("k1", 7);
    let issuer = Issuer::start(&[&key]).await;
    let attacker = Issuer::start(&[&key]).await;
    let v = verifier(DEV, NO_REFRESH);

    // The token names the attacker's issuer; the policy names the real one.
    let mut c = issuer.claims("refs/heads/main");
    c["iss"] = json!(attacker.url());
    assert_eq!(
        verify(&v, key.mint(&c), &issuer.url()).await,
        Err(Refused("issuer"))
    );
    assert_eq!(issuer.total_requests().await, 0);
    assert_eq!(attacker.total_requests().await, 0);

    // A missing `iss` is the same refusal.
    c.as_object_mut().unwrap().remove("iss");
    assert_eq!(
        verify(&v, key.mint(&c), &issuer.url()).await,
        Err(Refused("issuer"))
    );
    assert_eq!(issuer.total_requests().await, 0);
}

#[tokio::test]
async fn workload_verify_discovery_naming_another_issuer_is_refused() {
    let key = TestKey::new("k1", 7);
    let issuer = Issuer::start(&[&key]).await;
    issuer.server.reset().await;
    Mock::given(method("GET"))
        .and(path(DISCOVERY))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": "https://token.actions.githubusercontent.com",
            "jwks_uri": format!("{}/jwks", issuer.url()),
        })))
        .mount(&issuer.server)
        .await;
    let v = verifier(DEV, NO_REFRESH);
    assert_eq!(
        verify(
            &v,
            key.mint(&issuer.claims("refs/heads/main")),
            &issuer.url()
        )
        .await,
        Err(Refused("issuer_unavailable"))
    );
    assert_eq!(issuer.requests("/jwks").await, 0);
}

#[tokio::test]
async fn workload_verify_alg_none_is_refused() {
    let key = TestKey::new("k1", 7);
    let issuer = Issuer::start(&[&key]).await;
    let v = verifier(DEV, NO_REFRESH);
    let c = issuer.claims("refs/heads/main");
    for alg in ["none", "None", "NONE"] {
        let t = raw_token(&json!({"alg": alg, "typ": "JWT", "kid": "k1"}), &c, b"");
        assert_eq!(
            verify(&v, t, &issuer.url()).await,
            Err(Refused("malformed")),
            "{alg}"
        );
    }
    // An empty signature segment on an ES256 header is still a forgery.
    let t = raw_token(&json!({"alg": "ES256", "kid": "k1"}), &c, b"");
    assert_eq!(verify(&v, t, &issuer.url()).await, Err(Refused("invalid")));
}

#[tokio::test]
async fn workload_verify_hs256_key_confusion_is_refused() {
    let key = TestKey::new("k1", 7);
    let issuer = Issuer::start(&[&key]).await;
    let v = verifier(DEV, NO_REFRESH);
    let c = issuer.claims("refs/heads/main");
    // HMAC keyed with public material the attacker can read: the JWK coordinates and the JWKS.
    let jwk = key.jwk();
    let x = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap();
    let jwks_text = serde_json::to_vec(&json!({"keys": [jwk]})).unwrap();
    for (alg, secret) in [
        (Algorithm::HS256, x.as_slice()),
        (Algorithm::HS256, jwks_text.as_slice()),
        (Algorithm::HS384, x.as_slice()),
        (Algorithm::HS512, x.as_slice()),
    ] {
        let mut header = Header::new(alg);
        header.kid = Some("k1".into());
        let t =
            jsonwebtoken::encode(&header, &c, &EncodingKey::from_secret(secret).unwrap()).unwrap();
        assert_eq!(
            verify(&v, t, &issuer.url()).await,
            Err(Refused("algorithm")),
            "{alg:?}"
        );
    }
    // Refused on the header alone: the issuer was never contacted.
    assert_eq!(issuer.total_requests().await, 0);

    // An ES256 key cannot be used for an RS256 header either.
    let t = raw_token(&json!({"alg": "RS256", "kid": "k1"}), &c, &[0u8; 256]);
    assert_eq!(
        verify(&v, t, &issuer.url()).await,
        Err(Refused("algorithm"))
    );
}

#[tokio::test]
async fn workload_verify_unknown_kid_gets_one_rate_limited_refresh() {
    let key = TestKey::new("k1", 7);
    let stranger = TestKey::new("k-unknown", 9);
    let issuer = Issuer::start(&[&key]).await;
    let v = verifier(DEV, NO_REFRESH);
    let c = issuer.claims("refs/heads/main");

    assert_eq!(
        verify(&v, stranger.mint(&c), &issuer.url()).await,
        Err(Refused("unknown_key"))
    );
    assert_eq!(issuer.requests("/jwks").await, 1);
    // A burst of unknown kids inside the interval causes no further fetch.
    for i in 0..10 {
        let k = TestKey::new(&format!("random-{i}"), 20 + i);
        assert_eq!(
            verify(&v, k.mint(&c), &issuer.url()).await,
            Err(Refused("unknown_key"))
        );
    }
    assert_eq!(issuer.requests("/jwks").await, 1);
    assert_eq!(issuer.requests(DISCOVERY).await, 1);
    // A token without a kid is refused outright.
    let mut header = Header::new(Algorithm::ES256);
    header.kid = None;
    assert_eq!(
        verify(&v, key.mint_with(header, &c), &issuer.url()).await,
        Err(Refused("no_kid"))
    );
}

#[tokio::test]
async fn workload_verify_rotated_key_is_picked_up_after_the_refresh_interval() {
    let old = TestKey::new("old", 7);
    let new = TestKey::new("new", 11);
    let issuer = Issuer::start(&[&old]).await;
    let v = verifier(DEV, SHORT_REFRESH);
    let c = issuer.claims("refs/heads/main");
    assert!(verify(&v, old.mint(&c), &issuer.url()).await.is_ok());

    issuer.publish(&[&new]).await;
    tokio::time::sleep(SHORT_REFRESH + Duration::from_millis(200)).await;
    assert!(verify(&v, new.mint(&c), &issuer.url()).await.is_ok());
    // A key with a known kid but the wrong material fails the signature.
    let impostor = TestKey::new("new", 12);
    assert_eq!(
        verify(&v, impostor.mint(&c), &issuer.url()).await,
        Err(Refused("invalid"))
    );
}

#[tokio::test]
async fn workload_verify_issuer_down_fails_closed() {
    let key = TestKey::new("k1", 7);
    let issuer = Issuer::start(&[&key]).await;
    let c = issuer.claims("refs/heads/main");

    // Discovery answers 500.
    issuer.server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&issuer.server)
        .await;
    let v = verifier(DEV, NO_REFRESH);
    assert_eq!(
        verify(&v, key.mint(&c), &issuer.url()).await,
        Err(Refused("issuer_unavailable"))
    );
    // A failed discovery is not retried inside the interval.
    assert_eq!(
        verify(&v, key.mint(&c), &issuer.url()).await,
        Err(Refused("issuer_unavailable"))
    );
    assert_eq!(issuer.requests(DISCOVERY).await, 1);

    // Discovery works but the JWKS endpoint is down.
    issuer.server.reset().await;
    Mock::given(method("GET"))
        .and(path(DISCOVERY))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer.url(), "jwks_uri": format!("{}/jwks", issuer.url()),
        })))
        .mount(&issuer.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&issuer.server)
        .await;
    let v = verifier(DEV, NO_REFRESH);
    assert_eq!(
        verify(&v, key.mint(&c), &issuer.url()).await,
        Err(Refused("unknown_key"))
    );

    // Nothing listening at all.
    let v = verifier(DEV, NO_REFRESH);
    let gone = "http://127.0.0.1:1";
    let mut c = c.clone();
    c["iss"] = json!(gone);
    assert_eq!(
        verify(&v, key.mint(&c), gone).await,
        Err(Refused("issuer_unavailable"))
    );
}

#[tokio::test]
async fn workload_verify_oversized_discovery_document_is_refused() {
    let key = TestKey::new("k1", 7);
    let issuer = Issuer::start(&[&key]).await;
    issuer.server.reset().await;
    Mock::given(method("GET"))
        .and(path(DISCOVERY))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b' '; 64 * 1024 + 1]))
        .mount(&issuer.server)
        .await;
    let v = verifier(DEV, NO_REFRESH);
    assert_eq!(
        verify(
            &v,
            key.mint(&issuer.claims("refs/heads/main")),
            &issuer.url()
        )
        .await,
        Err(Refused("issuer_unavailable"))
    );
}

#[tokio::test]
async fn workload_verify_issuer_at_a_private_address_is_never_contacted() {
    let key = TestKey::new("k1", 7);
    let issuer = Issuer::start(&[&key]).await;
    let port = issuer.server.address().port();
    let v = verifier(PUBLIC, NO_REFRESH);

    // IP literals: refused before any request.
    for url in [
        format!("https://127.0.0.1:{port}"),
        "https://169.254.169.254".to_owned(),
        "https://10.0.0.8".to_owned(),
        "https://[::1]".to_owned(),
    ] {
        let mut c = issuer.claims("refs/heads/main");
        c["iss"] = json!(url);
        assert_eq!(
            verify(&v, key.mint(&c), &url).await,
            Err(Refused("issuer_address")),
            "{url}"
        );
    }
    // A name that resolves to loopback: refused by the guarded resolver, no connection made.
    let url = format!("https://localhost:{port}");
    let mut c = issuer.claims("refs/heads/main");
    c["iss"] = json!(url);
    assert_eq!(
        verify(&v, key.mint(&c), &url).await,
        Err(Refused("issuer_unavailable"))
    );
    // Plain http is refused without the local-dev flag.
    let url = issuer.url();
    assert_eq!(
        verify(&v, key.mint(&issuer.claims("refs/heads/main")), &url).await,
        Err(Refused("issuer_url"))
    );
    assert_eq!(issuer.total_requests().await, 0);

    // The create-time check refuses the same issuers.
    let registry = v.issuers();
    assert!(
        registry
            .check_issuer_host(&format!("https://localhost:{port}"))
            .await
            .is_err()
    );
    assert!(
        registry
            .check_issuer_host("https://169.254.169.254")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn workload_verify_metadata_address_is_refused_even_with_the_dev_flag() {
    let key = TestKey::new("k1", 7);
    let v = verifier(DEV, NO_REFRESH);
    let url = "http://169.254.169.254";
    let t = now();
    let token = key.mint(&json!({
        "iss": url, "aud": AUDIENCE, "sub": "x", "iat": t, "exp": t + 60,
    }));
    assert_eq!(verify(&v, token, url).await, Err(Refused("issuer_address")));
}

#[tokio::test]
async fn workload_verify_jku_and_x5u_headers_are_ignored() {
    let key = TestKey::new("k1", 7);
    let attacker_key = TestKey::new("k1", 13);
    let issuer = Issuer::start(&[&key]).await;
    let attacker = Issuer::start(&[&attacker_key]).await;
    let v = verifier(DEV, NO_REFRESH);
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("k1".into());
    header.jku = Some(format!("{}/jwks", attacker.url()));
    header.x5u = Some(format!("{}/cert", attacker.url()));
    let t = attacker_key.mint_with(header, &issuer.claims("refs/heads/main"));
    assert_eq!(verify(&v, t, &issuer.url()).await, Err(Refused("invalid")));
    assert_eq!(attacker.total_requests().await, 0);
}

#[tokio::test]
async fn workload_verify_oversized_and_malformed_tokens_are_refused() {
    let key = TestKey::new("k1", 7);
    let issuer = Issuer::start(&[&key]).await;
    let v = verifier(DEV, NO_REFRESH);
    assert_eq!(
        verify(&v, "a".repeat(9 * 1024), &issuer.url()).await,
        Err(Refused("too_large"))
    );
    for junk in ["", "not-a-jwt", "a.b.c", "...."] {
        assert_eq!(
            verify(&v, junk.to_owned(), &issuer.url()).await,
            Err(Refused("malformed")),
            "{junk}"
        );
    }
    assert_eq!(issuer.total_requests().await, 0);
}
