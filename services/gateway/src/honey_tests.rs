//! t5-honey-tokens task 2.4: the owner-only honey reveal against the real control plane and its
//! Postgres ledger (ls-pg-test; needs Docker), with a local mock OIDC issuer (wiremock JWKS) and
//! the gateway's real decrypt path (material from the control plane, a stand-in KMS).
//!
//! Covers: the owner gets the value and `honey.revealed` lands without it; agent tokens and
//! short-lived credentials are refused with `403` before the control plane is asked; a secret of
//! kind `standard` and a disabled honey token are `409`; another org's person is `403`; unknown
//! and malformed ids are `404`; a token for another audience (an MCP hub token) is `401`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ls_control_plane::agent_token::{AUDIENCE as AGENT_AUDIENCE, AgentClaims, AgentTokenSigner};
use ls_control_plane::auth::ServiceToken;
use ls_control_plane::auth::human::{HumanAuth, HumanAuthConfig};
use ls_control_plane::db::{Database, PoolSettings, sql};
use ls_control_plane::readiness::ReadyFlag;
use p256::pkcs8::EncodePrivateKey as _;
use secrecy::SecretString;
use serde_json::{Value, json};
use tower::ServiceExt;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zeroize::Zeroizing;

use super::*;
use crate::app::{self, AppState};
use crate::audit::MemoryAudit;
use crate::auth::testkit::StubJwks;
use crate::auth::{AgentAuth, JwksSettings};
use crate::config::Bindings;
use crate::decrypt::testkit::{FakeKms, seal};
use crate::decrypt::{CacheSettings, Decryptor, DekCache};
use crate::egress::testkit::StubResolver;
use crate::grants::testkit::StubGrants;
use crate::relay::{Relay, RelayOptions};

const SERVICE_TOKEN: &str = "test-only-gateway-service-token-0123456789";
const ISSUER: &str = "https://idp.test/realms/locksmith";
const API_AUDIENCE: &str = "locksmith-api";
const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a1);
/// The decoy (a fake AWS access key id shape). Must never appear in any event or refusal.
fn value() -> &'static [u8] {
    // Built at runtime so no secret scanner flags the source.
    static V: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    V.get_or_init(|| [b"AKIA".as_slice(), b"HONEYCANARY7QX2Z"].concat())
}
/// A standard secret's value, sealed too, so a wrong reveal would have something to leak.
const STANDARD_VALUE: &[u8] = b"standard-canary-value-9Lm";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A deterministic throwaway P-256 issuer key (test only).
struct IssuerKey(p256::ecdsa::SigningKey);

impl IssuerKey {
    fn new() -> Self {
        Self(p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap())
    }

    fn jwk(&self) -> Value {
        let point = self.0.verifying_key().to_sec1_point(false);
        json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        })
    }

    /// A person's access token for `aud`.
    fn person(&self, sub: &str, aud: &str) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("k1".to_owned());
        let claims = json!({
            "iss": ISSUER, "aud": aud, "sub": sub, "exp": now() + 600,
            "email": format!("{sub}@example.com"), "email_verified": true,
        });
        let der = self.0.to_pkcs8_der().unwrap();
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ec_der(der.as_bytes())).unwrap()
    }
}

fn client() -> reqwest::Client {
    crate::http_client::build(
        std::time::Duration::from_secs(2),
        std::time::Duration::from_secs(10),
        None,
    )
    .unwrap()
}

/// A secret row of kind `honey` (with `template`) or `standard` (without), as the NestJS API
/// would create it. `ids` is (org, project, environment).
async fn insert_secret(
    admin: &mut sql::PgConnection,
    ids: (Uuid, Uuid, Uuid),
    name: &str,
    template: Option<&str>,
    disabled: bool,
) -> Uuid {
    let kind = if template.is_some() {
        "honey"
    } else {
        "standard"
    };
    sql::query_scalar(
        "INSERT INTO secrets (org_id, project_id, environment_id, name, kind, honey_template, disabled_at) \
         VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $7 THEN now() END) RETURNING id",
    )
    .bind(ids.0)
    .bind(ids.1)
    .bind(ids.2)
    .bind(name)
    .bind(kind)
    .bind(template)
    .bind(disabled)
    .fetch_one(admin)
    .await
    .unwrap()
}

struct Fixture {
    pg: ls_pg_test::Pg,
    db: Database,
    _issuer: MockServer,
    cp_url: Url,
    cp_server: tokio::task::JoinHandle<()>,
    app: Router,
    kms: Arc<FakeKms>,
    org: Uuid,
    owner: Uuid,
    owner_token: String,
    other_token: String,
    mcp_token: String,
    agent_token: String,
    honey: Uuid,
    standard: Uuid,
    disabled: Uuid,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.cp_server.abort();
    }
}

impl Fixture {
    async fn start() -> Self {
        let pg = ls_pg_test::Pg::start().await;
        ls_control_plane::migrate::run(pg.bootstrap())
            .await
            .expect("migrate");
        let key = IssuerKey::new();
        let issuer = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [key.jwk()] })))
            .mount(&issuer)
            .await;
        let human = HumanAuth::new(&HumanAuthConfig {
            issuer: ISSUER.to_owned(),
            audience: API_AUDIENCE.to_owned(),
            jwks_url: format!("{}/jwks", issuer.uri()),
        })
        .unwrap();
        let db = Database::connect_lazy(pg.app(), PoolSettings::default());
        let state =
            ls_control_plane::app::AppState::new(false, Arc::new(ReadyFlag::new(true)), db.clone())
                .with_service_token(ServiceToken::new(SecretString::from(SERVICE_TOKEN)))
                .with_human_auth(human);
        let cp = ls_control_plane::app::build(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cp_url: Url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let cp_server = tokio::spawn(async move {
            let _ = axum::serve(listener, cp).await;
        });

        // Two people sign in; each gets a personal org. The first is the gateway org's owner.
        let owner_token = key.person("owner", API_AUDIENCE);
        let other_token = key.person("stranger", API_AUDIENCE);
        let http = client();
        for t in [&owner_token, &other_token] {
            let r = http
                .post(cp_url.join("v1/auth/sign-in").unwrap())
                .bearer_auth(t)
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 204);
        }
        let mut admin = pg.admin().await;
        let (owner, org): (Uuid, Uuid) =
            sql::query_as("SELECT id, personal_org_id FROM users WHERE subject = 'owner'")
                .fetch_one(&mut admin)
                .await
                .unwrap();
        let project: Uuid =
            sql::query_scalar("INSERT INTO projects (org_id, name) VALUES ($1, 'p') RETURNING id")
                .bind(org)
                .fetch_one(&mut admin)
                .await
                .unwrap();
        let env: Uuid = sql::query_scalar(
            "INSERT INTO environments (org_id, project_id, name) VALUES ($1, $2, 'dev') RETURNING id",
        )
        .bind(org)
        .bind(project)
        .fetch_one(&mut admin)
        .await
        .unwrap();
        let ids = (org, project, env);
        let honey = insert_secret(
            &mut admin,
            ids,
            "prod-aws-decoy",
            Some("aws_access_key"),
            false,
        )
        .await;
        let standard = insert_secret(&mut admin, ids, "real-key", None, false).await;
        let disabled = insert_secret(&mut admin, ids, "old-decoy", Some("github_pat"), true).await;
        // Seal values as the control plane would; the stand-in KMS hands back the honey DEK.
        let sealed = seal(org, honey, 1, value());
        for (id, s) in [
            (honey, &sealed),
            (standard, &seal(org, standard, 1, STANDARD_VALUE)),
            (disabled, &seal(org, disabled, 1, value())),
        ] {
            sql::query(
                "INSERT INTO secret_versions (org_id, secret_id, version, ciphertext, wrapped_dek, key_id) \
                 VALUES ($1, $2, 1, $3, $4, 'gateway:v1')",
            )
            .bind(org)
            .bind(id)
            .bind(&s.ciphertext)
            .bind(&s.wrapped)
            .execute(&mut admin)
            .await
            .unwrap();
        }

        // The gateway for `org`: material from the real control plane, the stand-in KMS.
        let control_plane = Arc::new(
            ControlPlane::new(cp_url.clone(), org, SERVICE_TOKEN.to_owned().into()).unwrap(),
        );
        let kms = Arc::new(FakeKms {
            dek: Some(sealed.dek),
            calls: AtomicUsize::new(0),
        });
        let decryptor = Decryptor::new(
            org,
            control_plane.clone(),
            kms.clone(),
            Arc::new(DekCache::new(CacheSettings::default())),
        );
        let signer = AgentTokenSigner::from_seed(Zeroizing::new([9u8; 32])).unwrap();
        let auth = Arc::new(AgentAuth::new(
            org,
            Arc::new(StubJwks::with(vec![signer.jwk().clone()])),
            JwksSettings::default(),
        ));
        let t = now() as i64;
        let agent_token = signer
            .sign(&AgentClaims {
                sub: AGENT,
                org,
                aud: AGENT_AUDIENCE.to_owned(),
                iat: t,
                exp: t + 600,
            })
            .unwrap();
        let relay = Relay::new(
            auth,
            Arc::new(StubGrants::default()),
            Bindings {
                org_id: org,
                bindings: Vec::new(),
                aws_bindings: Vec::new(),
                pg: Vec::new(),
                git_bindings: Vec::new(),
                mcp_upstreams: Vec::new(),
            },
            decryptor,
            Arc::new(StubResolver::default()),
            Arc::new(MemoryAudit::default()),
            RelayOptions::default(),
        )
        .with_honey(control_plane);
        let app =
            app::build(AppState::new(Arc::new(ReadyFlag::new(true))).with_relay(Arc::new(relay)));
        Self {
            pg,
            db,
            _issuer: issuer,
            cp_url,
            cp_server,
            app,
            kms,
            org,
            owner,
            owner_token,
            other_token,
            mcp_token: key.person("owner", "https://hub.test/mcp"),
            agent_token,
            honey,
            standard,
            disabled,
        }
    }

    /// `(status, content-type, cache-control, raw body)`.
    async fn get(&self, uri: &str, bearer: Option<&str>) -> (u16, String, String, Vec<u8>) {
        let mut b = Request::get(uri);
        if let Some(t) = bearer {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        let resp = self
            .app
            .clone()
            .oneshot(b.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let h = |n: &str| {
            resp.headers()
                .get(n)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        };
        let (ct, cc) = (h("content-type"), h("cache-control"));
        let body = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, ct, cc, body)
    }

    async fn value(&self, id: impl std::fmt::Display, bearer: Option<&str>) -> (u16, Vec<u8>) {
        let (s, _, _, b) = self
            .get(&format!("/v1/honey-tokens/{id}/value"), bearer)
            .await;
        (s, b)
    }

    /// The org's ledger as the app role (RLS applies).
    async fn records(&self) -> Vec<ls_audit::Record> {
        let org = self.org;
        self.db
            .with_org(org, move |c| {
                Box::pin(async move { ls_audit::pg::records_in_tx(c, org).await })
            })
            .await
            .unwrap()
    }

    async fn revealed(&self) -> Vec<ls_audit::Record> {
        self.records()
            .await
            .into_iter()
            .filter(|r| r.kind == "honey.revealed")
            .collect()
    }

    /// Every stored ledger row in every org as text, as the bootstrap superuser.
    async fn ledger_text(&self) -> String {
        let mut admin = self.pg.admin().await;
        let text: Option<String> =
            sql::query_scalar("SELECT string_agg(t::text, E'\\n') FROM audit_events t")
                .fetch_one(&mut admin)
                .await
                .unwrap();
        text.unwrap_or_default()
    }

    fn kms_calls(&self) -> usize {
        self.kms.calls.load(Ordering::SeqCst)
    }
}

fn attr<'a>(r: &'a ls_audit::Record, key: &str) -> Option<&'a str> {
    r.attrs
        .as_ref()?
        .entries()
        .iter()
        .find(|(k, _, _)| k == key)
        .map(|(_, _, v)| v.as_str())
}

fn assert_no_value(what: &str, bytes: &[u8]) {
    for v in [value(), STANDARD_VALUE] {
        assert!(
            !bytes.windows(v.len()).any(|w| w == v),
            "{what} contains a secret value"
        );
    }
}

fn slug(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body).unwrap()["error"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn owner_reveals_a_honey_value_and_the_ledger_records_it_without_the_value() {
    let f = Fixture::start().await;

    // Name to id: honey tokens only, ids and metadata only.
    let (s, ct, _, body) = f
        .get("/v1/honey-tokens?name=prod-aws-decoy", Some(&f.owner_token))
        .await;
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&body));
    assert!(ct.starts_with("application/json"));
    assert_no_value("lookup", &body);
    let found: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        found,
        json!({ "items": [{
            "id": f.honey, "name": "prod-aws-decoy", "template": "aws_access_key", "disabled": false
        }]})
    );
    let (s, _, _, body) = f
        .get("/v1/honey-tokens?name=real-key", Some(&f.owner_token))
        .await;
    assert_eq!(s, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({ "items": [] }),
        "a standard secret is not a honey token"
    );

    assert!(f.revealed().await.is_empty());
    let (s, ct, cc, body) = f
        .get(
            &format!("/v1/honey-tokens/{}/value", f.honey),
            Some(&f.owner_token),
        )
        .await;
    assert_eq!(s, 200);
    assert_eq!(body, value());
    assert_eq!(ct, "application/octet-stream");
    assert_eq!(cc, "no-store");
    assert_eq!(f.kms_calls(), 1);

    let rows = f.revealed().await;
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(r.actor, format!("user:{}", f.owner));
    assert_eq!(r.target.as_deref(), Some(&*format!("secret:{}", f.honey)));
    assert_eq!(r.outcome, "ok");
    assert_eq!(attr(r, "version"), Some("1"));
    assert_eq!(attr(r, "honey_template"), Some("aws_access_key"));
    let walk = ls_audit::verify(f.records().await.iter().map(ls_audit::Record::link), &[]);
    assert!(walk.ok(), "{walk:?}");
    assert_no_value("ledger", f.ledger_text().await.as_bytes());
}

#[tokio::test]
async fn agents_strangers_and_non_honey_secrets_are_refused_without_a_reveal() {
    let f = Fixture::start().await;
    let short_lived = format!("{}{}", crate::short_lived::PREFIX, "A".repeat(43));

    // Agent credentials: refused before the control plane is asked, on both routes.
    for (token, want) in [
        (f.agent_token.as_str(), "agent_token_refused"),
        (short_lived.as_str(), "agent_credential_refused"),
    ] {
        let (s, body) = f.value(f.honey, Some(token)).await;
        assert_eq!((s, slug(&body).as_str()), (403, want));
        let (s, _, _, body) = f
            .get("/v1/honey-tokens?name=prod-aws-decoy", Some(token))
            .await;
        assert_eq!((s, slug(&body).as_str()), (403, want));
    }
    // An agent token signed for another org is still an agent token.
    let other_signer = AgentTokenSigner::from_seed(Zeroizing::new([3u8; 32])).unwrap();
    let foreign = other_signer
        .mint(AGENT, Uuid::now_v7(), time::OffsetDateTime::now_utc())
        .unwrap()
        .token;
    assert_eq!(f.value(f.honey, Some(&foreign)).await.0, 403);

    // No credential, or a person's token minted for the MCP hub (another audience).
    assert_eq!(f.value(f.honey, None).await.0, 401);
    assert_eq!(f.value(f.honey, Some(&f.mcp_token)).await.0, 401);
    assert_eq!(f.value(f.honey, Some("not-a-token")).await.0, 401);

    // A person, but not this org's owner.
    let (s, body) = f.value(f.honey, Some(&f.other_token)).await;
    assert_eq!((s, slug(&body).as_str()), (403, "not_owner"));
    let (s, _, _, _) = f
        .get("/v1/honey-tokens?name=prod-aws-decoy", Some(&f.other_token))
        .await;
    assert_eq!(s, 403);

    // The owner, but not a revealable honey token.
    let (s, body) = f.value(f.standard, Some(&f.owner_token)).await;
    assert_eq!(
        (s, slug(&body).as_str()),
        (409, "not_a_revealable_honey_token")
    );
    assert_no_value("standard refusal", &body);
    assert_eq!(f.value(f.disabled, Some(&f.owner_token)).await.0, 409);
    assert_eq!(f.value(Uuid::now_v7(), Some(&f.owner_token)).await.0, 404);
    assert_eq!(f.value("not-a-uuid", Some(&f.owner_token)).await.0, 404);
    // A query without a name is a 400.
    let (s, _, _, _) = f.get("/v1/honey-tokens", Some(&f.owner_token)).await;
    assert_eq!(s, 400);

    // Nothing was decrypted and nothing was recorded as revealed.
    assert_eq!(f.kms_calls(), 0, "no unwrap for a refused caller");
    assert!(f.revealed().await.is_empty());
    assert_no_value("ledger", f.ledger_text().await.as_bytes());
    // The control plane was really behind these answers (not a stub): it is still up.
    assert!(
        client()
            .get(f.cp_url.join("healthz").unwrap())
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
}

/// t5-honey-tokens tasks 3.1-3.3 through the real control plane: the material names the kind, the
/// scan list feeds the value scan, and `honey.triggered` lands in the org's ledger with the
/// template the control plane looked up, the path, the grant and the peer, and never the value.
#[tokio::test]
async fn honey_triggered_lands_in_the_ledger_by_reference_and_by_value() {
    use crate::audit::HttpAudit;
    use crate::config::Binding;
    use crate::grants::Grant;
    use crate::honey_guard::HoneyScan;

    let f = Fixture::start().await;
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    let control_plane = Arc::new(
        ControlPlane::new(f.cp_url.clone(), f.org, SERVICE_TOKEN.to_owned().into()).unwrap(),
    );
    let decryptor = Decryptor::new(
        f.org,
        control_plane.clone(),
        f.kms.clone(),
        Arc::new(DekCache::new(CacheSettings::default())),
    );
    let signer = AgentTokenSigner::from_seed(Zeroizing::new([9u8; 32])).unwrap();
    let auth = Arc::new(AgentAuth::new(
        f.org,
        Arc::new(StubJwks::with(vec![signer.jwk().clone()])),
        JwksSettings::default(),
    ));
    let grant = |secret_id| Grant {
        grant_id: Uuid::now_v7(),
        secret_id,
        secret_name: "K".to_owned(),
        mode: "relay".to_owned(),
        scope: None,
        expires_at: None,
    };
    let (honey_grant, standard_grant) = (grant(f.honey), grant(f.standard));
    let honey_grant_id = honey_grant.grant_id;
    let grants = Arc::new(StubGrants::default());
    grants.set(AGENT, vec![honey_grant, standard_grant]);
    let origin = format!("http://127.0.0.1:{}", upstream.address().port());
    let bind = |secret_id| Binding {
        secret_id,
        origin: origin.clone(),
        header: "Authorization".to_owned(),
        template: "Bearer {secret}".to_owned(),
        allow_private_hosts: true,
    };
    let relay = Arc::new(
        Relay::new(
            auth,
            grants,
            Bindings {
                org_id: f.org,
                bindings: vec![bind(f.honey), bind(f.standard)],
                aws_bindings: Vec::new(),
                pg: Vec::new(),
                git_bindings: Vec::new(),
                mcp_upstreams: Vec::new(),
            },
            decryptor,
            Arc::new(StubResolver::default()),
            Arc::new(HttpAudit::new(control_plane.clone())),
            RelayOptions::default(),
        )
        .with_honey_scan(Arc::new(HoneyScan::new(control_plane))),
    );
    let relay_req = |secret: Uuid, headers: Value| {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            "authorization",
            format!("Bearer {}", f.agent_token).parse().unwrap(),
        );
        let body = json!({
            "secret_id": secret, "version": 1, "method": "GET",
            "url": format!("{origin}/v1/items"), "headers": headers,
        });
        (h, axum::body::Bytes::from(body.to_string()))
    };

    // By reference, from a known peer.
    let (h, b) = relay_req(f.honey, json!([]));
    let peer: std::net::IpAddr = "192.0.2.7".parse().unwrap();
    let resp = crate::relay::handle_from(relay.clone(), h, b, Some(peer)).await;
    assert_eq!(resp.status().as_u16(), 403);
    // By value: the base64 decoy in a request that names the standard secret.
    let (h, b) = relay_req(
        f.standard,
        json!([[
            "authorization",
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(value())
            )
        ]]),
    );
    let resp = crate::relay::handle_from(relay.clone(), h, b, None).await;
    assert_eq!(resp.status().as_u16(), 403);
    let raw = resp.into_body().collect().await.unwrap().to_bytes();
    assert_no_value("value-match answer", &raw);
    assert!(
        upstream.received_requests().await.unwrap().is_empty(),
        "nothing forwarded"
    );
    // Only the scan opened the honey value (once); the reference use unwrapped nothing, and the
    // disabled token (same decoy) is not in the scan.
    assert_eq!(f.kms_calls(), 1);

    let rows: Vec<_> = f
        .records()
        .await
        .into_iter()
        .filter(|r| r.kind == "honey.triggered")
        .collect();
    assert_eq!(rows.len(), 2, "{rows:?}");
    for r in &rows {
        assert_eq!(r.actor, format!("agent:{AGENT}"));
        assert_eq!(r.target.as_deref(), Some(&*format!("secret:{}", f.honey)));
        assert_eq!(r.outcome, "denied");
        assert_eq!(attr(r, "honey_template"), Some("aws_access_key"));
    }
    assert_eq!(attr(&rows[0], "path"), Some("relay"));
    let honey_grant_text = honey_grant_id.to_string();
    assert_eq!(
        attr(&rows[0], "binding_id"),
        Some(honey_grant_text.as_str())
    );
    assert_eq!(attr(&rows[0], "peer_address"), Some("192.0.2.7"));
    assert_eq!(attr(&rows[1], "path"), Some("value_match"));
    assert_eq!(attr(&rows[1], "binding_id"), None);
    assert_eq!(attr(&rows[1], "peer_address"), None);
    let allowed = ["binding_id", "honey_template", "path", "peer_address"];
    for r in &rows {
        for (k, _, _) in r.attrs.as_ref().unwrap().entries() {
            assert!(allowed.contains(&k.as_str()), "unexpected field {k}");
        }
    }
    let walk = ls_audit::verify(f.records().await.iter().map(ls_audit::Record::link), &[]);
    assert!(walk.ok(), "{walk:?}");
    assert_no_value("ledger", f.ledger_text().await.as_bytes());

    // The control plane refuses `honey.triggered` for a secret that is not a honey token.
    let http = client();
    let r = http
        .post(f.cp_url.join("internal/v1/audit/events").unwrap())
        .bearer_auth(SERVICE_TOKEN)
        .header("x-locksmith-org", f.org.to_string())
        .json(&json!({
            "kind": "honey.triggered", "outcome": "denied", "agent_id": AGENT,
            "secret_id": f.standard, "honey_path": "relay",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409);
    // Nor does it take a request field on one.
    let r = http
        .post(f.cp_url.join("internal/v1/audit/events").unwrap())
        .bearer_auth(SERVICE_TOKEN)
        .header("x-locksmith-org", f.org.to_string())
        .json(&json!({
            "kind": "honey.triggered", "outcome": "denied", "agent_id": AGENT,
            "secret_id": f.honey, "honey_path": "relay", "host": "example.com",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
}
