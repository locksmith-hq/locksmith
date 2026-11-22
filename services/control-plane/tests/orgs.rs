//! T6 tasks 3.1 to 3.3: org selection with `X-Locksmith-Org` (membership checked in the binding
//! transaction) and the team-org routes (`GET/POST /v1/orgs`, rename, delete). Human bearer
//! tokens are signed by a local mock issuer (wiremock serving a JWKS). Needs a Docker daemon
//! (throwaway `postgres:18`).
//!
//! Test names start with `org_select` or `orgs` so `cargo nextest run -p ls-control-plane
//! org_select orgs` selects them.

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ls_control_plane::app::{self, AppState};
use ls_control_plane::auth::human::{HumanAuth, HumanAuthConfig};
use ls_control_plane::db::sql;
use ls_control_plane::migrate;
use ls_control_plane::readiness::ReadyFlag;
use p256::pkcs8::EncodePrivateKey as _;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ISSUER: &str = "https://idp.test/realms/locksmith";
const AUDIENCE: &str = "locksmith-api";

/// A deterministic throwaway P-256 signing key (test only).
struct TestKey(p256::ecdsa::SigningKey);

impl TestKey {
    fn new() -> Self {
        Self(p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap())
    }

    fn jwk(&self) -> Value {
        let point = self.0.verifying_key().to_sec1_point(false);
        json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        })
    }

    /// A valid token for `sub` with the verified email `<sub>@example.com`.
    fn token(&self, sub: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": sub, "exp": now + 600,
            "email": format!("{sub}@example.com"), "email_verified": true,
        });
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("k1".to_owned());
        let der = self.0.to_pkcs8_der().unwrap();
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ec_der(der.as_bytes())).unwrap()
    }
}

struct Env {
    key: TestKey,
    pg: common::Pg,
    app: Router,
    _issuer: MockServer,
}

impl Env {
    /// A migrated database behind the app, dev auth off.
    async fn start() -> Self {
        Self::with_pg(common::Pg::migrated().await).await
    }

    async fn with_pg(pg: common::Pg) -> Self {
        let key = TestKey::new();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys": [key.jwk()]})))
            .mount(&server)
            .await;
        let human = HumanAuth::with_refresh(
            &HumanAuthConfig {
                issuer: ISSUER.to_owned(),
                audience: AUDIENCE.to_owned(),
                jwks_url: format!("{}/jwks", server.uri()),
            },
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        )
        .unwrap();
        let state = AppState::new(
            false,
            Arc::new(ReadyFlag::new(true)),
            pg.app_db(Default::default()),
        )
        .with_human_auth(human);
        Self {
            key,
            pg,
            app: app::build(state),
            _issuer: server,
        }
    }

    /// `method uri` as `sub`, optionally selecting `org`, with an optional JSON body.
    async fn call(
        &self,
        method: &str,
        uri: &str,
        sub: &str,
        org: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", self.key.token(sub)));
        if let Some(o) = org {
            b = b.header("x-locksmith-org", o);
        }
        let req = match body {
            Some(v) => b
                .header("content-type", "application/json")
                .body(Body::from(v.to_string())),
            None => b.body(Body::empty()),
        }
        .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, value)
    }

    async fn get(&self, uri: &str, sub: &str, org: Option<&str>) -> (StatusCode, Value) {
        self.call("GET", uri, sub, org, None).await
    }

    /// `sub` creates a team org named `name`; returns its id.
    async fn create_org(&self, sub: &str, name: &str) -> String {
        let (status, body) = self
            .call("POST", "/v1/orgs", sub, None, Some(json!({"name": name})))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["id"].as_str().unwrap().to_owned()
    }

    /// The user id of `sub` (signs them in first).
    async fn user_id(&self, sub: &str) -> Uuid {
        let (status, _) = self.get("/v1/orgs/current", sub, None).await;
        assert_eq!(status, StatusCode::OK);
        let mut admin = self.pg.admin().await;
        sql::query_scalar("SELECT id FROM users WHERE subject = $1")
            .bind(sub)
            .fetch_one(&mut admin)
            .await
            .unwrap()
    }

    /// Add `sub` to `org` with `role` directly (member management is group 4).
    async fn add_member(&self, org: &str, sub: &str, role: &str) {
        let user = self.user_id(sub).await;
        let mut admin = self.pg.admin().await;
        sql::query("INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, $3)")
            .bind(Uuid::parse_str(org).unwrap())
            .bind(user)
            .bind(role)
            .execute(&mut admin)
            .await
            .unwrap();
    }

    /// Ledger kinds of `org`, oldest first.
    async fn ledger_kinds(&self, org: &str) -> Vec<String> {
        let mut admin = self.pg.admin().await;
        sql::query_scalar("SELECT kind FROM audit_events WHERE org_id = $1 ORDER BY seq")
            .bind(Uuid::parse_str(org).unwrap())
            .fetch_all(&mut admin)
            .await
            .unwrap()
    }
}

fn assert_404(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["type"], "urn:locksmith:problem:not-found", "{body}");
}

#[tokio::test]
async fn org_select_member_sees_the_team_org_and_a_non_member_gets_404() {
    let env = Env::start().await;
    let team = env.create_org("alice", "Acme").await;

    // The member selects it.
    let (status, body) = env.get("/v1/orgs/current", "alice", Some(&team)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], team.as_str());
    assert_eq!(body["name"], "Acme");

    // A non-member naming it, an org that does not exist and a malformed id: the same 404.
    let (s1, b1) = env.get("/v1/orgs/current", "mallory", Some(&team)).await;
    assert_404(s1, &b1);
    let missing = Uuid::now_v7().to_string();
    let (s2, b2) = env.get("/v1/orgs/current", "mallory", Some(&missing)).await;
    assert_404(s2, &b2);
    let (s3, b3) = env
        .get("/v1/orgs/current", "mallory", Some("not-a-uuid"))
        .await;
    assert_404(s3, &b3);
    assert_eq!(b1, b2, "a non-member and a missing org look the same");
    assert_eq!(b1, b3);
    // Other routes refuse too: nothing of the team org is read for the non-member.
    let (s4, b4) = env.get("/v1/projects", "mallory", Some(&team)).await;
    assert_404(s4, &b4);
    // Without the header the non-member still acts in their own personal org.
    let (s5, b5) = env.get("/v1/orgs/current", "mallory", None).await;
    assert_eq!(s5, StatusCode::OK, "{b5}");
    assert_ne!(b5["id"], team.as_str());
}

#[tokio::test]
async fn org_select_old_user_defaults_to_the_personal_org_as_owner() {
    // A user created before migration 0014 (no membership row of their own making).
    let pg = common::Pg::start().await;
    let mut admin = pg.admin().await;
    migrate::migrator()
        .run_to(13, &mut admin)
        .await
        .expect("migrations to 0013");
    let personal = Uuid::now_v7();
    sql::query("INSERT INTO orgs (id, name) VALUES ($1, 'Personal')")
        .bind(personal)
        .execute(&mut admin)
        .await
        .unwrap();
    sql::query(
        "INSERT INTO users (issuer, subject, email, email_verified, personal_org_id) \
         VALUES ($1, 'olduser', 'olduser@example.com', true, $2)",
    )
    .bind(ISSUER)
    .bind(personal)
    .execute(&mut admin)
    .await
    .unwrap();
    migrate::run(pg.bootstrap()).await.expect("0014+ apply");
    let env = Env::with_pg(pg).await;

    let (status, body) = env.get("/v1/orgs/current", "olduser", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], personal.to_string());

    let (status, body) = env.get("/v1/orgs", "olduser", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{body}");
    assert_eq!(items[0]["id"], personal.to_string());
    assert_eq!(items[0]["role"], "owner");
    assert_eq!(items[0]["personal"], true);

    // Naming the personal org explicitly is the same binding.
    let p = personal.to_string();
    let (status, body) = env.get("/v1/orgs/current", "olduser", Some(&p)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn org_select_new_user_owns_the_personal_org() {
    let env = Env::start().await;
    let (status, body) = env.get("/v1/orgs", "newbie", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{body}");
    assert_eq!(items[0]["role"], "owner");
    assert_eq!(items[0]["personal"], true);
}

#[tokio::test]
async fn org_select_removed_member_is_refused_on_the_next_request() {
    let env = Env::start().await;
    let team = env.create_org("alice", "Acme").await;
    env.add_member(&team, "bob", "member").await;

    let (status, body) = env.get("/v1/orgs/current", "bob", Some(&team)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let bob = env.user_id("bob").await;
    let mut admin = env.pg.admin().await;
    sql::query("DELETE FROM memberships WHERE org_id = $1 AND user_id = $2")
        .bind(Uuid::parse_str(&team).unwrap())
        .bind(bob)
        .execute(&mut admin)
        .await
        .unwrap();

    let (status, body) = env.get("/v1/orgs/current", "bob", Some(&team)).await;
    assert_404(status, &body);
    let (status, body) = env.get("/v1/orgs", "bob", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|o| o["id"] != team.as_str()),
        "{body}"
    );
}

#[tokio::test]
async fn orgs_create_and_list_with_roles_and_ledger() {
    let env = Env::start().await;
    let team = env.create_org("alice", "Acme").await;
    env.add_member(&team, "bob", "admin").await;

    let (status, body) = env.get("/v1/orgs", "alice", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{body}");
    let acme = items.iter().find(|o| o["id"] == team.as_str()).unwrap();
    assert_eq!(acme["name"], "Acme");
    assert_eq!(acme["role"], "owner");
    assert_eq!(acme["personal"], false);
    assert_eq!(
        items.iter().filter(|o| o["personal"] == true).count(),
        1,
        "{body}"
    );

    let (_, body) = env.get("/v1/orgs", "bob", None).await;
    let acme = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["id"] == team.as_str())
        .cloned()
        .unwrap();
    assert_eq!(acme["role"], "admin");

    // Someone else's list does not show it.
    let (_, body) = env.get("/v1/orgs", "carol", None).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1, "{body}");

    let kinds = env.ledger_kinds(&team).await;
    assert_eq!(kinds, ["org.created"]);
    let mut admin = env.pg.admin().await;
    let actor: String = sql::query_scalar("SELECT actor FROM audit_events WHERE org_id = $1")
        .bind(Uuid::parse_str(&team).unwrap())
        .fetch_one(&mut admin)
        .await
        .unwrap();
    assert_eq!(actor, format!("user:{}", env.user_id("alice").await));

    // Invalid names are refused before anything is written.
    let (status, _) = env
        .call(
            "POST",
            "/v1/orgs",
            "alice",
            None,
            Some(json!({"name": " "})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn orgs_rename_needs_owner_or_admin_and_the_bound_org() {
    let env = Env::start().await;
    let team = env.create_org("alice", "Acme").await;
    env.add_member(&team, "bob", "member").await;
    env.add_member(&team, "dan", "admin").await;
    let uri = format!("/v1/orgs/{team}");

    let (status, body) = env
        .call(
            "PATCH",
            &uri,
            "bob",
            Some(&team),
            Some(json!({"name": "Bob Co"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["type"], "urn:locksmith:problem:forbidden");

    // Without selecting the org, the path id is not the bound org: 404.
    let (status, body) = env
        .call(
            "PATCH",
            &uri,
            "alice",
            None,
            Some(json!({"name": "Acme 2"})),
        )
        .await;
    assert_404(status, &body);

    let (status, body) = env
        .call(
            "PATCH",
            &uri,
            "dan",
            Some(&team),
            Some(json!({"name": "Acme 2"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], "Acme 2");
    let (status, body) = env
        .call(
            "PATCH",
            &uri,
            "alice",
            Some(&team),
            Some(json!({"name": "Acme 3"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], "Acme 3");

    assert_eq!(
        env.ledger_kinds(&team).await,
        ["org.created", "org.renamed", "org.renamed"]
    );
}

#[tokio::test]
async fn orgs_delete_is_owner_only_and_refused_while_secrets_exist() {
    let env = Env::start().await;
    let team = env.create_org("alice", "Acme").await;
    env.add_member(&team, "dan", "admin").await;
    let org = Uuid::parse_str(&team).unwrap();
    let uri = format!("/v1/orgs/{team}");

    // A secret in the org (metadata only; no value is needed to block the delete).
    let mut admin = env.pg.admin().await;
    let (project, environment, secret) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    sql::query("INSERT INTO projects (id, org_id, name) VALUES ($1, $2, 'p')")
        .bind(project)
        .bind(org)
        .execute(&mut admin)
        .await
        .unwrap();
    sql::query("INSERT INTO environments (id, org_id, project_id, name) VALUES ($1, $2, $3, 'e')")
        .bind(environment)
        .bind(org)
        .bind(project)
        .execute(&mut admin)
        .await
        .unwrap();
    sql::query(
        "INSERT INTO secrets (id, org_id, project_id, environment_id, name) \
         VALUES ($1, $2, $3, $4, 's')",
    )
    .bind(secret)
    .bind(org)
    .bind(project)
    .bind(environment)
    .execute(&mut admin)
    .await
    .unwrap();

    let (status, body) = env.call("DELETE", &uri, "dan", Some(&team), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = env.call("DELETE", &uri, "alice", Some(&team), None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    // Nothing changed.
    let (status, _) = env.get("/v1/orgs/current", "dan", Some(&team)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(env.ledger_kinds(&team).await, ["org.created"]);

    sql::query("DELETE FROM secrets WHERE id = $1")
        .bind(secret)
        .execute(&mut admin)
        .await
        .unwrap();
    let (status, body) = env.call("DELETE", &uri, "alice", Some(&team), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Every membership ended: nobody can select it any more.
    for sub in ["alice", "dan"] {
        let (status, body) = env.get("/v1/orgs/current", sub, Some(&team)).await;
        assert_404(status, &body);
    }
    let (_, body) = env.get("/v1/orgs", "alice", None).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(
        env.ledger_kinds(&team).await,
        ["org.created", "org.deleted"]
    );

    // A personal org cannot be deleted.
    let (_, me) = env.get("/v1/orgs/current", "alice", None).await;
    let personal = me["id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .call(
            "DELETE",
            &format!("/v1/orgs/{personal}"),
            "alice",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}
