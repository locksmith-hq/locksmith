//! T6 tasks 4.1 to 4.3: invites (create, list, revoke, accept) and members (list, role change,
//! remove, leave) with the last-owner lock, including two owners acting at once. Human bearer
//! tokens are signed by a local mock issuer (wiremock serving a JWKS). Needs a Docker daemon
//! (throwaway `postgres:18`).
//!
//! Test names start with `invites` or `members` so `cargo nextest run -p ls-control-plane
//! members invites` selects them.

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
        self.token_with(sub, true)
    }

    /// As [`Self::token`], with the issuer's `email_verified` claim set to `verified`.
    fn token_with(&self, sub: &str, verified: bool) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": sub, "exp": now + 600,
            "email": format!("{sub}@example.com"), "email_verified": verified,
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

impl Env {
    /// `POST /v1/invites/accept` as `sub` with `token`.
    async fn accept(&self, sub: &str, token: &str) -> (StatusCode, Value) {
        self.call(
            "POST",
            "/v1/invites/accept",
            sub,
            None,
            Some(json!({"token": token})),
        )
        .await
    }

    /// `POST .../invites` in `org` as `sub`.
    async fn invite(&self, org: &str, sub: &str, email: &str, role: &str) -> (StatusCode, Value) {
        self.call(
            "POST",
            "/v1/orgs/current/invites",
            sub,
            Some(org),
            Some(json!({"email": email, "role": role})),
        )
        .await
    }

    async fn owners(&self, org: &str) -> i64 {
        let mut admin = self.pg.admin().await;
        sql::query_scalar("SELECT count(*) FROM memberships WHERE org_id = $1 AND role = 'owner'")
            .bind(Uuid::parse_str(org).unwrap())
            .fetch_one(&mut admin)
            .await
            .unwrap()
    }
}

fn assert_404(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["type"], "urn:locksmith:problem:not-found", "{body}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn invites_create_list_and_revoke_store_only_the_hash() {
    use sha2::{Digest, Sha256};
    let env = Env::start().await;
    let team = env.create_org("alice", "Acme").await;

    let (status, body) = env
        .invite(&team, "alice", "  Bob@Example.COM ", "member")
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = body["token"].as_str().unwrap().to_owned();
    assert_eq!(token.len(), 43, "32 bytes, base64url without padding");
    let invite = &body["invite"];
    assert_eq!(invite["email"], "bob@example.com");
    assert_eq!(invite["role"], "member");
    assert!(invite["accepted_at"].is_null() && invite["revoked_at"].is_null());
    assert!(invite.get("token").is_none());
    let id = invite["id"].as_str().unwrap().to_owned();
    let mut admin = env.pg.admin().await;

    let week: bool = sql::query_scalar(
        "SELECT expires_at - created_at = interval '7 days' FROM invites WHERE id = $1",
    )
    .bind(Uuid::parse_str(&id).unwrap())
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert!(week, "an invite lasts 7 days");

    // Only the SHA-256 is stored; the token is nowhere in the database or the ledger.
    let stored: Vec<u8> = sql::query_scalar("SELECT token_hash FROM invites WHERE id = $1")
        .bind(Uuid::parse_str(&id).unwrap())
        .fetch_one(&mut admin)
        .await
        .unwrap();
    assert_eq!(stored, Sha256::digest(token.as_bytes()).to_vec());
    let leaks: i64 = sql::query_scalar(
        "SELECT (SELECT count(*) FROM invites i WHERE i::text LIKE '%' || $1 || '%') \
         + (SELECT count(*) FROM audit_events e WHERE e::text LIKE '%' || $1 || '%')",
    )
    .bind(&token)
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert_eq!(leaks, 0, "the plaintext token is never stored");
    assert_eq!(hex(&stored).len(), 64);

    // The list never carries the token.
    let (status, list) = env
        .get("/v1/orgs/current/invites", "alice", Some(&team))
        .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    assert!(!list.to_string().contains(&token));

    // Revoke: 204, then 404, and the revoked token no longer works.
    let uri = format!("/v1/orgs/current/invites/{id}");
    let (status, _) = env.call("DELETE", &uri, "alice", Some(&team), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = env.call("DELETE", &uri, "alice", Some(&team), None).await;
    assert_404(status, &body);
    let (status, body) = env.accept("bob", &token).await;
    assert_404(status, &body);

    let kinds = env.ledger_kinds(&team).await;
    assert!(kinds.contains(&"member.invited".to_owned()), "{kinds:?}");
    assert!(
        kinds.contains(&"member.invite_revoked".to_owned()),
        "{kinds:?}"
    );
}

#[tokio::test]
async fn invites_role_rules_and_validation() {
    let env = Env::start().await;
    let team = env.create_org("alice", "Acme").await;
    env.add_member(&team, "adam", "admin").await;
    env.add_member(&team, "mia", "member").await;

    // An owner may invite any role.
    for role in ["owner", "admin", "member"] {
        let (status, body) = env.invite(&team, "alice", "x@example.com", role).await;
        assert_eq!(status, StatusCode::CREATED, "{role}: {body}");
    }
    // An admin may invite admin and member, not owner.
    let (status, _) = env.invite(&team, "adam", "y@example.com", "owner").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = env.invite(&team, "adam", "y@example.com", "admin").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    // A member may not invite, list or revoke.
    let (status, _) = env.invite(&team, "mia", "z@example.com", "member").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = env
        .get("/v1/orgs/current/invites", "mia", Some(&team))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = env
        .call(
            "DELETE",
            &format!("/v1/orgs/current/invites/{}", Uuid::now_v7()),
            "mia",
            Some(&team),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A non-member of the org gets the uniform 404 from the binding.
    let (status, body) = env
        .invite(&team, "mallory", "z@example.com", "member")
        .await;
    assert_404(status, &body);
    // An admin cannot revoke an owner invite.
    let (_, owner_invite) = env.invite(&team, "alice", "own@example.com", "owner").await;
    let id = owner_invite["invite"]["id"].as_str().unwrap();
    let (status, _) = env
        .call(
            "DELETE",
            &format!("/v1/orgs/current/invites/{id}"),
            "adam",
            Some(&team),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Bad addresses.
    for bad in ["", "plain", "a@", "@b", "a b@example.com", "a@b@c"] {
        let (status, body) = env.invite(&team, "alice", bad, "member").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad:?}: {body}");
    }
}

#[tokio::test]
async fn invites_accept_joins_once_and_every_failure_is_the_same_404() {
    let env = Env::start().await;
    let team = env.create_org("alice", "Acme").await;
    let (status, body) = env.invite(&team, "alice", "bob@example.com", "admin").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = body["token"].as_str().unwrap().to_owned();
    let id = body["invite"]["id"].as_str().unwrap().to_owned();

    // Guessing a token, and a valid token presented by another verified email.
    let (s1, b1) = env.accept("bob", &"A".repeat(43)).await;
    assert_404(s1, &b1);
    let (s2, b2) = env.accept("dave", &token).await;
    assert_404(s2, &b2);
    assert_eq!(b1, b2, "unknown token and wrong email look the same");
    for bad in ["", &"x".repeat(5000)] {
        let (s, b) = env.accept("bob", bad).await;
        assert_404(s, &b);
    }
    // Not signed in, and an unverified email: refused before the token is looked at.
    let resp = env
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/invites/accept")
                .header("content-type", "application/json")
                .body(Body::from(json!({"token": token}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = env
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/invites/accept")
                .header("content-type", "application/json")
                .header(
                    "authorization",
                    format!("Bearer {}", env.key.token_with("bob", false)),
                )
                .body(Body::from(json!({"token": token}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // None of that consumed the invite or added a member.
    let (status, orgs) = env.get("/v1/orgs", "bob", None).await;
    assert_eq!(status, StatusCode::OK, "{orgs}");
    assert_eq!(orgs["items"].as_array().unwrap().len(), 1);

    // The invited email joins with the invited role.
    let (status, body) = env.accept("bob", &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["org_id"], team.as_str());
    assert_eq!(body["role"], "admin");
    let (status, orgs) = env.get("/v1/orgs", "bob", None).await;
    assert_eq!(status, StatusCode::OK, "{orgs}");
    let mine: Vec<&Value> = orgs["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["id"] == team.as_str())
        .collect();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0]["role"], "admin");
    let (status, _) = env.get("/v1/orgs/current", "bob", Some(&team)).await;
    assert_eq!(status, StatusCode::OK);

    // Single use: reuse by the same user and by another are the same 404.
    let (s, b) = env.accept("bob", &token).await;
    assert_404(s, &b);
    let (s, b) = env.accept("dave", &token).await;
    assert_404(s, &b);
    // The invite shows as accepted, and the ledger has the join.
    let (_, list) = env
        .get("/v1/orgs/current/invites", "alice", Some(&team))
        .await;
    let accepted = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == id.as_str())
        .unwrap();
    assert!(!accepted["accepted_at"].is_null());
    assert!(
        env.ledger_kinds(&team)
            .await
            .contains(&"member.joined".to_owned())
    );
}

#[tokio::test]
async fn invites_expired_token_is_the_same_404() {
    let env = Env::start().await;
    let team = env.create_org("alice", "Acme").await;
    let (_, body) = env
        .invite(&team, "alice", "bob@example.com", "member")
        .await;
    let token = body["token"].as_str().unwrap();
    let mut admin = env.pg.admin().await;
    sql::query("UPDATE invites SET expires_at = now() - interval '1 second'")
        .execute(&mut admin)
        .await
        .unwrap();
    let (status, body) = env.accept("bob", token).await;
    assert_404(status, &body);
}

#[tokio::test]
async fn invites_concurrent_accepts_of_one_token_join_exactly_once() {
    let env = Env::start().await;
    let team = env.create_org("alice", "Acme").await;
    let (_, body) = env
        .invite(&team, "alice", "bob@example.com", "member")
        .await;
    let token = body["token"].as_str().unwrap().to_owned();
    let (a, b) = tokio::join!(env.accept("bob", &token), env.accept("bob", &token));
    let mut statuses = [a.0, b.0];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::OK, StatusCode::NOT_FOUND],
        "{a:?} {b:?}"
    );
}

#[tokio::test]
async fn members_list_change_role_remove_and_leave() {
    let env = Env::start().await;
    let team = env.create_org("alice", "Acme").await;
    env.add_member(&team, "adam", "admin").await;
    env.add_member(&team, "mia", "member").await;
    env.add_member(&team, "max", "member").await;
    let alice = env.user_id("alice").await;
    let adam = env.user_id("adam").await;
    let mia = env.user_id("mia").await;
    let max = env.user_id("max").await;
    let member_uri = |u: Uuid| format!("/v1/orgs/current/members/{u}");

    // Any member lists, with emails and their own role.
    let (status, list) = env
        .get("/v1/orgs/current/members", "mia", Some(&team))
        .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["caller_role"], "member");
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 4);
    let alice_row = items
        .iter()
        .find(|m| m["user_id"] == alice.to_string())
        .unwrap();
    assert_eq!(alice_row["email"], "alice@example.com");
    assert_eq!(alice_row["role"], "owner");
    // A non-member cannot.
    let (status, body) = env
        .get("/v1/orgs/current/members", "mallory", Some(&team))
        .await;
    assert_404(status, &body);

    let patch = |sub: &'static str, target: Uuid, role: &'static str| {
        let env = &env;
        let team = team.clone();
        async move {
            env.call(
                "PATCH",
                &format!("/v1/orgs/current/members/{target}"),
                sub,
                Some(&team),
                Some(json!({"role": role})),
            )
            .await
        }
    };
    // A member cannot change roles.
    assert_eq!(patch("mia", max, "admin").await.0, StatusCode::FORBIDDEN);
    // An admin can move members and admins between member and admin, but not touch owners or
    // make one.
    let (status, body) = patch("adam", mia, "admin").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["role"], "admin");
    assert_eq!(
        patch("adam", alice, "member").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(patch("adam", max, "owner").await.0, StatusCode::FORBIDDEN);
    // Unknown user.
    let (status, body) = patch("alice", Uuid::now_v7(), "member").await;
    assert_404(status, &body);
    // An owner promotes, and a second owner can then step down.
    assert_eq!(patch("alice", max, "owner").await.0, StatusCode::OK);
    assert_eq!(patch("max", alice, "member").await.0, StatusCode::OK);
    assert_eq!(patch("max", alice, "owner").await.0, StatusCode::OK);

    // Removing: a member cannot, an admin removes a member but not an owner.
    let (status, _) = env
        .call("DELETE", &member_uri(max), "adam", Some(&team), None)
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "admin must not remove an owner"
    );
    env.add_member(&team, "zed", "member").await;
    let zed = env.user_id("zed").await;
    let (status, _) = env
        .call("DELETE", &member_uri(zed), "adam", Some(&team), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = env
        .call("DELETE", &member_uri(zed), "adam", Some(&team), None)
        .await;
    assert_404(status, &body);
    // Leaving: a plain member leaves; the next request naming the org is 404.
    let (status, _) = env
        .call("DELETE", &member_uri(adam), "adam", Some(&team), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = env.get("/v1/orgs/current", "adam", Some(&team)).await;
    assert_404(status, &body);
    // A removed user's org list no longer has it.
    let (_, orgs) = env.get("/v1/orgs", "adam", None).await;
    assert!(
        orgs["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|o| o["id"] != team.as_str())
    );

    let kinds = env.ledger_kinds(&team).await;
    for k in ["member.role_changed", "member.removed", "member.left"] {
        assert!(kinds.contains(&k.to_owned()), "{k} in {kinds:?}");
    }
}

#[tokio::test]
async fn members_last_owner_cannot_demote_remove_or_leave() {
    let env = Env::start().await;
    let team = env.create_org("alice", "Acme").await;
    let alice = env.user_id("alice").await;
    let uri = format!("/v1/orgs/current/members/{alice}");

    let (status, body) = env
        .call(
            "PATCH",
            &uri,
            "alice",
            Some(&team),
            Some(json!({"role": "admin"})),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, body) = env.call("DELETE", &uri, "alice", Some(&team), None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(env.owners(&team).await, 1);
    // A no-op "change" to the same role is fine.
    let (status, _) = env
        .call(
            "PATCH",
            &uri,
            "alice",
            Some(&team),
            Some(json!({"role": "owner"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Nobody leaves their personal org, even with a co-owner there.
    let (_, personal) = env.get("/v1/orgs/current", "alice", None).await;
    let personal = personal["id"].as_str().unwrap().to_owned();
    env.add_member(&personal, "bob", "owner").await;
    let (status, body) = env
        .call("DELETE", &uri, "alice", Some(&personal), None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

#[tokio::test]
async fn members_two_owners_acting_at_once_never_leave_zero_owners() {
    let env = Env::start().await;
    for round in 0..6 {
        let team = env.create_org("alice", &format!("Acme {round}")).await;
        env.add_member(&team, "bob", "owner").await;
        let alice = env.user_id("alice").await;
        let bob = env.user_id("bob").await;

        let (alice_uri, bob_uri) = (
            format!("/v1/orgs/current/members/{alice}"),
            format!("/v1/orgs/current/members/{bob}"),
        );
        if round % 2 == 0 {
            // Both owners leave at the same moment.
            let ((sa, ba), (sb, bb)) = tokio::join!(
                env.call("DELETE", &alice_uri, "alice", Some(&team), None),
                env.call("DELETE", &bob_uri, "bob", Some(&team), None),
            );
            let mut got = [sa, sb];
            got.sort();
            assert_eq!(
                got,
                [StatusCode::NO_CONTENT, StatusCode::CONFLICT],
                "{ba} {bb}"
            );
        } else {
            // Each demotes the other at the same moment.
            let ((sa, ba), (sb, bb)) = tokio::join!(
                env.call(
                    "PATCH",
                    &bob_uri,
                    "alice",
                    Some(&team),
                    Some(json!({"role": "member"}))
                ),
                env.call(
                    "PATCH",
                    &alice_uri,
                    "bob",
                    Some(&team),
                    Some(json!({"role": "member"}))
                ),
            );
            let oks = [sa, sb].iter().filter(|s| **s == StatusCode::OK).count();
            assert_eq!(oks, 1, "exactly one demotion wins: {sa} {ba} / {sb} {bb}");
            let other = if sa == StatusCode::OK { sb } else { sa };
            assert!(
                other == StatusCode::FORBIDDEN || other == StatusCode::CONFLICT,
                "the loser is refused, got {other}"
            );
        }
        assert_eq!(env.owners(&team).await, 1, "round {round}");
    }
}
