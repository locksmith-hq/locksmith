//! Per-provider fakes for tests (C1 task 1.3), behind the `testing` feature.
//!
//! Each fake is a wiremock server that answers the provider's token, refresh, revoke and
//! account calls with that provider's real response shape and quirks:
//! - GitHub: JSON only when the request sends `Accept: application/json` (form otherwise);
//!   expiring user tokens rotate the refresh token.
//! - Google: standard JSON; the refresh answer carries no new refresh token.
//! - Slack: always `200`; `ok:false` on failure; the user token is nested under `authed_user`.
//! - Linear: standard JSON.
//! - Atlassian: JSON request bodies only; every refresh rotates the refresh token.
//!
//! The tokens are fixed fake strings, never real credentials.

use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// The authorization code every fake accepts.
pub const CODE: &str = "fake-code";
pub const ACCESS_1: &str = "fake-access-1";
pub const REFRESH_1: &str = "fake-refresh-1";
pub const ACCESS_2: &str = "fake-access-2";
pub const REFRESH_2: &str = "fake-refresh-2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Github,
    Google,
    Slack,
    Linear,
    Atlassian,
}

impl Kind {
    pub const ALL: [Kind; 5] = [
        Self::Github,
        Self::Google,
        Self::Slack,
        Self::Linear,
        Self::Atlassian,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Google => "google",
            Self::Slack => "slack",
            Self::Linear => "linear",
            Self::Atlassian => "atlassian",
        }
    }
}

/// What the refresh call does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refresh {
    /// A new access token (and, where the provider rotates, a new refresh token).
    Works,
    /// The provider refuses the refresh token (revoked or expired by the user).
    InvalidGrant,
}

pub struct FakeProvider {
    kind: Kind,
    server: MockServer,
}

fn json(status: u16, body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(body)
}

fn tokens(access: &str, refresh: Option<&str>) -> serde_json::Value {
    let mut v = serde_json::json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "fake.scope",
    });
    if let Some(r) = refresh {
        v["refresh_token"] = r.into();
    }
    v
}

impl FakeProvider {
    pub async fn start(kind: Kind) -> Self {
        Self::start_with(kind, Refresh::Works).await
    }

    pub async fn start_with(kind: Kind, refresh: Refresh) -> Self {
        let fake = Self {
            kind,
            server: MockServer::start().await,
        };
        fake.mount_token(refresh).await;
        fake.mount_revoke().await;
        fake.mount_account().await;
        fake
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn base_url(&self) -> String {
        self.server.uri()
    }

    pub fn token_url(&self) -> String {
        let p = match self.kind {
            Kind::Github => "/login/oauth/access_token",
            Kind::Google => "/token",
            Kind::Slack => "/api/oauth.v2.access",
            Kind::Linear | Kind::Atlassian => "/oauth/token",
        };
        format!("{}{p}", self.server.uri())
    }

    /// `None` for Atlassian: the registry has no revoke endpoint for it.
    pub fn revoke_url(&self) -> Option<String> {
        let p = match self.kind {
            Kind::Github => "/applications/fake-client/grant",
            Kind::Google => "/revoke",
            Kind::Slack => "/api/auth.revoke",
            Kind::Linear => "/oauth/revoke",
            Kind::Atlassian => return None,
        };
        Some(format!("{}{p}", self.server.uri()))
    }

    pub fn account_url(&self) -> String {
        let p = match self.kind {
            Kind::Github => "/user",
            Kind::Google => "/oauth2/v3/userinfo",
            Kind::Slack => "/api/users.identity",
            Kind::Linear => "/graphql",
            Kind::Atlassian => "/me",
        };
        format!("{}{p}", self.server.uri())
    }

    /// Every request the fake received, in order.
    pub async fn requests(&self) -> Vec<Request> {
        self.server.received_requests().await.unwrap_or_default()
    }

    async fn mount_token(&self, refresh: Refresh) {
        let token_path = self.token_url().replace(&self.server.uri(), "");
        let exchange = body_string_contains(format!("code={CODE}"));
        let renew = body_string_contains("grant_type=refresh_token");
        let s = &self.server;
        match self.kind {
            Kind::Github => {
                let ok = || {
                    json(
                        200,
                        serde_json::json!({
                            "access_token": ACCESS_1, "token_type": "bearer", "scope": "",
                            "expires_in": 28800, "refresh_token": REFRESH_1,
                            "refresh_token_expires_in": 15811200
                        }),
                    )
                };
                Mock::given(method("POST"))
                    .and(path(&token_path))
                    .and(header("accept", "application/json"))
                    .and(exchange)
                    .respond_with(ok())
                    .mount(s)
                    .await;
                // Without the Accept header GitHub answers form-encoded: a client that does not
                // ask for JSON fails to parse it.
                Mock::given(method("POST"))
                    .and(path(&token_path))
                    .respond_with(ResponseTemplate::new(200).set_body_raw(
                        format!("access_token={ACCESS_1}&token_type=bearer"),
                        "application/x-www-form-urlencoded",
                    ))
                    .with_priority(200)
                    .mount(s)
                    .await;
                let renewed = match refresh {
                    Refresh::Works => json(
                        200,
                        serde_json::json!({
                            "access_token": ACCESS_2, "token_type": "bearer", "scope": "",
                            "expires_in": 28800, "refresh_token": REFRESH_2,
                            "refresh_token_expires_in": 15811200
                        }),
                    ),
                    // GitHub reports errors with status 200 and an `error` field.
                    Refresh::InvalidGrant => {
                        json(200, serde_json::json!({"error": "bad_refresh_token"}))
                    }
                };
                Mock::given(method("POST"))
                    .and(path(&token_path))
                    .and(header("accept", "application/json"))
                    .and(renew)
                    .respond_with(renewed)
                    .mount(s)
                    .await;
            }
            Kind::Google | Kind::Linear => {
                Mock::given(method("POST"))
                    .and(path(&token_path))
                    .and(exchange)
                    .respond_with(json(200, tokens(ACCESS_1, Some(REFRESH_1))))
                    .mount(s)
                    .await;
                let renewed = match refresh {
                    // Google and Linear keep the refresh token: the answer carries none.
                    Refresh::Works => json(200, tokens(ACCESS_2, None)),
                    Refresh::InvalidGrant => {
                        json(400, serde_json::json!({"error": "invalid_grant"}))
                    }
                };
                Mock::given(method("POST"))
                    .and(path(&token_path))
                    .and(renew)
                    .respond_with(renewed)
                    .mount(s)
                    .await;
            }
            Kind::Slack => {
                let nested = |a: &str, r: &str| {
                    json(
                        200,
                        serde_json::json!({
                            "ok": true, "app_id": "A1", "team": {"id": "T1"},
                            "authed_user": {"id": "U1", "scope": "channels:read", "token_type": "user",
                                "access_token": a, "refresh_token": r, "expires_in": 43200}
                        }),
                    )
                };
                Mock::given(method("POST"))
                    .and(path(&token_path))
                    .and(exchange)
                    .respond_with(nested(ACCESS_1, REFRESH_1))
                    .mount(s)
                    .await;
                // Slack answers 200 with `ok:false` for every failure.
                Mock::given(method("POST"))
                    .and(path(&token_path))
                    .respond_with(json(
                        200,
                        serde_json::json!({"ok": false, "error": "invalid_code"}),
                    ))
                    .with_priority(200)
                    .mount(s)
                    .await;
                let renewed = match refresh {
                    Refresh::Works => json(
                        200,
                        serde_json::json!({"ok": true, "access_token": ACCESS_2, "refresh_token": REFRESH_2,
                            "token_type": "user", "expires_in": 43200, "scope": "channels:read"}),
                    ),
                    Refresh::InvalidGrant => json(
                        200,
                        serde_json::json!({"ok": false, "error": "invalid_refresh_token"}),
                    ),
                };
                Mock::given(method("POST"))
                    .and(path(&token_path))
                    .and(renew)
                    .respond_with(renewed)
                    .mount(s)
                    .await;
            }
            Kind::Atlassian => {
                // Atlassian takes JSON request bodies; every refresh rotates the refresh token.
                let json_in = || header("content-type", "application/json");
                Mock::given(method("POST"))
                    .and(path(&token_path))
                    .and(json_in())
                    .and(body_string_contains(format!("\"code\":\"{CODE}\"")))
                    .respond_with(json(200, tokens(ACCESS_1, Some(REFRESH_1))))
                    .mount(s)
                    .await;
                let renewed = match refresh {
                    Refresh::Works => json(200, tokens(ACCESS_2, Some(REFRESH_2))),
                    Refresh::InvalidGrant => {
                        json(403, serde_json::json!({"error": "invalid_grant"}))
                    }
                };
                Mock::given(method("POST"))
                    .and(path(&token_path))
                    .and(json_in())
                    .and(body_string_contains("\"grant_type\":\"refresh_token\""))
                    .respond_with(renewed)
                    .mount(s)
                    .await;
                Mock::given(method("POST"))
                    .and(path(&token_path))
                    .respond_with(json(403, serde_json::json!({"error": "access_denied"})))
                    .with_priority(200)
                    .mount(s)
                    .await;
            }
        }
    }

    async fn mount_revoke(&self) {
        let Some(url) = self.revoke_url() else { return };
        let p = url.replace(&self.server.uri(), "");
        let (m, resp) = match self.kind {
            Kind::Github => ("DELETE", ResponseTemplate::new(204)),
            Kind::Slack => (
                "POST",
                json(200, serde_json::json!({"ok": true, "revoked": true})),
            ),
            _ => ("POST", ResponseTemplate::new(200)),
        };
        Mock::given(method(m))
            .and(path(p))
            .respond_with(resp)
            .mount(&self.server)
            .await;
    }

    async fn mount_account(&self) {
        let p = self.account_url().replace(&self.server.uri(), "");
        let (m, body) = match self.kind {
            Kind::Github => ("GET", serde_json::json!({"login": "alice-gh", "id": 1001})),
            Kind::Google => (
                "GET",
                serde_json::json!({"sub": "g-1001", "email": "alice@example.test"}),
            ),
            Kind::Slack => (
                "GET",
                serde_json::json!({"ok": true, "user": {"id": "U1", "name": "alice"}, "team": {"id": "T1"}}),
            ),
            Kind::Linear => (
                "POST",
                serde_json::json!({"data": {"viewer": {"id": "l-1001", "name": "alice"}}}),
            ),
            Kind::Atlassian => (
                "GET",
                serde_json::json!({"account_id": "a-1001", "name": "alice"}),
            ),
        };
        Mock::given(method(m))
            .and(path(p))
            .respond_with(json(200, body))
            .mount(&self.server)
            .await;
    }
}
