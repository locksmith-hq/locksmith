//! S5 tasks 2.3 and 2.4: the control plane's audit ledger appends. S4 agent and grant admin
//! requests append their events in the same transaction, and the gateway appends relay events
//! through `POST /internal/v1/audit/events` behind the service token. Auth refusals need no
//! database; the rest use a throwaway `postgres:18` container (testcontainers; needs Docker).

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use ls_audit::{GENESIS, Record, verify};
use ls_control_plane::app::{self, AppState};
use ls_control_plane::auth::ServiceToken;
use ls_control_plane::db::{Database, PoolSettings};
use ls_control_plane::readiness::ReadyFlag;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use sqlx_core::query_scalar::query_scalar;
use sqlx_postgres::PgConnection;
use tower::ServiceExt;
use uuid::Uuid;

// Test-only values.
const TOKEN: &str = "test-only-gateway-service-token-0123456789";
const WRONG: &str = "test-only-gateway-service-token-0123456780";
// Underscores, like real API keys: a value made only of letters, digits, dots and hyphens is a
// valid host name, which the `host` attribute accepts by design.
const CANARY: &str = "CANARY_5e1d0c77_audit_do_not_store";
const EVENTS: &str = "/internal/v1/audit/events";

struct Reply {
    status: StatusCode,
    body: Value,
    raw: String,
}

fn state(db: Database, token: Option<&str>) -> AppState {
    let s = AppState::new(true, Arc::new(ReadyFlag::new(true)), db);
    match token {
        Some(t) => s.with_service_token(ServiceToken::new(SecretString::from(t))),
        None => s,
    }
}

fn bearer(t: &str) -> String {
    format!("Bearer {t}")
}

async fn send(app: &Router, req: Request<Body>) -> Reply {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        raw: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

/// `POST /internal/v1/audit/events` with optional `Authorization` and `X-Locksmith-Org`.
async fn post_event(app: &Router, auth: Option<&str>, org: Option<Uuid>, body: &Value) -> Reply {
    let mut b = Request::builder()
        .method("POST")
        .uri(EVENTS)
        .header("content-type", "application/json");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    if let Some(o) = org {
        b = b.header("x-locksmith-org", o.to_string());
    }
    send(app, b.body(Body::from(body.to_string())).unwrap()).await
}

/// A dev-auth request as `org`.
async fn dev(app: &Router, method: &str, uri: &str, org: Uuid, body: Option<Value>) -> Reply {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-locksmith-dev-org", org.to_string());
    let body = match body {
        Some(v) => {
            b = b.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    send(app, b.body(body).unwrap()).await
}

fn assert_problem(r: &Reply, status: StatusCode, slug: &str) {
    assert_eq!(r.status, status, "{}", r.raw);
    assert_eq!(r.body["type"], format!("urn:locksmith:problem:{slug}"));
    for s in [TOKEN, WRONG, CANARY] {
        assert!(!r.raw.contains(s), "problem echoes request data: {}", r.raw);
    }
}

fn attempt(agent: Uuid, secret: Uuid) -> Value {
    json!({
        "kind": "relay.attempt", "outcome": "pending",
        "agent_id": agent, "secret_id": secret, "version": 1,
        "method": "GET", "host": "api.example.com",
    })
}

/// No token, a wrong token, a token without an org, and no configured token are all `401`
/// before any database access (the pool here never connects).
#[tokio::test]
async fn missing_or_wrong_service_token_is_401() {
    let app = app::build(state(common::unreachable_db(), Some(TOKEN)));
    let org = Some(Uuid::now_v7());
    let body = attempt(Uuid::now_v7(), Uuid::now_v7());

    for auth in [
        None,
        Some(bearer(WRONG)),
        Some(TOKEN.to_owned()),
        Some(format!("Basic {TOKEN}")),
        Some("Bearer ".to_owned()),
    ] {
        let r = post_event(&app, auth.as_deref(), org, &body).await;
        assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    }
    let r = post_event(&app, Some(&bearer(TOKEN)), None, &body).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    // The dev org header does not open the internal route.
    let r = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(EVENTS)
            .header("content-type", "application/json")
            .header("x-locksmith-dev-org", Uuid::now_v7().to_string())
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");

    // Fail closed: with no token configured, every token is refused.
    let closed = app::build(state(common::unreachable_db(), None));
    for auth in [None, Some(bearer(TOKEN))] {
        let r = post_event(&closed, auth.as_deref(), org, &body).await;
        assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    }
}

/// Bodies outside the allow-list are `400` before any database access, and the problem never
/// echoes the value: free-form strings, a host with a port, path or query, unknown kinds,
/// outcomes or methods, and an outcome that does not fit the kind.
#[tokio::test]
async fn non_allow_listed_bodies_are_400() {
    let app = app::build(state(common::unreachable_db(), Some(TOKEN)));
    let auth = bearer(TOKEN);
    let org = Some(Uuid::now_v7());
    let base = attempt(Uuid::now_v7(), Uuid::now_v7());
    let with = |k: &str, v: Value| {
        let mut b = base.clone();
        b[k] = v;
        b
    };
    for bad in [
        with("url", json!(format!("https://api.example.com/?k={CANARY}"))),
        with("path", json!(format!("/v1/{CANARY}"))),
        with("header", json!(CANARY)),
        with("request_id", json!(CANARY)),
        with("host", json!(CANARY)),
        with("host", json!("api.example.com:443")),
        with("host", json!("api.example.com/v1")),
        with("host", json!(format!("api.example.com?token={CANARY}"))),
        with("kind", json!(CANARY)),
        with("kind", json!("agent.created")),
        with("outcome", json!(CANARY)),
        with("outcome", json!("ok")),
        with("method", json!(CANARY)),
        with("method", json!("CONNECT")),
        with("agent_id", json!(CANARY)),
        with("version", json!(0)),
        with("status", json!(42)),
        json!({"kind": "relay.outcome", "outcome": "pending", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        json!({"kind": "relay.denied", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        json!({"kind": "relay.attempt", "outcome": "pending", "agent_id": Uuid::now_v7()}),
        // Git events: one per call, never pending, and a denial only as `git.denied`.
        json!({"kind": "git.fetch", "outcome": "pending", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        json!({"kind": "git.push", "outcome": "denied", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        json!({"kind": "git.denied", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        // AWS events (D2): region and duration only, issued only as `ok`.
        json!({"kind": "aws.credentials.issued", "outcome": "denied", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7(), "region": "us-east-1", "duration_secs": 900}),
        json!({"kind": "aws.credentials.issued", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7(), "region": "us-east-1"}),
        json!({"kind": "aws.credentials.issued", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7(), "region": CANARY, "duration_secs": 900}),
        json!({"kind": "aws.credentials.issued", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7(), "region": "us-east-1", "duration_secs": 7200}),
        json!({"kind": "aws.credentials.denied", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7(), "region": "us-east-1"}),
        json!({"kind": "aws.credentials.denied", "outcome": "denied", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7(), "region": "us-east-1", "host": "sts.amazonaws.com"}),
        json!({"kind": "relay.denied", "outcome": "denied", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7(), "region": "us-east-1"}),
        // Postgres refusals (D3): only denial outcomes.
        json!({"kind": "db.session.denied", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        json!({"kind": "db.session.denied", "outcome": "pending", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        json!({"kind": "db.session.denied", "outcome": "upstream_timeout", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        // Session events (D3): outcome `ok` only; `reason` only on the closing event.
        json!({"kind": "db.session.opened", "outcome": "denied", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        json!({"kind": "db.session.opened", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7(), "reason": "revoked"}),
        json!({"kind": "db.session.opened", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7(), "bytes_in": 1}),
        json!({"kind": "db.session.closed", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        json!({"kind": "db.session.closed", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7(), "reason": "query text"}),
        // An outcome must name its attempt (the idempotency key).
        json!({"kind": "relay.outcome", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7()}),
        // A short-lived credential issue: outcome `ok`, its id and expiry, no upstream fields,
        // and no field for the credential itself.
        json!({"kind": "credential.issued", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7(), "expires_at": 1}),
        json!({"kind": "credential.issued", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7(), "credential_id": Uuid::now_v7()}),
        json!({"kind": "credential.issued", "outcome": "denied", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7(), "credential_id": Uuid::now_v7(), "expires_at": 1}),
        json!({"kind": "credential.issued", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7(), "credential_id": Uuid::now_v7(), "expires_at": 1, "host": "api.example.com"}),
        json!({"kind": "credential.issued", "outcome": "ok", "agent_id": Uuid::now_v7(), "secret_id": Uuid::now_v7(), "credential_id": Uuid::now_v7(), "expires_at": 1, "credential": CANARY}),
        with("credential_id", json!(Uuid::now_v7())),
        with("expires_at", json!(1)),
    ] {
        let r = post_event(&app, Some(&auth), org, &bad).await;
        assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    }
}

/// Git events (D1): `git.fetch`, `git.push` and `git.denied` append to the chain with their own
/// kinds, and carry the host, port and status but no attempt.
#[tokio::test]
async fn git_events_append_to_the_chain() {
    let f = Fixture::start().await;
    let org = f.org("git").await;
    let auth = bearer(TOKEN);
    let (agent, secret) = (Uuid::now_v7(), Uuid::now_v7());
    let base = |kind: &str, outcome: &str| {
        json!({
            "kind": kind, "outcome": outcome, "agent_id": agent, "secret_id": secret,
            "version": 1, "method": "POST", "host": "github.com", "status": 200,
        })
    };
    for (n, (kind, outcome)) in [
        ("git.fetch", "ok"),
        ("git.push", "upstream_timeout"),
        ("git.denied", "denied"),
        ("db.session.denied", "no_grant"),
        ("db.session.denied", "decrypt_failed"),
    ]
    .into_iter()
    .enumerate()
    {
        let r = post_event(&f.app, Some(&auth), Some(org), &base(kind, outcome)).await;
        assert_eq!(
            (r.status, r.body["seq"].as_u64()),
            (StatusCode::CREATED, Some(n as u64 + 1))
        );
    }
    let rows = f.records(org).await;
    assert_intact(&rows);
    let seen: Vec<_> = rows
        .iter()
        .map(|r| (r.kind.as_str(), r.outcome.as_str()))
        .collect();
    assert_eq!(
        seen,
        [
            ("git.fetch", "ok"),
            ("git.push", "upstream_timeout"),
            ("git.denied", "denied"),
            ("db.session.denied", "no_grant"),
            ("db.session.denied", "decrypt_failed")
        ]
    );
}

/// AWS credential events (D2): `aws.credentials.issued` and `.denied` append with the region
/// and duration as attributes and the binding's secret as the target.
#[tokio::test]
async fn aws_credential_events_append_to_the_chain() {
    let f = Fixture::start().await;
    let org = f.org("aws").await;
    let auth = bearer(TOKEN);
    let (agent, secret) = (Uuid::now_v7(), Uuid::now_v7());
    for (n, ev) in [
        json!({"kind": "aws.credentials.issued", "outcome": "ok", "agent_id": agent,
               "secret_id": secret, "region": "eu-west-2", "duration_secs": 900}),
        json!({"kind": "aws.credentials.denied", "outcome": "no_grant", "agent_id": agent,
               "secret_id": secret, "region": "eu-west-2"}),
        json!({"kind": "aws.credentials.denied", "outcome": "upstream_error", "agent_id": agent,
               "secret_id": secret, "region": "eu-west-2", "duration_secs": 1800}),
    ]
    .iter()
    .enumerate()
    {
        let r = post_event(&f.app, Some(&auth), Some(org), ev).await;
        assert_eq!(
            (r.status, r.body["seq"].as_u64()),
            (StatusCode::CREATED, Some(n as u64 + 1))
        );
    }
    let rows = f.records(org).await;
    assert_intact(&rows);
    let seen: Vec<_> = rows
        .iter()
        .map(|r| (r.kind.as_str(), r.outcome.as_str()))
        .collect();
    assert_eq!(
        seen,
        [
            ("aws.credentials.issued", "ok"),
            ("aws.credentials.denied", "no_grant"),
            ("aws.credentials.denied", "upstream_error")
        ]
    );
    let attrs = rows[0].attrs.as_ref().unwrap().to_json();
    assert_eq!(
        attrs,
        json!({"duration_secs": {"int": 900}, "region": {"host": "eu-west-2"}})
    );
    assert_eq!(
        rows[0].target.as_deref(),
        Some(format!("secret:{secret}").as_str())
    );
}

/// Session events (D3): `db.session.opened` then `db.session.closed` with reason, duration and
/// byte counts, linked by `attempt_id`.
#[tokio::test]
async fn db_session_events_append_to_the_chain() {
    let f = Fixture::start().await;
    let org = f.org("dbsession").await;
    let auth = bearer(TOKEN);
    let (agent, secret) = (Uuid::now_v7(), Uuid::now_v7());
    let opened = post_event(
        &f.app,
        Some(&auth),
        Some(org),
        &json!({"kind": "db.session.opened", "outcome": "ok", "agent_id": agent,
                "secret_id": secret, "version": 1, "host": "db.internal", "port": 5432}),
    )
    .await;
    assert_eq!(opened.status, StatusCode::CREATED);
    let closed = post_event(
        &f.app,
        Some(&auth),
        Some(org),
        &json!({"kind": "db.session.closed", "outcome": "ok", "agent_id": agent,
                "secret_id": secret, "version": 1, "host": "db.internal", "port": 5432,
                "attempt_id": opened.body["id"], "reason": "revoked",
                "duration_ms": 1234, "bytes_in": 10, "bytes_out": 2048}),
    )
    .await;
    assert_eq!(closed.status, StatusCode::CREATED);
    let rows = f.records(org).await;
    assert_intact(&rows);
    let seen: Vec<_> = rows
        .iter()
        .map(|r| (r.kind.as_str(), r.outcome.as_str()))
        .collect();
    assert_eq!(
        seen,
        [("db.session.opened", "ok"), ("db.session.closed", "ok")]
    );
}

/// m1-remote-mcp task 3.3: `credential.issued` appends with the credential's id and expiry as
/// attributes, actor the agent and target the secret.
#[tokio::test]
async fn credential_issued_appends_to_the_chain() {
    let f = Fixture::start().await;
    let org = f.org("short-lived").await;
    let auth = bearer(TOKEN);
    let (agent, secret, credential) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    let body = json!({
        "kind": "credential.issued", "outcome": "ok", "agent_id": agent, "secret_id": secret,
        "version": 1, "credential_id": credential, "expires_at": 1_900_000_000_i64,
    });
    let r = post_event(&f.app, Some(&auth), Some(org), &body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    let rows = f.records(org).await;
    assert_intact(&rows);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].kind.as_str(), rows[0].outcome.as_str()),
        ("credential.issued", "ok")
    );
    let text = f.ledger_text().await;
    assert!(text.contains(&credential.to_string()), "{text}");
    assert!(text.contains("1900000000"), "{text}");
}

/// m1-remote-mcp task 3.4: the gateway reads the org's agent-tool overrides (only its own org's,
/// and only the agent layer), and appends one `mcp.call` per agent MCP call.
#[tokio::test]
async fn gateway_reads_agent_tool_settings_and_appends_mcp_calls() {
    let f = Fixture::start().await;
    let (a, b) = (f.org("tools-a").await, f.org("tools-b").await);
    let auth = bearer(TOKEN);
    // Overrides set in the console: one agent tool on, one hub tool (never returned here).
    for (uri, on) in [
        ("/v1/mcp/tools/agent/issue_short_lived_credential", true),
        ("/v1/mcp/tools/agent/list_my_keys", false),
        ("/v1/mcp/tools/hub/revoke_grant", true),
    ] {
        let r = dev(&f.app, "PUT", uri, a, Some(json!({"enabled": on}))).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    }
    let get = |org: Option<Uuid>, auth: Option<&str>| {
        let mut b = Request::builder()
            .method("GET")
            .uri("/internal/v1/mcp/agent-tool-settings");
        if let Some(a) = auth {
            b = b.header("authorization", a);
        }
        if let Some(o) = org {
            b = b.header("x-locksmith-org", o.to_string());
        }
        send(&f.app, b.body(Body::empty()).unwrap())
    };
    let r = get(Some(a), Some(&auth)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(
        r.body["items"],
        json!([
            {"tool": "issue_short_lived_credential", "enabled": true},
            {"tool": "list_my_keys", "enabled": false},
        ])
    );
    assert_eq!(get(Some(b), Some(&auth)).await.body["items"], json!([]));
    assert_eq!(get(Some(a), None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        get(Some(a), Some(&bearer(WRONG))).await.status,
        StatusCode::UNAUTHORIZED
    );

    // Calls: a registry name is recorded as is, anything else as `unknown`.
    let agent = Uuid::now_v7();
    let call = |body: Value| {
        let req = Request::builder()
            .method("POST")
            .uri("/internal/v1/mcp/agent-calls")
            .header("content-type", "application/json")
            .header("authorization", auth.clone())
            .header("x-locksmith-org", a.to_string())
            .body(Body::from(body.to_string()))
            .unwrap();
        send(&f.app, req)
    };
    for body in [
        json!({"agent_id": agent, "tool": "list_my_keys", "outcome": "ok"}),
        json!({"agent_id": agent, "tool": "issue_short_lived_credential", "outcome": "denied", "reason": "tool_off"}),
        json!({"agent_id": agent, "tool": "SECRET sk_live_abc", "outcome": "denied", "reason": "tool_off"}),
    ] {
        assert_eq!(call(body).await.status, StatusCode::CREATED);
    }
    for bad in [
        json!({"agent_id": agent, "tool": "list_my_keys", "outcome": "ok", "reason": "tool_off"}),
        json!({"agent_id": agent, "tool": "list_my_keys", "outcome": "denied"}),
        json!({"agent_id": agent, "tool": "list_my_keys", "outcome": "ok", "arguments": {"x": 1}}),
        json!({"agent_id": agent, "tool": "list_my_keys", "outcome": "ok", "reason": "free text"}),
    ] {
        assert_eq!(call(bad).await.status, StatusCode::BAD_REQUEST);
    }
    let rows = f.records(a).await;
    assert_intact(&rows);
    let seen: Vec<_> = rows
        .iter()
        .map(|r| (r.kind.as_str(), r.outcome.as_str()))
        .collect();
    assert_eq!(
        seen,
        [
            ("mcp.call", "ok"),
            ("mcp.call", "denied"),
            ("mcp.call", "denied")
        ]
    );
    let text = f.ledger_text().await;
    assert!(text.contains("issue_short_lived_credential"), "{text}");
    assert!(text.contains("unknown"), "{text}");
    assert!(
        !text.contains("sk_live_abc"),
        "client text reached the ledger"
    );
}

/// m2-mcp-gateway task 4.1: `POST /internal/v1/mcp/upstream-calls` appends `mcp.upstream_call`
/// (`pending`, or `denied` alone for a refusal) and `mcp.upstream_outcome` (`ok` or `error`),
/// the outcome idempotent on `attempt_id`. Tool names are recorded only when they pass the MCP
/// rule, every reason is a closed code, nothing else is accepted, and the chain verifies.
#[tokio::test]
async fn upstream_calls_append_pairs_denials_and_idempotent_outcomes() {
    let f = Fixture::start().await;
    let (a, b) = (f.org("upstream-a").await, f.org("upstream-b").await);
    let auth = bearer(TOKEN);
    let agent = Uuid::now_v7();
    let post = |org: Option<Uuid>, auth: Option<String>, body: Value| {
        let mut r = Request::builder()
            .method("POST")
            .uri("/internal/v1/mcp/upstream-calls")
            .header("content-type", "application/json");
        if let Some(a) = auth {
            r = r.header("authorization", a);
        }
        if let Some(o) = org {
            r = r.header("x-locksmith-org", o.to_string());
        }
        send(&f.app, r.body(Body::from(body.to_string())).unwrap())
    };
    let call = |body: Value| post(Some(a), Some(auth.clone()), body);
    let pending = |tool: &str| {
        json!({"phase": "call", "agent_id": agent, "upstream": "github", "tool": tool,
            "decision": "allow", "outcome": "pending"})
    };

    // Auth first: no token, a wrong token, no org.
    let body = pending("list_issues");
    assert_eq!(
        post(Some(a), None, body.clone()).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post(Some(a), Some(bearer(WRONG)), body.clone())
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert!(
        post(None, Some(auth.clone()), body)
            .await
            .status
            .is_client_error()
    );

    // An allowed call: pending, then its outcome; a resend is the stored event, a different
    // outcome for the same attempt is a 409.
    let p = call(pending("list_issues")).await;
    assert_eq!(p.status, StatusCode::CREATED, "{}", p.raw);
    let outcome = json!({"phase": "outcome", "agent_id": agent, "upstream": "github",
        "tool": "list_issues", "decision": "allow", "outcome": "ok", "attempt_id": id(&p)});
    let first = call(outcome.clone()).await;
    assert_eq!(first.status, StatusCode::CREATED, "{}", first.raw);
    let again = call(outcome.clone()).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.raw);
    assert_eq!(again.body, first.body, "the stored event, not a new one");
    let mut other = outcome.clone();
    other["outcome"] = json!("error");
    other["reason"] = json!("upstream_error");
    assert_problem(&call(other).await, StatusCode::CONFLICT, "conflict");

    // A second call whose outcome is an error; every failure reason is accepted.
    let p2 = call(pending("create_issue")).await;
    assert_eq!(p2.status, StatusCode::CREATED, "{}", p2.raw);
    let fail = |reason: &str, attempt: Uuid| {
        json!({"phase": "outcome", "agent_id": agent, "upstream": "github",
            "tool": "create_issue", "decision": "allow", "outcome": "error",
            "reason": reason, "attempt_id": attempt})
    };
    let r = call(fail("upstream_timeout", id(&p2))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    // The other failure reasons, each on its own attempt.
    for reason in [
        "denied",
        "denied_address",
        "upstream_unreachable",
        "secret_unavailable",
        "secret_unusable",
        "upstream_error",
        "upstream_unsupported",
        "redaction_failed",
        "internal",
    ] {
        let p = call(pending("create_issue")).await;
        let r = call(fail(reason, id(&p))).await;
        assert_eq!(r.status, StatusCode::CREATED, "{reason}: {}", r.raw);
    }

    // Refusals: one denied call event each, the reason a refusal reason. A tool name outside the
    // MCP rule is recorded as `unknown`, never as sent.
    let denied = |tool: &str, decision: &str, reason: &str| {
        json!({"phase": "call", "agent_id": agent, "upstream": "github", "tool": tool,
            "decision": decision, "outcome": "denied", "reason": reason})
    };
    for body in [
        denied("delete_repository", "deny", "deny"),
        denied("create_issue", "hold", "hold"),
        denied("secret_admin", "hide", "hide"),
        denied("unknown", "hide", "unknown_tool"),
        denied("bad name CANARY_tool_text", "hide", "unknown_tool"),
        denied("unknown", "hide", "policy_unavailable"),
        denied("unknown", "hide", "catalogue_unavailable"),
    ] {
        let r = call(body.clone()).await;
        assert_eq!(r.status, StatusCode::CREATED, "{body}: {}", r.raw);
    }

    // Everything else is a 400: unknown fields, a name or code outside the closed sets, and
    // fields that do not fit together (phase, outcome, decision, reason, attempt).
    let mut with_args = pending("list_issues");
    with_args["arguments"] = json!({"q": CANARY});
    let mut with_result = outcome.clone();
    with_result["result"] = json!(CANARY);
    let mut bad_upstream = pending("list_issues");
    bad_upstream["upstream"] = json!("Git Hub");
    let mut long_upstream = pending("list_issues");
    long_upstream["upstream"] = json!("a".repeat(33));
    let mut empty_upstream = pending("list_issues");
    empty_upstream["upstream"] = json!("");
    let mut free_reason = denied("create_issue", "hold", "hold");
    free_reason["reason"] = json!(CANARY);
    let mut pending_reason = pending("list_issues");
    pending_reason["reason"] = json!("hide");
    let mut pending_attempt = pending("list_issues");
    pending_attempt["attempt_id"] = json!(Uuid::now_v7());
    let mut pending_deny = pending("list_issues");
    pending_deny["decision"] = json!("deny");
    let mut no_attempt = outcome.clone();
    no_attempt.as_object_mut().unwrap().remove("attempt_id");
    let mut ok_reason = outcome.clone();
    ok_reason["reason"] = json!("upstream_error");
    let mut ok_deny = outcome.clone();
    ok_deny["decision"] = json!("deny");
    let mut error_no_reason = fail("internal", id(&p));
    error_no_reason.as_object_mut().unwrap().remove("reason");
    let mut error_refusal_reason = fail("hide", id(&p));
    error_refusal_reason["decision"] = json!("allow");
    let mut denied_allow = denied("create_issue", "allow", "hold");
    denied_allow["decision"] = json!("allow");
    let mut denied_attempt = denied("create_issue", "hold", "hold");
    denied_attempt["attempt_id"] = json!(id(&p));
    let mut call_ok = pending("list_issues");
    call_ok["outcome"] = json!("ok");
    let mut outcome_denied = outcome.clone();
    outcome_denied["outcome"] = json!("denied");
    outcome_denied["reason"] = json!("deny");
    for (what, bad) in [
        ("arguments field", with_args),
        ("result field", with_result),
        ("upstream with a space and capitals", bad_upstream),
        ("upstream over 32 characters", long_upstream),
        ("empty upstream", empty_upstream),
        ("free-text reason", free_reason),
        ("reason on pending", pending_reason),
        ("attempt on a call", pending_attempt),
        ("pending with a deny decision", pending_deny),
        ("outcome without attempt", no_attempt),
        ("ok with a reason", ok_reason),
        ("outcome with a deny decision", ok_deny),
        ("error without a reason", error_no_reason),
        ("error with a refusal reason", error_refusal_reason),
        ("denied with decision allow", denied_allow),
        ("denied call with an attempt", denied_attempt),
        (
            "denied reason hold with decision deny",
            denied("x", "deny", "hold"),
        ),
        ("call phase with ok", call_ok),
        ("outcome phase with denied", outcome_denied),
        ("denied without a reason", {
            let mut d = denied("x", "deny", "deny");
            d.as_object_mut().unwrap().remove("reason");
            d
        }),
        (
            "unknown phase",
            json!({"phase": "x", "agent_id": agent, "upstream": "github",
            "tool": "t", "decision": "allow", "outcome": "pending"}),
        ),
    ] {
        let r = call(bad).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{what}: {}", r.raw);
    }

    // The ledger: the pairs, the denials, nothing from the 400s, the org's own chain only.
    let rows = f.records(a).await;
    assert_intact(&rows);
    let seen: Vec<_> = rows
        .iter()
        .map(|r| (r.kind.as_str(), r.outcome.as_str()))
        .collect();
    let mut expected = vec![
        ("mcp.upstream_call", "pending"),
        ("mcp.upstream_outcome", "ok"),
        ("mcp.upstream_call", "pending"),
        ("mcp.upstream_outcome", "error"),
    ];
    for _ in 0..9 {
        expected.push(("mcp.upstream_call", "pending"));
        expected.push(("mcp.upstream_outcome", "error"));
    }
    expected.extend([("mcp.upstream_call", "denied"); 7]);
    assert_eq!(seen, expected);
    assert!(f.records(b).await.is_empty());
    let attr_of = |r: &Record, key: &str| -> Option<String> {
        r.attrs
            .as_ref()?
            .entries()
            .iter()
            .find(|(k, _, _)| k == key)
            .map(|(_, _, v)| v.clone())
    };
    assert_eq!(attr_of(&rows[0], "tool").as_deref(), Some("list_issues"));
    assert_eq!(attr_of(&rows[0], "upstream").as_deref(), Some("github"));
    assert_eq!(attr_of(&rows[0], "decision").as_deref(), Some("allow"));
    assert_eq!(
        attr_of(&rows[1], "attempt_id"),
        Some(rows[0].id.to_string())
    );
    assert_eq!(rows[1].actor, format!("agent:{agent}"));
    let last = &rows[rows.len() - 3];
    assert_eq!(
        attr_of(last, "tool").as_deref(),
        Some("unknown"),
        "{last:?}"
    );
    let text = f.ledger_text().await;
    for needle in [CANARY, "CANARY_tool_text", "bad name"] {
        assert!(!text.contains(needle), "{needle} reached the ledger");
    }

    // Backstop: a direct append of a second `mcp.upstream_outcome` for the first attempt is
    // refused by the unique index of migration 0016, and the chain is unchanged.
    let event = ls_audit::Event {
        kind: ls_audit::kind::MCP_UPSTREAM_OUTCOME,
        actor: ls_audit::Actor::Agent(agent),
        target: Some(ls_audit::Target::Org(a)),
        outcome: ls_audit::outcome::OK,
        attrs: ls_audit::Attrs::new().id(ls_audit::attr::ATTEMPT_ID, id(&p)),
    };
    let mut c = PgConnection::connect_with(&f.pg.app()).await.unwrap();
    let mut tx = c.begin().await.unwrap();
    ls_audit::pg::bind_org(&mut tx, a).await.unwrap();
    let err = ls_audit::pg::append_in_tx(&mut tx, a, &event)
        .await
        .expect_err("second outcome for one attempt");
    assert_eq!(
        err.as_database_error().and_then(|d| d.code()).as_deref(),
        Some("23505")
    );
    tx.rollback().await.unwrap();
    assert_eq!(f.records(a).await.len(), rows.len());
}

/// A migrated database and the app as `locksmith_app`.
struct Fixture {
    app: Router,
    pg: common::Pg,
}

impl Fixture {
    async fn start() -> Self {
        let pg = common::Pg::migrated().await;
        let pool = PoolSettings {
            max_connections: 20,
            ..PoolSettings::default()
        };
        let app = app::build(state(pg.app_db(pool), Some(TOKEN)));
        Self { app, pg }
    }

    async fn org(&self, name: &str) -> Uuid {
        let r = send(
            &self.app,
            Request::builder()
                .method("POST")
                .uri("/v1/orgs")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "name": name }).to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
        id(&r)
    }

    /// `org`'s events as the app role bound to `org` (RLS applies).
    async fn records(&self, org: Uuid) -> Vec<Record> {
        let mut c = PgConnection::connect_with(&self.pg.app()).await.unwrap();
        let mut tx = c.begin().await.unwrap();
        ls_audit::pg::bind_org(&mut tx, org).await.unwrap();
        let rows = ls_audit::pg::records_in_tx(&mut tx, org).await.unwrap();
        tx.rollback().await.unwrap();
        rows
    }

    /// Every stored ledger row, all orgs, as text (bootstrap superuser, no RLS).
    async fn ledger_text(&self) -> String {
        let mut c = self.pg.admin().await;
        let text: Option<String> =
            query_scalar("SELECT string_agg(t::text, E'\\n') FROM audit_events t")
                .fetch_one(&mut c)
                .await
                .unwrap();
        c.close().await.unwrap();
        text.unwrap_or_default()
    }
}

fn id(r: &Reply) -> Uuid {
    r.body["id"].as_str().unwrap().parse().unwrap()
}

/// The chain read back from Postgres is seq 1..n, linked from GENESIS, with every recomputed
/// hash equal to the stored one.
fn assert_intact(rows: &[Record]) {
    assert_eq!(
        rows.iter().map(|r| r.seq).collect::<Vec<_>>(),
        (1..=rows.len() as u64).collect::<Vec<_>>()
    );
    let mut prev = GENESIS;
    for r in rows {
        assert_eq!(r.prev_hash, prev, "seq {} link", r.seq);
        assert_eq!(r.compute_hash(), r.hash, "seq {} hash", r.seq);
        prev = r.hash;
    }
    let walk = verify(rows.iter().map(Record::link), &[]);
    assert!(walk.ok(), "{walk:?}");
}

/// Scenario: concurrent appends stay linear, through the endpoint. 50 requests race on one org;
/// the responses carry seq 1..50 exactly once each and the stored chain is intact.
#[tokio::test]
async fn fifty_concurrent_endpoint_appends_give_seq_1_to_50() {
    let f = Fixture::start().await;
    let org = f.org("org-concurrent").await;
    let (agent, secret) = (Uuid::now_v7(), Uuid::now_v7());
    let auth = bearer(TOKEN);

    let mut tasks = Vec::new();
    for n in 0..50u16 {
        let app = f.app.clone();
        let auth = auth.clone();
        let body = json!({
            "kind": "relay.outcome", "outcome": "ok", "agent_id": agent, "secret_id": secret,
            "version": 1, "method": "POST", "host": "api.example.com", "status": 200 + n,
            "attempt_id": Uuid::now_v7(),
        });
        tasks.push(tokio::spawn(async move {
            post_event(&app, Some(&auth), Some(org), &body).await
        }));
    }
    let mut seqs = BTreeSet::new();
    for t in tasks {
        let r = t.await.unwrap();
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
        assert!(seqs.insert(r.body["seq"].as_u64().unwrap()));
    }
    assert_eq!(seqs, (1..=50).collect::<BTreeSet<u64>>());

    let rows = f.records(org).await;
    assert_eq!(rows.len(), 50);
    assert_intact(&rows);
    let r = &rows[0];
    assert_eq!(r.kind, "relay.outcome");
    assert_eq!(r.outcome, "ok");
    assert_eq!(r.actor, format!("agent:{agent}"));
    assert_eq!(r.target.as_deref(), Some(&*format!("secret:{secret}")));
}

/// Scenario: cross-org isolation through the endpoint. Each org's events go to its own chain
/// (both start at seq 1), and an org's binding sees none of the other org's events.
#[tokio::test]
async fn endpoint_appends_are_isolated_per_org() {
    let f = Fixture::start().await;
    let (a, b) = (f.org("a").await, f.org("b").await);
    let auth = bearer(TOKEN);
    let (agent_a, agent_b, secret) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());

    for n in 1..=3u64 {
        let r = post_event(&f.app, Some(&auth), Some(a), &attempt(agent_a, secret)).await;
        assert_eq!(
            (r.status, r.body["seq"].as_u64()),
            (StatusCode::CREATED, Some(n))
        );
    }
    let denied = json!({
        "kind": "relay.denied", "outcome": "no_grant", "agent_id": agent_b, "secret_id": secret,
    });
    let r = post_event(&f.app, Some(&auth), Some(b), &denied).await;
    assert_eq!(
        (r.status, r.body["seq"].as_u64()),
        (StatusCode::CREATED, Some(1))
    );

    let rows_a = f.records(a).await;
    let rows_b = f.records(b).await;
    assert_eq!(rows_a.len(), 3);
    assert_eq!(rows_b.len(), 1);
    assert_intact(&rows_a);
    assert_intact(&rows_b);
    assert!(
        rows_a
            .iter()
            .all(|r| r.org_id == a && r.actor.contains(&agent_a.to_string()))
    );
    assert_eq!(rows_b[0].org_id, b);
    assert_eq!(rows_b[0].kind, "relay.denied");
    assert_eq!(rows_b[0].outcome, "no_grant");

    // RLS: bound to B, reading A's chain by its id returns nothing.
    let mut c = PgConnection::connect_with(&f.pg.app()).await.unwrap();
    let mut tx = c.begin().await.unwrap();
    ls_audit::pg::bind_org(&mut tx, b).await.unwrap();
    assert!(
        ls_audit::pg::records_in_tx(&mut tx, a)
            .await
            .unwrap()
            .is_empty()
    );
    let all: i64 = query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(all, 1);
    tx.rollback().await.unwrap();
}

/// S5 task 3.1 (design decision 5): `relay.outcome` is idempotent on `attempt_id`. A resend
/// with the same fields returns the stored event (`200`, same id and seq) and appends nothing; a
/// different outcome for the same attempt is a `409`; concurrent resends append once. The partial
/// unique index from migration 0009 refuses a second outcome even past the endpoint.
#[tokio::test]
async fn relay_outcome_is_idempotent_on_attempt_id() {
    let f = Fixture::start().await;
    let org = f.org("org-idempotent").await;
    let auth = bearer(TOKEN);
    let (agent, secret) = (Uuid::now_v7(), Uuid::now_v7());
    let a = post_event(&f.app, Some(&auth), Some(org), &attempt(agent, secret)).await;
    assert_eq!(a.status, StatusCode::CREATED, "{}", a.raw);
    let outcome = json!({
        "kind": "relay.outcome", "outcome": "ok", "agent_id": agent, "secret_id": secret,
        "version": 1, "method": "GET", "host": "api.example.com", "status": 200,
        "attempt_id": id(&a),
    });
    let first = post_event(&f.app, Some(&auth), Some(org), &outcome).await;
    assert_eq!(first.status, StatusCode::CREATED, "{}", first.raw);
    let again = post_event(&f.app, Some(&auth), Some(org), &outcome).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.raw);
    assert_eq!(again.body, first.body, "the stored event, not a new one");

    let mut other = outcome.clone();
    other["status"] = json!(502);
    other["outcome"] = json!("upstream_error");
    let r = post_event(&f.app, Some(&auth), Some(org), &other).await;
    assert_problem(&r, StatusCode::CONFLICT, "conflict");

    // Concurrent resends of a second attempt's outcome: one append, every answer the same event.
    let b = post_event(&f.app, Some(&auth), Some(org), &attempt(agent, secret)).await;
    let mut second = outcome.clone();
    second["attempt_id"] = json!(id(&b));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (app, auth, body) = (f.app.clone(), auth.clone(), second.clone());
        tasks.push(tokio::spawn(async move {
            post_event(&app, Some(&auth), Some(org), &body).await
        }));
    }
    let mut ids = BTreeSet::new();
    let mut created = 0;
    for t in tasks {
        let r = t.await.unwrap();
        assert!(
            matches!(r.status, StatusCode::CREATED | StatusCode::OK),
            "{}",
            r.raw
        );
        created += usize::from(r.status == StatusCode::CREATED);
        ids.insert(id(&r));
    }
    assert_eq!((created, ids.len()), (1, 1));

    let rows = f.records(org).await;
    assert_eq!(
        rows.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>(),
        [
            "relay.attempt",
            "relay.outcome",
            "relay.attempt",
            "relay.outcome"
        ]
    );
    assert_intact(&rows);

    // Backstop: a direct append of a second outcome for the first attempt is refused by the
    // unique index (unique_violation), and the chain is unchanged.
    let event = ls_audit::Event {
        kind: ls_audit::kind::RELAY_OUTCOME,
        actor: ls_audit::Actor::Agent(agent),
        target: Some(ls_audit::Target::Secret(secret)),
        outcome: ls_audit::outcome::OK,
        attrs: ls_audit::Attrs::new().id(ls_audit::attr::ATTEMPT_ID, id(&a)),
    };
    let mut c = PgConnection::connect_with(&f.pg.app()).await.unwrap();
    let mut tx = c.begin().await.unwrap();
    ls_audit::pg::bind_org(&mut tx, org).await.unwrap();
    let err = ls_audit::pg::append_in_tx(&mut tx, org, &event)
        .await
        .expect_err("second outcome for one attempt");
    assert_eq!(
        err.as_database_error().and_then(|d| d.code()).as_deref(),
        Some("23505")
    );
    tx.rollback().await.unwrap();
    assert_eq!(f.records(org).await.len(), 4);
}

/// S4 admin requests append `agent.created`, `grant.created`, `agent.rotated`,
/// `grant.revoked`, `grant.created` and `agent.deleted` in order, with ids and codes only. Failed
/// requests (404, 409) append nothing, because the event shares the change's transaction. No
/// stored event contains the canary (used as names and descriptions, and sent to the endpoint
/// in refused bodies) or the enrollment secret.
#[tokio::test]
async fn admin_events_are_chained_and_hold_no_canary() {
    let f = Fixture::start().await;
    let org = f.org("org-admin").await;

    let p = id(&dev(
        &f.app,
        "POST",
        "/v1/projects",
        org,
        Some(json!({"name": CANARY})),
    )
    .await);
    let e = id(&dev(
        &f.app,
        "POST",
        &format!("/v1/projects/{p}/environments"),
        org,
        Some(json!({"name": "dev", "description": CANARY})),
    )
    .await);
    let secret = id(&dev(
        &f.app,
        "POST",
        &format!("/v1/projects/{p}/environments/{e}/secrets"),
        org,
        Some(json!({"name": CANARY, "description": CANARY})),
    )
    .await);

    let r = dev(
        &f.app,
        "POST",
        "/v1/agents",
        org,
        Some(json!({"name": CANARY, "description": CANARY})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    let agent: Uuid = r.body["agent"]["id"].as_str().unwrap().parse().unwrap();
    let mut enrollment = vec![r.body["enrollment_secret"].as_str().unwrap().to_owned()];

    let grants = format!("/v1/agents/{agent}/grants");
    let r = dev(
        &f.app,
        "POST",
        &grants,
        org,
        Some(json!({"secret_id": secret})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    let grant1 = id(&r);
    // A duplicate grant (409) and a grant on a missing secret (404) append nothing.
    let r = dev(
        &f.app,
        "POST",
        &grants,
        org,
        Some(json!({"secret_id": secret})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.raw);
    let r = dev(
        &f.app,
        "POST",
        &grants,
        org,
        Some(json!({"secret_id": Uuid::now_v7()})),
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.raw);

    let r = dev(
        &f.app,
        "POST",
        &format!("/v1/agents/{agent}/enrollment-secret"),
        org,
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    enrollment.push(r.body["enrollment_secret"].as_str().unwrap().to_owned());

    let r = dev(&f.app, "DELETE", &format!("{grants}/{grant1}"), org, None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.raw);
    // Revoking it again, and deleting a missing agent, are 404 and append nothing.
    let r = dev(&f.app, "DELETE", &format!("{grants}/{grant1}"), org, None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = dev(
        &f.app,
        "DELETE",
        &format!("/v1/agents/{}", Uuid::now_v7()),
        org,
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    let expires = "2099-01-01T00:00:00Z";
    let r = dev(
        &f.app,
        "POST",
        &grants,
        org,
        Some(json!({"secret_id": secret, "expires_at": expires})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    let grant2 = id(&r);

    let r = dev(&f.app, "DELETE", &format!("/v1/agents/{agent}"), org, None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.raw);

    // Refused relay bodies carrying the canary store nothing.
    let auth = bearer(TOKEN);
    for bad in [
        json!({"kind": "relay.attempt", "outcome": "pending", "agent_id": agent,
               "secret_id": secret, "host": CANARY}),
        json!({"kind": "relay.attempt", "outcome": "pending", "agent_id": agent,
               "secret_id": secret, "query": CANARY}),
    ] {
        let r = post_event(&f.app, Some(&auth), Some(org), &bad).await;
        assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    }

    let rows = f.records(org).await;
    assert_intact(&rows);
    let actor = "service:dev_auth";
    let summary: Vec<(&str, &str, Option<&str>, &str)> = rows
        .iter()
        .map(|r| (&*r.kind, &*r.actor, r.target.as_deref(), &*r.outcome))
        .collect();
    let (ag, g1, g2) = (
        format!("agent:{agent}"),
        format!("grant:{grant1}"),
        format!("grant:{grant2}"),
    );
    assert_eq!(
        summary,
        [
            ("agent.created", actor, Some(&*ag), "ok"),
            ("grant.created", actor, Some(&*g1), "ok"),
            ("agent.rotated", actor, Some(&*ag), "ok"),
            ("grant.revoked", actor, Some(&*g1), "ok"),
            ("grant.created", actor, Some(&*g2), "ok"),
            ("agent.deleted", actor, Some(&*ag), "ok"),
        ]
    );
    let attrs = |i: usize| rows[i].attrs.as_ref().unwrap().to_json();
    assert_eq!(
        attrs(1),
        json!({"agent_id": {"id": agent}, "mode": {"code": "relay"}, "secret_id": {"id": secret}})
    );
    assert_eq!(attrs(3), json!({"agent_id": {"id": agent}}));
    assert_eq!(attrs(4)["expires_at"], json!({"int": 4_070_908_800_i64}));
    assert_eq!(attrs(5), json!({"grants_revoked": {"int": 1}}));

    // Canary and enrollment secrets appear in no stored event, of any org.
    let text = f.ledger_text().await;
    assert_eq!(text.lines().count(), 6, "{text}");
    assert!(!text.contains(CANARY));
    for s in &enrollment {
        assert!(!text.contains(s.as_str()));
    }
}

/// S5 task 6.1: `GET /v1/audit/events` pages the bound org's events newest first and never shows
/// another org's; `GET /v1/audit/status` reports the head, the latest checkpoint and the latest
/// verify run.
#[tokio::test]
async fn audit_read_api_pages_newest_first_and_is_org_scoped() {
    let f = Fixture::start().await;
    let (a, b) = (f.org("a").await, f.org("b").await);
    let auth = bearer(TOKEN);
    let (agent, secret) = (Uuid::now_v7(), Uuid::now_v7());
    for _ in 0..5 {
        let r = post_event(&f.app, Some(&auth), Some(a), &attempt(agent, secret)).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    }
    let denied = json!({
        "kind": "relay.denied", "outcome": "no_grant", "agent_id": agent, "secret_id": secret,
    });
    assert_eq!(
        post_event(&f.app, Some(&auth), Some(b), &denied)
            .await
            .status,
        StatusCode::CREATED
    );

    // Pages of 2: seq 5,4 then 3,2 then 1; `next` only while more remain.
    let mut seen = Vec::new();
    let mut uri = "/v1/audit/events?limit=2".to_owned();
    loop {
        let r = dev(&f.app, "GET", &uri, a, None).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
        let items = r.body["items"].as_array().unwrap();
        assert!(items.len() <= 2);
        seen.extend(items.iter().map(|e| e["seq"].as_i64().unwrap()));
        match r.body["next"].as_str() {
            Some(n) => uri = format!("/v1/audit/events?limit=2&cursor={n}"),
            None => break,
        }
    }
    assert_eq!(seen, [5, 4, 3, 2, 1]);

    let r = dev(&f.app, "GET", "/v1/audit/events", a, None).await;
    let first = &r.body["items"][0];
    assert_eq!(first["kind"], "relay.attempt");
    assert_eq!(first["outcome"], "pending");
    assert_eq!(first["actor"], format!("agent:{agent}"));
    assert_eq!(first["target"], format!("secret:{secret}"));
    assert_eq!(first["attrs"]["host"]["host"], "api.example.com");
    let recs = f.records(a).await;
    assert_eq!(first["digest"], hex::encode(recs[4].hash));
    assert_eq!(first["prev_digest"], hex::encode(recs[3].hash));
    assert!(r.body.get("next").is_none());

    // Org B sees only its own event.
    let r = dev(&f.app, "GET", "/v1/audit/events", b, None).await;
    assert_eq!(r.body["items"].as_array().unwrap().len(), 1);
    assert_eq!(r.body["items"][0]["kind"], "relay.denied");

    for bad in [
        "/v1/audit/events?limit=0",
        "/v1/audit/events?limit=101",
        "/v1/audit/events?cursor=not-a-cursor",
        "/v1/audit/events?unknown=1",
    ] {
        let r = dev(&f.app, "GET", bad, a, None).await;
        assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
    }
    // No org binding: 401.
    let r = send(
        &f.app,
        Request::builder()
            .uri("/v1/audit/events")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");

    // Status: no checkpoint and no verify run yet.
    let r = dev(&f.app, "GET", "/v1/audit/status", a, None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(r.body, json!({"head_seq": 5}));
    let r = dev(&f.app, "GET", "/v1/audit/status", Uuid::now_v7(), None).await;
    assert_eq!(r.body, json!({"head_seq": 0}));

    // Seed a checkpoint (app role) and two verify runs (owner); the newest run wins, and org B
    // sees neither.
    let mut c = PgConnection::connect_with(&f.pg.app()).await.unwrap();
    let mut tx = c.begin().await.unwrap();
    ls_audit::pg::bind_org(&mut tx, a).await.unwrap();
    sqlx_core::query::query(
        "INSERT INTO audit_checkpoints (org_id, seq, hash, at, key_id, signature) \
         VALUES ($1, 5, $2, now(), 'audit-checkpoint:1', $3)",
    )
    .bind(a)
    .bind(recs[4].hash.as_slice())
    .bind([7u8; 64].as_slice())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let mut o = PgConnection::connect_with(&f.pg.owner()).await.unwrap();
    for (ok, finished, broken) in [
        (false, "2026-01-01T00:00:00Z", Some(3i64)),
        (true, "2026-01-02T00:00:00Z", None),
    ] {
        let mut tx = o.begin().await.unwrap();
        ls_audit::pg::bind_org(&mut tx, a).await.unwrap();
        sqlx_core::query::query(
            "INSERT INTO audit_verify_runs (org_id, mode, started_at, finished_at, ok, events, \
             checkpoints, broken_seq, break_kind) \
             VALUES ($1, 'db', $2::timestamptz, $2::timestamptz, $3, 5, 1, $4, \
             CASE WHEN $4::bigint IS NULL THEN NULL ELSE 'hash' END)",
        )
        .bind(a)
        .bind(finished)
        .bind(ok)
        .bind(broken)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let r = dev(&f.app, "GET", "/v1/audit/status", a, None).await;
    assert_eq!(r.body["head_seq"], 5);
    assert_eq!(r.body["latest_checkpoint"]["seq"], 5);
    assert_eq!(
        r.body["latest_checkpoint"]["digest"],
        hex::encode(recs[4].hash)
    );
    assert_eq!(r.body["latest_checkpoint"]["key_id"], "audit-checkpoint:1");
    assert!(r.body["latest_checkpoint"].get("signature").is_none());
    let v = &r.body["latest_verify"];
    assert_eq!(
        (v["ok"].clone(), v["mode"].clone()),
        (json!(true), json!("db"))
    );
    assert_eq!(
        (v["events"].clone(), v["checkpoints"].clone()),
        (json!(5), json!(1))
    );
    assert_eq!(v["finished_at"], "2026-01-02T00:00:00Z");
    assert!(v.get("broken_seq").is_none());
    let r = dev(&f.app, "GET", "/v1/audit/status", b, None).await;
    assert_eq!(r.body, json!({"head_seq": 1}));
}

/// m1-remote-mcp task 4.2 (gateway half): the gateway records an agent as an MCP client on
/// `initialize`, the console lists and revokes it, and the gateway reads the revoked set. All of
/// it per org, service token only.
#[tokio::test]
async fn gateway_records_agent_mcp_clients_and_reads_the_revoked_ones() {
    let f = Fixture::start().await;
    let (a, b) = (f.org("rev-a").await, f.org("rev-b").await);
    let auth = bearer(TOKEN);
    let agent_of = |org: Uuid, name: &'static str| {
        let app = f.app.clone();
        async move {
            let r = dev(&app, "POST", "/v1/agents", org, Some(json!({"name": name}))).await;
            assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
            r.body["agent"]["id"]
                .as_str()
                .unwrap()
                .parse::<Uuid>()
                .unwrap()
        }
    };
    let (one, two, theirs) = (
        agent_of(a, "one").await,
        agent_of(a, "two").await,
        agent_of(b, "theirs").await,
    );
    let upsert = |org: Option<Uuid>, auth: Option<&str>, body: Value| {
        let mut r = Request::builder()
            .method("POST")
            .uri("/internal/v1/mcp/agent-clients")
            .header("content-type", "application/json");
        if let Some(a) = auth {
            r = r.header("authorization", a);
        }
        if let Some(o) = org {
            r = r.header("x-locksmith-org", o.to_string());
        }
        send(&f.app, r.body(Body::from(body.to_string())).unwrap())
    };
    let revoked = |org: Uuid| {
        send(
            &f.app,
            Request::builder()
                .method("GET")
                .uri("/internal/v1/mcp/revoked-agent-clients")
                .header("authorization", auth.clone())
                .header("x-locksmith-org", org.to_string())
                .body(Body::empty())
                .unwrap(),
        )
    };

    // Initialize records the agent (twice is one row); nothing is revoked yet.
    for _ in 0..2 {
        let r = upsert(
            Some(a),
            Some(&auth),
            json!({"agent_id": one, "client_name": "claude"}),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
        assert_eq!(r.body, json!({"revoked": false}));
    }
    upsert(
        Some(a),
        Some(&auth),
        json!({"agent_id": two, "client_name": "x"}),
    )
    .await;
    let r = dev(&f.app, "GET", "/v1/mcp/clients", a, None).await;
    let items = r.body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{}", r.raw);
    let row = items
        .iter()
        .find(|i| i["client_id"] == one.to_string())
        .unwrap();
    assert_eq!(row["layer"], "agent");
    assert_eq!(row["principal"], one.to_string());
    assert_eq!(row["client_name"], "claude");
    assert_eq!(revoked(a).await.body["items"], json!([]));

    // The console revokes agent one; only that agent is listed, and only in its org.
    let r = dev(
        &f.app,
        "POST",
        &format!("/v1/mcp/clients/{}/revoke", row["id"].as_str().unwrap()),
        a,
        Some(json!({})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(revoked(a).await.body["items"], json!([{"agent_id": one}]));
    assert_eq!(revoked(b).await.body["items"], json!([]));
    // A second initialize keeps it revoked and says so; the row is not recreated.
    let r = upsert(
        Some(a),
        Some(&auth),
        json!({"agent_id": one, "client_name": "again"}),
    )
    .await;
    assert_eq!(r.body, json!({"revoked": true}));
    let r = dev(&f.app, "GET", "/v1/mcp/clients", a, None).await;
    assert_eq!(r.body["items"].as_array().unwrap().len(), 2);

    // Another org's agent is a 404 (like one that does not exist); no token, a wrong token and
    // unknown fields are refused.
    assert_eq!(
        upsert(
            Some(a),
            Some(&auth),
            json!({"agent_id": theirs, "client_name": "x"})
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        upsert(
            Some(a),
            Some(&auth),
            json!({"agent_id": Uuid::now_v7(), "client_name": "x"})
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        upsert(Some(a), None, json!({"agent_id": one, "client_name": "x"}))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        upsert(
            Some(a),
            Some(&bearer(WRONG)),
            json!({"agent_id": one, "client_name": "x"})
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        upsert(
            Some(a),
            Some(&auth),
            json!({"agent_id": one, "client_name": "x", "token": "t"})
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    let no_token = send(
        &f.app,
        Request::builder()
            .method("GET")
            .uri("/internal/v1/mcp/revoked-agent-clients")
            .header("x-locksmith-org", a.to_string())
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(no_token.status, StatusCode::UNAUTHORIZED);
}

const HUMAN_EVENTS: &str = "/internal/v1/audit/human-events";

/// `POST /internal/v1/audit/human-events` with optional `Authorization` and `X-Locksmith-Org`.
async fn post_human(app: &Router, auth: Option<&str>, org: Option<Uuid>, body: &Value) -> Reply {
    let mut b = Request::builder()
        .method("POST")
        .uri(HUMAN_EVENTS)
        .header("content-type", "application/json");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    if let Some(o) = org {
        b = b.header("x-locksmith-org", o.to_string());
    }
    send(app, b.body(Body::from(body.to_string())).unwrap()).await
}

fn human(kind: &str, user: Uuid) -> Value {
    json!({ "kind": kind, "user_id": user, "issuer": "idp.example.com" })
}

/// B8 1.2: no token, a wrong token and an agent token are `401` before any database access.
#[tokio::test]
async fn human_events_need_the_service_token() {
    let app = app::build(state(common::unreachable_db(), Some(TOKEN)));
    let org = Some(Uuid::now_v7());
    let body = human("auth.sign_in", Uuid::now_v7());
    // An agent token is a JWT, not the service token.
    let agent = "Bearer eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZ2VudCJ9.c2ln";
    for auth in [None, Some(bearer(WRONG)), Some(agent.to_owned())] {
        let r = post_human(&app, auth.as_deref(), org, &body).await;
        assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    }
    let r = post_human(&app, Some(&bearer(TOKEN)), None, &body).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
}

/// B8 1.2: unknown fields and kinds, and an issuer that is not a bare host, are `400` before
/// any database access, and the problem never echoes the value.
#[tokio::test]
async fn human_events_outside_the_allow_list_are_400() {
    let app = app::build(state(common::unreachable_db(), Some(TOKEN)));
    let auth = bearer(TOKEN);
    let org = Some(Uuid::now_v7());
    let user = Uuid::now_v7();
    let with = |k: &str, v: Value| {
        let mut b = human("auth.sign_in", user);
        b[k] = v;
        b
    };
    for bad in [
        with("email", json!(CANARY)),
        with("subject", json!(CANARY)),
        with("kind", json!(CANARY)),
        with("kind", json!("auth.verify_failed")),
        with("kind", json!("relay.attempt")),
        with("user_id", json!(CANARY)),
        with("issuer", json!("idp.example.com:8443")),
        with("issuer", json!("idp.example.com/realms/x")),
        with("issuer", json!(format!("idp.example.com?t={CANARY}"))),
        with("issuer", json!(format!("{CANARY}@idp.example.com"))),
        with("issuer", json!("https://idp.example.com")),
        with("issuer", json!("{{issuer}}")),
        with("issuer", json!("<issuer>")),
        with("issuer", json!("")),
        with("issuer", json!(CANARY)),
        json!({"kind": "auth.sign_in", "user_id": user}),
        json!({"kind": "auth.sign_in", "issuer": "idp.example.com"}),
    ] {
        let r = post_human(&app, Some(&auth), org, &bad).await;
        assert_problem(&r, StatusCode::BAD_REQUEST, "validation");
        assert!(!r.raw.contains(CANARY), "{}", r.raw);
    }
}

/// B8 1.2: each kind appends in the named org's chain with the user as actor and the issuer
/// host only; the chain verifies, and the other org sees nothing.
#[tokio::test]
async fn human_events_append_per_kind_in_the_named_org_only() {
    let f = Fixture::start().await;
    let (a, b) = (f.org("a").await, f.org("b").await);
    let auth = bearer(TOKEN);
    let user = Uuid::now_v7();
    let mut last = 0;
    for kind in ["auth.sign_in", "auth.sign_out", "org.personal_created"] {
        let r = post_human(&f.app, Some(&auth), Some(a), &human(kind, user)).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
        let seq = r.body["seq"].as_u64().unwrap();
        assert!(seq > last, "seq advances: {seq} after {last}");
        last = seq;
    }
    let rows = f.records(a).await;
    let human_rows: Vec<_> = rows
        .iter()
        .filter(|r| r.actor == format!("user:{user}"))
        .collect();
    assert_eq!(human_rows.len(), 3);
    for (row, kind) in
        human_rows
            .iter()
            .zip(["auth.sign_in", "auth.sign_out", "org.personal_created"])
    {
        assert_eq!(row.kind, kind);
        assert_eq!(row.outcome, "ok");
        assert_eq!(row.target.as_deref(), Some(format!("org:{a}").as_str()));
        let attrs = row.attrs.as_ref().unwrap().to_json();
        assert_eq!(attrs, json!({ "issuer": { "host": "idp.example.com" } }));
    }
    assert_intact(&rows);
    assert!(
        f.records(b)
            .await
            .iter()
            .all(|r| r.actor != format!("user:{user}")),
        "the event lands only in the org named by the header"
    );
}
