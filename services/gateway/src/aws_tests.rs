//! D2 task 3.4: `POST /v1/aws/credentials`.
//!
//! The success path runs against Floci (`docker compose -f infra/compose/compose.yaml up -d --wait
//! floci`, 127.0.0.1:4566 or `FLOCI_URL`) and skips when Floci is unreachable, unless
//! `E2E_REQUIRE_FLOCI=1`. The compose Floci runs without IAM enforcement, so the policy sent to STS
//! is asserted from a captured request (design.md decision 6).
//! The refusals and the STS failure modes need no STS at all, or a wiremock STS that must not be
//! called (or returns a crafted answer), so they always run.
//!
//! All credentials here are fakes; none is printed.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use ls_control_plane::agent_token::{AUDIENCE, AgentClaims, AgentTokenSigner};
use ls_control_plane::readiness::ReadyFlag;
use ls_proxy::aws::sigv4::{self, Scope};
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::app::{self, AppState};
use crate::audit::MemoryAudit;
use crate::auth::testkit::StubJwks;
use crate::auth::{AgentAuth, JwksSettings};
use crate::aws_policy::AwsGrantScope;
use crate::config::Bindings;
use crate::decrypt::testkit::{FakeKms, FakeMaterial, seal};
use crate::decrypt::{CacheSettings, Decryptor, DekCache};
use crate::egress::testkit::StubResolver;
use crate::grants::testkit::StubGrants;
use crate::relay::RelayOptions;

const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_000000000001);
const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a1);
/// The vending binding's base-credential secret (the one sealed secret).
const VEND: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000c1);
/// A binding without `vend`.
const NO_VEND: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000c2);
/// Floci's fixed account id.
const ACCOUNT: &str = "000000000000";
const REGION: &str = "us-east-1";
/// Fake base key (Floci accepts any key unless IAM enforcement is on). Never in any output.
const BASE_KEY_ID: &str = "AKIALOCKSMITHGW00001";
const BASE_SECRET: &str = "locksmith-gw-fake-base-secret-not-real-7Qx";

fn base_json() -> Vec<u8> {
    json!({"access_key_id": BASE_KEY_ID, "secret_access_key": BASE_SECRET})
        .to_string()
        .into_bytes()
}

fn binding(secret_id: Uuid, role: &str, vend: bool) -> AwsBinding {
    AwsBinding {
        secret_id,
        role_arn: format!("arn:aws:iam::{ACCOUNT}:role/{role}"),
        region: REGION.to_owned(),
        external_id: Some("ext-gw-1".to_owned()),
        vend,
        unrestricted: false,
        max_duration_secs: 1800,
        version: 1,
    }
}

fn scope(actions: &[&str], resources: &[&str]) -> AwsGrantScope {
    AwsGrantScope {
        actions: actions.iter().map(|s| (*s).to_owned()).collect(),
        resources: resources.iter().map(|s| (*s).to_owned()).collect(),
        max_duration_secs: None,
    }
}

fn s3_scope() -> AwsGrantScope {
    scope(&["s3:GetObject"], &["arn:aws:s3:::ls-bucket/*"])
}

fn grant(secret_id: Uuid, mode: &str, scope: Option<AwsGrantScope>) -> Grant {
    Grant {
        grant_id: Uuid::now_v7(),
        secret_id,
        secret_name: "AWS_BASE".to_owned(),
        mode: mode.to_owned(),
        scope,
        expires_at: None,
        budget: None,
        agent_budget: None,
    }
}

struct Harness {
    app: Router,
    token: String,
    audit: Arc<MemoryAudit>,
    material: Arc<FakeMaterial>,
}

impl Harness {
    fn start(
        bindings: Vec<AwsBinding>,
        grants: Vec<Grant>,
        sts: Option<String>,
        audit: MemoryAudit,
    ) -> Self {
        let sealed = seal(ORG, VEND, 1, &base_json());
        let kms = Arc::new(FakeKms {
            dek: Some(sealed.dek),
            calls: AtomicUsize::new(0),
        });
        let material = Arc::new(FakeMaterial {
            sealed,
            secret: VEND,
            version: 1,
            fetches: AtomicUsize::new(0),
        });
        let decryptor = Decryptor::new(
            ORG,
            material.clone(),
            kms,
            Arc::new(DekCache::new(CacheSettings::default())),
        );
        let signer = AgentTokenSigner::from_seed(Zeroizing::new([9u8; 32])).unwrap();
        let auth = Arc::new(AgentAuth::new(
            ORG,
            Arc::new(StubJwks::with(vec![signer.jwk().clone()])),
            JwksSettings::default(),
        ));
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let token = signer
            .sign(&AgentClaims {
                sub: AGENT,
                org: ORG,
                aud: AUDIENCE.to_owned(),
                iat: now,
                exp: now + 600,
            })
            .unwrap();
        let stub = Arc::new(StubGrants::default());
        stub.set(AGENT, grants);
        let audit = Arc::new(audit);
        let relay = Relay::new(
            auth,
            stub,
            Bindings {
                org_id: ORG,
                bindings: Vec::new(),
                aws_bindings: bindings,
                pg: Vec::new(),
                git_bindings: Vec::new(),
                mcp_upstreams: Vec::new(),
            },
            decryptor,
            Arc::new(StubResolver::default()),
            audit.clone(),
            RelayOptions {
                outcome_retry_backoff: Duration::from_millis(1),
                ..RelayOptions::default()
            },
        )
        .with_aws(AwsOptions { sts_endpoint: sts });
        let app =
            app::build(AppState::new(Arc::new(ReadyFlag::new(true))).with_relay(Arc::new(relay)));
        Self {
            app,
            token,
            audit,
            material,
        }
    }

    /// `(status, raw body)`.
    async fn post(&self, body: Value) -> (StatusCode, String) {
        self.post_with(Some(&self.token), body).await
    }

    async fn post_with(&self, token: Option<&str>, body: Value) -> (StatusCode, String) {
        let mut req =
            Request::post("/v1/aws/credentials").header("content-type", "application/json");
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let resp = self
            .app
            .clone()
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    fn fetches(&self) -> usize {
        self.material.fetches.load(Ordering::SeqCst)
    }
}

fn slug(body: &str) -> String {
    serde_json::from_str::<Value>(body).unwrap()["error"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn assert_no_base(text: &str) {
    assert!(!text.contains(BASE_KEY_ID), "base key id leaked");
    assert!(!text.contains(BASE_SECRET), "base secret leaked");
}

/// A wiremock STS. `reply` answers every POST; requests are recorded.
async fn mock_sts(reply: ResponseTemplate) -> MockServer {
    let sts = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(reply)
        .mount(&sts)
        .await;
    sts
}

async fn sts_calls(sts: &MockServer) -> usize {
    sts.received_requests().await.unwrap().len()
}

const MOCK_KEY: &str = "ASIAMOCKSTS000000001";
const MOCK_SECRET: &str = "mock-temporary-secret-0123456789abcdef";
const MOCK_TOKEN: &str = "mock-session-token-0123456789abcdefghij";

fn sts_ok(secret: &str) -> ResponseTemplate {
    let exp = (OffsetDateTime::now_utc() + time::Duration::seconds(900))
        .replace_nanosecond(0)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    ResponseTemplate::new(200).set_body_string(format!(
        "<AssumeRoleResponse><AssumeRoleResult><Credentials>\
         <AccessKeyId>{MOCK_KEY}</AccessKeyId><SecretAccessKey>{secret}</SecretAccessKey>\
         <SessionToken>{MOCK_TOKEN}</SessionToken><Expiration>{exp}</Expiration>\
         </Credentials></AssumeRoleResult></AssumeRoleResponse>"
    ))
}

/// The form parameters of the one STS request the mock received.
async fn sts_form(sts: &MockServer) -> std::collections::HashMap<String, String> {
    let reqs = sts.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "one STS call");
    url::form_urlencoded::parse(&reqs[0].body)
        .into_owned()
        .collect()
}

#[tokio::test]
async fn aws_unauthenticated_is_401() {
    let h = Harness::start(
        vec![binding(VEND, "r", true)],
        vec![grant(VEND, "delegate", Some(s3_scope()))],
        None,
        MemoryAudit::default(),
    );
    let (status, body) = h.post_with(None, json!({})).await;
    assert_eq!(
        (status, slug(&body).as_str()),
        (StatusCode::UNAUTHORIZED, "unauthenticated")
    );
    assert_eq!(h.fetches(), 0);
}

#[tokio::test]
async fn aws_unbound_is_403_before_decrypt() {
    let sts = mock_sts(sts_ok(MOCK_SECRET)).await;
    let h = Harness::start(
        vec![binding(VEND, "r", true)],
        vec![grant(VEND, "delegate", Some(s3_scope()))],
        Some(format!("{}/", sts.uri())),
        MemoryAudit::default(),
    );
    for req in [
        json!({"secret_id": Uuid::now_v7()}),
        json!({"role_arn": format!("arn:aws:iam::{ACCOUNT}:role/other")}),
    ] {
        let (status, body) = h.post(req).await;
        assert_eq!(
            (status, slug(&body).as_str()),
            (StatusCode::FORBIDDEN, "not_bound")
        );
    }
    // No AWS binding at all.
    let none = Harness::start(Vec::new(), Vec::new(), None, MemoryAudit::default());
    let (status, body) = none.post(json!({})).await;
    assert_eq!(
        (status, slug(&body).as_str()),
        (StatusCode::FORBIDDEN, "not_bound")
    );
    assert_eq!(h.fetches() + none.fetches(), 0, "no decrypt");
    assert_eq!(sts_calls(&sts).await, 0, "no STS call");
}

#[tokio::test]
async fn aws_binding_without_vend_is_403() {
    let sts = mock_sts(sts_ok(MOCK_SECRET)).await;
    let h = Harness::start(
        vec![binding(VEND, "r", true), binding(NO_VEND, "nv", false)],
        vec![grant(NO_VEND, "delegate", Some(s3_scope()))],
        Some(format!("{}/", sts.uri())),
        MemoryAudit::default(),
    );
    let (status, body) = h.post(json!({"secret_id": NO_VEND})).await;
    assert_eq!(
        (status, slug(&body).as_str()),
        (StatusCode::FORBIDDEN, "vend_disabled")
    );
    assert_eq!(h.fetches(), 0, "no decrypt");
    assert_eq!(sts_calls(&sts).await, 0, "no STS call");
    let ev = h.audit.aws_events();
    assert_eq!(ev.len(), 1);
    assert_eq!(
        (ev[0].kind, ev[0].secret_id, ev[0].region.as_str()),
        (AwsEventKind::Denied(Outcome::Denied), NO_VEND, REGION)
    );
}

#[tokio::test]
async fn aws_relay_only_grant_is_403() {
    let sts = mock_sts(sts_ok(MOCK_SECRET)).await;
    let h = Harness::start(
        vec![binding(VEND, "r", true)],
        vec![grant(VEND, "relay", None)],
        Some(format!("{}/", sts.uri())),
        MemoryAudit::default(),
    );
    let (status, body) = h.post(json!({"secret_id": VEND})).await;
    assert_eq!(
        (status, slug(&body).as_str()),
        (StatusCode::FORBIDDEN, "no_grant")
    );
    // Selected without naming it too (the only binding).
    let (status, _) = h.post(json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(h.fetches(), 0, "no decrypt");
    assert_eq!(sts_calls(&sts).await, 0, "no STS call");
    let kinds: Vec<_> = h.audit.aws_events().iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![AwsEventKind::Denied(Outcome::NoGrant); 2]);
}

#[tokio::test]
async fn aws_empty_or_broad_grant_is_403() {
    let sts = mock_sts(sts_ok(MOCK_SECRET)).await;
    for (scope, want) in [
        (None, "empty_grant"),
        (Some(scope(&[], &["arn:aws:s3:::b"])), "empty_grant"),
        (Some(scope(&["s3:GetObject"], &[])), "empty_grant"),
        (Some(scope(&["*"], &["*"])), "grant_too_broad"),
    ] {
        let h = Harness::start(
            vec![binding(VEND, "r", true)],
            vec![grant(VEND, "delegate", scope)],
            Some(format!("{}/", sts.uri())),
            MemoryAudit::default(),
        );
        let (status, body) = h.post(json!({"secret_id": VEND})).await;
        assert_eq!(
            (status, slug(&body).as_str()),
            (StatusCode::FORBIDDEN, want)
        );
        assert_eq!(h.fetches(), 0, "no decrypt");
        let ev = h.audit.aws_events();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, AwsEventKind::Denied(Outcome::Denied));
    }
    assert_eq!(sts_calls(&sts).await, 0, "no STS call");
}

#[tokio::test]
async fn aws_duration_floor_is_400_and_cap_is_clamped() {
    let sts = mock_sts(sts_ok(MOCK_SECRET)).await;
    let h = Harness::start(
        vec![binding(VEND, "r", true)],
        vec![grant(VEND, "delegate", Some(s3_scope()))],
        Some(format!("{}/", sts.uri())),
        MemoryAudit::default(),
    );
    let (status, body) = h.post(json!({"duration_secs": 600})).await;
    assert_eq!(
        (status, slug(&body).as_str()),
        (StatusCode::BAD_REQUEST, "duration_too_short")
    );
    assert_eq!(h.fetches(), 0);
    // Over the cap: clamped to the binding's 1800; an agent-supplied policy is ignored.
    let (status, body) = h
        .post(json!({
            "duration_secs": 7200,
            "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
        }))
        .await;
    assert_eq!(status, StatusCode::OK, "{}", slug(&body));
    let form = sts_form(&sts).await;
    assert_eq!(
        form.get("DurationSeconds").map(String::as_str),
        Some("1800")
    );
    let want = render_session_policy(&binding(VEND, "r", true), &s3_scope()).unwrap();
    assert_eq!(
        form.get("Policy"),
        Some(&want),
        "policy rendered from the grant only"
    );
    assert_eq!(form.get("ExternalId").map(String::as_str), Some("ext-gw-1"));
    assert_eq!(
        form.get("RoleSessionName").map(String::as_str),
        Some(format!("locksmith-{}", AGENT.simple()).as_str())
    );
    let ev = h.audit.aws_events();
    assert_eq!(ev.len(), 1);
    assert_eq!(
        (ev[0].kind, ev[0].duration_secs),
        (AwsEventKind::Issued, Some(1800))
    );
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["Version"], 1);
    assert_eq!(v["AccessKeyId"], MOCK_KEY);
    assert_no_base(&body);
}

#[tokio::test]
async fn aws_sts_error_is_a_fixed_slug() {
    // STS answers with an error that echoes request details and the base key id.
    let reply = ResponseTemplate::new(403).set_body_string(format!(
        "<ErrorResponse><Error><Code>AccessDenied</Code><Message>User {BASE_KEY_ID} \
         is not authorized; request RoleSessionName=x Policy=y</Message></Error></ErrorResponse>"
    ));
    let sts = mock_sts(reply).await;
    let h = Harness::start(
        vec![binding(VEND, "r", true)],
        vec![grant(VEND, "delegate", Some(s3_scope()))],
        Some(format!("{}/", sts.uri())),
        MemoryAudit::default(),
    );
    let (status, body) = h.post(json!({})).await;
    assert_eq!(
        (status, slug(&body).as_str()),
        (StatusCode::BAD_GATEWAY, "sts_error")
    );
    assert!(!body.contains("AccessDenied") && !body.contains("authorized"));
    assert_no_base(&body);
    let ev = h.audit.aws_events();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].kind, AwsEventKind::Denied(Outcome::UpstreamError));
    assert_no_base(&format!("{ev:?}"));

    // Unreachable STS: its own fixed slug.
    let h = Harness::start(
        vec![binding(VEND, "r", true)],
        vec![grant(VEND, "delegate", Some(s3_scope()))],
        Some("http://127.0.0.1:9/".to_owned()),
        MemoryAudit::default(),
    );
    let (status, body) = h.post(json!({})).await;
    assert_eq!(
        (status, slug(&body).as_str()),
        (StatusCode::BAD_GATEWAY, "sts_unreachable")
    );
}

#[tokio::test]
async fn aws_response_carrying_the_base_credential_is_withheld() {
    let sts = mock_sts(sts_ok(BASE_SECRET)).await;
    let h = Harness::start(
        vec![binding(VEND, "r", true)],
        vec![grant(VEND, "delegate", Some(s3_scope()))],
        Some(format!("{}/", sts.uri())),
        MemoryAudit::default(),
    );
    let (status, body) = h.post(json!({})).await;
    assert_eq!(
        (status, slug(&body).as_str()),
        (StatusCode::BAD_GATEWAY, "redaction_failed")
    );
    assert_no_base(&body);
    assert_eq!(
        h.audit.aws_events()[0].kind,
        AwsEventKind::Denied(Outcome::RedactionFailed)
    );
}

#[tokio::test]
async fn aws_ledger_failure_withholds_credentials() {
    let sts = mock_sts(sts_ok(MOCK_SECRET)).await;
    let h = Harness::start(
        vec![binding(VEND, "r", true)],
        vec![grant(VEND, "delegate", Some(s3_scope()))],
        Some(format!("{}/", sts.uri())),
        MemoryAudit {
            fail: true,
            ..MemoryAudit::default()
        },
    );
    let (status, body) = h.post(json!({})).await;
    assert_eq!(
        (status, slug(&body).as_str()),
        (StatusCode::INTERNAL_SERVER_ERROR, "audit_failed")
    );
    assert!(!body.contains(MOCK_SECRET) && !body.contains(MOCK_TOKEN));
    assert!(h.audit.tries() >= 2, "issued event retried");
}

#[test]
fn aws_base_credential_parse_and_leak_check() {
    assert!(parse_base(b"not json").is_none());
    assert!(parse_base(br#"{"access_key_id":"","secret_access_key":"x"}"#).is_none());
    let base = parse_base(&base_json()).unwrap();
    assert!(leaks_base(format!("x{BASE_SECRET}y").as_bytes(), &base));
    assert!(leaks_base(BASE_KEY_ID.as_bytes(), &base));
    assert!(!leaks_base(b"{\"AccessKeyId\":\"ASIA\"}", &base));
}

// ---- Floci ----

fn floci_url() -> String {
    std::env::var("FLOCI_URL").unwrap_or_else(|_| "http://127.0.0.1:4566".into())
}

fn http() -> reqwest::Client {
    crate::http_client::build(Duration::from_secs(5), Duration::from_secs(10), None).unwrap()
}

/// Floci's base URL when it answers; `None` skips (a failure with `E2E_REQUIRE_FLOCI=1`).
async fn floci_or_skip(test: &str) -> Option<String> {
    let base = floci_url();
    let up = http()
        .get(format!("{base}/_floci/health"))
        .send()
        .await
        .is_ok_and(|r| r.status().is_success());
    if up {
        return Some(base);
    }
    assert!(
        std::env::var("E2E_REQUIRE_FLOCI").is_err(),
        "{test}: Floci is not reachable at {base} and E2E_REQUIRE_FLOCI is set"
    );
    eprintln!("{test}: skipped, Floci is not reachable at {base}");
    None
}

fn form_enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// A SigV4-signed AWS query-protocol POST; returns (status, body). Never print a body that
/// carries credentials.
async fn aws_query(
    base: &str,
    creds: &Credentials,
    service: &str,
    params: &[(&str, &str)],
) -> (u16, String) {
    let body = params
        .iter()
        .map(|(k, v)| format!("{}={}", form_enc(k), form_enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    let host = base.split_once("://").map_or(base, |(_, h)| h).to_owned();
    let ct = "application/x-www-form-urlencoded; charset=utf-8";
    let req = sigv4::Request {
        method: "POST".into(),
        path: "/".into(),
        query: String::new(),
        headers: vec![("host".into(), host), ("content-type".into(), ct.into())],
        payload_hash: sigv4::hex_sha256(body.as_bytes()),
    };
    let amz_date = sigv4::amz_date(SystemTime::now());
    let scope = Scope {
        date: amz_date[..8].to_string(),
        region: REGION.into(),
        service: service.into(),
    };
    let signed = sigv4::sign(&req, creds, &scope, &amz_date, &[]);
    let mut rb = http().post(format!("{base}/")).header("content-type", ct);
    for (k, v) in &signed.headers {
        rb = rb.header(*k, v.as_str());
    }
    let resp = rb.body(body).send().await.unwrap();
    (resp.status().as_u16(), resp.text().await.unwrap())
}

/// `sts:GetCallerIdentity` with the issued credentials; returns the caller ARN.
async fn caller_arn(base: &str, creds: &Credentials) -> String {
    let (status, text) = aws_query(
        base,
        creds,
        "sts",
        &[("Action", "GetCallerIdentity"), ("Version", "2011-06-15")],
    )
    .await;
    assert_eq!(status, 200, "GetCallerIdentity");
    let start = text.find("<Arn>").expect("Arn") + 5;
    let end = text[start..].find("</Arn>").unwrap() + start;
    text[start..end].to_owned()
}

/// Floci refuses AssumeRole on a role it does not know, so the test creates it first.
async fn floci_create_role(base: &str, role: &str) {
    let base_creds = Credentials {
        access_key_id: BASE_KEY_ID.into(),
        secret_access_key: Zeroizing::new(BASE_SECRET.into()),
        session_token: None,
    };
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}"#;
    let (status, _) = aws_query(
        base,
        &base_creds,
        "iam",
        &[
            ("Action", "CreateRole"),
            ("Version", "2010-05-08"),
            ("RoleName", role),
            ("AssumeRolePolicyDocument", trust),
        ],
    )
    .await;
    assert_eq!(status, 200, "CreateRole on Floci");
}

#[tokio::test(flavor = "multi_thread")]
async fn aws_floci_issues_scoped_credentials() {
    let Some(floci) = floci_or_skip("aws_floci_issues_scoped_credentials").await else {
        return;
    };
    let role = format!(
        "ls-gw-{}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    floci_create_role(&floci, &role).await;
    let b = binding(VEND, &role, true);
    let mut sc = s3_scope();
    sc.max_duration_secs = Some(1200);
    let h = Harness::start(
        vec![b.clone(), binding(NO_VEND, "nv", false)],
        vec![grant(VEND, "delegate", Some(sc.clone()))],
        Some(format!("{floci}/")),
        MemoryAudit::default(),
    );
    let (status, body) = h
        .post(json!({
            "secret_id": VEND,
            "duration_secs": 3600,
            "policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
        }))
        .await;
    assert_eq!(status, StatusCode::OK, "{}", slug(&body));
    assert_no_base(&body);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["Version"], 1);
    let key = v["AccessKeyId"].as_str().unwrap().to_owned();
    assert!(key.starts_with("ASIA"), "temporary key id");
    let exp = OffsetDateTime::parse(
        v["Expiration"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let left = (exp - OffsetDateTime::now_utc()).whole_seconds();
    assert!(
        (1100..=1260).contains(&left),
        "clamped to the grant's 1200 s: {left}"
    );

    // The exact session policy sent to STS is asserted from the captured request in
    // `aws_duration_floor_is_400_and_cap_is_clamped` (no Floci endpoint exposing it was found), and
    // Floci's enforcement of a session policy in `tests/e2e/tests/aws_sts_floci.rs`.

    // The credentials work as the assumed role.
    let creds = Credentials {
        access_key_id: key,
        secret_access_key: Zeroizing::new(v["SecretAccessKey"].as_str().unwrap().to_owned()),
        session_token: Some(Zeroizing::new(
            v["SessionToken"].as_str().unwrap().to_owned(),
        )),
    };
    assert_eq!(
        caller_arn(&floci, &creds).await,
        format!(
            "arn:aws:sts::{ACCOUNT}:assumed-role/{role}/locksmith-{}",
            AGENT.simple()
        )
    );

    let ev = h.audit.aws_events();
    assert_eq!(ev.len(), 1);
    assert_eq!(
        (
            ev[0].kind,
            ev[0].secret_id,
            ev[0].region.as_str(),
            ev[0].duration_secs
        ),
        (AwsEventKind::Issued, VEND, REGION, Some(1200))
    );
    assert_eq!(h.fetches(), 1, "one decrypt");
}
