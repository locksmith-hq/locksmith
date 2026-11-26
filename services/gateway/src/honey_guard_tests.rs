//! t5-honey-tokens group 3: honey tokens caught by reference on every gateway path (task 3.1, one
//! table row per path) and by value in the relay (tasks 3.2 and 3.3), with in-memory fakes: the
//! material source marks honey secrets, the KMS counts unwraps, the ledger is `MemoryAudit`, and
//! the upstreams are wiremock servers that must not be reached.
//!
//! The Postgres-backed check of the same events through the real control plane is in
//! `honey_tests.rs`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use ls_control_plane::agent_token::{AUDIENCE, AgentClaims, AgentTokenSigner};
use ls_control_plane::readiness::ReadyFlag;
use ls_envelope::SecretBytes;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};
use zeroize::Zeroizing;

use super::*;
use crate::app::{self, AppState};
use crate::audit::{HoneyEvent, HoneyPath, MemoryAudit};
use crate::auth::testkit::StubJwks;
use crate::auth::{AgentAuth, AgentIdentity, JwksSettings};
use crate::aws_policy::{AwsBinding, AwsGrantScope};
use crate::config::{Binding, Bindings, McpUpstream, PgBinding, PgTls};
use crate::decrypt::testkit::{FakeKmsMany, FakeVault, seal};
use crate::decrypt::{CacheSettings, Decryptor, DekCache};
use crate::egress::testkit::StubResolver;
use crate::git::{GitBinding, GitService};
use crate::grants::Grant;
use crate::grants::testkit::StubGrants;
use crate::mcp_upstream::hop::{self, Forward, HopDeps, HopError};
use crate::pg::listener::{PgListener, PgListenerOptions, tls_acceptor};
use crate::pg::{ClientIo, PgSession, PgUpstream};
use crate::relay::{Relay, RelayOptions};

const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_000000000001);
const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a1);
/// One honey token per path kind (a secret has one binding of each kind at most).
const HTTP_HONEY: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000d1);
const GIT_HONEY: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000d2);
const AWS_HONEY: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000d3);
const PG_HONEY: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000d4);
const MCP_HONEY: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000d5);
/// A disabled honey token: still refused by reference, ignored by the value scan.
const DISABLED: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000d6);
/// A standard secret bound to the mock upstream.
const STANDARD_SECRET: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000e1);

const HONEY: [Uuid; 6] = [
    HTTP_HONEY, GIT_HONEY, AWS_HONEY, PG_HONEY, MCP_HONEY, DISABLED,
];

/// The decoy of honey token `id` (an AWS access key id shape), built at runtime so no secret
/// scanner flags the source.
fn decoy(id: Uuid) -> Vec<u8> {
    let n = id.as_u128() & 0xff;
    format!("{}{}{n:03}", "AKIA", "QTRIPWIRE7Z9X").into_bytes()
}

const STANDARD_VALUE: &[u8] = b"standard-relay-value-5Kq2";

/// Every form of every value the gateway holds: none may reach a log, an event or an answer.
fn forbidden_forms() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for v in HONEY
        .iter()
        .map(|id| decoy(*id))
        .chain([STANDARD_VALUE.to_vec()])
    {
        out.push(STANDARD.encode(&v).into_bytes());
        out.push(URL_SAFE_NO_PAD.encode(&v).into_bytes());
        out.push(v);
    }
    out
}

fn assert_clean(what: &str, bytes: &[u8]) {
    for f in forbidden_forms() {
        assert!(
            !bytes.windows(f.len()).any(|w| w == f.as_slice()),
            "{what} holds a secret value"
        );
    }
}

/// The control plane's scan list, as a fake: (token, disabled, version); counts reads.
#[derive(Default)]
struct StaticList {
    items: Mutex<Vec<HoneyListItem>>,
    reads: AtomicUsize,
    fail: std::sync::atomic::AtomicBool,
}

impl StaticList {
    fn with(items: &[(Uuid, bool)]) -> Self {
        let s = Self::default();
        s.set(items);
        s
    }

    fn set(&self, items: &[(Uuid, bool)]) {
        *self.items.lock().unwrap() = items
            .iter()
            .map(|(id, disabled)| HoneyListItem {
                secret_id: *id,
                disabled: *disabled,
                version: Some(1),
            })
            .collect();
    }
}

impl HoneyListSource for StaticList {
    fn honey_tokens(&self) -> BoxFuture<'_, Result<Vec<HoneyListItem>, ScanError>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let out = if self.fail.load(Ordering::SeqCst) {
            Err(ScanError::ListUnavailable)
        } else {
            Ok(self.items.lock().unwrap().clone())
        };
        Box::pin(async move { out })
    }
}

/// A Postgres upstream that must never be reached.
#[derive(Default)]
struct NoUpstream(AtomicUsize);

impl PgUpstream for NoUpstream {
    fn serve(&self, _s: PgSession, _c: Box<dyn ClientIo>) -> BoxFuture<'_, ()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {})
    }
}

fn relay_grant(secret_id: Uuid) -> Grant {
    Grant {
        grant_id: Uuid::now_v7(),
        secret_id,
        secret_name: "K".to_owned(),
        mode: "relay".to_owned(),
        scope: None,
        expires_at: None,
    }
}

struct Harness {
    app: Router,
    relay: Arc<Relay>,
    audit: Arc<MemoryAudit>,
    kms: Arc<FakeKmsMany>,
    list: Arc<StaticList>,
    upstream: MockServer,
    token: String,
    grants: BTreeMap<Uuid, Uuid>,
}

impl Harness {
    /// A gateway with every kind of binding on a honey token, a standard secret bound to the mock
    /// upstream, grants for all of them, and the value scan over the active honey tokens.
    async fn start() -> Self {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&upstream)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&upstream)
            .await;
        let port = upstream.address().port();
        let origin = format!("http://127.0.0.1:{port}");

        let vault = Arc::new(FakeVault::default());
        let kms = Arc::new(FakeKmsMany::default());
        for (id, value, honey) in HONEY.iter().map(|id| (*id, decoy(*id), true)).chain([(
            STANDARD_SECRET,
            STANDARD_VALUE.to_vec(),
            false,
        )]) {
            let sealed = seal(ORG, id, 1, &value);
            kms.deks.lock().unwrap().push((id, 1, sealed.dek));
            vault.put(id, 1, honey, sealed);
        }
        let decryptor = Decryptor::new(
            ORG,
            vault,
            kms.clone(),
            Arc::new(DekCache::new(CacheSettings::default())),
        );
        let signer = AgentTokenSigner::from_seed(Zeroizing::new([9u8; 32])).unwrap();
        let auth = Arc::new(AgentAuth::new(
            ORG,
            Arc::new(StubJwks::with(vec![signer.jwk().clone()])),
            JwksSettings::default(),
        ));
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = signer
            .sign(&AgentClaims {
                sub: AGENT,
                org: ORG,
                aud: AUDIENCE.to_owned(),
                iat: now,
                exp: now + 600,
            })
            .unwrap();

        let mut grants = BTreeMap::new();
        let mut list = Vec::new();
        for id in [
            HTTP_HONEY,
            GIT_HONEY,
            PG_HONEY,
            MCP_HONEY,
            STANDARD_SECRET,
            DISABLED,
        ] {
            let g = relay_grant(id);
            grants.insert(id, g.grant_id);
            list.push(g);
        }
        let aws = Grant {
            mode: "delegate".to_owned(),
            scope: Some(AwsGrantScope {
                actions: vec!["s3:GetObject".to_owned()],
                resources: vec!["arn:aws:s3:::ls-bucket/*".to_owned()],
                max_duration_secs: None,
            }),
            ..relay_grant(AWS_HONEY)
        };
        grants.insert(AWS_HONEY, aws.grant_id);
        list.push(aws);
        let stub = Arc::new(StubGrants::default());
        stub.set(AGENT, list);

        let http = |secret_id| Binding {
            secret_id,
            origin: origin.clone(),
            header: "Authorization".to_owned(),
            template: "Bearer {secret}".to_owned(),
            allow_private_hosts: true,
        };
        let bindings = Bindings {
            org_id: ORG,
            bindings: vec![http(HTTP_HONEY), http(STANDARD_SECRET), http(DISABLED)],
            aws_bindings: vec![AwsBinding {
                secret_id: AWS_HONEY,
                role_arn: "arn:aws:iam::000000000000:role/decoy".to_owned(),
                region: "us-east-1".to_owned(),
                external_id: None,
                vend: true,
                unrestricted: false,
                max_duration_secs: 1800,
                version: 1,
            }],
            pg: vec![PgBinding {
                name: "app".to_owned(),
                secret_id: PG_HONEY,
                version: 1,
                host: "127.0.0.1".to_owned(),
                port,
                user: "app_rw".to_owned(),
                database: "app".to_owned(),
                tls: PgTls::Require,
                allow_private_hosts: true,
            }],
            git_bindings: vec![GitBinding {
                secret_id: GIT_HONEY,
                host: "127.0.0.1".to_owned(),
                repo_prefix: "acme".to_owned(),
                services: vec![GitService::Fetch],
                allow_private_hosts: true,
                version: 1,
                port: Some(port),
                plain_http: true,
            }],
            mcp_upstreams: vec![McpUpstream {
                name: "tracker".to_owned(),
                url: format!("{origin}/mcp"),
                secret_id: MCP_HONEY,
                header: "Authorization".to_owned(),
                template: "Bearer {secret}".to_owned(),
                default: ls_mcp_server::upstream::ToolDecision::Allow,
                allow_private_hosts: true,
                version: 1,
                tools: BTreeMap::new(),
            }],
        };
        let list = Arc::new(StaticList::with(&HONEY.map(|id| (id, id == DISABLED))));
        let audit = Arc::new(MemoryAudit::default());
        let relay = Arc::new(
            Relay::new(
                auth,
                stub,
                bindings,
                decryptor,
                Arc::new(StubResolver::default()),
                audit.clone(),
                RelayOptions {
                    outcome_retry_backoff: Duration::from_millis(1),
                    ..RelayOptions::default()
                },
            )
            .with_honey_scan(Arc::new(HoneyScan::new(list.clone()))),
        );
        let app =
            app::build(AppState::new(Arc::new(ReadyFlag::new(true))).with_relay(relay.clone()));
        Self {
            app,
            relay,
            audit,
            kms,
            list,
            upstream,
            token,
            grants,
        }
    }

    fn agent() -> AgentIdentity {
        AgentIdentity {
            agent_id: AGENT,
            org_id: ORG,
        }
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, Vec<u8>) {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec();
        (status, body)
    }

    /// `POST /v1/relay` with `bearer`.
    async fn relay_call(&self, bearer: &str, body: Value) -> (StatusCode, Vec<u8>) {
        self.send(
            Request::post("/v1/relay")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    /// A relay call to the mock upstream naming `secret` (`headers` and `body` as given).
    async fn relay_to(
        &self,
        secret: Uuid,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> (StatusCode, Vec<u8>) {
        let mut req = json!({
            "secret_id": secret,
            "version": 1,
            "method": if body.is_some() { "POST" } else { "GET" },
            "url": format!("http://127.0.0.1:{}{path}", self.upstream.address().port()),
            "headers": headers,
        });
        if let Some(b) = body {
            req["body"] = b.into();
        }
        self.relay_call(&self.token.clone(), req).await
    }

    async fn upstream_hits(&self) -> usize {
        self.upstream.received_requests().await.unwrap().len()
    }

    fn unwraps(&self) -> usize {
        self.kms.calls.load(Ordering::SeqCst)
    }

    /// Use the honey token of `path` by reference on that path; whether it was refused.
    async fn use_by_reference(&self, path: HoneyPath) -> bool {
        match path {
            HoneyPath::Relay => {
                let (s, body) = self.relay_to(HTTP_HONEY, "/v1/items", &[], None).await;
                assert_clean("relay answer", &body);
                s == StatusCode::FORBIDDEN && slug(&body) == "denied"
            }
            HoneyPath::ShortLived => {
                let now = time::OffsetDateTime::now_utc();
                let minted = self
                    .relay
                    .short_lived()
                    .mint(
                        AGENT,
                        ORG,
                        HTTP_HONEY,
                        now + time::Duration::minutes(5),
                        now,
                    )
                    .unwrap();
                self.relay.short_lived().insert(&minted, now).unwrap();
                let credential = secrecy::ExposeSecret::expose_secret(minted.token()).to_owned();
                let req = json!({
                    "secret_id": HTTP_HONEY, "version": 1, "method": "GET",
                    "url": format!("http://127.0.0.1:{}/v1/items", self.upstream.address().port()),
                });
                let (s, body) = self.relay_call(&credential, req).await;
                assert_clean("short-lived answer", &body);
                s == StatusCode::FORBIDDEN && slug(&body) == "denied"
            }
            HoneyPath::Delegate => {
                let args = json!({"secret_id": HTTP_HONEY, "job": "nightly", "ttl_secs": 300});
                let result = crate::mcp_tools::call(
                    Some(&self.relay),
                    &Self::agent(),
                    "issue_short_lived_credential",
                    args.as_object().cloned(),
                )
                .await
                .unwrap();
                let v = serde_json::to_value(&result).unwrap();
                assert_clean("tool result", v.to_string().as_bytes());
                assert_eq!(
                    self.relay
                        .short_lived()
                        .live(time::OffsetDateTime::now_utc()),
                    0
                );
                result.is_error == Some(true) && v["structuredContent"]["error"]["code"] == "denied"
            }
            HoneyPath::Git => {
                let (s, body) = self
                    .send(
                        Request::get(
                            "/git/127.0.0.1/acme/repo.git/info/refs?service=git-upload-pack",
                        )
                        .header("authorization", format!("Bearer {}", self.token))
                        .body(Body::empty())
                        .unwrap(),
                    )
                    .await;
                assert_clean("git answer", &body);
                s == StatusCode::FORBIDDEN && slug(&body) == "denied"
            }
            HoneyPath::Aws => {
                let (s, body) = self
                    .send(
                        Request::post("/v1/aws/credentials")
                            .header("content-type", "application/json")
                            .header("authorization", format!("Bearer {}", self.token))
                            .body(Body::from(json!({"secret_id": AWS_HONEY}).to_string()))
                            .unwrap(),
                    )
                    .await;
                assert_clean("aws answer", &body);
                s == StatusCode::FORBIDDEN && slug(&body) == "denied"
            }
            HoneyPath::Db => {
                let cert =
                    rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
                let tls = tls_acceptor(
                    cert.cert.pem().as_bytes(),
                    cert.signing_key.serialize_pem().as_bytes(),
                )
                .unwrap();
                let upstream = Arc::new(NoUpstream::default());
                let listener = PgListener::new(
                    self.relay.clone(),
                    tls,
                    upstream.clone(),
                    PgListenerOptions::default(),
                );
                let r = listener.check_for_test(Self::agent(), "app").await;
                assert_eq!(upstream.0.load(Ordering::SeqCst), 0);
                r == Err("denied")
            }
            HoneyPath::Inject => {
                let upstream = &self.relay.bindings().mcp_upstreams[0];
                let deps = HopDeps {
                    relay: Some(&self.relay),
                    decryptor: self.relay.decryptor(),
                    resolver: self.relay.resolver(),
                    connect_timeout: Duration::from_secs(2),
                };
                let r = hop::forward(&deps, upstream, Self::agent(), Forward::Ping).await;
                matches!(r, Err(HopError::Honey)) && HopError::Honey.slug() == "denied"
            }
            HoneyPath::ValueMatch => {
                let auth = format!("Bearer {}", STANDARD.encode(decoy(HTTP_HONEY)));
                let (s, body) = self
                    .relay_to(STANDARD_SECRET, "/v1/items", &[("x-api-key", &auth)], None)
                    .await;
                assert_clean("value-match answer", &body);
                s == StatusCode::FORBIDDEN && slug(&body) == "denied"
            }
        }
    }
}

fn slug(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body).unwrap()["error"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// Task 3.1 (and the by-value row of 3.2): one row per path. Each path refuses its honey token
/// with the same `denied` as any refusal, appends exactly one `honey.triggered` event naming the
/// agent, the token, the path and (where a grant was checked) the grant, never unwraps a key and
/// never reaches an upstream.
#[tokio::test]
async fn every_path_refuses_a_honey_token_and_records_one_event() {
    let table = [
        (HoneyPath::Relay, HTTP_HONEY, true),
        (HoneyPath::Inject, MCP_HONEY, false),
        (HoneyPath::Delegate, HTTP_HONEY, true),
        (HoneyPath::Git, GIT_HONEY, true),
        (HoneyPath::Aws, AWS_HONEY, true),
        (HoneyPath::Db, PG_HONEY, true),
        (HoneyPath::ShortLived, HTTP_HONEY, true),
        (HoneyPath::ValueMatch, HTTP_HONEY, false),
    ];
    assert_eq!(table.map(|(p, _, _)| p), HoneyPath::ALL, "one row per path");
    for (path, token, names_grant) in table {
        let h = Harness::start().await;
        assert!(h.use_by_reference(path).await, "{path:?} was not refused");
        let events = h.audit.honey();
        assert_eq!(events.len(), 1, "{path:?}: {events:?}");
        let HoneyEvent {
            agent_id,
            secret_id,
            path: got,
            binding_id,
            peer: _,
        } = events[0];
        assert_eq!((agent_id, secret_id, got), (AGENT, token, path));
        let want = names_grant.then(|| h.grants[&token]);
        assert_eq!(binding_id, want, "{path:?}");
        // Only the scan's own loading of the active values unwraps keys (paths that consult the
        // scan); the path's own resolution of the token unwraps nothing.
        let scan_unwraps = if matches!(
            path,
            HoneyPath::Relay | HoneyPath::ShortLived | HoneyPath::Delegate | HoneyPath::ValueMatch
        ) {
            HONEY.len() - 1
        } else {
            0
        };
        assert_eq!(
            h.unwraps(),
            scan_unwraps,
            "{path:?}: no unwrap for the honey token"
        );
        assert_eq!(h.upstream_hits().await, 0, "{path:?} reached the upstream");
        // The relay closes the attempt it opened as denied; no other path writes a relay event.
        let relay_events: Vec<_> = h.audit.events().iter().map(|e| e.kind).collect();
        match path {
            HoneyPath::Relay | HoneyPath::ShortLived => assert_eq!(
                relay_events,
                [
                    crate::audit::EventKind::Attempt,
                    crate::audit::EventKind::Outcome(crate::audit::Outcome::Denied)
                ],
                "{path:?}"
            ),
            _ => assert!(relay_events.is_empty(), "{path:?}: {relay_events:?}"),
        }
        assert!(h.audit.aws_events().is_empty());
    }
}

/// A honey token is refused by reference even when disabled (it is still not a credential).
#[tokio::test]
async fn a_disabled_honey_token_is_still_refused_by_reference() {
    let h = Harness::start().await;
    let (s, body) = h.relay_to(DISABLED, "/", &[], None).await;
    assert_eq!((s, slug(&body).as_str()), (StatusCode::FORBIDDEN, "denied"));
    assert_eq!(h.audit.honey().len(), 1);
    assert_eq!(h.audit.honey()[0].secret_id, DISABLED);
    assert_eq!(h.upstream_hits().await, 0);
}

/// One by-value case: a label, request headers, an optional body, the URL path.
type Case = (&'static str, Vec<(String, String)>, Option<String>, String);

/// Task 3.2: an active value in any of the scanned forms and places is caught; nothing is
/// forwarded, nothing about the call is recorded but the `value_match` event.
#[tokio::test]
async fn honey_values_are_caught_raw_base64_and_url_encoded_anywhere_in_the_request() {
    let v = decoy(GIT_HONEY);
    let text = String::from_utf8(v.clone()).unwrap();
    let pct_all: String = v.iter().map(|b| format!("%{b:02X}")).collect();
    let basic = STANDARD.encode(format!("deploy:{text}"));
    let cases: Vec<Case> = vec![
        (
            "raw header",
            vec![("authorization".into(), format!("Bearer {text}"))],
            None,
            "/".into(),
        ),
        (
            "base64 header",
            vec![("authorization".into(), STANDARD.encode(&v))],
            None,
            "/".into(),
        ),
        (
            "base64 basic auth",
            vec![("authorization".into(), format!("Basic {basic}"))],
            None,
            "/".into(),
        ),
        (
            "url-safe base64 header",
            vec![("x-token".into(), URL_SAFE.encode(&v))],
            None,
            "/".into(),
        ),
        (
            "raw body",
            vec![],
            Some(format!("{{\"key\":\"{text}\"}}")),
            "/".into(),
        ),
        (
            "base64 body",
            vec![],
            Some(format!("payload={}", STANDARD.encode(&v))),
            "/".into(),
        ),
        (
            "percent-encoded query",
            vec![],
            None,
            format!("/search?q={pct_all}"),
        ),
        (
            "lower-case percent-encoded body",
            vec![],
            Some(pct_all.to_lowercase()),
            "/".into(),
        ),
        ("raw path", vec![], None, format!("/keys/{text}")),
    ];
    for (what, headers, body, path) in cases {
        let h = Harness::start().await;
        let hdrs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let (s, resp) = h
            .relay_to(STANDARD_SECRET, &path, &hdrs, body.as_deref())
            .await;
        assert_eq!(
            (s, slug(&resp).as_str()),
            (StatusCode::FORBIDDEN, "denied"),
            "{what}"
        );
        assert_eq!(h.upstream_hits().await, 0, "{what}: forwarded");
        let events = h.audit.honey();
        assert_eq!(events.len(), 1, "{what}");
        assert_eq!(
            (events[0].secret_id, events[0].path, events[0].binding_id),
            (GIT_HONEY, HoneyPath::ValueMatch, None),
            "{what}"
        );
        assert!(
            h.audit.events().is_empty(),
            "{what}: no relay event, no attempt"
        );
        assert_clean(what, &resp);
    }
}

/// Task 3.2: the automaton is rebuilt only when the active set changes: a newly disabled token is
/// ignored after the next refresh, a re-read of the same set opens nothing again, and a list
/// that cannot be read keeps the previous scan.
#[tokio::test]
async fn the_scan_is_rebuilt_on_change_only() {
    let h = Harness::start().await;
    let scan = h.relay.honey_scan().unwrap();
    let d = h.relay.decryptor();
    scan.refresh(d).await.unwrap();
    let active = HONEY.len() - 1;
    assert_eq!(h.unwraps(), active);
    scan.refresh(d).await.unwrap();
    assert_eq!(h.unwraps(), active, "same set: nothing reopened");
    let git = String::from_utf8(decoy(GIT_HONEY)).unwrap();
    assert_eq!(
        scan.scanner(d).await.unwrap().find(git.as_bytes()),
        Some(GIT_HONEY)
    );

    // Disable the Git token: after a refresh its value no longer matches.
    h.list
        .set(&HONEY.map(|id| (id, id == DISABLED || id == GIT_HONEY)));
    scan.refresh(d).await.unwrap();
    assert_eq!(scan.scanner(d).await.unwrap().find(git.as_bytes()), None);
    let (s, _) = h.relay_to(STANDARD_SECRET, "/", &[], Some(&git)).await;
    assert_eq!(s, StatusCode::OK, "a disabled token's value is forwarded");
    assert!(h.audit.honey().is_empty());

    // An unreadable list keeps the scan in force.
    h.list.fail.store(true, Ordering::SeqCst);
    assert!(scan.refresh(d).await.is_err());
    let pg = String::from_utf8(decoy(PG_HONEY)).unwrap();
    assert_eq!(
        scan.scanner(d).await.unwrap().find(pg.as_bytes()),
        Some(PG_HONEY)
    );
    assert!(h.list.reads.load(Ordering::SeqCst) >= 4);
}

/// A scan that never loaded refuses the relay (fail closed) without forwarding.
#[tokio::test]
async fn an_unloadable_scan_refuses_the_relay() {
    let h = Harness::start().await;
    h.list.fail.store(true, Ordering::SeqCst);
    let (s, body) = h.relay_to(STANDARD_SECRET, "/", &[], None).await;
    assert_eq!(
        (s, slug(&body).as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    );
    assert_eq!(h.upstream_hits().await, 0);
}

/// The scanner itself: each form matches, unrelated and partial input does not, and every
/// pattern points at its own token.
#[test]
fn scanner_matches_each_form_of_each_value() {
    let values: Vec<(Uuid, SecretBytes)> = [HTTP_HONEY, GIT_HONEY]
        .iter()
        .map(|id| (*id, SecretBytes::new(decoy(*id))))
        .collect();
    let s = HoneyScanner::new(&values);
    for (id, _) in &values {
        let v = decoy(*id);
        let forms: Vec<Vec<u8>> = vec![
            v.clone(),
            STANDARD.encode(&v).into_bytes(),
            URL_SAFE_NO_PAD.encode(&v).into_bytes(),
            STANDARD.encode([b"x".as_slice(), &v].concat()).into_bytes(),
            STANDARD
                .encode([b"xy".as_slice(), &v].concat())
                .into_bytes(),
            v.iter()
                .map(|b| format!("%{b:02x}"))
                .collect::<String>()
                .into_bytes(),
        ];
        for f in forms {
            let mut text = b"prefix ".to_vec();
            text.extend_from_slice(&f);
            text.extend_from_slice(b" suffix");
            assert_eq!(s.find(&text), Some(*id));
        }
        assert_eq!(s.find(&v[..v.len() - 1]), None, "a prefix is not the value");
    }
    assert_eq!(s.find(b"AKIA nothing to see"), None);
    assert_eq!(HoneyScanner::new(&[]).find(b"anything"), None);
}
