//! D3 task 2.4: the listener's TLS, agent-token and check-order refusals. Every refusal asserts
//! that nothing was decrypted (no material fetch, no KMS call) and nothing reached the upstream
//! leg; the one positive case shows the same harness does decrypt and hand off.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use ls_control_plane::agent_token::{AUDIENCE, AgentClaims, AgentTokenSigner};
use pgwire::messages::Message;
use pgwire::messages::startup::{GssEncRequest, Password, SslRequest, Startup};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use uuid::Uuid;

use super::*;
use crate::audit::{MemoryAudit, RelayEvent};
use crate::auth::testkit::StubJwks;
use crate::auth::{AgentAuth, JwksSettings};
use crate::config::{Bindings, PgTls};
use crate::decrypt::testkit::{FakeKms, FakeMaterial, seal};
use crate::decrypt::{BoxFuture, CacheSettings, Decryptor, DekCache};
use crate::egress::testkit::StubResolver;
use crate::grants::Grant;
use crate::grants::testkit::StubGrants;
use crate::pg::{ClientIo, PgSession, PgUpstream};
use crate::relay::{Relay, RelayOptions};

const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000d1);
const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000d2);
/// Bound as `app`, private address allowed; the agent holds a grant.
const APP: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000d3);
/// Bound as `internal` to a loopback host without `allow_private_hosts`; granted.
const INTERNAL: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000d4);
/// Bound as `nogrant`; the agent holds no grant for it.
const NOGRANT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000d5);
/// Bound as `nowhere` to a host that does not resolve; granted.
const NOWHERE: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000d6);
/// Bound as `nomaterial`; granted, but the control plane has no material for it.
const NOMATERIAL: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000d7);
/// A canary database password.
const PASSWORD: &[u8] = b"canary-pg-Zq7/x+K2=";

fn pg(name: &str, secret_id: Uuid, host: &str, allow_private: bool) -> PgBinding {
    PgBinding {
        name: name.to_owned(),
        secret_id,
        version: 1,
        host: host.to_owned(),
        port: 5432,
        user: "app_rw".to_owned(),
        database: "app".to_owned(),
        tls: PgTls::Require,
        allow_private_hosts: allow_private,
    }
}

fn grant(secret_id: Uuid) -> Grant {
    Grant {
        grant_id: Uuid::now_v7(),
        secret_id,
        secret_name: "DB".to_owned(),
        mode: "relay".to_owned(),
        expires_at: None,
        scope: None,
    }
}

/// Records what reached the upstream leg and answers `AuthenticationOk`.
#[derive(Default)]
struct RecordingUpstream {
    calls: AtomicUsize,
    /// Whether the password handed over was the stored one (never the value itself).
    password_matched: Mutex<Option<bool>>,
    params: Mutex<Option<BTreeMap<String, String>>>,
    addrs: Mutex<Vec<std::net::SocketAddr>>,
    /// Keep the session open (counting bytes) until the client leaves or the listener drops it.
    hold: bool,
}

impl PgUpstream for RecordingUpstream {
    fn serve(&self, session: PgSession, mut client: Box<dyn ClientIo>) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.password_matched.lock().unwrap() = Some(session.password.expose() == PASSWORD);
            *self.params.lock().unwrap() = Some(session.client_parameters.clone());
            *self.addrs.lock().unwrap() = session.addrs.clone();
            let _ = write_message(&mut client, &Authentication::Ok).await;
            let _ = client.flush().await;
            if self.hold {
                session.stats.add_in(7);
                session.stats.add_out(11);
                let mut buf = [0u8; 64];
                while matches!(client.read(&mut buf).await, Ok(n) if n > 0) {}
                session.stats.ended_by_client();
            }
            let _ = client.shutdown().await;
        })
    }
}

struct Harness {
    addr: std::net::SocketAddr,
    connector: TlsConnector,
    material: Arc<FakeMaterial>,
    kms: Arc<FakeKms>,
    grants: Arc<StubGrants>,
    resolver: Arc<StubResolver>,
    audit: Arc<MemoryAudit>,
    upstream: Arc<RecordingUpstream>,
    signer: AgentTokenSigner,
}

impl Harness {
    async fn start() -> Self {
        Self::start_with(|_| {}, Duration::from_secs(5)).await
    }

    async fn start_with(tweak: impl FnOnce(&mut StubGrants), handshake: Duration) -> Self {
        Self::start_full(
            tweak,
            handshake,
            Duration::from_secs(10),
            MemoryAudit::default(),
            false,
        )
        .await
    }

    async fn start_full(
        tweak: impl FnOnce(&mut StubGrants),
        handshake: Duration,
        watch_interval: Duration,
        audit: MemoryAudit,
        hold: bool,
    ) -> Self {
        let sealed = seal(ORG, APP, 1, PASSWORD);
        let dek = sealed.dek;
        let material = Arc::new(FakeMaterial {
            sealed,
            secret: APP,
            version: 1,
            fetches: AtomicUsize::new(0),
        });
        let kms = Arc::new(FakeKms {
            dek: Some(dek),
            calls: AtomicUsize::new(0),
        });
        let decryptor = Decryptor::new(
            ORG,
            material.clone(),
            kms.clone(),
            Arc::new(DekCache::new(CacheSettings::default())),
        );
        let signer = AgentTokenSigner::from_seed(zeroize::Zeroizing::new([9u8; 32])).unwrap();
        let auth = Arc::new(AgentAuth::new(
            ORG,
            Arc::new(StubJwks::with(vec![signer.jwk().clone()])),
            JwksSettings::default(),
        ));
        let mut stub = StubGrants::default();
        tweak(&mut stub);
        let grants = Arc::new(stub);
        grants.set(
            AGENT,
            vec![
                grant(APP),
                grant(INTERNAL),
                grant(NOWHERE),
                grant(NOMATERIAL),
            ],
        );
        let resolver = Arc::new(StubResolver::with(&[
            ("db.test", "127.0.0.1".parse().unwrap()),
            ("internal.test", "127.0.0.1".parse().unwrap()),
        ]));
        let bindings = Bindings {
            org_id: ORG,
            bindings: Vec::new(),
            aws_bindings: Vec::new(),
            pg: vec![
                pg("app", APP, "db.test", true),
                pg("internal", INTERNAL, "internal.test", false),
                pg("nogrant", NOGRANT, "db.test", true),
                pg("nowhere", NOWHERE, "nowhere.test", true),
                pg("nomaterial", NOMATERIAL, "db.test", true),
            ],
            git_bindings: Vec::new(),
            mcp_upstreams: Vec::new(),
        };
        let audit = Arc::new(audit);
        let relay = Arc::new(Relay::new(
            auth,
            grants.clone(),
            bindings,
            decryptor,
            resolver.clone(),
            audit.clone(),
            RelayOptions::default(),
        ));

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let tls = tls_acceptor(
            cert.cert.pem().as_bytes(),
            cert.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(cert.cert.der().to_vec()))
            .unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client.alpn_protocols = vec![b"postgresql".to_vec()];

        let upstream = Arc::new(RecordingUpstream {
            hold,
            ..RecordingUpstream::default()
        });
        let listener = Arc::new(PgListener::new(
            relay,
            tls,
            upstream.clone(),
            PgListenerOptions {
                handshake_timeout: handshake,
                watch_interval,
            },
        ));
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        tokio::spawn(listener.serve(tcp));
        Self {
            addr,
            connector: TlsConnector::from(Arc::new(client)),
            material,
            kms,
            grants,
            resolver,
            audit,
            upstream,
            signer,
        }
    }

    fn token(&self, aud: &str, exp_in: i64) -> String {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        self.signer
            .sign(&AgentClaims {
                sub: AGENT,
                org: ORG,
                aud: aud.to_owned(),
                iat: now - 1,
                exp: now + exp_in,
            })
            .unwrap()
    }

    fn valid_token(&self) -> String {
        self.token(AUDIENCE, 600)
    }

    /// TCP, `SSLRequest`, TLS.
    async fn tls(&self) -> tokio_rustls::client::TlsStream<TcpStream> {
        let mut tcp = TcpStream::connect(self.addr).await.unwrap();
        send(&mut tcp, &SslRequest::new()).await;
        assert_eq!(tcp.read_u8().await.unwrap(), b'S');
        self.connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap()
    }

    /// TLS, startup for `database`, then the password. Returns every backend message.
    async fn login(&self, database: &str, password: &str) -> Vec<(u8, BytesMut)> {
        let mut s = self.tls().await;
        send(&mut s, &startup(database, &[])).await;
        let (tag, body) = read_message(&mut s).await.expect("auth request");
        assert_eq!((tag, &body[..]), (b'R', &3i32.to_be_bytes()[..]));
        send(&mut s, &Password::new(password.to_owned())).await;
        read_all(&mut s).await
    }

    /// Nothing was decrypted and nothing reached the upstream leg.
    fn assert_untouched(&self) {
        assert_eq!(
            self.material.fetches.load(Ordering::SeqCst),
            0,
            "material fetched"
        );
        assert_eq!(self.kms.calls.load(Ordering::SeqCst), 0, "KMS called");
        assert_eq!(
            self.upstream.calls.load(Ordering::SeqCst),
            0,
            "upstream reached"
        );
    }

    /// The ledger events once at least `n` are stored (the closing event is appended after the
    /// session ends).
    async fn wait_events(&self, n: usize) -> Vec<RelayEvent> {
        for _ in 0..200 {
            if self.audit.events().len() >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        self.audit.events()
    }

    fn denied(&self) -> Vec<(Outcome, Uuid)> {
        self.audit
            .events()
            .into_iter()
            .map(|e| match e.kind {
                EventKind::DbDenied(o) => (o, e.secret_id),
                other => panic!("unexpected event {other:?}"),
            })
            .collect()
    }
}

fn startup(database: &str, extra: &[(&str, &str)]) -> Startup {
    let mut s = Startup::new();
    s.parameters
        .insert("user".to_owned(), "postgres".to_owned());
    s.parameters
        .insert("database".to_owned(), database.to_owned());
    for (k, v) in extra {
        s.parameters.insert((*k).to_owned(), (*v).to_owned());
    }
    s
}

async fn send<S: AsyncWrite + Unpin, M: Message>(s: &mut S, m: &M) {
    let mut buf = BytesMut::new();
    m.encode(&mut buf).unwrap();
    s.write_all(&buf).await.unwrap();
    s.flush().await.unwrap();
}

/// One backend message, or `None` at EOF.
async fn read_message<S: AsyncRead + Unpin>(s: &mut S) -> Option<(u8, BytesMut)> {
    let tag = s.read_u8().await.ok()?;
    let len = s.read_i32().await.ok()? as usize;
    let mut body = BytesMut::zeroed(len - 4);
    s.read_exact(&mut body).await.ok()?;
    Some((tag, body))
}

async fn read_all<S: AsyncRead + Unpin>(s: &mut S) -> Vec<(u8, BytesMut)> {
    let mut out = Vec::new();
    while let Ok(Some(m)) =
        tokio::time::timeout(Duration::from_secs(5), read_message(&mut *s)).await
    {
        out.push(m);
    }
    out
}

/// The SQLSTATE of the only message, which must be a `FATAL` `ErrorResponse`.
fn sqlstate_of(msgs: &[(u8, BytesMut)]) -> String {
    assert_eq!(msgs.len(), 1, "one message, then close");
    let (tag, body) = &msgs[0];
    assert_eq!(*tag, b'E');
    let mut b = body.clone();
    let mut fields = BTreeMap::new();
    while b.has_remaining() {
        let code = b.get_u8();
        if code == 0 {
            break;
        }
        let end = b.iter().position(|&c| c == 0).unwrap();
        let v = String::from_utf8(b.split_to(end).to_vec()).unwrap();
        b.advance(1);
        fields.insert(code, v);
    }
    assert_eq!(fields.get(&b'S').map(String::as_str), Some("FATAL"));
    fields.remove(&b'C').expect("SQLSTATE")
}

fn assert_no_token(msgs: &[(u8, BytesMut)], token: &str) {
    for (_, body) in msgs {
        let text = String::from_utf8_lossy(body);
        assert!(!text.contains(token), "the answer echoes the token");
    }
}

#[tokio::test]
async fn pg_auth_valid_session_is_decrypted_and_handed_upstream() {
    let h = Harness::start().await;
    // GSSENC first, answered `N`, then TLS as libpq does with gssencmode=prefer.
    let mut tcp = TcpStream::connect(h.addr).await.unwrap();
    send(&mut tcp, &GssEncRequest::new()).await;
    assert_eq!(tcp.read_u8().await.unwrap(), b'N');
    send(&mut tcp, &SslRequest::new()).await;
    assert_eq!(tcp.read_u8().await.unwrap(), b'S');
    let mut s = h
        .connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    send(
        &mut s,
        &startup(
            "app",
            &[
                ("application_name", "psql"),
                ("options", "-c role=postgres"),
                ("search_path", "evil"),
            ],
        ),
    )
    .await;
    let (tag, body) = read_message(&mut s).await.unwrap();
    assert_eq!((tag, &body[..]), (b'R', &3i32.to_be_bytes()[..]));
    send(&mut s, &Password::new(h.valid_token())).await;
    let msgs = read_all(&mut s).await;
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].0, b'R', "the upstream leg answered");

    assert_eq!(h.upstream.calls.load(Ordering::SeqCst), 1);
    assert_eq!(*h.upstream.password_matched.lock().unwrap(), Some(true));
    let params = h.upstream.params.lock().unwrap().clone().unwrap();
    assert_eq!(
        params,
        BTreeMap::from([("application_name".to_owned(), "psql".to_owned())]),
        "only allow-listed parameters reach the upstream leg"
    );
    assert_eq!(
        *h.upstream.addrs.lock().unwrap(),
        vec!["127.0.0.1:5432".parse().unwrap()]
    );
    assert_eq!(h.material.fetches.load(Ordering::SeqCst), 1);
    let kinds = h.wait_events(2).await;
    assert!(
        matches!(kinds[0].kind, EventKind::DbOpened)
            && matches!(kinds[1].kind, EventKind::DbClosed(_)),
        "an opened and a closed event, no refusal"
    );
}

#[tokio::test]
async fn pg_auth_plaintext_startup_is_refused() {
    let h = Harness::start().await;
    let mut tcp = TcpStream::connect(h.addr).await.unwrap();
    send(&mut tcp, &startup("app", &[])).await;
    let msgs = read_all(&mut tcp).await;
    assert_eq!(sqlstate_of(&msgs), "28000");
    // GSSENC refused, then a plaintext startup: still refused.
    let mut tcp = TcpStream::connect(h.addr).await.unwrap();
    send(&mut tcp, &GssEncRequest::new()).await;
    assert_eq!(tcp.read_u8().await.unwrap(), b'N');
    send(&mut tcp, &startup("app", &[])).await;
    assert_eq!(sqlstate_of(&read_all(&mut tcp).await), "28000");
    h.assert_untouched();
    assert_eq!(h.grants.calls(), 0, "no grant read before TLS and a token");
    assert!(h.resolver.lookups.lock().unwrap().is_empty());
    assert!(h.audit.events().is_empty());
}

#[tokio::test]
async fn pg_auth_bad_token_is_refused_28p01() {
    let h = Harness::start().await;
    let expired = h.token(AUDIENCE, -3600);
    let wrong_audience = h.token("control-plane", 600);
    let other_signer = AgentTokenSigner::from_seed(zeroize::Zeroizing::new([3u8; 32]))
        .unwrap()
        .sign(&AgentClaims {
            sub: AGENT,
            org: ORG,
            aud: AUDIENCE.to_owned(),
            iat: 0,
            exp: i64::MAX / 2,
        })
        .unwrap();
    for token in [
        expired,
        wrong_audience,
        other_signer,
        "not-a-token".to_owned(),
        String::new(),
    ] {
        let msgs = h.login("app", &token).await;
        assert_eq!(sqlstate_of(&msgs), "28P01");
        if !token.is_empty() {
            assert_no_token(&msgs, &token);
        }
    }
    h.assert_untouched();
    assert_eq!(h.grants.calls(), 0, "no grant read for an unverified agent");
    assert!(h.audit.events().is_empty(), "no agent to record");
}

#[tokio::test]
async fn pg_auth_unbound_database_is_refused_3d000() {
    let h = Harness::start().await;
    let token = h.valid_token();
    let msgs = h.login("not-bound", &token).await;
    assert_eq!(sqlstate_of(&msgs), "3D000");
    let text = String::from_utf8_lossy(&msgs[0].1);
    assert!(
        !text.contains("not-bound"),
        "the database name is not echoed"
    );
    h.assert_untouched();
    assert!(h.resolver.lookups.lock().unwrap().is_empty());
    assert!(h.audit.events().is_empty(), "no secret to name");
}

#[tokio::test]
async fn pg_auth_no_grant_is_refused_and_recorded() {
    let h = Harness::start().await;
    let msgs = h.login("nogrant", &h.valid_token()).await;
    assert_eq!(sqlstate_of(&msgs), "28000");
    h.assert_untouched();
    assert!(
        h.resolver.lookups.lock().unwrap().is_empty(),
        "no DNS before the grant"
    );
    assert_eq!(h.denied(), vec![(Outcome::NoGrant, NOGRANT)]);
    let ev = &h.audit.events()[0];
    assert_eq!(
        (ev.agent_id, ev.host.as_deref(), ev.port),
        (AGENT, Some("db.test"), Some(5432))
    );
}

#[tokio::test]
async fn pg_auth_unreadable_grants_fail_closed() {
    let h = Harness::start_with(|g| g.fail = true, Duration::from_secs(5)).await;
    let msgs = h.login("app", &h.valid_token()).await;
    assert_eq!(sqlstate_of(&msgs), "28000");
    h.assert_untouched();
    assert_eq!(h.denied(), vec![(Outcome::GrantsUnavailable, APP)]);
}

#[tokio::test]
async fn pg_auth_private_host_without_permission_is_refused() {
    let h = Harness::start().await;
    let msgs = h.login("internal", &h.valid_token()).await;
    assert_eq!(sqlstate_of(&msgs), "28000");
    h.assert_untouched();
    assert_eq!(h.denied(), vec![(Outcome::DeniedAddress, INTERNAL)]);
}

#[tokio::test]
async fn pg_auth_silent_client_hits_the_handshake_timeout() {
    let h = Harness::start_with(|_| {}, Duration::from_millis(200)).await;
    // Connected, nothing sent.
    let mut tcp = TcpStream::connect(h.addr).await.unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(3), tcp.read(&mut buf))
        .await
        .expect("closed by the gateway")
        .unwrap_or(0);
    assert_eq!(n, 0);
    // TLS done, startup never sent.
    let mut s = h.tls().await;
    let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf))
        .await
        .expect("closed by the gateway")
        .unwrap_or(0);
    assert_eq!(n, 0);
    h.assert_untouched();
}

#[tokio::test]
async fn pg_auth_protocol_errors_are_refused_without_upstream() {
    let h = Harness::start().await;
    // A query instead of the password message.
    let mut s = h.tls().await;
    send(&mut s, &startup("app", &[])).await;
    let _ = read_message(&mut s).await.unwrap();
    send(
        &mut s,
        &pgwire::messages::simplequery::Query::new("select 1".into()),
    )
    .await;
    assert_eq!(sqlstate_of(&read_all(&mut s).await), "08P01");
    // No user in the startup message.
    let mut s = h.tls().await;
    let mut st = Startup::new();
    st.parameters.insert("database".into(), "app".into());
    send(&mut s, &st).await;
    assert_eq!(sqlstate_of(&read_all(&mut s).await), "28000");
    // A cancel request in the clear is closed without an answer (cancel map: task 3.3).
    let mut tcp = TcpStream::connect(h.addr).await.unwrap();
    let mut cancel = BytesMut::new();
    for v in [16i32, 80877102, 1, 2] {
        cancel.extend_from_slice(&v.to_be_bytes());
    }
    tcp.write_all(&cancel).await.unwrap();
    assert!(read_all(&mut tcp).await.is_empty());
    h.assert_untouched();
}

#[tokio::test]
async fn pg_auth_unresolvable_upstream_is_refused_and_recorded() {
    let h = Harness::start().await;
    let msgs = h.login("nowhere", &h.valid_token()).await;
    assert_eq!(sqlstate_of(&msgs), "08001");
    h.assert_untouched();
    assert_eq!(h.denied(), vec![(Outcome::UpstreamUnreachable, NOWHERE)]);
}

#[tokio::test]
async fn pg_auth_decrypt_failure_is_refused_and_recorded() {
    let h = Harness::start().await;
    let msgs = h.login("nomaterial", &h.valid_token()).await;
    assert_eq!(sqlstate_of(&msgs), "08001");
    // The decrypt was tried (the last check) and failed: nothing unwrapped, nothing upstream.
    assert_eq!(h.material.fetches.load(Ordering::SeqCst), 1);
    assert_eq!(h.kms.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        h.upstream.calls.load(Ordering::SeqCst),
        0,
        "upstream reached"
    );
    assert_eq!(h.denied(), vec![(Outcome::MaterialError, NOMATERIAL)]);
}

#[tokio::test]
async fn pg_auth_newer_protocol_is_negotiated_down_to_3_0() {
    let h = Harness::start().await;
    let mut s = h.tls().await;
    let mut st = startup("app", &[("_pq_.future_option", "on")]);
    st.protocol_number_minor = 2;
    send(&mut s, &st).await;
    let (tag, mut body) = read_message(&mut s).await.unwrap();
    assert_eq!(tag, b'v', "NegotiateProtocolVersion first");
    assert_eq!(body.get_i32(), 0, "newest minor version served");
    assert_eq!(body.get_i32(), 1);
    assert_eq!(&body[..], b"_pq_.future_option\0");
    let (tag, body) = read_message(&mut s).await.unwrap();
    assert_eq!((tag, &body[..]), (b'R', &3i32.to_be_bytes()[..]));
    send(&mut s, &Password::new(h.valid_token())).await;
    let msgs = read_all(&mut s).await;
    assert_eq!(msgs.len(), 1);
    assert_eq!(
        msgs[0].0, b'R',
        "the session still reaches the upstream leg"
    );
    let params = h.upstream.params.lock().unwrap().clone().unwrap();
    assert!(params.is_empty(), "`_pq_.` options are not forwarded");
}

/// TLS, startup and a valid token; returns the open stream after the upstream's `AuthenticationOk`.
async fn open_session(h: &Harness, token: &str) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut s = h.tls().await;
    send(&mut s, &startup("app", &[])).await;
    let (tag, _) = read_message(&mut s).await.expect("auth request");
    assert_eq!(tag, b'R');
    send(&mut s, &Password::new(token.to_owned())).await;
    let (tag, body) = read_message(&mut s).await.expect("auth ok");
    assert_eq!((tag, &body[..]), (b'R', &0i32.to_be_bytes()[..]));
    s
}

fn closed(ev: &RelayEvent) -> crate::audit::SessionClose {
    match ev.kind {
        EventKind::DbClosed(c) => c,
        other => panic!("not a closing event: {other:?}"),
    }
}

#[tokio::test]
async fn pg_audit_opened_then_closed_with_reason_duration_and_bytes() {
    let h = Harness::start_full(
        |_| {},
        Duration::from_secs(5),
        Duration::from_secs(10),
        MemoryAudit::default(),
        true,
    )
    .await;
    let mut s = open_session(&h, &h.valid_token()).await;
    let opened = h.wait_events(1).await;
    assert_eq!(
        opened.len(),
        1,
        "opened is recorded while the session is open"
    );
    assert!(matches!(opened[0].kind, EventKind::DbOpened));
    assert_eq!(opened[0].secret_id, APP);
    assert_eq!(opened[0].agent_id, AGENT);
    assert_eq!(opened[0].host.as_deref(), Some("db.test"));
    s.shutdown().await.unwrap();
    drop(s);
    let stored = {
        for _ in 0..200 {
            if h.audit.stored().len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        h.audit.stored()
    };
    assert_eq!(stored.len(), 2);
    let c = closed(&stored[1].1);
    assert_eq!(c.reason, crate::audit::CloseReason::ClientClosed);
    assert_eq!((c.bytes_in, c.bytes_out), (7, 11));
    assert_eq!(
        stored[1].1.attempt_id,
        Some(stored[0].0),
        "the closing event names the opening one"
    );
}

#[tokio::test]
async fn pg_audit_ledger_down_refuses_the_session_before_any_upstream_leg_work() {
    let h = Harness::start_full(
        |_| {},
        Duration::from_secs(5),
        Duration::from_secs(10),
        MemoryAudit {
            fail: true,
            ..MemoryAudit::default()
        },
        true,
    )
    .await;
    let msgs = h.login("app", &h.valid_token()).await;
    assert_eq!(sqlstate_of(&msgs), "08001");
    assert_eq!(
        h.upstream.calls.load(Ordering::SeqCst),
        0,
        "no upstream connect without the opened event"
    );
    assert!(h.audit.events().is_empty());
}

#[tokio::test]
async fn pg_revoke_grant_revoked_mid_session_closes_it_within_the_interval() {
    let h = Harness::start_full(
        |_| {},
        Duration::from_secs(5),
        Duration::from_millis(100),
        MemoryAudit::default(),
        true,
    )
    .await;
    let mut s = open_session(&h, &h.valid_token()).await;
    h.wait_events(1).await;
    h.grants.set(AGENT, vec![grant(NOGRANT)]);
    let started = std::time::Instant::now();
    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .expect("the gateway closed the connection")
        .unwrap_or(0);
    assert_eq!(n, 0, "closed");
    assert!(started.elapsed() < Duration::from_secs(2));
    let events = h.wait_events(2).await;
    assert_eq!(
        closed(&events[1]).reason,
        crate::audit::CloseReason::Revoked
    );
}

#[tokio::test]
async fn pg_revoke_expired_agent_token_closes_the_session() {
    let h = Harness::start_full(
        |_| {},
        Duration::from_secs(5),
        Duration::from_millis(100),
        MemoryAudit::default(),
        true,
    )
    .await;
    let mut s = open_session(&h, &h.token(AUDIENCE, 1)).await;
    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(8), s.read(&mut buf))
        .await
        .expect("the gateway closed the connection")
        .unwrap_or(0);
    assert_eq!(n, 0, "closed");
    let events = h.wait_events(2).await;
    assert_eq!(
        closed(&events[1]).reason,
        crate::audit::CloseReason::Expired
    );
}
