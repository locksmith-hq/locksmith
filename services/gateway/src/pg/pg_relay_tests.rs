//! D3 task 3.4: the upstream leg against a real `postgres:18` (testcontainers, needs Docker) with
//! SCRAM-SHA-256 and md5, and against an in-process fake server for the cases a real server
//! cannot produce on demand (a cleartext request on a plain network, the upstream echoing the
//! password). Every test goes the whole way: TLS, agent token, checks, decrypt, upstream.
//!
//! The clients here speak the protocol by hand (pgwire codec plus simple `Query` framing), so no
//! extra Postgres client or TLS connector crate is needed.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use ls_control_plane::agent_token::{AUDIENCE, AgentClaims, AgentTokenSigner};
use pgwire::messages::Message;
use pgwire::messages::cancel::CancelRequest;
use pgwire::messages::startup::{Password, SecretKey, SslRequest, Startup};
use rustls::pki_types::{CertificateDer, ServerName};
use testcontainers::core::{ExecCommand, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use uuid::Uuid;

use super::*;
use crate::audit::MemoryAudit;
use crate::auth::testkit::StubJwks;
use crate::auth::{AgentAuth, JwksSettings};
use crate::config::{Bindings, PgBinding, PgTls};
use crate::decrypt::testkit::{FakeKms, FakeMaterial, seal};
use crate::decrypt::{CacheSettings, Decryptor, DekCache};
use crate::egress::testkit::StubResolver;
use crate::grants::Grant;
use crate::grants::testkit::StubGrants;
use crate::pg::{PgListener, PgListenerOptions, tls_acceptor};
use crate::relay::{Relay, RelayOptions};

const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000e1);
const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000e2);
const APP: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000e3);

const SCRAM_USER: &str = "scram_user";
const SCRAM_PASSWORD: &str = "canary-scram-Qw8/x+Z1=";
const MD5_USER: &str = "md5_user";
const MD5_PASSWORD: &str = "canary-md5-Hk3/y+T9=";

/// A real `postgres:18` with one SCRAM role and one md5 role.
struct Postgres {
    _container: ContainerAsync<GenericImage>,
    port: u16,
}

impl Postgres {
    async fn start() -> Self {
        // `md5` in pg_hba accepts both verifier kinds: the stored verifier picks the method.
        let container = GenericImage::new("postgres", "18")
            .with_exposed_port(5432.tcp())
            .with_wait_for(WaitFor::message_on_stderr(
                "database system is ready to accept connections",
            ))
            // TLS on with a throwaway self-signed certificate, so the `require` leg is exercised.
            .with_entrypoint("sh")
            .with_cmd([
                "-c",
                "openssl req -new -x509 -nodes -days 2 -subj /CN=localhost \
                 -keyout /tmp/s.key -out /tmp/s.crt 2>/dev/null \
                 && chown postgres:postgres /tmp/s.key /tmp/s.crt && chmod 600 /tmp/s.key \
                 && exec docker-entrypoint.sh postgres -c ssl=on \
                 -c ssl_cert_file=/tmp/s.crt -c ssl_key_file=/tmp/s.key",
            ])
            .with_env_var("POSTGRES_PASSWORD", "bootstrap-test-only")
            .with_env_var("POSTGRES_HOST_AUTH_METHOD", "md5")
            .with_startup_timeout(Duration::from_secs(120))
            .start()
            .await
            .expect("start postgres:18 (is Docker running?)");
        let port = container.get_host_port_ipv4(5432.tcp()).await.unwrap();
        // The image restarts the server once after init; only the final one listens on TCP.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            if exec(&container, &["pg_isready", "-h", "127.0.0.1"]).await == Some(0) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "postgres did not come up"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let sql = format!(
            "SET password_encryption = 'scram-sha-256'; \
             CREATE ROLE {SCRAM_USER} LOGIN PASSWORD '{SCRAM_PASSWORD}'; \
             SET password_encryption = 'md5'; \
             CREATE ROLE {MD5_USER} LOGIN PASSWORD '{MD5_PASSWORD}';"
        );
        let code = exec(&container, &["psql", "-U", "postgres", "-c", &sql]).await;
        assert_eq!(code, Some(0), "role setup");
        // CREATE DATABASE cannot run inside the implicit transaction of a multi-statement -c.
        let code = exec(
            &container,
            &["psql", "-U", "postgres", "-c", "CREATE DATABASE app"],
        )
        .await;
        assert_eq!(code, Some(0), "database setup");
        Self {
            _container: container,
            port,
        }
    }
}

/// Run a command in the container and return its exit code once it has finished.
async fn exec(container: &ContainerAsync<GenericImage>, cmd: &[&str]) -> Option<i64> {
    let mut r = container
        .exec(ExecCommand::new(cmd.iter().copied()))
        .await
        .unwrap();
    // The exit code is only known after the output has been drained.
    let _ = r.stdout_to_vec().await;
    r.exit_code().await.unwrap()
}

fn binding(addr_port: u16, user: &str, tls: PgTls, host: &str) -> PgBinding {
    PgBinding {
        name: "app".to_owned(),
        secret_id: APP,
        version: 1,
        host: host.to_owned(),
        port: addr_port,
        user: user.to_owned(),
        database: "app".to_owned(),
        tls,
        allow_private_hosts: true,
    }
}

struct Harness {
    addr: SocketAddr,
    connector: TlsConnector,
    signer: AgentTokenSigner,
    cancels: Arc<CancelMap>,
    audit: Arc<MemoryAudit>,
}

impl Harness {
    /// A gateway whose `app` binding points at `upstream_port` on 127.0.0.1 (name `host`),
    /// with `password` as the decrypted secret.
    async fn start(upstream: PgBinding, host_addr: &str, password: &str) -> Self {
        let sealed = seal(ORG, APP, 1, password.as_bytes());
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
            material,
            kms,
            Arc::new(DekCache::new(CacheSettings::default())),
        );
        let signer = AgentTokenSigner::from_seed(zeroize::Zeroizing::new([9u8; 32])).unwrap();
        let auth = Arc::new(AgentAuth::new(
            ORG,
            Arc::new(StubJwks::with(vec![signer.jwk().clone()])),
            JwksSettings::default(),
        ));
        let grants = Arc::new(StubGrants::default());
        grants.set(
            AGENT,
            vec![Grant {
                grant_id: Uuid::now_v7(),
                secret_id: APP,
                secret_name: "DB".to_owned(),
                mode: "relay".to_owned(),
                expires_at: None,
            }],
        );
        let resolver = Arc::new(StubResolver::with(&[(
            upstream.host.as_str(),
            host_addr.parse().unwrap(),
        )]));
        let bindings = Bindings {
            org_id: ORG,
            bindings: Vec::new(),
            pg: vec![upstream],
            git_bindings: Vec::new(),
        };
        let audit = Arc::new(MemoryAudit::default());
        let relay = Arc::new(Relay::new(
            auth,
            grants,
            bindings,
            decryptor,
            resolver,
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
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        client.alpn_protocols = vec![b"postgresql".to_vec()];
        // `verify-full` toward the upstream would need the container's certificate; these tests
        // use `require` (libpq semantics), so the verified config is never consulted.
        let verified = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let up = Arc::new(PgRelayUpstream::new(Connector::new(verified).unwrap()));
        let cancels = up.cancel_map();
        let listener = Arc::new(
            PgListener::new(
                relay,
                tls,
                up,
                PgListenerOptions {
                    handshake_timeout: Duration::from_secs(20),
                    ..PgListenerOptions::default()
                },
            )
            .with_cancel_map(cancels.clone()),
        );
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        tokio::spawn(listener.serve(tcp));
        Self {
            addr,
            connector: TlsConnector::from(Arc::new(client)),
            signer,
            cancels,
            audit,
        }
    }

    fn token(&self) -> String {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        self.signer
            .sign(&AgentClaims {
                sub: AGENT,
                org: ORG,
                aud: AUDIENCE.to_owned(),
                iat: now - 1,
                exp: now + 600,
            })
            .unwrap()
    }

    async fn tls(&self) -> tokio_rustls::client::TlsStream<TcpStream> {
        let mut tcp = TcpStream::connect(self.addr).await.unwrap();
        send(&mut tcp, &SslRequest::new()).await;
        assert_eq!(tcp.read_u8().await.unwrap(), b'S');
        self.connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap()
    }

    /// Log in as a hostile client: `user=postgres` and `options` selecting another role.
    async fn login(&self) -> Client {
        self.login_with(&[
            ("options", "-c role=postgres"),
            ("application_name", "relay"),
        ])
        .await
    }

    async fn login_with(&self, extra: &[(&str, &str)]) -> Client {
        let mut stream = self.tls().await;
        let mut startup = Startup::new();
        startup
            .parameters
            .insert("user".to_owned(), "postgres".to_owned());
        startup
            .parameters
            .insert("database".to_owned(), "app".to_owned());
        for (k, v) in extra {
            startup.parameters.insert((*k).to_owned(), (*v).to_owned());
        }
        send(&mut stream, &startup).await;
        let (tag, body) = read_message(&mut stream).await.expect("auth request");
        assert_eq!((tag, &body[..]), (b'R', &3i32.to_be_bytes()[..]));
        send(&mut stream, &Password::new(self.token())).await;
        Client { stream }
    }
}

struct Client {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
}

/// What the gateway sent up to `ReadyForQuery`.
struct Ready {
    tags: Vec<u8>,
    pid: i32,
    secret: Bytes,
}

impl Client {
    async fn ready(&mut self) -> Ready {
        let mut out = Ready {
            tags: Vec::new(),
            pid: 0,
            secret: Bytes::new(),
        };
        loop {
            let (tag, body) = read_message(&mut self.stream).await.expect("startup reply");
            out.tags.push(tag);
            match tag {
                b'K' => {
                    out.pid = i32::from_be_bytes(body[..4].try_into().unwrap());
                    out.secret = Bytes::copy_from_slice(&body[4..]);
                }
                b'E' => panic!("unexpected error: {}", error_fields(&body)[&b'M']),
                b'Z' => return out,
                _ => {}
            }
        }
    }

    /// A simple query: the first column of every row as text, or the error's SQLSTATE.
    async fn query(&mut self, sql: &str) -> Result<Vec<String>, String> {
        let mut m = BytesMut::new();
        m.put_u8(b'Q');
        m.put_i32(sql.len() as i32 + 5);
        m.put_slice(sql.as_bytes());
        m.put_u8(0);
        self.stream.write_all(&m).await.unwrap();
        self.stream.flush().await.unwrap();
        let mut rows = Vec::new();
        let mut error = None;
        loop {
            let (tag, body) = read_message(&mut self.stream).await.expect("query reply");
            match tag {
                b'D' => {
                    let len = i32::from_be_bytes(body[2..6].try_into().unwrap()) as usize;
                    rows.push(String::from_utf8(body[6..6 + len].to_vec()).unwrap());
                }
                b'E' => error = Some(error_fields(&body)[&b'C'].clone()),
                b'Z' => break,
                _ => {}
            }
        }
        error.map_or(Ok(rows), Err)
    }
}

fn error_fields(body: &[u8]) -> BTreeMap<u8, String> {
    let mut fields = BTreeMap::new();
    let mut rest = body;
    while let Some((&code, tail)) = rest.split_first() {
        if code == 0 {
            break;
        }
        let end = tail.iter().position(|&c| c == 0).unwrap();
        fields.insert(code, String::from_utf8_lossy(&tail[..end]).into_owned());
        rest = &tail[end + 1..];
    }
    fields
}

async fn send<S: AsyncWrite + Unpin, M: Message>(s: &mut S, m: &M) {
    let mut buf = BytesMut::new();
    m.encode(&mut buf).unwrap();
    s.write_all(&buf).await.unwrap();
    s.flush().await.unwrap();
}

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

async fn current_user_through_gateway(user: &str, password: &str) {
    let pg = Postgres::start().await;
    let h = Harness::start(
        binding(pg.port, user, PgTls::Require, "db.test"),
        "127.0.0.1",
        password,
    )
    .await;
    let mut c = h.login().await;
    let ready = c.ready().await;
    assert_eq!(ready.tags.first(), Some(&b'R'), "AuthenticationOk first");
    assert!(ready.tags.contains(&b'S'), "parameter status forwarded");
    assert_eq!(ready.tags.last(), Some(&b'Z'));

    // The client said `user=postgres` and `options=-c role=postgres`: the session runs as the
    // bound role regardless.
    assert_eq!(
        c.query("SELECT current_user").await.unwrap(),
        vec![user.to_owned()]
    );
    assert_eq!(
        c.query("SELECT session_user").await.unwrap(),
        vec![user.to_owned()]
    );
    assert_eq!(
        c.query("SELECT current_database()").await.unwrap(),
        vec!["app".to_owned()]
    );
    // An allow-listed parameter did reach the session.
    assert_eq!(
        c.query("SHOW application_name").await.unwrap(),
        vec!["relay".to_owned()]
    );
    // The gateway's key is not the upstream's.
    let upstream_pid = c.query("SELECT pg_backend_pid()").await.unwrap()[0]
        .parse::<i32>()
        .unwrap();
    assert_ne!(ready.pid, upstream_pid);
    // Errors pass through with their SQLSTATE.
    assert_eq!(c.query("SELECT 1/0").await, Err("22012".to_owned()));
    assert_eq!(c.query("SELECT 2").await.unwrap(), vec!["2".to_owned()]);
    // The session is recorded as opened (no denial), once.
    let events = h.audit.events();
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0].kind, crate::audit::EventKind::DbOpened));
}

#[tokio::test]
async fn pg_relay_scram_query_works_and_client_identity_is_ignored() {
    current_user_through_gateway(SCRAM_USER, SCRAM_PASSWORD).await;
}

#[tokio::test]
async fn pg_relay_md5_query_works_and_client_identity_is_ignored() {
    current_user_through_gateway(MD5_USER, MD5_PASSWORD).await;
}

#[tokio::test]
async fn pg_relay_wrong_password_is_a_fixed_error_without_the_password() {
    let pg = Postgres::start().await;
    let wrong = "canary-wrong-Pp5/m+L7=";
    let h = Harness::start(
        binding(pg.port, SCRAM_USER, PgTls::Require, "db.test"),
        "127.0.0.1",
        wrong,
    )
    .await;
    let mut c = h.login().await;
    let msgs = read_all(&mut c.stream).await;
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].0, b'E');
    let f = error_fields(&msgs[0].1);
    assert_eq!(f[&b'C'], "08001");
    for (_, body) in &msgs {
        assert!(!String::from_utf8_lossy(body).contains(wrong));
    }
}

#[tokio::test]
async fn pg_relay_cancel_reaches_the_upstream_and_is_cleaned_up() {
    let pg = Postgres::start().await;
    let h = Harness::start(
        binding(pg.port, SCRAM_USER, PgTls::Require, "db.test"),
        "127.0.0.1",
        SCRAM_PASSWORD,
    )
    .await;
    let mut c = h.login().await;
    let ready = c.ready().await;
    assert_eq!(h.cancels.len(), 1);

    // A guessed key cancels nothing: the query runs to completion.
    let guess = CancelRequest::new(
        ready.pid,
        SecretKey::I32(i32::from_be_bytes(ready.secret[..4].try_into().unwrap()) ^ 1),
    );
    send_cancel(&h, &guess).await;
    assert_eq!(
        c.query("SELECT pg_sleep(1), 7").await.map(|r| r.len()),
        Ok(1)
    );

    // The real gateway key cancels the running query (over TLS, as libpq 17 sends it).
    let mut sleep = BytesMut::new();
    let sql = "SELECT pg_sleep(30)";
    sleep.put_u8(b'Q');
    sleep.put_i32(sql.len() as i32 + 5);
    sleep.put_slice(sql.as_bytes());
    sleep.put_u8(0);
    c.stream.write_all(&sleep).await.unwrap();
    c.stream.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    let key = CancelRequest::new(
        ready.pid,
        SecretKey::I32(i32::from_be_bytes(ready.secret[..4].try_into().unwrap())),
    );
    send_cancel(&h, &key).await;
    let started = tokio::time::Instant::now();
    let mut code = None;
    loop {
        let (tag, body) = read_message(&mut c.stream).await.expect("reply");
        match tag {
            b'E' => code = Some(error_fields(&body)[&b'C'].clone()),
            b'Z' => break,
            _ => {}
        }
    }
    assert_eq!(code.as_deref(), Some("57014"), "query_canceled");
    assert!(started.elapsed() < Duration::from_secs(20));
    // The session is still usable.
    assert_eq!(c.query("SELECT 3").await.unwrap(), vec!["3".to_owned()]);

    // Closing the session removes its cancel entry.
    drop(c);
    for _ in 0..50 {
        if h.cancels.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("cancel entry outlived the session");
}

/// A `CancelRequest` on its own TLS connection, as libpq sends it.
async fn send_cancel(h: &Harness, req: &CancelRequest) {
    let mut s = h.tls().await;
    send(&mut s, req).await;
    // No answer; the gateway closes the connection.
    assert!(
        tokio::time::timeout(Duration::from_secs(10), read_message(&mut s))
            .await
            .expect("cancel connection closed")
            .is_none()
    );
}

/// How the fake upstream behaves.
#[derive(Clone, Copy)]
enum Fake {
    /// Ask for a cleartext password.
    Cleartext,
    /// Accept, then answer any query with an error and a notice that echo the password.
    EchoPassword(&'static str),
}

struct FakeServer {
    port: u16,
    startup: tokio::sync::oneshot::Receiver<BTreeMap<String, String>>,
    /// Bytes the gateway sent after the startup message (the password would be here).
    after: tokio::sync::oneshot::Receiver<Vec<u8>>,
}

impl FakeServer {
    async fn start(mode: Fake) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (startup_tx, startup) = tokio::sync::oneshot::channel();
        let (after_tx, after) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let len = s.read_i32().await.unwrap() as usize;
            let mut body = vec![0u8; len - 4];
            s.read_exact(&mut body).await.unwrap();
            let mut params = BTreeMap::new();
            let mut parts = body[4..].split(|b| *b == 0);
            while let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                if k.is_empty() {
                    break;
                }
                params.insert(
                    String::from_utf8_lossy(k).into_owned(),
                    String::from_utf8_lossy(v).into_owned(),
                );
            }
            let _ = startup_tx.send(params);
            match mode {
                Fake::Cleartext => {
                    s.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 3]).await.unwrap();
                    let mut got = Vec::new();
                    let _ =
                        tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut got)).await;
                    let _ = after_tx.send(got);
                }
                Fake::EchoPassword(password) => {
                    let mut out = vec![b'R', 0, 0, 0, 8, 0, 0, 0, 0];
                    out.extend_from_slice(&[b'K', 0, 0, 0, 12, 0, 0, 0, 42, 0, 0, 0, 7]);
                    out.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);
                    s.write_all(&out).await.unwrap();
                    // Wait for a query, then echo the password in an E and an N.
                    let mut q = [0u8; 1];
                    s.read_exact(&mut q).await.unwrap();
                    let mut buf = vec![0u8; 256];
                    let _ =
                        tokio::time::timeout(Duration::from_millis(200), s.read(&mut buf)).await;
                    for tag in *b"NE" {
                        let mut f = Vec::new();
                        for (c, v) in [
                            (b'S', "ERROR".to_owned()),
                            (b'C', "P0001".to_owned()),
                            (b'M', format!("boom {password} boom")),
                        ] {
                            f.push(c);
                            f.extend_from_slice(v.as_bytes());
                            f.push(0);
                        }
                        f.push(0);
                        s.write_all(&frame(tag, &f)).await.unwrap();
                    }
                    s.write_all(&[b'Z', 0, 0, 0, 5, b'I']).await.unwrap();
                    let _ = after_tx.send(Vec::new());
                    let mut sink = Vec::new();
                    let _ = s.read_to_end(&mut sink).await;
                }
            }
        });
        Self {
            port,
            startup,
            after,
        }
    }
}

#[tokio::test]
async fn pg_relay_cleartext_over_a_plain_network_is_refused() {
    let fake = FakeServer::start(Fake::Cleartext).await;
    // `db.test` is not loopback by name and the leg is plain (`disable`).
    let h = Harness::start(
        binding(fake.port, "app_rw", PgTls::Disable, "db.test"),
        "127.0.0.1",
        SCRAM_PASSWORD,
    )
    .await;
    let mut c = h.login().await;
    let msgs = read_all(&mut c.stream).await;
    assert_eq!(msgs.len(), 1, "one fixed error, then close");
    assert_eq!(msgs[0].0, b'E');
    assert_eq!(error_fields(&msgs[0].1)[&b'C'], "08001");
    assert!(!String::from_utf8_lossy(&msgs[0].1).contains(SCRAM_PASSWORD));

    // The upstream never got a byte after its startup: no password was sent.
    let sent = fake.after.await.unwrap();
    assert!(sent.is_empty(), "{} bytes reached the upstream", sent.len());
    // Only the bound identity and the allow-listed parameters were sent.
    let params = fake.startup.await.unwrap();
    assert_eq!(
        params,
        BTreeMap::from([
            ("user".to_owned(), "app_rw".to_owned()),
            ("database".to_owned(), "app".to_owned()),
            ("application_name".to_owned(), "relay".to_owned()),
        ])
    );
    assert!(h.cancels.is_empty());
}

#[tokio::test]
async fn pg_relay_cleartext_to_a_loopback_host_is_answered() {
    let fake = FakeServer::start(Fake::Cleartext).await;
    let h = Harness::start(
        binding(fake.port, "app_rw", PgTls::Disable, "localhost"),
        "127.0.0.1",
        SCRAM_PASSWORD,
    )
    .await;
    let mut c = h.login().await;
    let _ = read_all(&mut c.stream).await;
    let sent = fake.after.await.unwrap();
    // `p`, length, password, NUL.
    assert_eq!(sent[0], b'p');
    assert_eq!(&sent[5..sent.len() - 1], SCRAM_PASSWORD.as_bytes());
}

#[tokio::test]
async fn pg_relay_error_and_notice_text_is_redacted() {
    let password = "canary-echo-Xv2/r+D4=";
    let fake = FakeServer::start(Fake::EchoPassword(password)).await;
    let h = Harness::start(
        binding(fake.port, "app_rw", PgTls::Disable, "localhost"),
        "127.0.0.1",
        password,
    )
    .await;
    let mut c = h.login().await;
    let ready = c.ready().await;
    // The gateway replaced the upstream key (42, 7).
    assert!(ready.pid != 42 || ready.secret[..] != [0, 0, 0, 7]);

    let m = [b'Q', 0, 0, 0, 6, b'x', 0];
    c.stream.write_all(&m).await.unwrap();
    let mut texts = Vec::new();
    loop {
        let (tag, body) = read_message(&mut c.stream).await.unwrap();
        if tag == b'Z' {
            break;
        }
        assert!(matches!(tag, b'N' | b'E'));
        texts.push(String::from_utf8_lossy(&body).into_owned());
    }
    assert_eq!(texts.len(), 2);
    for t in &texts {
        assert!(!t.contains(password), "password reached the client: {t}");
        assert!(t.contains("boom"), "the rest of the message survives");
    }
}
