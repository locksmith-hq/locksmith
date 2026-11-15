//! Daemon wire protocol: one length-prefixed CBOR frame per message, versioned envelope,
//! one operation per request (design: openspec/changes/m3-daemon-sessions/design.md).
//!
//! Invariant (spec broker-daemon "No plaintext egress over IPC"): no [`Response`] carries a
//! secret value. Secrets leave the daemon only as environment variables of a child process the
//! daemon itself spawns (`Request::Run`). `tests::no_response_carries_secret_material` enforces it.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub const PROTOCOL_VERSION: u16 = 1;
/// Upper bound for one frame; larger lengths are rejected before allocating.
pub const MAX_FRAME: u32 = 1 << 20;
pub const SOCKET_FILE: &str = "locksmithd.sock";
pub const LOCK_FILE: &str = "locksmithd.lock";

/// Directory holding the socket and the single-instance lock (forced to 0700 by the daemon).
/// `LOCKSMITH_RUNTIME_DIR` overrides; with `LOCKSMITH_HOME` set it is `$LOCKSMITH_HOME/run` so
/// isolated homes never share a daemon; on Linux `$XDG_RUNTIME_DIR/locksmith` when available.
pub fn runtime_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("LOCKSMITH_RUNTIME_DIR") {
        return PathBuf::from(d);
    }
    if std::env::var_os("LOCKSMITH_HOME").is_none()
        && cfg!(target_os = "linux")
        && let Some(x) = std::env::var_os("XDG_RUNTIME_DIR")
    {
        return PathBuf::from(x).join("locksmith");
    }
    ls_core::config_dir().join("run")
}

pub fn socket_path() -> PathBuf {
    runtime_dir().join(SOCKET_FILE)
}

/// Passphrase sent client → daemon for unlock. Zeroized on drop; no Debug/Display/Clone.
pub struct Passphrase(Vec<u8>);

impl Passphrase {
    pub fn new(v: Vec<u8>) -> Self {
        Self(v)
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for Passphrase {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl Serialize for Passphrase {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}
impl<'de> Deserialize<'de> for Passphrase {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
        }
        Ok(Self(d.deserialize_byte_buf(V)?))
    }
}

#[derive(Serialize, Deserialize)]
pub enum Request {
    /// Version and liveness. The only request served to unattested callers.
    Ping,
    Unlock {
        passphrase: Passphrase,
    },
    /// Drop key material; leases are kept but suspended until the next unlock.
    Lock,
    /// Create a lease rooted at the calling process (kernel-identified, never a claim).
    /// Always carries the passphrase: an unlocked vault must not let any attested `smith`
    /// (e.g. one an agent double-forked out of its session tree) mint a lease on its own.
    SessionStart {
        passphrase: Passphrase,
        ttl_secs: u64,
        project: String,
        env: String,
        scopes: Vec<String>,
        /// Agent command line, for `smith status` display only.
        command: String,
        /// The `.locksmith.toml` in effect where the session starts. The daemon pins it for the
        /// lease: HTTP token hosts and database targets come from this copy, never from a file
        /// edited later inside the session.
        #[serde(default)]
        binding: Option<Vec<u8>>,
    },
    /// End the lease rooted at the calling process (agent exited).
    SessionEnd,
    Status,
    /// `None` revokes every lease.
    Revoke {
        id: Option<String>,
    },
    /// Spawn `cmd` with secrets injected, under the lease the caller descends from. The client
    /// sends its stdin/stdout/stderr right after this frame (SCM_RIGHTS); the daemon replies
    /// `RunStarted`, accepts `Signal` frames, and finishes with `RunExited`.
    Run(RunSpec),
    /// Forward a signal to the running child of this connection.
    Signal {
        sig: i32,
    },
    AuditList {
        limit: u32,
    },
    AuditVerify,
    /// Which vault secrets (any encoding) occur in `text`? Answered with key names only.
    ScanText {
        text: String,
    },
    /// Same for the content of the regular file at absolute `path` (read by the daemon).
    ScanPath {
        path: PathBuf,
    },
    /// `smith git credential get`: mint a forwarder token for `host`/`repo` under the caller's
    /// lease (scope `git`). `remotes` are the repository's own `host/owner/repo` remotes, used
    /// as the allowlist when the binding lists none. Never returns the upstream credential.
    GitCredential {
        host: String,
        repo: String,
        binding: Option<Vec<u8>>,
        remotes: Vec<String>,
    },
    /// Forwarder port and include-file path (for `smith git setup|status`, doctor).
    GitInfo,
    /// `smith db connect <name>`: open (or reuse) this session's loopback relay for the
    /// binding's `[db.<name>]` target, under the caller's lease (scope `db`). Answered with
    /// [`Response::DbEndpoint`]; never returns the password.
    DbConnect {
        name: String,
        binding: Option<Vec<u8>>,
    },
    /// Names of the keys stored for `project`/`env` (never values; for doctor). Needs an
    /// unlocked vault.
    KeyNames {
        project: String,
        env: String,
    },
    /// `smith token issue`: mint an opaque `lsk_` token for vault key `key` under the caller's
    /// lease (scope `http`). Hosts and placement come from these fields, else the binding's
    /// `[http.keys]` entry, else the provider catalog. Never returns the value (M6 D1).
    TokenIssue {
        key: String,
        provider: Option<String>,
        hosts: Vec<String>,
        placement: Option<String>,
        binding: Option<Vec<u8>>,
    },
    /// Live opaque tokens: names, hosts, placements, leases and a short prefix only.
    TokenList,
    /// Revoke one token (the token or a unique prefix of at least 12 characters), or all.
    TokenRevoke {
        token: Option<String>,
    },
    /// HTTP relay port and the hosts enabled for explicit-proxy mode (doctor, `smith http`).
    HttpInfo,
    /// Record a hook decision (deny or ask) in the audit ledger.
    HookAudit {
        agent: String,
        event: String,
        decision: String,
        rule: String,
        target: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RunSpec {
    pub project: Option<String>,
    pub env: Option<String>,
    /// Keys to inject; empty means "the binding's keys" (or all with `all_keys`).
    pub keys: Vec<String>,
    pub all_keys: bool,
    /// Raw `.locksmith.toml` contents if one applies (key names only; re-checked by the daemon).
    pub binding: Option<Vec<u8>>,
    pub cmd: Vec<String>,
    pub cwd: PathBuf,
    /// The client's environment (names and values), minus LOCKSMITH_* variables.
    pub environ: Vec<(String, String)>,
    /// `smith gh`: inject only `GH_TOKEN` (the github.com upstream credential, an installation
    /// token for this `owner/repo` in App mode) under the `git` scope. Contained (M5 D5).
    #[serde(default)]
    pub gh: Option<GhSpec>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GhSpec {
    pub repo: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Response {
    Pong {
        version: String,
    },
    Ok,
    Session {
        id: String,
        expires_at: i64,
    },
    Status {
        locked: bool,
        leases: Vec<LeaseInfo>,
    },
    Revoked {
        count: u32,
    },
    RunStarted {
        pid: u32,
    },
    RunExited {
        code: i32,
    },
    Audit {
        events: Vec<AuditEvent>,
    },
    AuditVerify {
        events: u64,
        /// First broken sequence number, if any.
        broken_at: Option<u64>,
        detail: String,
    },
    /// Session-scoped forwarder token (not the upstream credential).
    GitToken {
        username: String,
        token: String,
    },
    GitInfo {
        port: u16,
        include: PathBuf,
        hosts: Vec<String>,
    },
    /// A password-less local database endpoint on `127.0.0.1:<port>` (M6). Identifiers only.
    DbEndpoint {
        kind: String,
        port: u16,
        user: String,
        database: Option<String>,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
    /// Names of the secrets a scan found (never values).
    Keys {
        keys: Vec<String>,
    },
    /// Opaque relay token (a placeholder, not the credential) and the relay base URL.
    HttpToken(Box<IssuedToken>),
    HttpTokens {
        tokens: Vec<HttpTokenInfo>,
    },
    HttpInfo {
        port: u16,
        /// Hosts the local CA is constrained to; empty when explicit-proxy mode is off.
        ca_hosts: Vec<String>,
    },
}

/// `Response::HttpToken` (boxed: keeps `Response` small).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IssuedToken {
    pub token: String,
    pub key: String,
    pub hosts: Vec<String>,
    pub placement: String,
    pub lease: String,
    pub base_url: Option<String>,
}

/// A live opaque token as `smith token ls` shows it: never the full token, never a value.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HttpTokenInfo {
    pub prefix: String,
    pub key: String,
    pub project: String,
    pub env: String,
    pub hosts: Vec<String>,
    pub placement: String,
    pub lease: String,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Vault locked, or the lease is missing, expired or revoked (exit 4).
    Locked,
    /// Caller failed attestation or policy (exit 3).
    Denied,
    NotFound,
    BadRequest,
    /// Peer speaks another protocol version.
    Version,
    Internal,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LeaseInfo {
    pub id: String,
    pub root_pid: u32,
    pub command: String,
    pub project: String,
    pub env: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub state: String,
}

/// An audit row as shown to users. Never holds a value, only identifiers.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AuditEvent {
    pub seq: u64,
    pub ts: i64,
    pub session_id: Option<String>,
    pub actor_pid: u32,
    pub actor_exe: String,
    pub action: String,
    pub target: Option<String>,
    pub policy_rule: String,
    pub decision: String,
}

#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    v: u16,
    body: T,
}

fn encode<T: Serialize>(body: &T) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 4];
    ciborium::into_writer(
        &Envelope {
            v: PROTOCOL_VERSION,
            body,
        },
        &mut buf,
    )
    .map_err(|e| io::Error::other(e.to_string()))?;
    let n = u32::try_from(buf.len() - 4)
        .ok()
        .filter(|n| *n <= MAX_FRAME)
        .ok_or_else(|| io::Error::other("frame too large"))?;
    buf[..4].copy_from_slice(&n.to_be_bytes());
    Ok(buf)
}

/// Write one frame.
pub fn write_frame<T: Serialize>(w: &mut impl Write, body: &T) -> io::Result<()> {
    let mut buf = encode(body)?;
    let r = w.write_all(&buf).and_then(|_| w.flush());
    buf.zeroize(); // a request frame may hold a passphrase
    r
}

/// Outcome of reading a frame.
pub enum Frame<T> {
    Msg(T),
    /// Well-formed frame from another protocol version.
    Version(u16),
}

/// Read one frame. `Ok(None)` on clean EOF before a frame starts.
pub fn read_frame<T: for<'de> Deserialize<'de>>(r: &mut impl Read) -> io::Result<Option<Frame<T>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len);
    if n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; n as usize];
    r.read_exact(&mut buf)?;
    #[derive(Deserialize)]
    struct Head {
        v: u16,
    }
    let out = match ciborium::from_reader::<Head, _>(&buf[..]) {
        Ok(h) if h.v != PROTOCOL_VERSION => Ok(Some(Frame::Version(h.v))),
        _ => ciborium::from_reader::<Envelope<T>, _>(&buf[..])
            .map(|e| Some(Frame::Msg(e.body)))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    };
    buf.zeroize();
    out
}

/// A blocking client connection to the daemon.
pub struct Client {
    pub stream: UnixStream,
}

impl Client {
    pub fn connect(path: &Path) -> io::Result<Client> {
        Ok(Client {
            stream: UnixStream::connect(path)?,
        })
    }

    /// Connect to the per-user daemon at [`socket_path`].
    pub fn connect_default() -> io::Result<Client> {
        Self::connect(&socket_path())
    }

    pub fn send(&mut self, req: &Request) -> io::Result<()> {
        write_frame(&mut self.stream, req)
    }

    pub fn recv(&mut self) -> io::Result<Response> {
        match read_frame(&mut self.stream)? {
            Some(Frame::Msg(r)) => Ok(r),
            Some(Frame::Version(v)) => Err(io::Error::other(format!(
                "daemon speaks protocol v{v}, this client v{PROTOCOL_VERSION}; restart the daemon"
            ))),
            None => Err(io::ErrorKind::UnexpectedEof.into()),
        }
    }

    /// One request, one response.
    pub fn call(&mut self, req: &Request) -> io::Result<Response> {
        self.send(req)?;
        self.recv()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;

    /// One instance of every response variant. The match below fails to compile when a variant
    /// is added without extending this list, so the schema test cannot silently miss one.
    fn every_response() -> Vec<Response> {
        let all = vec![
            Response::Pong {
                version: "0".into(),
            },
            Response::Ok,
            Response::Session {
                id: "s".into(),
                expires_at: 1,
            },
            Response::Status {
                locked: false,
                leases: vec![LeaseInfo {
                    id: "s".into(),
                    root_pid: 1,
                    command: "claude".into(),
                    project: "p".into(),
                    env: "e".into(),
                    scopes: vec!["run".into()],
                    created_at: 1,
                    expires_at: 2,
                    state: "active".into(),
                }],
            },
            Response::Revoked { count: 1 },
            Response::RunStarted { pid: 1 },
            Response::RunExited { code: 0 },
            Response::Audit {
                events: vec![AuditEvent {
                    seq: 1,
                    ts: 1,
                    session_id: Some("s".into()),
                    actor_pid: 1,
                    actor_exe: "/bin/smith".into(),
                    action: "ACCESS".into(),
                    target: Some("p/e/K".into()),
                    policy_rule: "lease".into(),
                    decision: "ALLOW".into(),
                }],
            },
            Response::AuditVerify {
                events: 1,
                broken_at: None,
                detail: String::new(),
            },
            Response::Error {
                code: ErrorCode::Internal,
                message: "m".into(),
            },
            Response::Keys {
                keys: vec!["STRIPE_KEY".into()],
            },
            // The forwarder token is session-scoped by design (M5 D2), never the upstream one.
            Response::GitToken {
                username: "locksmith".into(),
                token: "fwd".into(),
            },
            Response::GitInfo {
                port: 1,
                include: "/x".into(),
                hosts: vec!["github.com".into()],
            },
            Response::DbEndpoint {
                kind: "postgres".into(),
                port: 5432,
                user: "app".into(),
                database: Some("appdb".into()),
            },
            // Opaque relay token: a placeholder bound to a lease (M6 D1), not the credential.
            Response::HttpToken(Box::new(IssuedToken {
                token: "lsk_x".into(),
                key: "STRIPE_KEY".into(),
                hosts: vec!["api.stripe.com".into()],
                placement: "bearer".into(),
                lease: "s".into(),
                base_url: Some("http://127.0.0.1:1/h/api.stripe.com".into()),
            })),
            Response::HttpTokens {
                tokens: vec![HttpTokenInfo {
                    prefix: "lsk_12345678".into(),
                    key: "STRIPE_KEY".into(),
                    project: "p".into(),
                    env: "e".into(),
                    hosts: vec!["api.stripe.com".into()],
                    placement: "bearer".into(),
                    lease: "s".into(),
                    created_at: 1,
                }],
            },
            Response::HttpInfo {
                port: 1,
                ca_hosts: vec![],
            },
        ];
        for r in &all {
            match r {
                Response::Pong { .. }
                | Response::Ok
                | Response::Session { .. }
                | Response::Status { .. }
                | Response::Revoked { .. }
                | Response::RunStarted { .. }
                | Response::RunExited { .. }
                | Response::Audit { .. }
                | Response::AuditVerify { .. }
                | Response::Error { .. }
                | Response::Keys { .. }
                | Response::GitToken { .. }
                | Response::GitInfo { .. }
                | Response::DbEndpoint { .. }
                | Response::HttpToken(_)
                | Response::HttpTokens { .. }
                | Response::HttpInfo { .. } => {}
            }
        }
        all
    }

    const FORBIDDEN: &[&str] = &[
        "value",
        "values",
        "secret",
        "secret_value",
        "plaintext",
        "password",
        "passphrase",
        "phrase",
        "payload",
        "vk",
        "dek",
        "key_material",
        "env_value",
    ];

    /// Walk a CBOR value: no forbidden field name and no byte string anywhere.
    fn audit(v: &Value, path: &str) {
        match v {
            Value::Bytes(_) => panic!("byte string in response at {path}"),
            Value::Map(m) => {
                for (k, v) in m {
                    if let Value::Text(k) = k {
                        assert!(
                            !FORBIDDEN.contains(&k.to_lowercase().as_str()),
                            "forbidden field {path}.{k}"
                        );
                        audit(v, &format!("{path}.{k}"));
                    } else {
                        audit(v, path);
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|v| audit(v, path)),
            Value::Tag(_, v) => audit(v, path),
            _ => {}
        }
    }

    #[test]
    fn no_response_carries_secret_material() {
        for r in every_response() {
            audit(&Value::serialized(&r).unwrap(), "response");
        }
    }

    #[test]
    fn frames_roundtrip() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        for r in every_response() {
            write_frame(&mut a, &r).unwrap();
            match read_frame::<Response>(&mut b).unwrap() {
                Some(Frame::Msg(got)) => assert_eq!(got, r),
                _ => panic!("no frame"),
            }
        }
        write_frame(
            &mut a,
            &Request::Unlock {
                passphrase: Passphrase::new(b"pw".to_vec()),
            },
        )
        .unwrap();
        match read_frame::<Request>(&mut b).unwrap() {
            Some(Frame::Msg(Request::Unlock { passphrase })) => {
                assert_eq!(passphrase.expose(), b"pw")
            }
            _ => panic!("bad unlock"),
        }
        drop(a);
        assert!(
            read_frame::<Request>(&mut b).unwrap().is_none(),
            "clean EOF"
        );
    }

    #[test]
    fn other_version_and_oversize_frames_are_rejected() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let mut buf = vec![0u8; 4];
        ciborium::into_writer(
            &Envelope {
                v: 99u16,
                body: &Request::Ping,
            },
            &mut buf,
        )
        .unwrap();
        let n = (buf.len() - 4) as u32;
        buf[..4].copy_from_slice(&n.to_be_bytes());
        a.write_all(&buf).unwrap();
        assert!(matches!(
            read_frame::<Request>(&mut b).unwrap(),
            Some(Frame::Version(99))
        ));
        a.write_all(&(MAX_FRAME + 1).to_be_bytes()).unwrap();
        assert!(read_frame::<Request>(&mut b).is_err());
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&3u32.to_be_bytes()).unwrap();
        a.write_all(b"\xff\x00\x13").unwrap();
        assert!(read_frame::<Request>(&mut b).is_err());
    }
}
