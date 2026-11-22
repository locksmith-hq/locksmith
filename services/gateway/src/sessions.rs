//! Live agent sessions: reporting, and closing them on revoke or pause (change
//! t8-sessions-and-revoke, task 3.1).
//!
//! Requests that open or continue an agent session call [`Sessions::enter`] after the caller
//! passed the revoke and pause check ([`crate::relay::Relay::admit`]). The registry keeps one
//! live entry per agent token (`jti`), kind and slug. A background tick ([`Sessions::run`], every
//! [`HEARTBEAT`]) does three things, all in one place so the control plane sees one small batch:
//!
//! 1. refreshes each live agent's grant set from the control plane (never from a cache older than
//!    the call, [`crate::grants::GrantSource::refresh`]) and closes the sessions of a paused org
//!    and of a revoked `jti`;
//! 2. closes sessions whose refresh keeps failing for a whole cache TTL (fail closed), and idle
//!    ones;
//! 3. reports `open`, `heartbeat` and `close` to the control plane's internal sessions endpoint.
//!
//! A closed session is never heartbeated again (a heartbeat after a close would revive it in the
//! control plane's list). Holders of a [`SessionHandle`] race their work against
//! [`SessionHandle::closed`], and streamed responses end with [`end_when_closed`], so a live
//! request stops within one tick plus one fetch: inside the 10 s cache TTL the spec allows.
//!
//! This is the gateway's watcher for every kind of session. The Postgres relay (d3) is not on
//! this branch; when it lands it enters with [`SessionKind::Pg`] and races its relay loop against
//! `closed()`, reusing this tick instead of a second watcher.
//!
//! Nothing here handles a secret value; the report carries ids, a kind and a fixed label only.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::response::Response;
use tokio::sync::watch;
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::auth::AgentIdentity;
use crate::decrypt::{BoxFuture, ControlPlane};
use crate::grants::{GrantError, GrantSet, GrantSource};
use crate::ttl::MAX_CACHE_TTL;

/// How often live sessions are heartbeated (t8 design decision 1). Three missed heartbeats (15 s)
/// and the control plane stops listing the session as live.
pub const HEARTBEAT: Duration = Duration::from_secs(5);

/// A session with no request for this long has ended.
pub const IDLE: Duration = Duration::from_secs(30);

/// Path of the control plane's internal report endpoint.
const REPORT_PATH: &str = "internal/v1/sessions";
/// Largest report answer read.
const MAX_REPORT_RESPONSE: usize = 4096;

/// Which gateway path a session came in on; the control plane's session kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionKind {
    /// An HTTP relay (`/v1/relay`, `/git/...`).
    Http,
    /// A Postgres relay (d3).
    Pg,
    /// A remote MCP session (`/mcp`).
    Mcp,
}

impl SessionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Pg => "pg",
            Self::Mcp => "mcp",
        }
    }
}

/// A report did not land. Carries nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportError;

/// What the gateway tells the control plane about its sessions.
pub trait SessionReporter: Send + Sync {
    /// A session opened; the answer is the control plane's id for it.
    fn open(
        &self,
        agent_id: Uuid,
        token_jti: Uuid,
        kind: SessionKind,
        slug: &str,
    ) -> BoxFuture<'_, Result<Uuid, ReportError>>;
    /// The session is still open.
    fn heartbeat(&self, session_id: Uuid) -> BoxFuture<'_, Result<(), ReportError>>;
    /// The session ended.
    fn close(&self, session_id: Uuid) -> BoxFuture<'_, Result<(), ReportError>>;
}

impl ControlPlane {
    async fn report(&self, body: serde_json::Value) -> Result<(u16, Vec<u8>), ReportError> {
        self.internal_post_json(
            REPORT_PATH,
            body.to_string().into_bytes(),
            MAX_REPORT_RESPONSE,
        )
        .await
        .map_err(|_| ReportError)
    }

    async fn report_open(
        &self,
        agent_id: Uuid,
        token_jti: Uuid,
        kind: SessionKind,
        slug: &str,
    ) -> Result<Uuid, ReportError> {
        #[derive(serde::Deserialize)]
        struct Opened {
            id: Uuid,
        }
        let (status, body) = self
            .report(serde_json::json!({
                "event": "open",
                "agent_id": agent_id,
                "token_jti": token_jti,
                "kind": kind.as_str(),
                "slug": slug,
            }))
            .await?;
        if status != 201 {
            return Err(ReportError);
        }
        serde_json::from_slice::<Opened>(&body)
            .map(|o| o.id)
            .map_err(|_| ReportError)
    }

    async fn report_event(&self, event: &str, session_id: Uuid) -> Result<(), ReportError> {
        let (status, _) = self
            .report(serde_json::json!({ "event": event, "session_id": session_id }))
            .await?;
        if status == 204 {
            Ok(())
        } else {
            Err(ReportError)
        }
    }
}

impl SessionReporter for ControlPlane {
    fn open(
        &self,
        agent_id: Uuid,
        token_jti: Uuid,
        kind: SessionKind,
        slug: &str,
    ) -> BoxFuture<'_, Result<Uuid, ReportError>> {
        let slug = slug.to_owned();
        Box::pin(async move { self.report_open(agent_id, token_jti, kind, &slug).await })
    }

    fn heartbeat(&self, session_id: Uuid) -> BoxFuture<'_, Result<(), ReportError>> {
        Box::pin(self.report_event("heartbeat", session_id))
    }

    fn close(&self, session_id: Uuid) -> BoxFuture<'_, Result<(), ReportError>> {
        Box::pin(self.report_event("close", session_id))
    }
}

/// Timing of the registry.
#[derive(Debug, Clone, Copy)]
pub struct SessionSettings {
    /// How long a failing refresh keeps a session open before it is closed (fail closed). At
    /// most the grant cache TTL.
    pub ttl: Duration,
    /// A session with no request for this long ends.
    pub idle: Duration,
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            ttl: MAX_CACHE_TTL,
            idle: IDLE,
        }
    }
}

type Key = (Uuid, SessionKind, String);

struct EntryState {
    /// The control plane's id once `open` landed.
    remote: Option<Uuid>,
    last_activity: Instant,
    /// The last time the revoke and pause state was read successfully.
    last_ok: Instant,
}

struct Entry {
    agent_id: Uuid,
    jti: Uuid,
    kind: SessionKind,
    slug: String,
    closed: watch::Sender<bool>,
    state: Mutex<EntryState>,
}

impl Entry {
    fn lock(&self) -> MutexGuard<'_, EntryState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    fn close(&self) {
        self.closed.send_replace(true);
    }
}

/// A live session as the request holding it sees it. Cheap to clone.
#[derive(Clone)]
pub struct SessionHandle(Arc<Entry>);

impl SessionHandle {
    /// Resolves once the gateway closed the session (revoke, pause, refresh failure or idle).
    /// Never resolves for a session that stays open, so race it with the work.
    pub async fn closed(&self) {
        let mut rx = self.0.closed.subscribe();
        let _ = rx.wait_for(|c| *c).await;
    }

    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}

/// The registry of live sessions and their watcher. Share it behind an `Arc`.
pub struct Sessions {
    source: Arc<dyn GrantSource>,
    reporter: Arc<dyn SessionReporter>,
    settings: SessionSettings,
    live: Mutex<HashMap<Key, Arc<Entry>>>,
}

impl Sessions {
    /// `source` is the grant source the relay reads (its [`GrantSource::refresh`] is what the
    /// watcher calls); `reporter` is the control plane's report endpoint.
    pub fn new(
        source: Arc<dyn GrantSource>,
        reporter: Arc<dyn SessionReporter>,
        settings: SessionSettings,
    ) -> Self {
        Self {
            source,
            reporter,
            settings: SessionSettings {
                ttl: settings.ttl.min(MAX_CACHE_TTL),
                ..settings
            },
            live: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<Key, Arc<Entry>>> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// How many sessions are open locally.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Register a request of an agent that passed the revoke and pause check, as part of its
    /// session of `kind` on `slug` (a fixed, non-secret label). `None` for a caller without a
    /// token `jti` (a short-lived credential), which has no session of its own.
    pub fn enter(
        &self,
        agent: &AgentIdentity,
        kind: SessionKind,
        slug: &str,
    ) -> Option<SessionHandle> {
        self.enter_at(agent, kind, slug, Instant::now())
    }

    fn enter_at(
        &self,
        agent: &AgentIdentity,
        kind: SessionKind,
        slug: &str,
        now: Instant,
    ) -> Option<SessionHandle> {
        let jti = agent.jti?;
        let key = (jti, kind, slug.to_owned());
        let mut live = self.lock();
        if let Some(e) = live.get(&key).filter(|e| !e.is_closed()) {
            e.lock().last_activity = now;
            return Some(SessionHandle(e.clone()));
        }
        let entry = Arc::new(Entry {
            agent_id: agent.agent_id,
            jti,
            kind,
            slug: slug.to_owned(),
            closed: watch::channel(false).0,
            state: Mutex::new(EntryState {
                remote: None,
                last_activity: now,
                last_ok: now,
            }),
        });
        live.insert(key, entry.clone());
        Some(SessionHandle(entry))
    }

    /// Run [`Self::tick`] every `interval` until the task is aborted.
    pub fn run(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                timer.tick().await;
                self.tick(Instant::now()).await;
            }
        })
    }

    /// One watcher pass at `now`: refresh, close, report. See the module docs.
    pub async fn tick(&self, now: Instant) {
        let entries: Vec<Arc<Entry>> = self.lock().values().cloned().collect();
        if entries.is_empty() {
            return;
        }

        // 1. The revoke and pause state of every agent with a live session.
        let agents: HashSet<Uuid> = entries
            .iter()
            .filter(|e| !e.is_closed())
            .map(|e| e.agent_id)
            .collect();
        let timeout = (self.settings.ttl / 2).max(Duration::from_millis(1));
        let mut reads = JoinSet::new();
        for agent_id in agents {
            let source = self.source.clone();
            reads.spawn(async move {
                let read = tokio::time::timeout(timeout, source.refresh(agent_id))
                    .await
                    .unwrap_or(Err(GrantError::Unavailable));
                (agent_id, read)
            });
        }
        let mut state: HashMap<Uuid, Result<GrantSet, GrantError>> = HashMap::new();
        while let Some(done) = reads.join_next().await {
            if let Ok((agent_id, read)) = done {
                state.insert(agent_id, read);
            }
        }

        // 2. Close what must not stay open.
        for e in &entries {
            if e.is_closed() {
                continue;
            }
            let reason = {
                let mut s = e.lock();
                if now.saturating_duration_since(s.last_activity) >= self.settings.idle {
                    Some("idle")
                } else {
                    match state.get(&e.agent_id) {
                        Some(Ok(set)) => {
                            s.last_ok = now;
                            set.refuses(Some(e.jti)).then_some(if set.agents_paused {
                                "paused"
                            } else {
                                "revoked"
                            })
                        }
                        // Fail closed: the state could not be read for a whole TTL.
                        Some(Err(_)) | None
                            if now.saturating_duration_since(s.last_ok) >= self.settings.ttl =>
                        {
                            Some("state_unreadable")
                        }
                        Some(Err(_)) | None => None,
                    }
                }
            };
            if let Some(reason) = reason {
                e.close();
                tracing::info!(
                    agent.id = %e.agent_id,
                    session.kind = e.kind.as_str(),
                    reason,
                    "agent session closed"
                );
            }
        }

        // 3. Report: close what closed (and forget it), open what is new, heartbeat the rest.
        let mut reports: JoinSet<(Arc<Entry>, Report)> = JoinSet::new();
        for e in entries {
            let remote = e.lock().remote;
            let reporter = self.reporter.clone();
            if e.is_closed() {
                self.forget(&e);
                if let Some(id) = remote {
                    reports.spawn(async move {
                        let r = reporter.close(id).await;
                        (e, Report::Closed(r))
                    });
                }
            } else if let Some(id) = remote {
                reports.spawn(async move {
                    let r = reporter.heartbeat(id).await;
                    (e, Report::Heartbeat(r))
                });
            } else {
                reports.spawn(async move {
                    let r = reporter.open(e.agent_id, e.jti, e.kind, &e.slug).await;
                    (e, Report::Opened(r))
                });
            }
        }
        while let Some(done) = reports.join_next().await {
            let Ok((e, report)) = done else { continue };
            match report {
                Report::Opened(Ok(id)) => e.lock().remote = Some(id),
                // Retried on the next tick: the entry keeps no remote id.
                Report::Opened(Err(_)) => {
                    tracing::warn!(session.kind = e.kind.as_str(), "session open not reported")
                }
                Report::Heartbeat(Err(_)) | Report::Closed(Err(_)) => {
                    tracing::warn!(session.kind = e.kind.as_str(), "session report failed")
                }
                Report::Heartbeat(Ok(())) | Report::Closed(Ok(())) => {}
            }
        }
    }

    fn forget(&self, entry: &Arc<Entry>) {
        let key = (entry.jti, entry.kind, entry.slug.clone());
        let mut live = self.lock();
        if live.get(&key).is_some_and(|e| Arc::ptr_eq(e, entry)) {
            live.remove(&key);
        }
    }
}

enum Report {
    Opened(Result<Uuid, ReportError>),
    Heartbeat(Result<(), ReportError>),
    Closed(Result<(), ReportError>),
}

/// Why a response stream ended before its end.
#[derive(Debug)]
struct SessionClosed;

impl std::fmt::Display for SessionClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("session closed")
    }
}

impl std::error::Error for SessionClosed {}

struct EndWhenClosed {
    inner: Body,
    closed: Pin<Box<dyn Future<Output = ()> + Send>>,
    done: bool,
}

impl http_body::Body for EndWhenClosed {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, axum::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        if self.closed.as_mut().poll(cx).is_ready() {
            self.done = true;
            return Poll::Ready(Some(Err(axum::Error::new(SessionClosed))));
        }
        Pin::new(&mut self.inner).poll_frame(cx)
    }
}

/// Cut `response`'s body with an error as soon as `session` closes, so a streamed answer (an
/// MCP event stream, a Git pack) does not outlive a revoke.
pub fn end_when_closed(response: Response, session: SessionHandle) -> Response {
    response.map(|inner| {
        Body::new(EndWhenClosed {
            inner,
            closed: Box::pin(async move { session.closed().await }),
            done: false,
        })
    })
}

#[cfg(test)]
pub mod testkit {
    use super::*;

    /// One report the stub received.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Seen {
        Open {
            agent_id: Uuid,
            jti: Uuid,
            kind: SessionKind,
            slug: String,
        },
        Heartbeat(Uuid),
        Close(Uuid),
    }

    /// Records every report; ids are handed out in order. `fail` makes every report fail.
    #[derive(Default)]
    pub struct StubReporter {
        pub seen: Mutex<Vec<Seen>>,
        pub fail: std::sync::atomic::AtomicBool,
    }

    impl StubReporter {
        pub fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }

        fn push(&self, s: Seen) -> Result<(), ReportError> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(ReportError);
            }
            self.seen.lock().unwrap().push(s);
            Ok(())
        }
    }

    impl SessionReporter for StubReporter {
        fn open(
            &self,
            agent_id: Uuid,
            token_jti: Uuid,
            kind: SessionKind,
            slug: &str,
        ) -> BoxFuture<'_, Result<Uuid, ReportError>> {
            let r = self
                .push(Seen::Open {
                    agent_id,
                    jti: token_jti,
                    kind,
                    slug: slug.to_owned(),
                })
                .map(|()| Uuid::from_u128(0x5e55_0000 + self.seen.lock().unwrap().len() as u128));
            Box::pin(async move { r })
        }

        fn heartbeat(&self, session_id: Uuid) -> BoxFuture<'_, Result<(), ReportError>> {
            let r = self.push(Seen::Heartbeat(session_id));
            Box::pin(async move { r })
        }

        fn close(&self, session_id: Uuid) -> BoxFuture<'_, Result<(), ReportError>> {
            let r = self.push(Seen::Close(session_id));
            Box::pin(async move { r })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::{Seen, StubReporter};
    use super::*;
    use crate::grants::testkit::StubGrants;

    const AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a1);
    const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_000000000001);

    fn who(jti: Uuid) -> AgentIdentity {
        AgentIdentity {
            agent_id: AGENT,
            org_id: ORG,
            jti: Some(jti),
        }
    }

    fn setup() -> (Arc<StubGrants>, Arc<StubReporter>, Sessions) {
        let grants = Arc::new(StubGrants::default());
        let reporter = Arc::new(StubReporter::default());
        let sessions = Sessions::new(grants.clone(), reporter.clone(), SessionSettings::default());
        (grants, reporter, sessions)
    }

    #[tokio::test]
    async fn sessions_report_open_then_heartbeat_then_close() {
        let (_, reporter, sessions) = setup();
        let jti = Uuid::now_v7();
        let t0 = Instant::now();
        let h = sessions
            .enter_at(&who(jti), SessionKind::Mcp, "mcp", t0)
            .unwrap();
        let again = sessions
            .enter_at(&who(jti), SessionKind::Mcp, "mcp", t0)
            .unwrap();
        assert_eq!(sessions.len(), 1, "one session per token, kind and slug");
        sessions.tick(t0 + Duration::from_secs(1)).await;
        sessions.tick(t0 + Duration::from_secs(6)).await;
        let seen = reporter.seen();
        assert_eq!(
            seen[0],
            Seen::Open {
                agent_id: AGENT,
                jti,
                kind: SessionKind::Mcp,
                slug: "mcp".to_owned()
            }
        );
        assert!(matches!(seen[1], Seen::Heartbeat(_)));
        assert!(!h.is_closed() && !again.is_closed());
        // Idle: no request for the idle time ends it, and the end is reported once.
        sessions.tick(t0 + IDLE + Duration::from_secs(1)).await;
        sessions.tick(t0 + IDLE + Duration::from_secs(6)).await;
        assert!(h.is_closed());
        let seen = reporter.seen();
        assert_eq!(
            seen.iter().filter(|s| matches!(s, Seen::Close(_))).count(),
            1
        );
        assert!(
            matches!(seen.last(), Some(Seen::Close(_))),
            "no heartbeat after the close"
        );
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn sessions_without_a_jti_are_not_tracked() {
        let (_, reporter, sessions) = setup();
        let mut a = who(Uuid::now_v7());
        a.jti = None;
        assert!(sessions.enter(&a, SessionKind::Http, "relay").is_none());
        sessions.tick(Instant::now()).await;
        assert!(reporter.seen().is_empty());
    }

    #[tokio::test]
    async fn sessions_open_report_is_retried_until_it_lands() {
        let (_, reporter, sessions) = setup();
        reporter
            .fail
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let t0 = Instant::now();
        sessions
            .enter_at(&who(Uuid::now_v7()), SessionKind::Http, "relay", t0)
            .unwrap();
        sessions.tick(t0).await;
        assert!(reporter.seen().is_empty());
        reporter
            .fail
            .store(false, std::sync::atomic::Ordering::SeqCst);
        sessions.tick(t0 + HEARTBEAT).await;
        assert!(matches!(reporter.seen()[0], Seen::Open { .. }));
    }

    /// A body that never produces a frame.
    struct Never;

    impl http_body::Body for Never {
        type Data = Bytes;
        type Error = axum::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Bytes>, axum::Error>>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn sessions_end_when_closed_cuts_a_stream() {
        use http_body_util::BodyExt;
        let (grants, _, sessions) = setup();
        let jti = Uuid::now_v7();
        let h = sessions.enter(&who(jti), SessionKind::Mcp, "mcp").unwrap();
        let resp = end_when_closed(Response::new(Body::new(Never)), h);
        grants.revoke(jti);
        sessions.tick(Instant::now()).await;
        let end = tokio::time::timeout(Duration::from_secs(1), resp.into_body().collect()).await;
        assert!(matches!(end, Ok(Err(_))), "the stream ended with an error");
    }
}
