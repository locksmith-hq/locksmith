//! Task 3.1 of t8-sessions-and-revoke, gateway half: a paused org or a revoked agent token is
//! refused right after authentication and before any grant, binding, material fetch or decrypt;
//! live sessions are reported and closed within one cache TTL; and state that cannot be read
//! denies (fail closed). The grant cache is read with a zero TTL in the per-request tests, so
//! "the next request" is exact; the watcher tests use real, short TTLs.

use std::time::Instant;

use super::mcp::{INITIALIZE, rpc, session};
use super::*;
use crate::sessions::SessionKind;
use crate::sessions::testkit::{Seen, StubReporter};

async fn upstream_ok(h: &Harness) {
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("fine"))
        .mount(&h.upstream)
        .await;
}

/// How much work a request did: KMS decrypts, material fetches and upstream calls.
async fn work(h: &Harness) -> (usize, usize, usize) {
    (
        h.kms_calls().await,
        Harness::hits(&h.cp).await,
        Harness::hits(&h.upstream).await,
    )
}

async fn relayed(h: &Harness) -> (StatusCode, String) {
    let (status, raw) = h.relay_get(SECRET, &format!("{}/x", h.origin())).await;
    (status, String::from_utf8_lossy(&raw).into_owned())
}

/// The relay request as an owned future, so a test can leave it in flight.
fn in_flight(h: &Harness, url: String) -> tokio::task::JoinHandle<(StatusCode, Instant)> {
    let app = h.app.clone();
    let token = h.token.clone();
    tokio::spawn(async move {
        let body = serde_json::json!({
            "secret_id": SECRET, "version": 1, "method": "GET", "url": url,
        });
        let resp = app
            .oneshot(
                Request::post("/v1/relay")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        (resp.status(), Instant::now())
    })
}

/// A harness that tracks sessions, with a slow upstream so a call stays in flight.
async fn slow(ttl: Duration, reporter: &Arc<StubReporter>) -> Harness {
    let mut setup = Setup {
        grant_ttl: ttl,
        reporter: Some(reporter.clone()),
        ..Setup::default()
    };
    setup.options.timeout = Duration::from_secs(20);
    let h = harness(setup).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(10)))
        .mount(&h.upstream)
        .await;
    h
}

async fn wait_for_open(reporter: &StubReporter) {
    let until = Instant::now() + Duration::from_secs(3);
    while !reporter
        .seen()
        .iter()
        .any(|s| matches!(s, Seen::Open { .. }))
    {
        assert!(Instant::now() < until, "the session was never reported");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// After a pause, no request of any agent decrypts anything: no KMS call, no material fetch, no
/// upstream call, and the refusal is audited as a denial. Resume restores normal checks without
/// re-enrolment.
#[tokio::test]
async fn sessions_revoke_pause_makes_no_decrypt_call() {
    let h = harness(Setup {
        grant_ttl: Duration::ZERO,
        ..Setup::default()
    })
    .await;
    upstream_ok(&h).await;
    assert_eq!(relayed(&h).await.0, StatusCode::OK);
    let before = work(&h).await;
    assert_eq!(before.0, 1, "the first call decrypted");

    h.grants.set_paused(true);
    for _ in 0..3 {
        let (status, body) = relayed(&h).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("\"denied\""), "{body}");
    }
    assert_eq!(work(&h).await, before, "no decrypt, fetch or upstream call");
    assert_eq!(h.outcomes(), ["ok", "denied", "denied", "denied"]);
    h.assert_audit_clean();

    h.grants.set_paused(false);
    assert_eq!(
        relayed(&h).await.0,
        StatusCode::OK,
        "resume restores access"
    );
}

/// A revoked token `jti` is refused before the grant, the material and the KMS; another token of
/// the same agent still works.
#[tokio::test]
async fn sessions_revoke_revoked_jti_is_refused_before_decrypt() {
    let h = harness(Setup {
        grant_ttl: Duration::ZERO,
        ..Setup::default()
    })
    .await;
    upstream_ok(&h).await;
    assert_eq!(relayed(&h).await.0, StatusCode::OK);
    let before = work(&h).await;

    h.grants.revoke(h.jti);
    let (status, body) = relayed(&h).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("\"denied\""), "{body}");
    assert_eq!(work(&h).await, before, "no decrypt, fetch or upstream call");

    // Another token of the same agent: a different session, not revoked.
    let other = h.signer.sign(&agent_claims(ORG, AUDIENCE, 600)).unwrap();
    let (status, _) = h
        .call(
            Some(&other),
            serde_json::json!({
                "secret_id": SECRET, "version": 1, "method": "GET",
                "url": format!("{}/x", h.origin()),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

/// A paused org is refused on `/v1/grants` and on Git too, with no decrypt.
#[tokio::test]
async fn sessions_revoke_pause_refuses_grants_listing_and_git() {
    let h = harness(Setup {
        grant_ttl: Duration::ZERO,
        ..Setup::default()
    })
    .await;
    h.grants.set_paused(true);
    let listed = h
        .app
        .clone()
        .oneshot(
            Request::get("/v1/grants")
                .header("authorization", format!("Bearer {}", h.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::FORBIDDEN);
    let resp = h
        .app
        .clone()
        .oneshot(
            Request::get("/git/github.com/o/r/info/refs?service=git-upload-pack")
                .header("authorization", format!("Bearer {}", h.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(h.kms_calls().await, 0);
    assert_eq!(Harness::hits(&h.cp).await, 0, "no material fetch");
}

/// Spec "Control plane unreachable": state that cannot be read denies, with no decrypt.
#[tokio::test]
async fn sessions_revoke_unreadable_state_denies() {
    let h = harness(Setup {
        grant_ttl: Duration::ZERO,
        ..Setup::default()
    })
    .await;
    upstream_ok(&h).await;
    assert_eq!(relayed(&h).await.0, StatusCode::OK);
    let before = work(&h).await;

    h.grants.set_failing(true);
    let (status, body) = relayed(&h).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.contains("grants_unavailable"), "{body}");
    assert_eq!(work(&h).await, before, "no decrypt, fetch or upstream call");

    h.grants.set_failing(false);
    assert_eq!(relayed(&h).await.0, StatusCode::OK, "readable again");
}

/// Live sessions are reported with open, heartbeat and close; the report holds ids, a kind and a
/// fixed label, never a token or a value.
#[tokio::test]
async fn sessions_revoke_reports_http_sessions() {
    let reporter = Arc::new(StubReporter::default());
    let h = harness(Setup {
        reporter: Some(reporter.clone()),
        ..Setup::default()
    })
    .await;
    upstream_ok(&h).await;
    let sessions = h.sessions.clone().unwrap();
    assert_eq!(relayed(&h).await.0, StatusCode::OK);
    assert_eq!(relayed(&h).await.0, StatusCode::OK);
    assert_eq!(sessions.len(), 1, "one session per token");

    let t0 = Instant::now();
    sessions.tick(t0).await;
    sessions.tick(t0 + crate::sessions::HEARTBEAT).await;
    let seen = reporter.seen();
    assert_eq!(
        seen[0],
        Seen::Open {
            agent_id: AGENT,
            jti: h.jti,
            kind: SessionKind::Http,
            slug: "relay".to_owned()
        }
    );
    assert!(matches!(seen[1], Seen::Heartbeat(_)), "{seen:?}");

    let dump = format!("{seen:?}");
    assert!(!dump.contains(&h.token), "no token in a report");
    assert!(
        !dump.contains(&String::from_utf8_lossy(VALUE).into_owned()),
        "no value in a report"
    );
}

/// Spec "Revoke one": a live call is closed within one TTL of the revoke, and its session is
/// reported closed and not heartbeated again.
#[tokio::test]
async fn sessions_revoke_closes_a_live_session_within_one_ttl() {
    let ttl = Duration::from_secs(1);
    let reporter = Arc::new(StubReporter::default());
    let h = slow(ttl, &reporter).await;
    let watcher = h.sessions.clone().unwrap().run(Duration::from_millis(50));
    let call = in_flight(&h, format!("{}/x", h.origin()));
    wait_for_open(&reporter).await;
    let kms_before = h.kms_calls().await;

    let revoked_at = Instant::now();
    h.grants.revoke(h.jti);
    let (status, closed_at) = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the live call was never closed")
        .unwrap();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        closed_at - revoked_at < ttl,
        "closed {:?} after the revoke",
        closed_at - revoked_at
    );
    assert_eq!(
        h.kms_calls().await,
        kms_before,
        "no decrypt after the revoke"
    );

    tokio::time::sleep(Duration::from_millis(300)).await;
    watcher.abort();
    let seen = reporter.seen();
    let closes = seen.iter().filter(|s| matches!(s, Seen::Close(_))).count();
    assert_eq!(closes, 1, "{seen:?}");
    assert!(
        matches!(seen.last(), Some(Seen::Close(_))),
        "no heartbeat after the close: {seen:?}"
    );
    assert!(h.sessions.as_ref().unwrap().is_empty());
}

/// Spec "Pause during use": the same for a paused org, for every session of it.
#[tokio::test]
async fn sessions_revoke_pause_closes_a_live_session_within_one_ttl() {
    let ttl = Duration::from_secs(1);
    let reporter = Arc::new(StubReporter::default());
    let h = slow(ttl, &reporter).await;
    let watcher = h.sessions.clone().unwrap().run(Duration::from_millis(50));
    let call = in_flight(&h, format!("{}/x", h.origin()));
    wait_for_open(&reporter).await;
    let kms_before = h.kms_calls().await;

    let paused_at = Instant::now();
    h.grants.set_paused(true);
    let (status, closed_at) = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the live call was never closed")
        .unwrap();
    watcher.abort();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(closed_at - paused_at < ttl);
    assert_eq!(
        h.kms_calls().await,
        kms_before,
        "no decrypt after the pause"
    );
}

/// Fail closed on a live session: when the revoke and pause state cannot be read for a whole TTL
/// the session is closed; a shorter outage keeps it.
#[tokio::test]
async fn sessions_revoke_refresh_failure_closes_a_live_session() {
    let ttl = Duration::from_millis(800);
    let reporter = Arc::new(StubReporter::default());
    let h = slow(ttl, &reporter).await;
    let watcher = h.sessions.clone().unwrap().run(Duration::from_millis(50));
    let mut call = in_flight(&h, format!("{}/x", h.origin()));
    wait_for_open(&reporter).await;

    // A short outage does not close it.
    h.grants.set_failing(true);
    tokio::time::sleep(Duration::from_millis(250)).await;
    h.grants.set_failing(false);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(1), &mut call)
            .await
            .is_err(),
        "a short outage must not close the session"
    );

    // One that lasts the TTL does.
    let failing_at = Instant::now();
    h.grants.set_failing(true);
    let (status, closed_at) = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the session was never closed")
        .unwrap();
    watcher.abort();
    assert_eq!(status, StatusCode::FORBIDDEN);
    let after = closed_at - failing_at;
    assert!(
        after >= ttl - Duration::from_millis(100),
        "closed early: {after:?}"
    );
    assert!(after < ttl * 2, "closed late: {after:?}");
    assert!(
        reporter.seen().iter().any(|s| matches!(s, Seen::Close(_))),
        "the close is reported"
    );
}

/// `/mcp`: a paused org or revoked token gets `401` before any tool runs, the session is
/// reported as `mcp`, and the watcher closes it.
#[tokio::test]
async fn sessions_revoke_mcp_is_refused_and_closed() {
    let reporter = Arc::new(StubReporter::default());
    let h = harness(Setup {
        grant_ttl: Duration::ZERO,
        reporter: Some(reporter.clone()),
        ..Setup::default()
    })
    .await;
    let sid = session(&h).await;
    let sessions = h.sessions.clone().unwrap();
    let t0 = Instant::now();
    sessions.tick(t0).await;
    assert!(
        reporter.seen().iter().any(|s| matches!(
            s,
            Seen::Open { kind: SessionKind::Mcp, jti, .. } if *jti == h.jti
        )),
        "{:?}",
        reporter.seen()
    );

    h.grants.set_paused(true);
    sessions.tick(t0 + crate::sessions::HEARTBEAT).await;
    assert!(
        reporter.seen().iter().any(|s| matches!(s, Seen::Close(_))),
        "the paused session is closed"
    );
    let list = r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#;
    assert_eq!(
        rpc(&h, &h.token, Some(&sid), list).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        rpc(&h, &h.token, None, INITIALIZE).await.0,
        StatusCode::UNAUTHORIZED,
        "no new session while paused"
    );
    assert_eq!(h.kms_calls().await, 0);

    // Resume, then revoke this one token: a fresh token still works.
    h.grants.set_paused(false);
    assert_eq!(rpc(&h, &h.token, None, INITIALIZE).await.0, StatusCode::OK);
    h.grants.revoke(h.jti);
    assert_eq!(
        rpc(&h, &h.token, None, INITIALIZE).await.0,
        StatusCode::UNAUTHORIZED
    );
    let fresh = h.signer.sign(&agent_claims(ORG, AUDIENCE, 600)).unwrap();
    assert_eq!(rpc(&h, &fresh, None, INITIALIZE).await.0, StatusCode::OK);
}
