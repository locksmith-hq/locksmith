//! Tasks 4.2 and 4.3 of m2-mcp-gateway: the ledger events of a proxied `tools/call`, first
//! against the in-memory sink (every branch, retries, fail closed), then against the real
//! control plane and its Postgres ledger (needs Docker), read back with `ls-audit`.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ls_control_plane::auth::ServiceToken;
use ls_control_plane::db::{Database, PoolSettings, sql};
use ls_control_plane::readiness::ReadyFlag;
use ls_mcp_server::upstream::ToolDecision::{Allow, Deny, Hide, Hold};
use secrecy::SecretString;
use serde_json::{Value, json};
use url::Url;

use super::*;
use crate::audit::{AuditSink, HttpAudit, MemoryAudit};
use crate::decrypt::ControlPlane;
use crate::mcp_upstream::policy::tests::{RESULT_CANARY, Rig, VALUE};
use crate::mcp_upstream::tests::{AGENT, ORG};
use crate::relay::RelayOptions;
use crate::ttl::MAX_CACHE_TTL;

/// Text sent as a tool argument; it must never reach the ledger.
const ARG_CANARY: &str = "argument-canary-8c2f40";

fn fast_retries() -> RelayOptions {
    RelayOptions {
        outcome_retry_backoff: Duration::from_millis(1),
        ..RelayOptions::default()
    }
}

async fn rig_with(audit: &Arc<MemoryAudit>) -> Rig {
    let sink: Arc<dyn AuditSink> = audit.clone();
    Rig::build(MAX_CACHE_TTL, sink, fast_retries()).await
}

/// `(phase, tool, decision, outcome, reason)` of every stored event.
fn summary(
    audit: &MemoryAudit,
) -> Vec<(
    McpUpstreamPhase,
    String,
    ToolDecision,
    McpUpstreamOutcome,
    Option<McpUpstreamReason>,
)> {
    audit
        .mcp_upstream()
        .into_iter()
        .map(|(_, e)| (e.phase, e.tool, e.decision, e.outcome, e.reason))
        .collect()
}

#[tokio::test]
async fn an_allowed_call_appends_a_pending_event_then_an_ok_outcome() {
    let audit = Arc::new(MemoryAudit::default());
    let rig = rig_with(&audit).await;
    let answer = rig.call_with("list_issues", json!({"q": ARG_CANARY})).await;
    assert!(answer.text.contains("called"), "{}", answer.text);
    assert_eq!(rig.probe.calls(), ["list_issues"]);

    let stored = audit.mcp_upstream();
    assert_eq!(stored.len(), 2, "one event pair: {stored:?}");
    let (call_id, call) = &stored[0];
    let (_, outcome) = &stored[1];
    assert_eq!(call.phase, McpUpstreamPhase::Call);
    assert_eq!(call.outcome, McpUpstreamOutcome::Pending);
    assert_eq!(
        (call.agent_id, call.upstream.as_str(), call.tool.as_str()),
        (AGENT, "github", "list_issues")
    );
    assert_eq!(
        (call.decision, call.reason, call.attempt_id),
        (Allow, None, None)
    );
    assert_eq!(outcome.phase, McpUpstreamPhase::Outcome);
    assert_eq!(outcome.outcome, McpUpstreamOutcome::Ok);
    assert_eq!(
        outcome.attempt_id,
        Some(*call_id),
        "linked to the pending event"
    );
    assert_eq!((outcome.decision, outcome.reason), (Allow, None));
    // Nothing of the call's arguments or result is in an event.
    let text = format!("{stored:?}");
    for canary in [ARG_CANARY, RESULT_CANARY, VALUE] {
        assert!(!text.contains(canary), "{canary} in {text}");
    }
}

#[tokio::test]
async fn the_pending_append_failing_refuses_the_call_before_anything_is_forwarded() {
    let audit = Arc::new(MemoryAudit {
        fail_upstream_calls: true,
        ..MemoryAudit::default()
    });
    let rig = rig_with(&audit).await;
    let msg = rig.call("list_issues").await;
    assert_eq!(msg["error"]["message"], "audit_unavailable", "{msg}");
    assert!(msg["result"].is_null());
    assert!(rig.probe.calls().is_empty(), "forwarded without a record");
    assert!(audit.mcp_upstream().is_empty());
    assert_eq!(
        audit.upstream_tries(),
        1,
        "the pending append is not retried"
    );
}

#[tokio::test]
async fn an_unavailable_ledger_fails_every_audited_branch_closed_for_allowed_calls_only() {
    // `fail` takes every append down: allowed calls are refused, refusals stay refusals.
    let audit = Arc::new(MemoryAudit {
        fail: true,
        ..MemoryAudit::default()
    });
    let rig = rig_with(&audit).await;
    assert_eq!(
        rig.call("list_issues").await["error"]["message"],
        "audit_unavailable"
    );
    assert_eq!(
        rig.call("delete_repository").await["error"]["message"],
        "tool_denied"
    );
    assert_eq!(
        rig.call("does_not_exist").await["error"]["message"],
        "unknown_tool"
    );
    assert!(rig.probe.calls().is_empty());
}

#[tokio::test]
async fn every_refusal_appends_exactly_one_denied_event() {
    let audit = Arc::new(MemoryAudit::default());
    let rig = rig_with(&audit).await;
    for name in [
        "delete_repository",          // deny
        "create_issue",               // hold
        "secret_admin",               // hide by the table
        "unlisted_tool",              // hide by the default
        "ghost_tool",                 // a rule without a tool
        "does_not_exist",             // unknown
        "bad name",                   // an invalid upstream name
        "s\u{435}cret_admin\u{200b}", // look-alike
    ] {
        rig.call_with(name, json!({"q": ARG_CANARY})).await;
    }
    assert!(rig.probe.calls().is_empty(), "a refused call was forwarded");
    use McpUpstreamReason as R;
    let denied = |tool: &str, decision, reason| {
        (
            McpUpstreamPhase::Call,
            tool.to_owned(),
            decision,
            McpUpstreamOutcome::Denied,
            Some(reason),
        )
    };
    assert_eq!(
        summary(&audit),
        [
            denied("delete_repository", Deny, R::Deny),
            denied("create_issue", Hold, R::Hold),
            denied("secret_admin", Hide, R::Hide),
            denied("unlisted_tool", Hide, R::Hide),
            // Outside the catalogue (or not decided): the agent's text is never recorded.
            denied("unknown", Hide, R::UnknownTool),
            denied("unknown", Hide, R::UnknownTool),
            denied("unknown", Hide, R::UnknownTool),
            denied("unknown", Hide, R::UnknownTool),
        ]
    );
    let text = format!("{:?}", audit.mcp_upstream());
    for needle in [
        ARG_CANARY,
        "does_not_exist",
        "bad name",
        "ghost_tool",
        "\u{200b}",
    ] {
        assert!(!text.contains(needle), "{needle:?} in {text}");
    }
}

#[tokio::test]
async fn a_failed_catalogue_fetch_is_one_denied_event() {
    let audit = Arc::new(MemoryAudit::default());
    let rig = rig_with(&audit).await;
    rig.probe.fail_list.store(true, Ordering::SeqCst);
    let msg = rig.call("list_issues").await;
    assert_eq!(msg["error"]["message"], "upstream_error", "{msg}");
    assert_eq!(
        summary(&audit),
        [(
            McpUpstreamPhase::Call,
            "unknown".to_owned(),
            Hide,
            McpUpstreamOutcome::Denied,
            Some(McpUpstreamReason::CatalogueUnavailable)
        )]
    );
}

#[tokio::test]
async fn an_upstream_failure_is_an_error_outcome_with_the_hop_slug() {
    let audit = Arc::new(MemoryAudit::default());
    let rig = rig_with(&audit).await;
    rig.probe.fail_call.store(true, Ordering::SeqCst);
    let msg = rig.call("list_issues").await;
    assert_eq!(msg["error"]["message"], "upstream_error", "{msg}");
    let stored = audit.mcp_upstream();
    assert_eq!(stored.len(), 2, "{stored:?}");
    let outcome = &stored[1].1;
    assert_eq!(outcome.phase, McpUpstreamPhase::Outcome);
    assert_eq!(outcome.outcome, McpUpstreamOutcome::Error);
    assert_eq!(
        outcome.reason,
        Some(McpUpstreamReason::Hop(HopError::Upstream))
    );
    assert_eq!(outcome.attempt_id, Some(stored[0].0));
    // The upstream's own error text ("boom") is not in the event.
    assert!(!format!("{stored:?}").contains("boom"));
}

#[tokio::test]
async fn the_outcome_is_retried_three_times_and_never_fails_the_call() {
    // Three failures, then the fourth try lands.
    let audit = Arc::new(MemoryAudit {
        fail_upstream_outcomes_first: std::sync::Mutex::new(3),
        ..MemoryAudit::default()
    });
    let rig = rig_with(&audit).await;
    let msg = rig.call("list_issues").await;
    assert!(msg["result"].to_string().contains("called"), "{msg}");
    assert_eq!(
        audit.upstream_tries(),
        1 + 4,
        "pending plus four outcome tries"
    );
    assert_eq!(audit.mcp_upstream().len(), 2);

    // Four failures exhaust the retries: the agent still gets the answer, the ledger has the
    // pending event and no outcome.
    let audit = Arc::new(MemoryAudit {
        fail_upstream_outcomes_first: std::sync::Mutex::new(4),
        ..MemoryAudit::default()
    });
    let rig = rig_with(&audit).await;
    let msg = rig.call("list_issues").await;
    assert!(msg["result"].to_string().contains("called"), "{msg}");
    assert_eq!(audit.upstream_tries(), 1 + 4, "no fifth outcome try");
    assert_eq!(audit.mcp_upstream().len(), 1);
}

#[test]
fn reasons_are_the_closed_codes_the_control_plane_accepts() {
    use McpUpstreamReason as R;
    let all = [
        (R::Hide, "hide"),
        (R::Deny, "deny"),
        (R::Hold, "hold"),
        (R::UnknownTool, "unknown_tool"),
        (R::PolicyUnavailable, "policy_unavailable"),
        (R::CatalogueUnavailable, "catalogue_unavailable"),
        (R::Hop(HopError::Denied), "denied"),
        (R::Hop(HopError::DeniedAddress), "denied_address"),
        (R::Hop(HopError::Unreachable), "upstream_unreachable"),
        (R::Hop(HopError::SecretUnavailable), "secret_unavailable"),
        (R::Hop(HopError::SecretUnusable), "secret_unusable"),
        (R::Hop(HopError::Upstream), "upstream_error"),
        (R::Hop(HopError::Unsupported), "upstream_unsupported"),
        (R::Hop(HopError::Timeout), "upstream_timeout"),
        (R::Hop(HopError::RedactionFailed), "redaction_failed"),
        (R::Hop(HopError::Internal), "internal"),
    ];
    for (reason, code) in all {
        assert_eq!(reason.as_str(), code);
    }
}

// ---------------------------------------------------------------------------------------------
// Against the real control plane and its Postgres ledger.

/// Test-only service token shared by the gateway and the in-process control plane.
const SERVICE_TOKEN: &str = "test-only-gateway-service-token-0123456789";

/// A migrated `postgres:18` (ls-pg-test; needs Docker) with [`ORG`] created, and the control
/// plane serving it on a local port with [`SERVICE_TOKEN`].
struct Ledger {
    pg: ls_pg_test::Pg,
    db: Database,
    url: Url,
    server: tokio::task::JoinHandle<()>,
}

impl Ledger {
    async fn start() -> Self {
        let pg = ls_pg_test::Pg::start().await;
        ls_control_plane::migrate::run(pg.bootstrap())
            .await
            .expect("migrate");
        let mut admin = pg.admin().await;
        sql::query("INSERT INTO orgs (id, name) VALUES ($1, 'ledger-org')")
            .bind(ORG)
            .execute(&mut admin)
            .await
            .unwrap();
        let db = Database::connect_lazy(pg.app(), PoolSettings::default());
        let state =
            ls_control_plane::app::AppState::new(false, Arc::new(ReadyFlag::new(true)), db.clone())
                .with_service_token(ServiceToken::new(SecretString::from(SERVICE_TOKEN)));
        let app = ls_control_plane::app::build(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            pg,
            db,
            url,
            server,
        }
    }

    fn sink(&self) -> Arc<dyn AuditSink> {
        Arc::new(HttpAudit::new(Arc::new(
            ControlPlane::new(self.url.clone(), ORG, SERVICE_TOKEN.to_owned().into()).unwrap(),
        )))
    }

    /// [`ORG`]'s ledger as the app role (RLS applies).
    async fn records(&self) -> Vec<ls_audit::Record> {
        self.db
            .with_org(ORG, |c| {
                Box::pin(async move { ls_audit::pg::records_in_tx(c, ORG).await })
            })
            .await
            .unwrap()
    }

    /// Every stored ledger row as text, as the bootstrap superuser.
    async fn ledger_text(&self) -> String {
        let mut admin = self.pg.admin().await;
        let text: Option<String> =
            sql::query_scalar("SELECT string_agg(t::text, E'\\n') FROM audit_events t")
                .fetch_one(&mut admin)
                .await
                .unwrap();
        text.unwrap_or_default()
    }
}

impl Drop for Ledger {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn attr<'a>(r: &'a ls_audit::Record, key: &str) -> Option<&'a str> {
    r.attrs
        .as_ref()?
        .entries()
        .iter()
        .find(|(k, _, _)| k == key)
        .map(|(_, _, v)| v.as_str())
}

/// Spec "Audit events per call": an allowed call is an `mcp.upstream_call` (`pending`) and an
/// `mcp.upstream_outcome` (`ok`) linked by `attempt_id`, every refusal is one `denied`
/// `mcp.upstream_call`, the chain verifies, and no event holds an argument, a result or the
/// upstream credential.
#[tokio::test]
async fn upstream_calls_land_in_the_ledger_as_pairs_and_denials() {
    let l = Ledger::start().await;
    let rig = Rig::build(MAX_CACHE_TTL, l.sink(), RelayOptions::default()).await;

    let ok = rig.call_with("list_issues", json!({"q": ARG_CANARY})).await;
    assert!(ok.text.contains("called"), "{}", ok.text);
    for name in [
        "delete_repository",
        "create_issue",
        "secret_admin",
        "does_not_exist",
    ] {
        let msg = rig
            .call_with(name, json!({"q": ARG_CANARY}))
            .await
            .message();
        assert!(msg["error"].is_object(), "{name}: {msg}");
    }
    assert_eq!(rig.probe.calls(), ["list_issues"]);

    let rows = l.records().await;
    let got: Vec<(&str, &str)> = rows
        .iter()
        .map(|r| (r.kind.as_str(), r.outcome.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            ("mcp.upstream_call", "pending"),
            ("mcp.upstream_outcome", "ok"),
            ("mcp.upstream_call", "denied"),
            ("mcp.upstream_call", "denied"),
            ("mcp.upstream_call", "denied"),
            ("mcp.upstream_call", "denied"),
        ]
    );
    for r in &rows {
        assert_eq!(r.actor, format!("agent:{AGENT}"));
        assert_eq!(attr(r, "upstream"), Some("github"));
    }
    let attempt = rows[0].id.to_string();
    assert_eq!(attr(&rows[0], "tool"), Some("list_issues"));
    assert_eq!(attr(&rows[0], "decision"), Some("allow"));
    assert_eq!(attr(&rows[1], "attempt_id"), Some(attempt.as_str()));
    assert_eq!(attr(&rows[1], "tool"), Some("list_issues"));
    let denied: Vec<(&str, &str, &str)> = rows[2..]
        .iter()
        .map(|r| {
            (
                attr(r, "tool").unwrap(),
                attr(r, "decision").unwrap(),
                attr(r, "reason").unwrap(),
            )
        })
        .collect();
    assert_eq!(
        denied,
        [
            ("delete_repository", "deny", "deny"),
            ("create_issue", "hold", "hold"),
            ("secret_admin", "hide", "hide"),
            ("unknown", "hide", "unknown_tool"),
        ]
    );
    let walk = ls_audit::verify(rows.iter().map(ls_audit::Record::link), &[]);
    assert!(walk.ok(), "{walk:?}");

    let text = l.ledger_text().await;
    for canary in [ARG_CANARY, RESULT_CANARY, VALUE, "does_not_exist"] {
        assert!(!text.contains(canary), "{canary} in the ledger");
    }
}

/// An unreachable ledger refuses an allowed call before it is forwarded.
#[tokio::test]
async fn upstream_calls_are_refused_when_the_ledger_is_unreachable() {
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}/", l.local_addr().unwrap())
    };
    let sink: Arc<dyn AuditSink> = Arc::new(HttpAudit::new(Arc::new(
        ControlPlane::new(dead.parse().unwrap(), ORG, SERVICE_TOKEN.to_owned().into()).unwrap(),
    )));
    let rig = Rig::build(MAX_CACHE_TTL, sink, fast_retries()).await;
    let msg: Value = rig.call("list_issues").await;
    assert_eq!(msg["error"]["message"], "audit_unavailable", "{msg}");
    assert!(rig.probe.calls().is_empty());
}
