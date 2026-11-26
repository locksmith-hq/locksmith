//! Task 3.3 of m1-remote-mcp: `issue_short_lived_credential` (decision H1-2) over `/mcp`, the
//! credential's use on `/v1/relay`, and adversarial cases that the stored (long-lived) value
//! never appears in a tool result, a log line or an audit event, whatever the agent does.

use super::mcp::{call_tool, rpc, session, structured};
use super::*;
use serde_json::{Value, json};

const TOOL: &str = ls_mcp_server::SHORT_LIVED_TOOL;

fn on() -> Setup {
    Setup {
        mcp_tools: vec![(TOOL, true)],
        ..Setup::default()
    }
}

/// Issue a credential for `secret` and return the whole JSON-RPC answer.
async fn issue(h: &Harness, sid: &str, secret: Uuid, ttl: u32) -> Value {
    call_tool(
        h,
        sid,
        TOOL,
        json!({"secret_id": secret, "job": "ci/build-42", "ttl_secs": ttl}),
    )
    .await
}

fn credential(msg: &Value) -> String {
    structured(msg)["credential"]
        .as_str()
        .unwrap_or_else(|| panic!("no credential in {msg}"))
        .to_owned()
}

/// The `credential.issued` events in the sink.
fn issued(h: &Harness) -> Vec<RelayEvent> {
    h.audit
        .events()
        .into_iter()
        .filter(|e| e.kind == EventKind::CredentialIssued)
        .collect()
}

async fn get_grants(h: &Harness, token: &str) -> StatusCode {
    h.app
        .clone()
        .oneshot(
            Request::get("/v1/grants")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

fn echo_mock() -> Mock {
    Mock::given(method("GET"))
        .and(path("/echo"))
        .and(has_header("authorization", injected().as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-echo", injected().as_str())
                .set_body_string(json!({"echo": injected(), "ok": true}).to_string()),
        )
}

#[tokio::test]
async fn mcp_short_lived_off_by_default_is_unlisted_and_refused() {
    let h = harness(Setup::default()).await;
    let sid = session(&h).await;
    let (_, list, _) = rpc(
        &h,
        &h.token,
        Some(&sid),
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
    )
    .await;
    assert!(!list.to_string().contains(TOOL), "off tool listed: {list}");
    let msg = issue(&h, &sid, SECRET, 60).await;
    assert!(msg["error"].is_object(), "{msg}");
    assert!(h.audit.events().is_empty());
    assert_eq!(
        h.relay.short_lived().live(time::OffsetDateTime::now_utc()),
        0
    );
    assert_eq!(h.kms_calls().await, 0);
    // Switched off explicitly: the same.
    let h = harness(Setup {
        mcp_tools: vec![(TOOL, false)],
        ..Setup::default()
    })
    .await;
    let sid = session(&h).await;
    assert!(issue(&h, &sid, SECRET, 60).await["error"].is_object());
}

#[tokio::test]
async fn mcp_short_lived_on_is_listed_with_its_schemas() {
    let h = harness(on()).await;
    let sid = session(&h).await;
    let (_, list, _) = rpc(
        &h,
        &h.token,
        Some(&sid),
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
    )
    .await;
    let tool = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == TOOL)
        .unwrap_or_else(|| panic!("tool not listed: {list}"));
    assert_eq!(
        tool["inputSchema"]["required"],
        json!(["secret_id", "job", "ttl_secs"])
    );
    assert!(tool["outputSchema"]["properties"]["credential"].is_object());
}

/// Spec "Issue is audited and expires": a credential valid for the asked minutes, one audit
/// event naming the agent, the secret (scope) and the expiry but not the credential, and no
/// decrypt at all.
#[tokio::test]
async fn mcp_short_lived_issue_is_audited_and_never_the_stored_value() {
    let h = harness(on()).await;
    let sid = session(&h).await;
    let before = time::OffsetDateTime::now_utc();
    let msg = issue(&h, &sid, SECRET, 300).await;
    assert_ne!(msg["result"]["isError"], true, "{msg}");
    let out = structured(&msg);
    let token = credential(&msg);
    assert!(token.starts_with(crate::short_lived::PREFIX), "{msg}");
    assert!(!token.contains(std::str::from_utf8(VALUE).unwrap()));
    let expires = time::OffsetDateTime::parse(
        out["expires_at"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let ttl = (expires - before).whole_seconds();
    assert!((299..=301).contains(&ttl), "ttl {ttl}");
    assert_eq!(
        out["scope"],
        format!("relay secret_id={SECRET} job=ci/build-42")
    );
    // Issuing decrypts nothing: no KMS call, no material fetch.
    assert_eq!(h.kms_calls().await, 0);
    assert_eq!(Harness::hits(&h.cp).await, 0);
    // One `credential.issued` event: the agent, the secret, the credential id and expiry.
    let events = h.audit.events();
    assert_eq!(events.len(), 1, "{events:?}");
    let ev = &events[0];
    assert_eq!(ev.kind, EventKind::CredentialIssued);
    assert_eq!((ev.agent_id, ev.secret_id), (AGENT, SECRET));
    let i = ev.issued.expect("issue attributes");
    assert_eq!(
        i.credential_id.to_string(),
        out["credential_id"].as_str().unwrap()
    );
    assert_eq!(i.expires_at, expires.unix_timestamp());
    // Neither the stored value nor the credential is in the result's other fields or the audit.
    assert_clean("issue result", msg.to_string().as_bytes());
    let audit = format!("{:?}", h.audit.stored());
    assert_clean("issue audit", audit.as_bytes());
    assert!(!audit.contains(&token), "credential in the audit event");
    assert!(
        !audit.contains("ci/build-42"),
        "job label in the audit event"
    );
}

/// The credential relays its one secret through `/v1/relay`: the upstream receives the stored
/// value, the bearer of the credential never does, and the call is audited as the agent.
#[tokio::test]
async fn mcp_short_lived_credential_relays_its_secret_redacted() {
    let h = harness(on()).await;
    echo_mock().mount(&h.upstream).await;
    let sid = session(&h).await;
    let token = credential(&issue(&h, &sid, SECRET, 120).await);
    let (status, raw) = h
        .call(
            Some(&token),
            json!({"secret_id": SECRET, "version": 1, "method": "GET",
                   "url": format!("{}/echo", h.origin())}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&raw));
    assert!(String::from_utf8_lossy(&raw).contains("ok"));
    assert_clean("short-lived relay response", &raw);
    assert_eq!(Harness::hits(&h.upstream).await, 1);
    // The relay events are the agent's, as for an agent-token relay.
    assert_eq!(h.outcomes(), ["ok"]);
    assert!(h.closing().iter().all(|(_, e)| e.agent_id == AGENT));
    h.assert_audit_clean();
}

/// T9 task 2.3, short-lived: a credential's relay over the grant's burst limit is
/// `429 budget_exceeded`, with no KMS call, no material fetch and no upstream request.
#[tokio::test]
async fn mcp_short_lived_over_budget_is_429_before_unwrap() {
    let h = harness(Setup {
        budget: Some(crate::budget::BudgetGuard::new()),
        ..on()
    })
    .await;
    echo_mock().mount(&h.upstream).await;
    let mut g = grant(SECRET, "LIMITED", None);
    g.budget = Some(crate::grants::Budget {
        per_minute: Some(1),
        per_day: None,
    });
    h.grants.set(AGENT, vec![g]);
    let sid = session(&h).await;
    let token = credential(&issue(&h, &sid, SECRET, 120).await);
    let body = || {
        json!({"secret_id": SECRET, "version": 1, "method": "GET",
               "url": format!("{}/echo", h.origin())})
    };
    let (status, _) = h.call(Some(&token), body()).await;
    assert_eq!(status, StatusCode::OK, "inside the limit");
    let (kms, cp, up) = (
        h.kms_calls().await,
        Harness::hits(&h.cp).await,
        Harness::hits(&h.upstream).await,
    );
    let before = h.audit.events().len();

    let (status, raw) = h.call(Some(&token), body()).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(String::from_utf8_lossy(&raw).contains("budget_exceeded"));
    assert_clean("short-lived budget refusal", &raw);
    assert_eq!(h.kms_calls().await, kms, "no KMS call");
    assert_eq!(Harness::hits(&h.cp).await, cp, "no material fetch");
    assert_eq!(Harness::hits(&h.upstream).await, up, "no upstream request");
    let ev = h.audit.events();
    assert_eq!(ev.len(), before + 1, "one event");
    assert_eq!(ev[before].kind, EventKind::BudgetExceeded("per_minute"));
}

/// Scoped to one secret and one route: any other secret is refused before any unwrap, and the
/// credential is no agent token anywhere else (`/mcp`, `/v1/grants`).
#[tokio::test]
async fn mcp_short_lived_credential_is_scoped_to_its_secret_and_the_relay() {
    let h = harness(on()).await;
    let sid = session(&h).await;
    let token = credential(&issue(&h, &sid, SECRET, 120).await);
    // Another secret the agent holds a grant for: denied, audited, nothing unwrapped.
    let (status, raw) = h
        .call(
            Some(&token),
            json!({"secret_id": DEAD, "version": 1, "method": "GET",
                   "url": format!("{}/x", h.dead_origin())}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "{}",
        String::from_utf8_lossy(&raw)
    );
    assert_eq!(h.outcomes(), ["denied"]);
    // The right secret to a host outside its binding: denied as on any relay.
    let (status, _) = h
        .call(
            Some(&token),
            json!({"secret_id": SECRET, "version": 1, "method": "GET",
                   "url": "http://attacker.test/steal"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(h.kms_calls().await, 0);
    // Not an agent token: `/mcp` and `/v1/grants` refuse it.
    let (status, _, _) = rpc(&h, &token, None, super::mcp::INITIALIZE).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(get_grants(&h, &token).await, StatusCode::UNAUTHORIZED);
    // A forged or altered credential is a 401, with nothing audited.
    let n = h.audit.events().len();
    let mut forged = token.clone();
    forged.pop();
    forged.push(if token.ends_with('A') { 'B' } else { 'A' });
    let fake = format!("{}{}", crate::short_lived::PREFIX, "A".repeat(43));
    for t in [forged.as_str(), fake.as_str(), crate::short_lived::PREFIX] {
        let (status, _) = h
            .call(
                Some(t),
                json!({"secret_id": SECRET, "version": 1, "method": "GET",
                       "url": format!("{}/x", h.origin())}),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{t}");
    }
    assert_eq!(h.audit.events().len(), n);
    assert_eq!(h.kms_calls().await, 0);
}

/// Destroyed after: the credential never outlives the grant, and once expired it is a `401`
/// and gone from the store.
#[tokio::test]
async fn mcp_short_lived_credential_expires_with_the_grant_and_is_destroyed() {
    let h = harness(on()).await;
    echo_mock().mount(&h.upstream).await;
    let grant_end = time::OffsetDateTime::now_utc() + time::Duration::seconds(2);
    h.grants
        .set(AGENT, vec![grant(SECRET, "STRIPE_KEY", Some(grant_end))]);
    let sid = session(&h).await;
    let msg = issue(&h, &sid, SECRET, 900).await;
    let expires = time::OffsetDateTime::parse(
        structured(&msg)["expires_at"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert!(expires <= grant_end, "credential outlives its grant");
    let token = credential(&msg);
    let body = json!({"secret_id": SECRET, "version": 1, "method": "GET",
                      "url": format!("{}/echo", h.origin())});
    let (status, _) = h.call(Some(&token), body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(2200)).await;
    let (status, _) = h.call(Some(&token), body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h.relay.short_lived().live(time::OffsetDateTime::now_utc()),
        0
    );
}

/// Refusals issue nothing: no grant, no binding, bad arguments, a ledger that cannot take the
/// issue (fail closed) and the per-agent limit.
#[tokio::test]
async fn mcp_short_lived_refusals_issue_nothing() {
    let h = harness(on()).await;
    let sid = session(&h).await;
    // No relay grant for the secret (the harness grants SECRET, INTERNAL, DEAD and UNBOUND).
    let msg = issue(&h, &sid, Uuid::now_v7(), 60).await;
    assert_eq!(msg["result"]["isError"], true, "{msg}");
    assert_eq!(structured(&msg)["error"]["code"], "no_grant");
    // A grant but no binding: nothing the credential could relay.
    let msg = issue(&h, &sid, UNBOUND, 60).await;
    assert_eq!(structured(&msg)["error"]["code"], "denied");
    // Arguments outside the schema are a protocol error.
    for args in [
        json!({"secret_id": SECRET, "job": "j", "ttl_secs": 59}),
        json!({"secret_id": SECRET, "job": "j", "ttl_secs": 901}),
        json!({"secret_id": SECRET, "job": "", "ttl_secs": 60}),
        json!({"secret_id": SECRET, "job": "a b", "ttl_secs": 60}),
        json!({"secret_id": SECRET, "job": "j".repeat(129), "ttl_secs": 60}),
        json!({"secret_id": SECRET, "ttl_secs": 60}),
        json!({"secret_id": SECRET, "job": "j", "ttl_secs": 60, "value": "x"}),
    ] {
        let msg = call_tool(&h, &sid, TOOL, args).await;
        assert!(msg["error"].is_object(), "{msg}");
    }
    assert!(h.audit.events().is_empty());
    assert_eq!(
        h.relay.short_lived().live(time::OffsetDateTime::now_utc()),
        0
    );

    // Per-agent limit: the 17th live credential is refused.
    for _ in 0..crate::short_lived::MAX_LIVE_PER_AGENT {
        let msg = issue(&h, &sid, SECRET, 60).await;
        assert_ne!(msg["result"]["isError"], true, "{msg}");
    }
    let msg = issue(&h, &sid, SECRET, 60).await;
    assert_eq!(structured(&msg)["error"]["code"], "too_many_credentials");
    assert_eq!(issued(&h).len(), crate::short_lived::MAX_LIVE_PER_AGENT);
    assert_eq!(h.kms_calls().await, 0);

    // The ledger refuses the issue: nothing is issued or stored.
    let h = harness(Setup {
        audit_fails: true,
        ..on()
    })
    .await;
    let sid = session(&h).await;
    let msg = issue(&h, &sid, SECRET, 60).await;
    assert_eq!(structured(&msg)["error"]["code"], "audit_unavailable");
    assert!(structured(&msg).get("credential").is_none());
    assert_eq!(
        h.relay.short_lived().live(time::OffsetDateTime::now_utc()),
        0
    );
}

/// Adversarial: trace-level logs of every path (issue, use, refusals) under the gateway's own
/// filter (`RUST_LOG=trace` plus [`crate::mcp_endpoint::cap_rmcp_logs`]) hold no encoding of the
/// stored value and never the credential. Without the cap, rmcp's `debug` response log would
/// carry the credential.
#[tokio::test]
async fn mcp_short_lived_logs_hold_no_value_and_no_credential() {
    let cap = Capture::default();
    let writer = cap.clone();
    let filter = crate::mcp_endpoint::cap_rmcp_logs(tracing_subscriber::EnvFilter::new(
        "trace,rmcp::service=trace",
    ));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let h = harness(on()).await;
    echo_mock().mount(&h.upstream).await;
    let sid = session(&h).await;
    let token = credential(&issue(&h, &sid, SECRET, 60).await);
    let (status, raw) = h
        .call(
            Some(&token),
            json!({"secret_id": SECRET, "version": 1, "method": "GET",
                   "url": format!("{}/echo", h.origin())}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_clean("response", &raw);
    h.call(
        Some(&token),
        json!({"secret_id": DEAD, "version": 1, "method": "GET",
               "url": format!("{}/x", h.dead_origin())}),
    )
    .await;
    rpc(&h, &token, None, super::mcp::INITIALIZE).await;
    h.grants.set(AGENT, Vec::new());
    issue(&h, &sid, SECRET, 60).await;

    let logs = cap.0.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&logs);
    assert!(
        text.contains("short-lived credential issued"),
        "capture saw the issue"
    );
    assert_clean("trace logs", &logs);
    assert!(!text.contains(&token), "credential in the logs");
    // The random part alone, in case a prefix-stripping path logged it.
    assert!(!text.contains(&token[crate::short_lived::PREFIX.len()..]));
}

/// Adversarial, against the real control plane and its Postgres ledger: the issue lands as one
/// `credential.issued` row (agent actor, secret target, credential id, expiry), the chain stays
/// intact, and no row holds the stored value or the credential.
#[tokio::test]
async fn mcp_short_lived_issue_lands_in_the_ledger_without_value_or_credential() {
    let l = Ledger::start().await;
    let h = harness(Setup {
        audit: Some(l.sink()),
        ..on()
    })
    .await;
    echo_mock().mount(&h.upstream).await;
    let sid = session(&h).await;
    let msg = issue(&h, &sid, SECRET, 120).await;
    assert_ne!(msg["result"]["isError"], true, "{msg}");
    let token = credential(&msg);
    let (status, _) = h
        .call(
            Some(&token),
            json!({"secret_id": SECRET, "version": 1, "method": "GET",
                   "url": format!("{}/echo", h.origin())}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let rows = l.records().await;
    let got: Vec<(&str, &str)> = rows
        .iter()
        .map(|r| (r.kind.as_str(), r.outcome.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            ("credential.issued", "ok"),
            // The MCP call itself (task 3.4): layer and tool only, no arguments.
            ("mcp.call", "ok"),
            ("relay.attempt", "pending"),
            ("relay.outcome", "ok"),
        ]
    );
    let row = &rows[0];
    assert_eq!(
        attr(row, "credential_id"),
        structured(&msg)["credential_id"].as_str()
    );
    assert!(attr(row, "expires_at").is_some());
    assert!(attr(row, "version").is_none(), "not version-bound");
    let call = &rows[1];
    assert_eq!(attr(call, "layer"), Some("agent"));
    assert_eq!(attr(call, "tool"), Some("issue_short_lived_credential"));
    let walk = ls_audit::verify(rows.iter().map(ls_audit::Record::link), &[]);
    assert!(walk.ok(), "{walk:?}");
    let text = l.ledger_text().await;
    assert_clean("ledger rows", text.as_bytes());
    assert!(!text.contains(&token), "credential in the ledger");
    assert!(!text.contains(&token[crate::short_lived::PREFIX.len()..]));
}
