//! Task 3.4 of m1-remote-mcp: the org's tool switches are read on every list and call, and every
//! call appends one `mcp.call` event (agent, tool, outcome, static reason; no arguments).

use std::collections::HashMap;
use std::sync::Mutex;

use super::mcp::{call_tool, rpc, session, structured};
use super::*;
use crate::audit::{McpCallEvent, McpOutcome, McpReason};
use crate::decrypt::BoxFuture;
use crate::mcp_settings::{SettingsError, ToolSettingsSource};
use serde_json::{Value, json};

const TOOL: &str = ls_mcp_server::SHORT_LIVED_TOOL;

/// Switches the test flips between calls; `None` is an unreadable control plane.
struct Switches(Mutex<Option<HashMap<String, bool>>>);

impl Switches {
    fn new(init: &[(&str, bool)]) -> Arc<Self> {
        let s = Arc::new(Self(Mutex::new(None)));
        s.set(Some(init));
        s
    }

    fn set(&self, to: Option<&[(&str, bool)]>) {
        *self.0.lock().unwrap() =
            to.map(|t| t.iter().map(|(n, on)| ((*n).to_owned(), *on)).collect());
    }
}

impl ToolSettingsSource for Switches {
    fn settings(&self) -> BoxFuture<'_, Result<HashMap<String, bool>, SettingsError>> {
        let v = self.0.lock().unwrap().clone().ok_or(SettingsError);
        Box::pin(async move { v })
    }
}

async fn with(source: &Arc<Switches>) -> Harness {
    let src: Arc<dyn ToolSettingsSource> = source.clone();
    harness(Setup {
        settings_source: Some(src),
        ..Setup::default()
    })
    .await
}

async fn list(h: &Harness, sid: &str) -> Value {
    let (_, msg, _) = rpc(
        h,
        &h.token,
        Some(sid),
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
    )
    .await;
    msg
}

fn names(msg: &Value) -> Vec<String> {
    let mut n: Vec<String> = msg["result"]["tools"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect();
    n.sort();
    n
}

fn calls(h: &Harness) -> Vec<McpCallEvent> {
    h.audit.mcp_calls()
}

#[tokio::test]
async fn a_switch_flipped_in_the_org_settings_applies_to_the_next_list_and_call() {
    let sw = Switches::new(&[("list_my_keys", false)]);
    let h = with(&sw).await;
    let sid = session(&h).await;
    assert_eq!(names(&list(&h, &sid).await), ["explain_block", "relay_http_request"]);
    // Off by the org: hidden and refused by name.
    let refused = call_tool(&h, &sid, "list_my_keys", json!({})).await;
    assert!(refused["error"].is_object(), "{refused}");
    // The org turns it back on and the default-off tool on.
    sw.set(Some(&[("list_my_keys", true), (TOOL, true)]));
    assert_eq!(
        names(&list(&h, &sid).await),
        ["explain_block", "issue_short_lived_credential", "list_my_keys", "relay_http_request"]
    );
    let ok = call_tool(&h, &sid, "list_my_keys", json!({})).await;
    assert!(structured(&ok)["items"].is_array(), "{ok}");
}

#[tokio::test]
async fn an_unreadable_switch_fails_closed_it_never_falls_back_to_the_defaults() {
    let sw = Switches::new(&[]);
    let h = with(&sw).await;
    let sid = session(&h).await;
    sw.set(None);
    let listed = list(&h, &sid).await;
    assert!(listed["error"].is_object(), "{listed}");
    let msg = call_tool(&h, &sid, "list_my_keys", json!({})).await;
    assert_eq!(msg["result"]["isError"], true, "{msg}");
    assert_eq!(structured(&msg)["error"]["code"], "settings_unavailable");
    assert_eq!(structured(&msg)["error"]["status"], 503);
    assert_eq!(h.kms_calls().await, 0);
    let c = calls(&h);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].outcome, McpOutcome::Denied);
    assert_eq!(c[0].reason, Some(McpReason::SettingsUnavailable));
}

#[tokio::test]
async fn every_call_appends_one_mcp_call_event_with_no_arguments() {
    let sw = Switches::new(&[]);
    let h = with(&sw).await;
    let sid = session(&h).await;
    // ok
    call_tool(&h, &sid, "list_my_keys", json!({})).await;
    // refused: the default-off tool (denied, tool_off)
    call_tool(&h, &sid, TOOL, json!({"secret_id": SECRET, "job": "j", "ttl_secs": 60})).await;
    // an unknown name is recorded as `unknown`, never as the client's text
    call_tool(&h, &sid, "drop_table_users", json!({})).await;
    // bad arguments are an error
    call_tool(&h, &sid, "list_my_keys", json!({"cursor": "not-a-number"})).await;
    // a tool error that is a 403 is a denial
    let denied = call_tool(
        &h,
        &sid,
        "relay_http_request",
        json!({"secret_id": SECRET, "method": "GET", "url": "http://x.test/", "version": 1}),
    )
    .await;
    assert_eq!(denied["result"]["isError"], true, "{denied}");

    let c = calls(&h);
    let tools: Vec<&str> = c.iter().map(|e| e.tool).collect();
    assert_eq!(
        tools,
        [
            "list_my_keys",
            "issue_short_lived_credential",
            "unknown",
            "list_my_keys",
            "relay_http_request"
        ]
    );
    assert_eq!(c[0].outcome, McpOutcome::Ok);
    assert_eq!((c[1].outcome, c[1].reason), (McpOutcome::Denied, Some(McpReason::ToolOff)));
    assert_eq!((c[2].outcome, c[2].reason), (McpOutcome::Denied, Some(McpReason::ToolOff)));
    assert_eq!(
        (c[3].outcome, c[3].reason),
        (McpOutcome::Error, Some(McpReason::InvalidArguments))
    );
    assert!(c.iter().all(|e| e.agent_id == AGENT));
    // Nothing from the arguments reaches the event.
    assert!(!format!("{c:?}").contains("not-a-number"));
}

#[tokio::test]
async fn a_ledger_that_cannot_take_mcp_call_does_not_fail_the_call() {
    let h = harness(Setup {
        audit_fails: true,
        ..Setup::default()
    })
    .await;
    let sid = session(&h).await;
    let msg = call_tool(&h, &sid, "list_my_keys", json!({})).await;
    assert!(structured(&msg)["items"].is_array(), "{msg}");
}
