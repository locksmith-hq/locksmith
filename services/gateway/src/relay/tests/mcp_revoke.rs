//! Task 4.2 of m1-remote-mcp, gateway half: revoking the agent behind an MCP client. A revoked
//! agent gets `401` on its next call and on a fresh `initialize`, no new client row is made for
//! it, a registry that cannot be read refuses every request, and the agent's live short-lived
//! credentials are destroyed when the gateway first sees the revoke. The registry is read with a
//! zero cache TTL here, so "the next call" is exact.

use std::collections::HashSet;
use std::sync::Mutex;

use super::mcp::{INITIALIZE, call_tool, rpc, session, structured};
use super::*;
use crate::decrypt::BoxFuture;
use crate::mcp_clients::{AgentClients, ClientsCache, ClientsError};
use serde_json::{Value, json};

const TOOL: &str = ls_mcp_server::SHORT_LIVED_TOOL;
const OTHER_AGENT: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a2);

/// The control plane's agent-layer `mcp_clients` rows, as far as the gateway sees them.
#[derive(Default)]
struct Registry {
    revoked: Mutex<HashSet<Uuid>>,
    unreadable: Mutex<bool>,
    /// `(agent, client name)` for every record call that reached the "control plane".
    recorded: Mutex<Vec<(Uuid, String)>>,
}

impl Registry {
    fn revoke(&self, agent: Uuid) {
        self.revoked.lock().unwrap().insert(agent);
    }

    fn recorded(&self) -> Vec<(Uuid, String)> {
        self.recorded.lock().unwrap().clone()
    }
}

impl AgentClients for Registry {
    fn revoked(&self) -> BoxFuture<'_, Result<HashSet<Uuid>, ClientsError>> {
        let r = if *self.unreadable.lock().unwrap() {
            Err(ClientsError)
        } else {
            Ok(self.revoked.lock().unwrap().clone())
        };
        Box::pin(async move { r })
    }

    fn record(&self, agent: Uuid, name: &str) -> BoxFuture<'_, Result<bool, ClientsError>> {
        // A revoked row stays revoked and is never recreated: the answer says so.
        let revoked = self.revoked.lock().unwrap().contains(&agent);
        if !revoked {
            self.recorded.lock().unwrap().push((agent, name.to_owned()));
        }
        Box::pin(async move { Ok(revoked) })
    }
}

async fn with(registry: &Arc<Registry>) -> Harness {
    let source: Arc<dyn AgentClients> = registry.clone();
    harness(Setup {
        mcp_tools: vec![(TOOL, true)],
        // Zero TTL: every request reads the revoked set.
        clients: Some(Arc::new(ClientsCache::new(
            source,
            std::time::Duration::ZERO,
        ))),
        ..Setup::default()
    })
    .await
}

async fn tools_list(h: &Harness, sid: &str) -> StatusCode {
    rpc(
        h,
        &h.token,
        Some(sid),
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
    )
    .await
    .0
}

#[tokio::test]
async fn mcp_initialize_records_the_agent_as_a_client_and_a_revoked_one_is_refused_on_every_request()
 {
    let reg = Arc::new(Registry::default());
    let h = with(&reg).await;
    let sid = session(&h).await;
    // One row, keyed by the agent, with the client's display name.
    assert_eq!(reg.recorded(), vec![(AGENT, "test".to_owned())]);
    assert_eq!(tools_list(&h, &sid).await, StatusCode::OK);
    let ok = call_tool(&h, &sid, "list_my_keys", json!({})).await;
    assert!(structured(&ok)["items"].is_array(), "{ok}");

    reg.revoke(AGENT);

    // The next call on the live session is a 401 with the same challenge as a bad token.
    let body = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                      "params": {"name": "list_my_keys", "arguments": {}}});
    let (status, _, _) = rpc(&h, &h.token, Some(&sid), &body.to_string()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(tools_list(&h, &sid).await, StatusCode::UNAUTHORIZED);
    // So is a fresh initialize with the same, still valid, agent token ...
    let (status, msg, new_sid) = rpc(&h, &h.token, None, INITIALIZE).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{msg}");
    assert!(new_sid.is_none(), "no session was opened");
    // ... and no new client row was created for the revoked agent.
    assert_eq!(reg.recorded().len(), 1);
    // No key was touched.
    assert_eq!(h.kms_calls().await, 0);
}

#[tokio::test]
async fn mcp_revoking_another_agent_changes_nothing_for_this_one() {
    // The revoke is per agent: an unrelated agent id in the set changes nothing for this one.
    let reg = Arc::new(Registry::default());
    let h = with(&reg).await;
    reg.revoke(OTHER_AGENT);
    let sid = session(&h).await;
    assert_eq!(tools_list(&h, &sid).await, StatusCode::OK);
}

#[tokio::test]
async fn mcp_an_unreadable_registry_refuses_every_request_it_never_assumes_nobody_is_revoked() {
    let reg = Arc::new(Registry::default());
    let h = with(&reg).await;
    let sid = session(&h).await;
    *reg.unreadable.lock().unwrap() = true;
    assert_eq!(tools_list(&h, &sid).await, StatusCode::UNAUTHORIZED);
    let (status, _, _) = rpc(&h, &h.token, None, INITIALIZE).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Readable again: service resumes.
    *reg.unreadable.lock().unwrap() = false;
    assert_eq!(tools_list(&h, &sid).await, StatusCode::OK);
}

#[tokio::test]
async fn mcp_an_agent_that_cannot_be_recorded_gets_no_session() {
    struct Refusing;
    impl AgentClients for Refusing {
        fn revoked(&self) -> BoxFuture<'_, Result<HashSet<Uuid>, ClientsError>> {
            Box::pin(async { Ok(HashSet::new()) })
        }
        fn record(&self, _a: Uuid, _n: &str) -> BoxFuture<'_, Result<bool, ClientsError>> {
            Box::pin(async { Err(ClientsError) })
        }
    }
    let h = harness(Setup {
        clients: Some(Arc::new(Refusing)),
        ..Setup::default()
    })
    .await;
    let (_, msg, sid) = rpc(&h, &h.token, None, INITIALIZE).await;
    assert!(msg["error"].is_object(), "{msg}");
    assert!(msg["result"].is_null());
    let _ = sid;
}

fn credential(msg: &Value) -> String {
    structured(msg)["credential"]
        .as_str()
        .unwrap_or_else(|| panic!("no credential in {msg}"))
        .to_owned()
}

#[tokio::test]
async fn mcp_revoke_drops_the_agents_live_short_lived_credentials() {
    let reg = Arc::new(Registry::default());
    let h = with(&reg).await;
    Mock::given(method("GET"))
        .and(path("/echo"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.upstream)
        .await;
    let sid = session(&h).await;
    let msg = call_tool(
        &h,
        &sid,
        TOOL,
        json!({"secret_id": SECRET, "job": "ci/build-42", "ttl_secs": 600}),
    )
    .await;
    let token = credential(&msg);
    // Another agent's credential, minted straight into the store, for the same secret.
    let t = time::OffsetDateTime::now_utc();
    let theirs = h
        .relay
        .short_lived()
        .mint(OTHER_AGENT, ORG, SECRET, t + time::Duration::minutes(10), t)
        .unwrap();
    h.relay.short_lived().insert(&theirs, t).unwrap();
    assert_eq!(h.relay.short_lived().live(t), 2);
    let relay_body = json!({"secret_id": SECRET, "version": 1, "method": "GET",
                            "url": format!("{}/echo", h.origin())});
    let (status, _) = h.call(Some(&token), relay_body.clone()).await;
    assert_eq!(status, StatusCode::OK, "usable before the revoke");

    reg.revoke(AGENT);
    // Nothing has dropped yet: the gateway learns of the revoke on the next /mcp request.
    let (status, _, _) = rpc(
        &h,
        &h.token,
        Some(&sid),
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The revoked agent's credential is gone and refused like an unknown one; the live count
    // shows only the other agent's.
    let (status, _) = h.call(Some(&token), relay_body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h.relay.short_lived().live(time::OffsetDateTime::now_utc()),
        1
    );
}

#[tokio::test]
async fn mcp_the_first_sighting_of_a_revoke_drops_credentials_even_when_another_agent_calls() {
    let reg = Arc::new(Registry::default());
    let h = with(&reg).await;
    let t = time::OffsetDateTime::now_utc();
    let theirs = h
        .relay
        .short_lived()
        .mint(OTHER_AGENT, ORG, SECRET, t + time::Duration::minutes(10), t)
        .unwrap();
    h.relay.short_lived().insert(&theirs, t).unwrap();
    reg.revoke(OTHER_AGENT);
    // The harness agent (not revoked) makes a request; that read sees OTHER_AGENT revoked.
    let sid = session(&h).await;
    assert_eq!(tools_list(&h, &sid).await, StatusCode::OK);
    assert_eq!(
        h.relay.short_lived().live(time::OffsetDateTime::now_utc()),
        0
    );
}
