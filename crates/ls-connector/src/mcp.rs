//! M2 task 6: the agent side of the MCP gateway. `GET /v1/mcp/upstreams` lists the upstreams the
//! agent may use, and [`Bridge`] forwards one JSON-RPC message at a time to
//! `/mcp/upstream/<name>` with the agent token (read fresh per request by the caller).
//!
//! Only `initialize`, `ping`, `tools/list` and `tools/call` cross; the gateway enforces the same.
//! Every answer is passed through the agent token's redactor, and failures are fixed messages:
//! no server or transport text reaches the caller.

use secrecy::ExposeSecret;
use serde_json::{Value, json};

use crate::{Result, State, client, fail, http_fail, read_body, redact_str, transport};

/// Methods the bridge forwards.
pub const FORWARDED: &[&str] = &["initialize", "ping", "tools/list", "tools/call"];

/// An upstream name: `[a-z0-9-]{1,32}` (the gateway's rule).
pub fn valid_upstream_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `GET /v1/mcp/upstreams`: the names the agent holds a relay grant for, sorted, nothing else.
pub fn upstreams(st: &State) -> Result<Vec<String>> {
    let resp = client()?
        .get(format!("{}/v1/mcp/upstreams", st.gateway_url))
        .bearer_auth(st.token.expose_secret())
        .send()
        .map_err(|e| transport(&e))?;
    let status = resp.status();
    let body = read_body(resp)?;
    if !status.is_success() {
        return Err(http_fail(status, &body, "mcp upstreams"));
    }
    let bad = || fail("mcp upstreams failed: unexpected response from the gateway");
    let v: Value = serde_json::from_slice(&body).map_err(|_| bad())?;
    let names = v
        .get("upstreams")
        .and_then(Value::as_array)
        .ok_or_else(bad)?;
    let mut out = Vec::new();
    for n in names {
        let n = n
            .as_str()
            .filter(|n| valid_upstream_name(n))
            .ok_or_else(bad)?;
        out.push(n.to_owned());
    }
    out.sort();
    Ok(out)
}

/// Forwards MCP messages to one upstream path, keeping the gateway's session id between calls.
pub struct Bridge {
    name: String,
    session: Option<String>,
}

impl Bridge {
    /// A bridge to `/mcp/upstream/<name>`; the name must be valid.
    pub fn new(name: &str) -> Result<Self> {
        if !valid_upstream_name(name) {
            return Err(crate::usage("upstream name must match [a-z0-9-]{1,32}"));
        }
        Ok(Self {
            name: name.to_owned(),
            session: None,
        })
    }

    /// Forward one JSON-RPC request or notification. A request returns its response; a
    /// notification returns `None` (it is not forwarded: the gateway is stateless-friendly and
    /// answers `initialize` itself).
    pub fn forward(&mut self, st: &State, message: &Value) -> Result<Option<Value>> {
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        if message.get("id").is_none() {
            return Ok(None);
        }
        if !FORWARDED.contains(&method) {
            return Err(fail("method not supported by the Locksmith MCP bridge"));
        }
        let mut req = client()?
            .post(format!("{}/mcp/upstream/{}", st.gateway_url, self.name))
            .bearer_auth(st.token.expose_secret())
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
        if let Some(s) = &self.session {
            req = req
                .header("mcp-session-id", s.as_str())
                .header("mcp-protocol-version", "2025-06-18");
        }
        let resp = req
            .body(message.to_string())
            .send()
            .map_err(|e| transport(&e))?;
        let status = resp.status();
        if let Some(s) = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic()))
        {
            self.session = Some(s.to_owned());
        }
        let raw = read_body(resp)?;
        if !status.is_success() {
            // A stale session (the gateway restarted) is dropped so the next call starts anew.
            if status.as_u16() == 404 {
                self.session = None;
            }
            return Err(http_fail(status, &raw, "mcp upstream"));
        }
        let text = String::from_utf8_lossy(&raw);
        let id = message.get("id");
        let answer = parse_answer(&text, id)
            .ok_or_else(|| fail("mcp upstream failed: unexpected response from the gateway"))?;
        // The gateway redacted the upstream credential; this removes the agent's own token.
        let red = st.redactor();
        let out: Value = serde_json::from_str(&redact_str(&red, &answer.to_string()))
            .map_err(|_| fail("mcp upstream failed: unexpected response from the gateway"))?;
        Ok(Some(out))
    }
}

/// The JSON-RPC response for `id` in a JSON or SSE body.
fn parse_answer(text: &str, id: Option<&Value>) -> Option<Value> {
    let matches =
        |v: &Value| v.get("id") == id && (v.get("result").is_some() || v.get("error").is_some());
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        return matches(&v).then_some(v);
    }
    text.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
        .find(matches)
}

/// A JSON-RPC error response for request `id`.
pub fn rpc_error(id: Option<&Value>, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": {"code": -32000, "message": message},
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_gateway_rule() {
        for ok in ["github", "a", "a-1", &"x".repeat(32)] {
            assert!(valid_upstream_name(ok), "{ok}");
        }
        for bad in ["", "GitHub", "a b", "a/b", "../x", "a_b", &"x".repeat(33)] {
            assert!(!valid_upstream_name(bad), "{bad}");
        }
    }

    #[test]
    fn the_answer_is_found_in_json_and_sse() {
        let id = json!(7);
        let m = r#"{"jsonrpc":"2.0","id":7,"result":{"tools":[]}}"#;
        assert!(parse_answer(m, Some(&id)).is_some());
        let sse = format!(
            "data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/x\"}}\n\nid: 1\ndata: {m}\n\n"
        );
        assert_eq!(parse_answer(&sse, Some(&id)).unwrap()["id"], 7);
        // Another id is not the answer.
        assert!(parse_answer(m, Some(&json!(8))).is_none());
        assert!(parse_answer("not json", Some(&id)).is_none());
    }
}
