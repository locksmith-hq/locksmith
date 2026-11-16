//! `locksmith-mcp`: the agent-facing MCP server (stdio, newline-delimited JSON-RPC).
//!
//! It is an attested daemon client (`Role::Mcp`). Every tool answers with names and metadata or an
//! opaque `lsk_` token; no tool input or output has a field that can carry a secret value (see the
//! `schemas_carry_no_value_field` test). The agent's lease, not the agent, picks the project.
// shortcut: hand-rolled JSON-RPC instead of `rmcp` (design D1 names it), to avoid a new
// dependency for a handful of tools; switch to rmcp when request_secret/rotate_secret (task 1.3) land.

use ls_ipc::{Client, Request, Response};
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::Path;

const BINDING_URI: &str = "locksmith://project/binding";

fn tools() -> Value {
    json!([
        {"name": "locksmith_list_keys",
         "description": "Names of the keys available to this session's project and environment. Never values.",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "locksmith_status",
         "description": "Active sessions: project, environment, scopes and expiry.",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "locksmith_issue_token",
         "description": "Mint an opaque lsk_ token for a key. Pass it to the API as the credential; the real key never reaches you.",
         "inputSchema": {"type": "object", "required": ["key"], "properties": {
             "key": {"type": "string", "description": "Key name from locksmith_list_keys."},
             "provider": {"type": "string"},
             "hosts": {"type": "array", "items": {"type": "string"}},
             "placement": {"type": "string"}}}},
        {"name": "locksmith_start_session",
         "description": "Start a session for this process within the human's agent policy. Out-of-policy requests are refused, never narrowed; the human must start those.",
         "inputSchema": {"type": "object", "required": ["project", "env", "scopes", "ttl_secs"], "properties": {
             "project": {"type": "string"},
             "env": {"type": "string"},
             "scopes": {"type": "array", "items": {"type": "string", "enum": ["run", "git", "http", "db", "aws"]}},
             "ttl_secs": {"type": "integer", "minimum": 1}}}},
        {"name": "locksmith_explain_block",
         "description": "Explain why an action was blocked and what the supported path is.",
         "inputSchema": {"type": "object", "required": ["reason"], "properties": {
             "reason": {"type": "string", "description": "The block message or rule id you received."}}}}
    ])
}

fn explain(reason: &str) -> &'static str {
    let r = reason.to_lowercase();
    let table: [(&str, &str); 7] = [
        (
            "agent_policy",
            "The agent policy does not allow that session. Do not retry with other values; ask the human to start it or to change the policy.",
        ),
        (
            "http_host_not_bound",
            "That host is not approved for the key. The human lists it under [http.keys] in .locksmith.toml and starts a new session.",
        ),
        (
            "expired",
            "The session lease expired. Ask the human to start a new session.",
        ),
        (
            "revoked",
            "The session was revoked. Stop and ask the human.",
        ),
        (
            "locked",
            "The vault is locked or no session covers this process. Ask the human to unlock and start a session.",
        ),
        (
            "attestation",
            "The caller is not an attested Locksmith binary. Use `smith` or this MCP server.",
        ),
        (
            "role",
            "That request is not available to agents. Use the MCP tools or `smith run`.",
        ),
    ];
    table.iter().find(|(k, _)| r.contains(k)).map_or(
        "No known rule matches. Do not retry or look for a workaround; ask the human.",
        |(_, v)| v,
    )
}

/// `.locksmith.toml` of the repository containing the cwd (up to the git root).
fn find_binding() -> Option<std::path::PathBuf> {
    let mut d = std::env::current_dir().ok()?;
    loop {
        let f = d.join(".locksmith.toml");
        if f.is_file() {
            return Some(f);
        }
        if d.join(".git").exists() || !d.pop() {
            return None;
        }
    }
}

fn binding_bytes() -> Option<Vec<u8>> {
    find_binding().and_then(|p| std::fs::read(p).ok())
}

fn call_daemon(req: &Request) -> Result<Response, String> {
    let mut c = Client::connect_default().map_err(|e| format!("daemon not reachable: {e}"))?;
    c.call(req).map_err(|e| e.to_string())
}

fn text(s: String, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": s}], "isError": is_error})
}

fn tool_call(name: &str, args: &Value) -> Value {
    let strs = |k: &str| -> Vec<String> {
        args[k]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let req = match name {
        "locksmith_list_keys" => Request::LeaseKeys,
        "locksmith_status" => Request::Status,
        "locksmith_issue_token" => {
            let Some(key) = args["key"].as_str() else {
                return text("`key` is required".into(), true);
            };
            Request::TokenIssue {
                key: key.into(),
                provider: args["provider"].as_str().map(String::from),
                hosts: strs("hosts"),
                placement: args["placement"].as_str().map(String::from),
                binding: binding_bytes(),
            }
        }
        "locksmith_start_session" => {
            let (Some(project), Some(env), Some(ttl_secs)) = (
                args["project"].as_str(),
                args["env"].as_str(),
                args["ttl_secs"].as_u64(),
            ) else {
                return text("`project`, `env` and `ttl_secs` are required".into(), true);
            };
            let scopes = strs("scopes");
            if scopes.is_empty() {
                return text("`scopes` must list at least one scope".into(), true);
            }
            Request::AgentSessionStart {
                project: project.into(),
                env: env.into(),
                scopes,
                ttl_secs,
                command: "agent via locksmith-mcp".into(),
                binding: binding_bytes(),
            }
        }
        "locksmith_explain_block" => {
            let r = args["reason"].as_str().unwrap_or_default();
            return text(explain(r).into(), false);
        }
        _ => return text(format!("unknown tool {name}"), true),
    };
    match call_daemon(&req) {
        Ok(Response::Keys { keys }) => text(json!({"keys": keys}).to_string(), false),
        Ok(Response::Status { locked, leases }) => {
            let l: Vec<Value> = leases
                .iter()
                .map(|l| {
                    json!({"id": l.id, "project": l.project, "env": l.env,
                           "scopes": l.scopes, "expires_at": l.expires_at, "state": l.state})
                })
                .collect();
            text(json!({"locked": locked, "sessions": l}).to_string(), false)
        }
        Ok(Response::HttpToken(t)) => text(
            json!({"token": t.token, "key": t.key, "hosts": t.hosts,
                   "placement": t.placement, "base_url": t.base_url})
            .to_string(),
            false,
        ),
        Ok(Response::Session { id, expires_at }) => text(
            json!({"session": id, "expires_at": expires_at}).to_string(),
            false,
        ),
        Ok(Response::Error { message, .. }) => text(message, true),
        Ok(_) => text("unexpected daemon response".into(), true),
        Err(e) => text(e, true),
    }
}

/// One JSON-RPC message in, at most one out (notifications get none).
fn handle(msg: &Value) -> Option<Value> {
    let id = msg.get("id")?.clone();
    let reply = |r: Result<Value, (i64, &str)>| match r {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err((code, m)) => {
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": m}})
        }
    };
    let p = &msg["params"];
    Some(reply(match msg["method"].as_str().unwrap_or_default() {
        "initialize" => Ok(json!({
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {}, "resources": {}},
            "serverInfo": {"name": "locksmith", "version": env!("CARGO_PKG_VERSION")}})),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => Ok(tool_call(
            p["name"].as_str().unwrap_or_default(),
            &p["arguments"],
        )),
        "resources/list" => Ok(json!({"resources": [{
            "uri": BINDING_URI, "name": "Project binding (.locksmith.toml)",
            "mimeType": "application/toml"}]})),
        "resources/read" if p["uri"] == BINDING_URI => {
            let body = find_binding()
                .and_then(|f| std::fs::read_to_string(Path::new(&f)).ok())
                .unwrap_or_default();
            Ok(
                json!({"contents": [{"uri": BINDING_URI, "mimeType": "application/toml", "text": body}]}),
            )
        }
        "resources/read" => Err((-32002, "unknown resource")),
        _ => Err((-32601, "method not found")),
    }))
}

fn main() {
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if let Some(r) = handle(&msg)
            && writeln!(out, "{r}").and_then(|_| out.flush()).is_err()
        {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gate A7 groundwork: no tool input can carry a secret value.
    #[test]
    fn schemas_carry_no_value_field() {
        fn keys(v: &Value, out: &mut Vec<String>) {
            if let Some(o) = v.as_object() {
                for (k, x) in o {
                    out.push(k.to_lowercase());
                    keys(x, out);
                }
            } else if let Some(a) = v.as_array() {
                a.iter().for_each(|x| keys(x, out));
            }
        }
        let mut all = vec![];
        keys(&tools(), &mut all);
        for bad in ["value", "secret", "password", "passphrase", "token_value"] {
            assert!(!all.iter().any(|k| k == bad), "schema has a `{bad}` field");
        }
    }

    #[test]
    fn lists_five_tools_and_notifications_get_no_reply() {
        let r = handle(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})).unwrap();
        assert_eq!(r["result"]["tools"].as_array().unwrap().len(), 5);
        assert!(handle(&json!({"jsonrpc":"2.0","method":"notifications/initialized"})).is_none());
    }

    #[test]
    fn explain_block_knows_the_host_rule_and_defaults_to_ask_human() {
        assert!(explain("http_host_not_bound:evil.com").contains("not approved"));
        assert!(explain("???").contains("ask the human"));
    }

    #[test]
    fn start_session_validates_arguments_before_the_daemon() {
        for args in [
            json!({}),
            json!({"project": "p", "env": "dev", "scopes": ["http"]}),
            json!({"project": "p", "env": "dev", "scopes": [], "ttl_secs": 60}),
            json!({"project": "p", "env": "dev", "scopes": ["http"], "ttl_secs": -1}),
        ] {
            assert_eq!(
                tool_call("locksmith_start_session", &args)["isError"],
                true,
                "{args}"
            );
        }
        assert!(
            explain("agent_policy: env 'p/prod' is not in the agent policy")
                .contains("ask the human")
        );
    }

    #[test]
    fn issue_token_requires_a_key() {
        let r = tool_call("locksmith_issue_token", &json!({}));
        assert_eq!(r["isError"], true);
    }
}
