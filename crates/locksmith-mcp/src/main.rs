//! `locksmith-mcp`: the agent-facing MCP server (stdio, newline-delimited JSON-RPC).
//!
//! It is an attested daemon client (`Role::Mcp`). Every tool answers with names and metadata or an
//! opaque `lsk_` token; no tool input or output has a field that can carry a secret value (see the
//! `schemas_carry_no_value_field` test). The agent's lease, not the agent, picks the project.
//!
//! Remote mode (S4 task 3.2): `list_grants` and `relay_request` talk to the Locksmith gateway with
//! the short-lived agent token that `smith login --agent` saved (0600 state file, shared code in
//! `ls-connector`). The token never appears in a tool result (it is redacted), the gateway injects
//! the credential upstream, and the local-vault tools above are unchanged.
// shortcut: hand-rolled JSON-RPC instead of `rmcp` (design D1 names it), to avoid a new
// dependency for a handful of tools; switch to rmcp when request_secret/rotate_secret (task 1.3) land.

use ls_connector::{RelayBody, RelayRequest, State};
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
         "description": "Start a session for this agent (the process that launched this MCP server) and every command it runs, within the human's agent policy. Starting again replaces your earlier session. Out-of-policy requests are refused, never narrowed; the human must start those.",
         "inputSchema": {"type": "object", "required": ["project", "env", "scopes", "ttl_secs"], "properties": {
             "project": {"type": "string"},
             "env": {"type": "string"},
             "scopes": {"type": "array", "items": {"type": "string", "enum": ["run", "git", "http", "db", "aws"]}},
             "ttl_secs": {"type": "integer", "minimum": 1},
             "agent": {"type": "string", "maxLength": 64, "description": "Your client name, e.g. claude-code. Shown to the human as self-reported; never affects what is granted."},
             "model": {"type": "string", "maxLength": 64, "description": "Your model id, e.g. claude-fable-5-2. Shown as self-reported; never affects what is granted."}}}},
        {"name": "locksmith_explain_block",
         "description": "Explain why an action was blocked and what the supported path is.",
         "inputSchema": {"type": "object", "required": ["reason"], "properties": {
             "reason": {"type": "string", "description": "The block message or rule id you received."}}}},
        {"name": "list_grants",
         "description": "Remote mode: secrets this agent may use through the Locksmith gateway (id, name, mode, allowed host, expiry). Never values. Needs `smith login --agent` first.",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "relay_request",
         "description": "Remote mode: send an HTTP request through the Locksmith gateway, which adds the granted credential and returns the upstream response with secrets redacted. Never pass a credential yourself: Authorization, Proxy-Authorization and Cookie headers are refused.",
         "inputSchema": {"type": "object", "required": ["secret_id", "url"], "properties": {
             "secret_id": {"type": "string", "description": "Secret id (UUID) from list_grants."},
             "version": {"type": "integer", "minimum": 1, "description": "Secret version, default 1."},
             "method": {"type": "string", "description": "HTTP method, default GET."},
             "url": {"type": "string", "description": "Upstream URL on the grant's allowed host."},
             "headers": {"type": "object", "additionalProperties": {"type": "string"},
                         "description": "Extra request headers, name to string. No credentials."},
             "body": {"type": "string", "description": "Request body (text)."}}}}
    ])
}

fn explain(reason: &str) -> &'static str {
    let r = reason.to_lowercase().replace('-', "_");
    let table: [(&str, &str); 9] = [
        (
            "relay_only",
            "That key is relay-only for agent sessions: it is never injected into a command. Get an http token with locksmith_issue_token and send it through the relay. Only the human can add the key to `inject` in the agent policy.",
        ),
        (
            "relay_host",
            "For agent sessions a key goes only to hosts the human lists for it in the agent policy, not .locksmith.toml. Do not edit files to add hosts; ask the human.",
        ),
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
                // Validated by the daemon (the trust boundary); empty means not reported.
                agent: args["agent"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(String::from),
                model: args["model"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(String::from),
            }
        }
        "locksmith_explain_block" => {
            let r = args["reason"].as_str().unwrap_or_default();
            return text(explain(r).into(), false);
        }
        "list_grants" => return remote(list_grants()),
        "relay_request" => return remote(relay_request(args)),
        _ => return text(format!("unknown tool {name}"), true),
    };
    match call_daemon(&req) {
        Ok(Response::Keys { keys }) => text(json!({"keys": keys}).to_string(), false),
        Ok(Response::Status { locked, leases }) => {
            text(status_json(locked, &leases).to_string(), false)
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

/// A remote-mode result: the (already redacted) JSON, or a fixed, value-free error message.
fn remote(r: Result<Value, ls_connector::Error>) -> Value {
    match r {
        Ok(v) => text(v.to_string(), false),
        Err(e) => text(e.message, true),
    }
}

/// `list_grants`: names, modes, hosts and expiries from the gateway; the token is redacted.
fn list_grants() -> Result<Value, ls_connector::Error> {
    let st = State::load_fresh()?;
    ls_connector::grants(&st)
}

fn usage(msg: &str) -> ls_connector::Error {
    ls_connector::Error {
        kind: ls_connector::ErrorKind::Usage,
        message: msg.to_owned(),
    }
}

/// Validate `relay_request` arguments. No network or state access.
fn relay_args(args: &Value) -> Result<RelayRequest, ls_connector::Error> {
    let (Some(secret_id), Some(url)) = (args["secret_id"].as_str(), args["url"].as_str()) else {
        return Err(usage("`secret_id` and `url` are required"));
    };
    let secret_id = ls_connector::uuid_like(secret_id)?;
    let version = match &args["version"] {
        Value::Null => 1,
        v => v
            .as_u64()
            .filter(|n| *n >= 1)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| usage("`version` must be a positive integer"))?,
    };
    let method = match &args["method"] {
        Value::Null => "GET".to_owned(),
        Value::String(m) if !m.is_empty() => m.to_ascii_uppercase(),
        _ => return Err(usage("`method` must be a non-empty string")),
    };
    let mut headers = Vec::new();
    match &args["headers"] {
        Value::Null => {}
        Value::Object(m) => {
            for (n, v) in m {
                let Some(v) = v.as_str() else {
                    return Err(usage("`headers` values must be strings"));
                };
                headers.push((n.trim().to_owned(), v.trim().to_owned()));
            }
        }
        _ => return Err(usage("`headers` must be an object of name to string")),
    }
    ls_connector::reject_credential_headers(&headers)?;
    let body = match &args["body"] {
        Value::Null => None,
        Value::String(b) => Some(RelayBody::Text(b.clone())),
        _ => return Err(usage("`body` must be a string")),
    };
    Ok(RelayRequest {
        secret_id,
        version,
        method,
        url: url.to_owned(),
        headers,
        body,
    })
}

/// `relay_request`: the redacted upstream response `{status, headers, body | body_base64}`.
fn relay_request(args: &Value) -> Result<Value, ls_connector::Error> {
    let req = relay_args(args)?;
    let st = State::load_fresh()?;
    Ok(ls_connector::relay(&st, req)?.to_json())
}

/// `locksmith_status`: lease metadata and key names only.
fn status_json(locked: bool, leases: &[ls_ipc::LeaseInfo]) -> Value {
    let l: Vec<Value> = leases
        .iter()
        .map(|l| {
            let mut v = json!({"id": l.id, "project": l.project, "env": l.env,
                   "scopes": l.scopes, "expires_at": l.expires_at, "state": l.state});
            // Agent-started (M10e): key names it may inject; every other key is relay-only.
            if let Some(i) = &l.inject {
                v["inject"] = json!(i);
                v["other_keys"] = json!("relay-only (use locksmith_issue_token)");
            }
            v
        })
        .collect();
    json!({"locked": locked, "sessions": l})
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
    fn lists_seven_tools_and_notifications_get_no_reply() {
        let r = handle(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})).unwrap();
        let names: Vec<&str> = r["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "locksmith_list_keys",
                "locksmith_status",
                "locksmith_issue_token",
                "locksmith_start_session",
                "locksmith_explain_block",
                "list_grants",
                "relay_request"
            ]
        );
        assert!(handle(&json!({"jsonrpc":"2.0","method":"notifications/initialized"})).is_none());
    }

    /// M10e 3.1: an agent lease shows the injectable key names and "relay-only" for the rest; a
    /// human lease shows neither. No field can carry a value.
    #[test]
    fn status_shows_inject_names_for_agent_sessions_only() {
        let lease = |inject: Option<Vec<String>>| ls_ipc::LeaseInfo {
            id: "s".into(),
            root_pid: 1,
            command: "c".into(),
            project: "p".into(),
            env: "e".into(),
            scopes: vec!["run".into()],
            created_at: 0,
            expires_at: 1,
            state: "active".into(),
            root_exe: String::new(),
            started_by: Default::default(),
            source: Default::default(),
            host: None,
            report: None,
            inject,
        };
        let v = status_json(false, &[lease(Some(vec!["OK".into()])), lease(None)]);
        let s = &v["sessions"];
        assert_eq!(s[0]["inject"], json!(["OK"]));
        assert!(s[0]["other_keys"].as_str().unwrap().contains("relay-only"));
        assert!(s[1].get("inject").is_none() && s[1].get("other_keys").is_none());
        let keys: Vec<&String> = s[0].as_object().unwrap().keys().collect();
        for bad in ["value", "secret", "values"] {
            assert!(!keys.iter().any(|k| k.as_str() == bad), "{keys:?}");
        }
    }

    #[test]
    fn explain_block_knows_the_host_rule_and_defaults_to_ask_human() {
        assert!(explain("http_host_not_bound:evil.com").contains("not approved"));
        assert!(explain("relay_only: TEST is relay-only").contains("locksmith_issue_token"));
        assert!(explain("relay-only").contains("locksmith_issue_token"));
        assert!(explain("relay_host:evil.example").contains("agent policy"));
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

    #[test]
    fn relay_request_validates_arguments_before_any_call() {
        const ID: &str = "0191a3b2-7c1e-7a3f-8b2d-5e6f7a8b9c0d";
        for args in [
            json!({}),
            json!({"secret_id": ID}),
            json!({"secret_id": "nope", "url": "https://a.example/"}),
            json!({"secret_id": ID, "url": "https://a.example/", "version": 0}),
            json!({"secret_id": ID, "url": "https://a.example/", "method": 3}),
            json!({"secret_id": ID, "url": "https://a.example/", "headers": [["a", "b"]]}),
            json!({"secret_id": ID, "url": "https://a.example/", "headers": {"a": 1}}),
            json!({"secret_id": ID, "url": "https://a.example/", "body": {"k": 1}}),
            json!({"secret_id": ID, "url": "https://a.example/", "headers": {"Authorization": "Bearer x"}}),
            json!({"secret_id": ID, "url": "https://a.example/", "headers": {"cookie": "s=1"}}),
        ] {
            let e = relay_args(&args).err().unwrap_or_else(|| panic!("{args}"));
            assert_eq!(e.kind, ls_connector::ErrorKind::Usage, "{args}");
        }
        let r = relay_args(&json!({"secret_id": ID, "url": "https://a.example/",
            "method": "post", "headers": {"x-a": "b"}, "body": "{}"}))
        .unwrap();
        assert_eq!((r.version, r.method.as_str()), (1, "POST"));
        assert_eq!(r.headers, [("x-a".to_owned(), "b".to_owned())]);
    }
}
