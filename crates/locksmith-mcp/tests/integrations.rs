//! Smoke test for the MCP entries shipped in `integrations/` (Gemini CLI, Copilot, generic): each
//! names `locksmith-mcp` with no secrets, and the real binary answers `initialize` and
//! `tools/list` over stdio. The live agent CLI is not run here: `skip live` is printed for it.

use serde_json::{Value, json};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn entry(file: &str, key: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../integrations")
        .join(file);
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    v[key]["locksmith"].clone()
}

fn handshake() -> Vec<Value> {
    let home = std::env::temp_dir().join(format!("lsmcp-int-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_locksmith-mcp"))
        .env("LOCKSMITH_HOME", &home)
        .env("XDG_RUNTIME_DIR", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = c.stdin.take().unwrap();
    for m in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    ] {
        writeln!(stdin, "{m}").unwrap();
    }
    drop(stdin);
    let o = c.wait_with_output().unwrap();
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

#[test]
fn shipped_mcp_entries_name_locksmith_mcp_and_the_server_handshakes() {
    for (file, key, live) in [
        ("gemini-cli/settings.json", "mcpServers", "gemini"),
        ("copilot/mcp.json", "servers", "copilot"),
        ("cursor/mcp.json", "mcpServers", "cursor-agent"),
        ("generic-mcp/mcp.json", "mcpServers", ""),
    ] {
        let e = entry(file, key);
        assert_eq!(e["command"], "locksmith-mcp", "{file}");
        assert_eq!(e["args"], json!([]), "{file}: no secrets or arguments");
        assert!(e.get("env").is_none(), "{file}: no env values");
        if live.is_empty() {
            continue; // generic client: there is no agent CLI to run live
        }
        let on_path = std::env::var_os("PATH")
            .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(live).is_file()));
        if !on_path {
            println!("skip live: `{live}` is not on PATH ({file})");
        }
    }
    let replies = handshake();
    let init = replies
        .iter()
        .find(|r| r["id"] == 1)
        .expect("initialize reply");
    assert!(init["result"]["serverInfo"].is_object(), "{init}");
    let tools = replies
        .iter()
        .find(|r| r["id"] == 2)
        .expect("tools/list reply");
    assert!(
        !tools["result"]["tools"].as_array().unwrap().is_empty(),
        "{tools}"
    );
}
