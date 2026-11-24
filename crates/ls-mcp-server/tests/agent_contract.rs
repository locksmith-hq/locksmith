//! Drift tests for the agent contract fixtures in `tests/kit/agent-contract/`. The mock gateway
//! and every framework adapter read those files, so they must equal what the gateway serves.
//! `UPDATE_FIXTURES=1 cargo test -p ls-mcp-server agent_contract` regenerates them.

use std::path::PathBuf;

use ls_mcp_server::{FORBIDDEN_LAST_WORDS, agent_tools, tool_from_def};
use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/kit/agent-contract").join(name)
}

fn check(name: &str, actual: &Value) {
    let path = fixture(name);
    let text = format!("{}\n", serde_json::to_string_pretty(actual).unwrap());
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, text).unwrap();
        return;
    }
    let on_disk = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing {name}: run with UPDATE_FIXTURES=1"));
    assert_eq!(on_disk, text, "{name} drifted: run with UPDATE_FIXTURES=1 and review the diff");
}

#[test]
fn agent_contract_mcp_tools() {
    let tools: Vec<_> = agent_tools().iter().map(tool_from_def).collect();
    check("mcp-tools.json", &serde_json::to_value(tools).unwrap());
}

#[test]
fn agent_contract_forbidden_words() {
    check("forbidden-words.json", &serde_json::to_value(FORBIDDEN_LAST_WORDS).unwrap());
}
