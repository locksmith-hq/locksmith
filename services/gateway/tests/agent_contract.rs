//! The agent contract fixtures in `tests/kit/agent-contract/` must deserialize into the gateway's
//! own types, so the mock gateway cannot drift from the real one.

use std::path::PathBuf;

use ls_gateway::grants::GrantList;
use ls_gateway::relay::{RelayRequest, RelayResponse};

fn read(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/kit/agent-contract")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|_| panic!("missing fixture {name}"))
}

#[test]
fn agent_contract_grants() {
    let list: GrantList = serde_json::from_slice(&read("grants.json")).unwrap();
    assert!(!list.grants.is_empty());
}

#[test]
fn agent_contract_relay_request() {
    let req: RelayRequest = serde_json::from_slice(&read("relay-request.json")).unwrap();
    assert_eq!(req.method, "GET");
}

#[test]
fn agent_contract_relay_response() {
    let res: RelayResponse = serde_json::from_slice(&read("relay-response.json")).unwrap();
    assert_eq!(res.status, 200);
}
