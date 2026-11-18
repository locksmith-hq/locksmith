//! `TransitSigner` against an in-process fake of `POST /v1/transit/sign/{key}` (wiremock): the
//! request shape, the `vault:vN:` signature parsing and the error mapping. The control plane's
//! checkpoint tests (S5 task 4.3) sign and verify real Ed25519 signatures through it; the live
//! OpenBao check is in `kms_live.rs`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ls_envelope::{BaoToken, TransitSigner, WrapError};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// Test-only fake token (not a credential).
const TOKEN: &str = "fake-sign-only";
const SIGN_PATH: &str = "/v1/transit/sign/audit-checkpoint";

fn signer(server: &MockServer) -> TransitSigner {
    TransitSigner::new(
        &server.uri(),
        "audit-checkpoint",
        BaoToken::new(TOKEN.to_owned()),
    )
    .unwrap()
}

async fn answering(resp: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(SIGN_PATH))
        .respond_with(resp)
        .mount(&server)
        .await;
    server
}

fn signature(s: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(json!({ "data": { "signature": s, "key_version": 2 } }))
}

#[tokio::test]
async fn sign_sends_base64_input_with_the_token_and_parses_the_signature() {
    let server = MockServer::start().await;
    let sig = [7u8; 64];
    Mock::given(method("POST"))
        .and(path(SIGN_PATH))
        .and(header("x-vault-token", TOKEN))
        .and(body_json(
            json!({ "input": B64.encode(b"checkpoint bytes") }),
        ))
        .respond_with(signature(&format!("vault:v2:{}", B64.encode(sig))))
        .expect(1)
        .mount(&server)
        .await;
    let s = signer(&server).sign(b"checkpoint bytes").await.unwrap();
    assert_eq!(s.key_version, 2);
    assert_eq!(s.signature, sig.to_vec());
}

#[tokio::test]
async fn malformed_signatures_are_bad_responses() {
    for bad in [
        "AAAA",
        "vault:v0:AAAA",
        "vault:vx:AAAA",
        "vault:v1:",
        "vault:v1:not base64!",
        "vault:v1",
    ] {
        let server = answering(signature(bad)).await;
        assert_eq!(
            signer(&server).sign(b"m").await.err(),
            Some(WrapError::BadResponse),
            "{bad}"
        );
    }
    let server = answering(ResponseTemplate::new(200).set_body_string("{}")).await;
    assert_eq!(
        signer(&server).sign(b"m").await.err(),
        Some(WrapError::BadResponse)
    );
}

#[tokio::test]
async fn refusals_map_to_denied_and_rejected() {
    let server = answering(ResponseTemplate::new(403)).await;
    assert_eq!(
        signer(&server).sign(b"m").await.err(),
        Some(WrapError::Denied)
    );
    let server = answering(ResponseTemplate::new(500)).await;
    assert_eq!(
        signer(&server).sign(b"m").await.err(),
        Some(WrapError::Rejected { status: 500 })
    );
}

#[test]
fn config_is_checked_and_debug_redacts_the_token() {
    let new =
        |addr: &str, key: &str| TransitSigner::new(addr, key, BaoToken::new(TOKEN.to_owned()));
    for key in ["", "a/b", "../x", &"k".repeat(65)] {
        assert_eq!(
            new("http://127.0.0.1:8200", key)
                .err()
                .map(|e| e.to_string()),
            Some(WrapError::InvalidConfig.to_string()),
            "{key}"
        );
    }
    assert!(new("ftp://h", "audit-checkpoint").is_err());
    let s = new("http://127.0.0.1:8200/", "audit-checkpoint").unwrap();
    assert_eq!(s.key(), "audit-checkpoint");
    let dbg = format!("{s:?}");
    assert!(dbg.contains("audit-checkpoint") && dbg.contains("<redacted>"));
    assert!(!dbg.contains(TOKEN));
}
