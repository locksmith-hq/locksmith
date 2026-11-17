//! `OpenBaoTransit` against an in-process fake of the OpenBao transit API (wiremock), so these
//! tests need no live OpenBao. The fake encrypts for real (AES-256-GCM, `vault:vN:` format,
//! `associated_data` as AAD) and enforces the S2 permission split: one token may only encrypt,
//! the other only decrypt. Live OpenBao tests are task 2.3.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ls_envelope::{
    BaoToken, Binding, DataKey, Header, KeyWrapper, OpenBaoTransit, Purpose, SecretBytes,
    TransportKind, WRAPPED_DEK_LEN, WrapError, WrapKeyId, WrappedDek, open_version, seal_version,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

// Test-only fake tokens (not credentials).
const WRAP_TOKEN: &str = "fake-wrap-only";
const UNWRAP_TOKEN: &str = "fake-unwrap-only";

/// A transit key `gateway` with versions 1 and 2.
struct FakeTransit {
    keys: HashMap<u32, [u8; 32]>,
}

impl FakeTransit {
    fn new() -> Self {
        Self {
            keys: HashMap::from([(1, [0x41; 32]), (2, [0x42; 32])]),
        }
    }
}

fn err(status: u16, msg: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(json!({ "errors": [msg] }))
}

impl Respond for FakeTransit {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let token = req
            .headers
            .get("x-vault-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let path = req.url.path();
        let body: Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(_) => return err(400, "bad json"),
        };
        let aad = B64
            .decode(body["associated_data"].as_str().unwrap_or(""))
            .unwrap();
        if path == "/v1/transit/encrypt/gateway" {
            if token != WRAP_TOKEN {
                return err(403, "permission denied");
            }
            let v = body["key_version"].as_u64().unwrap_or(2) as u32;
            let Some(key) = self.keys.get(&v) else {
                return err(
                    400,
                    "requested version for encryption is higher than the latest key version",
                );
            };
            let pt = B64.decode(body["plaintext"].as_str().unwrap()).unwrap();
            let mut nonce = [0u8; 12];
            getrandom::getrandom(&mut nonce).unwrap();
            let ct = aes_gcm::Aes256Gcm::new(key.into())
                .encrypt(
                    aes_gcm::Nonce::from_slice(&nonce),
                    Payload {
                        msg: &pt,
                        aad: &aad,
                    },
                )
                .unwrap();
            let raw = [nonce.as_slice(), &ct].concat();
            ResponseTemplate::new(200).set_body_json(json!({
                "data": { "ciphertext": format!("vault:v{v}:{}", B64.encode(raw)), "key_version": v }
            }))
        } else if path == "/v1/transit/decrypt/gateway" {
            if token != UNWRAP_TOKEN {
                return err(403, "permission denied");
            }
            let ct = body["ciphertext"].as_str().unwrap();
            let rest = ct.strip_prefix("vault:v").unwrap();
            let (v, b64) = rest.split_once(':').unwrap();
            let Some(key) = self.keys.get(&v.parse().unwrap()) else {
                return err(400, "invalid key version");
            };
            let raw = B64.decode(b64).unwrap();
            match aes_gcm::Aes256Gcm::new(key.into()).decrypt(
                aes_gcm::Nonce::from_slice(&raw[..12]),
                Payload {
                    msg: &raw[12..],
                    aad: &aad,
                },
            ) {
                Ok(pt) => ResponseTemplate::new(200)
                    .set_body_json(json!({ "data": { "plaintext": B64.encode(pt) } })),
                Err(_) => err(400, "cipher: message authentication failed"),
            }
        } else {
            err(400, "encryption key not found")
        }
    }
}

async fn server() -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("^/v1/transit/(encrypt|decrypt)/[a-z]+$"))
        .respond_with(FakeTransit::new())
        .mount(&s)
        .await;
    s
}

fn transit(s: &MockServer, token: &str, version: u32) -> OpenBaoTransit {
    OpenBaoTransit::new(
        &s.uri(),
        WrapKeyId::new("gateway", version).unwrap(),
        BaoToken::new(token.to_owned()),
    )
    .unwrap()
}

fn binding(version: u32) -> Binding {
    Binding {
        org_id: [1; 16],
        secret_id: [2; 16],
        version,
        purpose: Purpose::SecretPayload,
    }
}

fn wrap_binding(version: u32) -> Binding {
    Binding {
        purpose: Purpose::DekWrap,
        ..binding(version)
    }
}

#[tokio::test]
async fn wrap_then_unwrap_opens_the_version() {
    let s = server().await;
    let sealed = seal_version(&binding(1), &SecretBytes::new(b"s3cr3t value".to_vec())).unwrap();
    let wrapped = transit(&s, WRAP_TOKEN, 1)
        .wrap(sealed.dek(), &wrap_binding(1))
        .await
        .unwrap();

    // Stored form: an 80-byte A0-7 v1 blob whose key id is the transit key name and version.
    assert_eq!(wrapped.as_bytes().len(), WRAPPED_DEK_LEN);
    assert_eq!(wrapped.key_id().to_string(), "gateway:v1");
    let h = Header::parse(wrapped.as_bytes()).unwrap();
    assert_eq!(h.key_id, WrapKeyId::new("gateway", 1).unwrap().to_key_id());

    // Round trip through storage bytes.
    let stored = WrappedDek::from_bytes(wrapped.into_bytes()).unwrap();
    let key = transit(&s, UNWRAP_TOKEN, 1)
        .unwrap(&stored, &wrap_binding(1))
        .await
        .unwrap();
    assert!(key.expose() == sealed.dek().expose(), "DEK mismatch");

    let blob = sealed.ciphertext();
    let dek = DataKey::from_parts(Header::parse(blob).unwrap().key_id, key);
    let pt = open_version(&dek, &binding(1), blob).unwrap();
    assert!(pt.expose() == b"s3cr3t value");
}

#[tokio::test]
async fn wrap_uses_the_configured_key_version() {
    let s = server().await;
    let sealed = seal_version(&binding(1), &SecretBytes::new(b"v".to_vec())).unwrap();
    let w = transit(&s, WRAP_TOKEN, 2)
        .wrap(sealed.dek(), &wrap_binding(1))
        .await
        .unwrap();
    assert_eq!(w.key_id().to_string(), "gateway:v2");
    // An unwrapper configured for v1 still unwraps v2: unwrap follows the header version.
    let key = transit(&s, UNWRAP_TOKEN, 1)
        .unwrap(&w, &wrap_binding(1))
        .await
        .unwrap();
    assert!(key.expose() == sealed.dek().expose());
    // A version the KMS does not have is rejected.
    let e = transit(&s, WRAP_TOKEN, 9)
        .wrap(sealed.dek(), &wrap_binding(1))
        .await
        .unwrap_err();
    assert_eq!(e, WrapError::Rejected { status: 400 });
}

#[tokio::test]
async fn wrap_only_token_cannot_unwrap_and_unwrap_token_cannot_wrap() {
    let s = server().await;
    let sealed = seal_version(&binding(1), &SecretBytes::new(b"v".to_vec())).unwrap();
    let w = transit(&s, WRAP_TOKEN, 1)
        .wrap(sealed.dek(), &wrap_binding(1))
        .await
        .unwrap();
    let e = transit(&s, WRAP_TOKEN, 1)
        .unwrap(&w, &wrap_binding(1))
        .await
        .err();
    assert_eq!(e, Some(WrapError::Denied));
    let e = transit(&s, UNWRAP_TOKEN, 1)
        .wrap(sealed.dek(), &wrap_binding(1))
        .await
        .err();
    assert_eq!(e, Some(WrapError::Denied));
}

#[tokio::test]
async fn unwrap_under_another_binding_fails() {
    let s = server().await;
    let sealed = seal_version(&binding(1), &SecretBytes::new(b"v".to_vec())).unwrap();
    let w = transit(&s, WRAP_TOKEN, 1)
        .wrap(sealed.dek(), &wrap_binding(1))
        .await
        .unwrap();
    let un = transit(&s, UNWRAP_TOKEN, 1);
    let base = wrap_binding(1);
    for other in [
        Binding { version: 2, ..base },
        Binding {
            secret_id: [9; 16],
            ..base
        },
        Binding {
            org_id: [9; 16],
            ..base
        },
    ] {
        assert_eq!(
            un.unwrap(&w, &other).await.err(),
            Some(WrapError::Rejected { status: 400 })
        );
    }
}

#[tokio::test]
async fn tampered_wrapped_dek_fails() {
    let s = server().await;
    let sealed = seal_version(&binding(1), &SecretBytes::new(b"v".to_vec())).unwrap();
    let w = transit(&s, WRAP_TOKEN, 1)
        .wrap(sealed.dek(), &wrap_binding(1))
        .await
        .unwrap();
    let un = transit(&s, UNWRAP_TOKEN, 1);
    // Every byte after the header (nonce, ciphertext, tag), plus the key version in the header.
    for i in (20..WRAPPED_DEK_LEN).chain([19]) {
        let mut b = w.as_bytes().to_vec();
        b[i] ^= if i == 19 { 0x03 } else { 0x01 };
        let t = WrappedDek::from_bytes(b).unwrap();
        assert_eq!(
            un.unwrap(&t, &wrap_binding(1)).await.err(),
            Some(WrapError::Rejected { status: 400 }),
            "byte {i}"
        );
    }
}

#[tokio::test]
async fn refuses_without_calling_the_kms() {
    let s = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(FakeTransit::new())
        .expect(0)
        .mount(&s)
        .await;
    let sealed = seal_version(&binding(1), &SecretBytes::new(b"v".to_vec())).unwrap();
    let t = transit(&s, WRAP_TOKEN, 1);
    // Payload purpose is refused on both paths.
    assert_eq!(
        t.wrap(sealed.dek(), &binding(1)).await.err(),
        Some(WrapError::Purpose)
    );
    let other = WrapKeyId::new("other", 1).unwrap();
    let foreign = WrappedDek::from_bytes(
        [
            Header::v1(other.to_key_id()).encode().as_slice(),
            &[0u8; 60],
        ]
        .concat(),
    )
    .unwrap();
    assert_eq!(
        t.unwrap(&foreign, &binding(1)).await.err(),
        Some(WrapError::Purpose)
    );
    // A blob wrapped under another key name.
    assert_eq!(
        t.unwrap(&foreign, &wrap_binding(1)).await.err(),
        Some(WrapError::KeyMismatch)
    );
}

#[tokio::test]
async fn each_wrap_differs() {
    let s = server().await;
    let t = transit(&s, WRAP_TOKEN, 1);
    let a = seal_version(&binding(1), &SecretBytes::new(b"v".to_vec())).unwrap();
    let b = seal_version(&binding(2), &SecretBytes::new(b"v".to_vec())).unwrap();
    let wa = t.wrap(a.dek(), &wrap_binding(1)).await.unwrap();
    let wa2 = t.wrap(a.dek(), &wrap_binding(1)).await.unwrap();
    let wb = t.wrap(b.dek(), &wrap_binding(2)).await.unwrap();
    assert_ne!(wa.as_bytes(), wa2.as_bytes());
    assert_ne!(wa.as_bytes(), wb.as_bytes());
}

/// Malformed transit answers map to `BadResponse` without echoing the body.
#[tokio::test]
async fn bad_kms_responses() {
    let sealed = seal_version(&binding(1), &SecretBytes::new(b"v".to_vec())).unwrap();
    let good_raw = B64.encode([0u8; 60]);
    for body in [
        json!({ "data": {} }),
        json!({ "data": { "ciphertext": format!("vault:v2:{good_raw}") } }),
        json!({ "data": { "ciphertext": format!("bao:v1:{good_raw}") } }),
        json!({ "data": { "ciphertext": format!("vault:v1:{}", B64.encode([0u8; 59])) } }),
        json!({ "data": { "ciphertext": "vault:v1:not base64!" } }),
    ] {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .mount(&s)
            .await;
        let e = transit(&s, WRAP_TOKEN, 1)
            .wrap(sealed.dek(), &wrap_binding(1))
            .await
            .err();
        assert_eq!(e, Some(WrapError::BadResponse), "{body}");
    }
    // Decrypt answering with a key of the wrong length.
    let s = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "data": { "plaintext": B64.encode([0u8; 31]) } })),
        )
        .mount(&s)
        .await;
    let w = WrappedDek::from_bytes(
        [
            Header::v1(WrapKeyId::new("gateway", 1).unwrap().to_key_id())
                .encode()
                .as_slice(),
            &[0u8; 60],
        ]
        .concat(),
    )
    .unwrap();
    let e = transit(&s, UNWRAP_TOKEN, 1)
        .unwrap(&w, &wrap_binding(1))
        .await
        .err();
    assert_eq!(e, Some(WrapError::BadResponse));
}

#[tokio::test]
async fn unreachable_kms_is_a_transport_error() {
    // Bind then drop a listener so the port is closed.
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let t = OpenBaoTransit::new(
        &format!("http://{addr}"),
        WrapKeyId::new("gateway", 1).unwrap(),
        BaoToken::new(WRAP_TOKEN.to_owned()),
    )
    .unwrap();
    let sealed = seal_version(&binding(1), &SecretBytes::new(b"v".to_vec())).unwrap();
    assert_eq!(
        t.wrap(sealed.dek(), &wrap_binding(1)).await.err(),
        Some(WrapError::Transport(TransportKind::Connect))
    );
}

#[tokio::test]
async fn token_never_appears_in_debug_or_errors() {
    let s = server().await;
    let t = transit(&s, WRAP_TOKEN, 1);
    let dbg = format!("{t:?}");
    assert!(!dbg.contains(WRAP_TOKEN), "{dbg}");
    assert!(dbg.contains("<redacted>"));
    let sealed = seal_version(&binding(1), &SecretBytes::new(b"v".to_vec())).unwrap();
    let w = t.wrap(sealed.dek(), &wrap_binding(1)).await.unwrap();
    let e = t.unwrap(&w, &wrap_binding(1)).await.err().unwrap();
    for text in [format!("{e}"), format!("{e:?}"), format!("{w:?}")] {
        assert!(!text.contains(WRAP_TOKEN), "{text}");
        assert!(!text.contains(&B64.encode(w.as_bytes())), "{text}");
    }
}

#[test]
fn config_validation() {
    let k = || WrapKeyId::new("gateway", 1).unwrap();
    let tok = || BaoToken::new(WRAP_TOKEN.to_owned());
    for addr in [
        "not a url",
        "ftp://bao:8200",
        "http://user:pw@bao:8200",
        "http://bao:8200/?q=1",
    ] {
        assert_eq!(
            OpenBaoTransit::new(addr, k(), tok()).err(),
            Some(WrapError::InvalidConfig),
            "{addr}"
        );
    }
    let t = OpenBaoTransit::new("https://bao.internal:8200/", k(), tok()).unwrap();
    assert!(format!("{t:?}").contains("addr: \"https://bao.internal:8200\""));
    assert!(t.with_mount("kms/transit").is_ok());
    let t = OpenBaoTransit::new("http://127.0.0.1:8200", k(), tok()).unwrap();
    assert_eq!(t.with_mount("../sys").err(), Some(WrapError::InvalidConfig));
    // A token that cannot be an HTTP header value.
    assert_eq!(
        OpenBaoTransit::new("http://127.0.0.1:8200", k(), BaoToken::new("a\nb".into())).err(),
        Some(WrapError::InvalidConfig)
    );
}
