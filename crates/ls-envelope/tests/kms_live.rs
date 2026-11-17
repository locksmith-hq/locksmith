//! `OpenBaoTransit` against the live dev OpenBao from `just up` (infra/compose): the S2
//! permission split with the real policies. The control-plane token may only encrypt (wrap);
//! the gateway token may only decrypt (unwrap).
//!
//! Without a reachable OpenBao these tests skip, unless `LS_REQUIRE_KMS=1` (then they fail).
//! Env: `OPENBAO_ADDR` (default `http://127.0.0.1:8200`), `OPENBAO_CONTROL_PLANE_TOKEN`
//! (default `dev-only-control-plane`), `OPENBAO_GATEWAY_TOKEN` (default `dev-only-gateway`).
//! The defaults are dev-only values from `infra/compose/.env.example`, not credentials.

use ls_envelope::{
    BaoToken, Binding, KeyWrapper, OpenBaoTransit, Purpose, SecretBytes, WrapError, WrapKeyId,
    WrappedDek, seal_version,
};

fn addr() -> String {
    std::env::var("OPENBAO_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_owned())
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn transit(token_env: &str, default: &str) -> OpenBaoTransit {
    OpenBaoTransit::new(
        &addr(),
        WrapKeyId::new("gateway", 1).unwrap(),
        BaoToken::new(env_or(token_env, default)),
    )
    .unwrap()
}

fn control_plane() -> OpenBaoTransit {
    transit("OPENBAO_CONTROL_PLANE_TOKEN", "dev-only-control-plane")
}

fn gateway() -> OpenBaoTransit {
    transit("OPENBAO_GATEWAY_TOKEN", "dev-only-gateway")
}

/// True when OpenBao answers; otherwise skip (or fail under `LS_REQUIRE_KMS=1`).
async fn available() -> bool {
    let up = tcp_probe(&addr()).await;
    if !up && std::env::var("LS_REQUIRE_KMS").as_deref() == Ok("1") {
        panic!("OpenBao not reachable and LS_REQUIRE_KMS=1");
    }
    if !up {
        eprintln!("skipping: OpenBao not reachable (run `just up`)");
    }
    up
}

/// Plain TCP connect to host:port of `addr`; no HTTP client dependency needed.
async fn tcp_probe(addr: &str) -> bool {
    let hostport = addr.trim_start_matches("http://").trim_end_matches('/');
    tokio::net::TcpStream::connect(hostport).await.is_ok()
}

fn binding(secret: u8, version: u32, purpose: Purpose) -> Binding {
    Binding {
        org_id: [1; 16],
        secret_id: [secret; 16],
        version,
        purpose,
    }
}

#[tokio::test]
async fn kms_wrap_with_control_plane_unwrap_with_gateway() {
    if !available().await {
        return;
    }
    let sealed = seal_version(
        &binding(2, 1, Purpose::SecretPayload),
        &SecretBytes::new(b"live kms value".to_vec()),
    )
    .unwrap();
    let b = binding(2, 1, Purpose::DekWrap);
    let wrapped = control_plane().wrap(sealed.dek(), &b).await.unwrap();
    assert_eq!(wrapped.key_id().to_string(), "gateway:v1");

    let stored = WrappedDek::from_bytes(wrapped.into_bytes()).unwrap();
    let key = gateway().unwrap(&stored, &b).await.unwrap();
    assert!(key.expose() == sealed.dek().expose(), "DEK mismatch");
}

#[tokio::test]
async fn kms_control_plane_token_cannot_unwrap() {
    if !available().await {
        return;
    }
    let sealed = seal_version(
        &binding(3, 1, Purpose::SecretPayload),
        &SecretBytes::new(b"v".to_vec()),
    )
    .unwrap();
    let b = binding(3, 1, Purpose::DekWrap);
    let wrapped = control_plane().wrap(sealed.dek(), &b).await.unwrap();
    assert_eq!(
        control_plane().unwrap(&wrapped, &b).await.err(),
        Some(WrapError::Denied)
    );
}

#[tokio::test]
async fn kms_gateway_token_cannot_wrap() {
    if !available().await {
        return;
    }
    let sealed = seal_version(
        &binding(4, 1, Purpose::SecretPayload),
        &SecretBytes::new(b"v".to_vec()),
    )
    .unwrap();
    assert_eq!(
        gateway()
            .wrap(sealed.dek(), &binding(4, 1, Purpose::DekWrap))
            .await
            .err(),
        Some(WrapError::Denied)
    );
}

#[tokio::test]
async fn kms_unwrap_under_another_binding_fails() {
    if !available().await {
        return;
    }
    let sealed = seal_version(
        &binding(5, 1, Purpose::SecretPayload),
        &SecretBytes::new(b"v".to_vec()),
    )
    .unwrap();
    let b = binding(5, 1, Purpose::DekWrap);
    let wrapped = control_plane().wrap(sealed.dek(), &b).await.unwrap();
    for other in [
        Binding { version: 2, ..b },
        Binding {
            secret_id: [9; 16],
            ..b
        },
        Binding {
            org_id: [9; 16],
            ..b
        },
    ] {
        assert!(
            matches!(
                gateway().unwrap(&wrapped, &other).await,
                Err(WrapError::Rejected { .. })
            ),
            "unwrap under a different binding must fail"
        );
    }
}
