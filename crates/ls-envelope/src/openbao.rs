//! [`KeyWrapper`] over the OpenBao transit engine (design decision 3).
//!
//! A thin client for two endpoints, `POST /v1/{mount}/encrypt/{key}` and
//! `POST /v1/{mount}/decrypt/{key}`, plus [`TransitSigner`] for `POST /v1/{mount}/sign/{key}`
//! (S5 audit checkpoints). `vaultrs` was rejected: its client settings derive
//! `Debug` and `Clone` over the token as a plain `String`, and its transit requests take the
//! plaintext as a `String`.
//!
//! For an `aes256-gcm96` key, transit returns `vault:v{N}:` then base64 of
//! `nonce(12) ‖ ciphertext ‖ tag(16)`, which is exactly the body of an A0-7 blob. The wrapped
//! DEK stores those bytes behind a `dek-wrap` header whose key id is the transit key name and
//! version `N`; unwrap rebuilds the `vault:v{N}:` string from the header. The A0-7 AAD is sent
//! as transit `associated_data`, so OpenBao refuses to unwrap under another binding.
//!
//! Wrap pins `key_version` to the configured [`WrapKeyId`] version, because the version is part
//! of the authenticated header and must be known before encrypting. Rotation (a later change)
//! means configuring the new version; unwrap accepts any version of the configured key name.
//!
//! Secret handling: the token lives in [`BaoToken`] (zeroized, no Debug/Display/Clone) and goes
//! out as a `sensitive` header. The DEK's base64 form, the request body and the decrypt response
//! are built in zeroizing buffers. Copies made inside hyper and rustls are outside this crate's
//! control and are not zeroized; this is best effort, as with any in-process KMS client.

use crate::DataKey;
use crate::header::{self, Binding, NONCE_LEN, TAG_LEN};
use crate::wrap::{self, KeyWrapper, TransportKind, WrapError, WrapKeyId, WrappedDek};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ls_crypto::{SecretBytes, SecretKey32};
use reqwest::header::{CONTENT_TYPE, HeaderValue};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// Transit ciphertext prefix (OpenBao kept Vault's).
const CT_PREFIX: &str = "vault:v";
/// Largest response body read. Transit answers are well under 1 KiB.
const MAX_RESPONSE: usize = 64 * 1024;
const TOKEN_HEADER: &str = "X-Vault-Token";

/// An OpenBao token. Zeroized on drop; no `Debug`, `Display`, `Clone` or serde.
pub struct BaoToken(SecretBytes);

impl BaoToken {
    /// Takes ownership of the token string without copying it.
    pub fn new(token: String) -> Self {
        Self(SecretBytes::new(token.into_bytes()))
    }

    fn header_value(&self) -> Result<HeaderValue, WrapError> {
        let mut v =
            HeaderValue::from_bytes(self.0.expose()).map_err(|_| WrapError::InvalidConfig)?;
        v.set_sensitive(true);
        Ok(v)
    }
}

/// Wraps DEKs with an OpenBao transit key. `Debug` shows the address, mount and key, never
/// the token.
pub struct OpenBaoTransit {
    client: reqwest::Client,
    addr: String,
    mount: String,
    key: WrapKeyId,
    token: BaoToken,
}

impl OpenBaoTransit {
    /// `addr` is the OpenBao base URL (`http://127.0.0.1:8200`); `key` is the transit key
    /// name and the version new wraps use. Mount defaults to `transit`. The default client
    /// verifies TLS against the OS trust store (rustls, ring), follows no redirects, ignores
    /// proxy environment variables and times out after 10 s.
    pub fn new(addr: &str, key: WrapKeyId, token: BaoToken) -> Result<Self, WrapError> {
        Self::with_client(default_client()?, addr, key, token)
    }

    /// As [`Self::new`] with a caller-built client (custom CA, proxy or timeouts).
    pub fn with_client(
        client: reqwest::Client,
        addr: &str,
        key: WrapKeyId,
        token: BaoToken,
    ) -> Result<Self, WrapError> {
        token.header_value()?;
        Ok(Self {
            client,
            addr: validate_addr(addr)?,
            mount: "transit".to_owned(),
            key,
            token,
        })
    }

    /// Use a transit engine mounted somewhere other than `transit` (e.g. `kms/transit`).
    pub fn with_mount(mut self, mount: &str) -> Result<Self, WrapError> {
        let mount = mount.trim_matches('/');
        if mount.is_empty() || !mount.split('/').all(wrap::valid_name) {
            return Err(WrapError::InvalidConfig);
        }
        self.mount = mount.to_owned();
        Ok(self)
    }

    pub fn key(&self) -> &WrapKeyId {
        &self.key
    }

    fn url(&self, op: &str) -> String {
        format!("{}/v1/{}/{op}/{}", self.addr, self.mount, self.key.name())
    }

    /// POST a JSON body; return the response body in a zeroizing buffer.
    async fn post(&self, op: &str, body: bytes::Bytes) -> Result<Zeroizing<Vec<u8>>, WrapError> {
        post(&self.client, &self.url(op), &self.token, body).await
    }
}

/// POST a JSON body with the token; return the response body in a zeroizing buffer.
async fn post(
    client: &reqwest::Client,
    url: &str,
    token: &BaoToken,
    body: bytes::Bytes,
) -> Result<Zeroizing<Vec<u8>>, WrapError> {
    let mut resp = client
        .post(url)
        .header(TOKEN_HEADER, token.header_value()?)
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .map_err(transport)?;
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(WrapError::Denied);
    }
    if !status.is_success() {
        return Err(WrapError::Rejected {
            status: status.as_u16(),
        });
    }
    let mut out = Zeroizing::new(Vec::with_capacity(1024));
    while let Some(chunk) = resp.chunk().await.map_err(transport)? {
        if out.len() + chunk.len() > MAX_RESPONSE {
            return Err(WrapError::BadResponse);
        }
        if out.len() + chunk.len() > out.capacity() {
            // Grow into a fresh zeroizing buffer so no unwiped copy is left behind.
            let mut bigger = Zeroizing::new(Vec::with_capacity((out.len() + chunk.len()) * 2));
            bigger.extend_from_slice(&out);
            out = bigger;
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

impl std::fmt::Debug for OpenBaoTransit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenBaoTransit")
            .field("addr", &self.addr)
            .field("mount", &self.mount)
            .field("key", &format_args!("{}", self.key))
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(serde::Serialize)]
struct EncryptReq<'a> {
    plaintext: &'a str,
    associated_data: &'a str,
    key_version: u32,
}

#[derive(serde::Deserialize)]
struct EncryptResp {
    data: EncryptData,
}

#[derive(serde::Deserialize)]
struct EncryptData {
    ciphertext: String,
}

#[derive(serde::Serialize)]
struct DecryptReq<'a> {
    ciphertext: &'a str,
    associated_data: &'a str,
}

#[derive(serde::Deserialize)]
struct DecryptResp<'a> {
    #[serde(borrow)]
    data: DecryptData<'a>,
}

/// Borrows the base64 plaintext from the zeroizing response buffer: no owned copy.
#[derive(serde::Deserialize)]
struct DecryptData<'a> {
    plaintext: &'a str,
}

impl KeyWrapper for OpenBaoTransit {
    async fn wrap(&self, dek: &DataKey, binding: &Binding) -> Result<WrappedDek, WrapError> {
        wrap::require_dek_wrap(binding)?;
        let header = crate::Header::v1(self.key.to_key_id()).encode();
        let aad = B64.encode(header::aad(&header, binding).as_bytes());
        let plaintext = Zeroizing::new(B64.encode(dek.expose()));
        let req = EncryptReq {
            plaintext: &plaintext,
            associated_data: &aad,
            key_version: self.key.version(),
        };
        // Sized up front so serde_json never reallocates (which would leave an unwiped copy).
        let mut body = Zeroizing::new(Vec::with_capacity(1024));
        serde_json::to_writer(&mut *body, &req).map_err(|_| WrapError::BadResponse)?;
        let resp = self.post("encrypt", bytes::Bytes::from_owner(body)).await?;
        let resp: EncryptResp =
            serde_json::from_slice(&resp).map_err(|_| WrapError::BadResponse)?;
        let kms_ct = parse_ciphertext(&resp.data.ciphertext, self.key.version())?;
        WrappedDek::assemble(&self.key, &kms_ct)
    }

    async fn unwrap(
        &self,
        wrapped: &WrappedDek,
        binding: &Binding,
    ) -> Result<SecretKey32, WrapError> {
        wrap::require_dek_wrap(binding)?;
        if wrapped.key_id().name() != self.key.name() {
            return Err(WrapError::KeyMismatch);
        }
        let aad = B64.encode(header::aad(&wrapped.header(), binding).as_bytes());
        let ciphertext = format!(
            "{CT_PREFIX}{}:{}",
            wrapped.key_id().version(),
            B64.encode(wrapped.kms_ciphertext())
        );
        let body = serde_json::to_vec(&DecryptReq {
            ciphertext: &ciphertext,
            associated_data: &aad,
        })
        .map_err(|_| WrapError::BadResponse)?;
        let resp = self.post("decrypt", body.into()).await?;
        let resp: DecryptResp<'_> =
            serde_json::from_slice(&resp).map_err(|_| WrapError::BadResponse)?;
        // decode_slice needs room for its length estimate (33 bytes for 44 base64 chars).
        let mut buf = Zeroizing::new([0u8; 48]);
        let n = B64
            .decode_slice(resp.data.plaintext, &mut buf[..])
            .map_err(|_| WrapError::BadResponse)?;
        if n != 32 {
            return Err(WrapError::BadResponse);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&buf[..32]);
        Ok(SecretKey32::from_bytes(*key))
    }
}

/// Signs messages with an OpenBao transit signing key: `POST /v1/{mount}/sign/{key}` (S5
/// design decision 4, the `audit-checkpoint` Ed25519 key). The token should hold a policy that
/// allows `update` on that one path only; this client never reads or exports the key.
///
/// Signing is not secret (the message and the signature are public), but the token is: it lives
/// in [`BaoToken`] and `Debug` shows the address, mount and key only.
pub struct TransitSigner {
    client: reqwest::Client,
    addr: String,
    mount: String,
    key: String,
    token: BaoToken,
}

/// A transit signature: the key version that made it and the raw signature bytes (64 for
/// Ed25519).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitSignature {
    pub key_version: u32,
    pub signature: Vec<u8>,
}

#[derive(serde::Serialize)]
struct SignReq<'a> {
    input: &'a str,
}

#[derive(serde::Deserialize)]
struct SignResp {
    data: SignData,
}

#[derive(serde::Deserialize)]
struct SignData {
    signature: String,
}

/// Longest transit key name accepted for signing (OpenBao allows more; ours are short).
const MAX_SIGN_KEY_LEN: usize = 64;

impl TransitSigner {
    /// `addr` is the OpenBao base URL; `key` the transit key name (1-64 bytes of
    /// `[A-Za-z0-9_-]`). Mount defaults to `transit`. Same client defaults as
    /// [`OpenBaoTransit::new`].
    pub fn new(addr: &str, key: &str, token: BaoToken) -> Result<Self, WrapError> {
        Self::with_client(default_client()?, addr, key, token)
    }

    /// As [`Self::new`] with a caller-built client.
    pub fn with_client(
        client: reqwest::Client,
        addr: &str,
        key: &str,
        token: BaoToken,
    ) -> Result<Self, WrapError> {
        token.header_value()?;
        let key_ok = !key.is_empty()
            && key.len() <= MAX_SIGN_KEY_LEN
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !key_ok {
            return Err(WrapError::InvalidConfig);
        }
        Ok(Self {
            client,
            addr: validate_addr(addr)?,
            mount: "transit".to_owned(),
            key: key.to_owned(),
            token,
        })
    }

    /// The transit key name.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Sign `message` with the latest version of the key.
    pub async fn sign(&self, message: &[u8]) -> Result<TransitSignature, WrapError> {
        let input = B64.encode(message);
        let body =
            serde_json::to_vec(&SignReq { input: &input }).map_err(|_| WrapError::BadResponse)?;
        let url = format!("{}/v1/{}/sign/{}", self.addr, self.mount, self.key);
        let resp = post(&self.client, &url, &self.token, body.into()).await?;
        let resp: SignResp = serde_json::from_slice(&resp).map_err(|_| WrapError::BadResponse)?;
        let rest = resp
            .data
            .signature
            .strip_prefix(CT_PREFIX)
            .ok_or(WrapError::BadResponse)?;
        let (v, b64) = rest.split_once(':').ok_or(WrapError::BadResponse)?;
        let key_version = v
            .parse::<u32>()
            .ok()
            .filter(|&v| v >= 1)
            .ok_or(WrapError::BadResponse)?;
        let signature = B64.decode(b64).map_err(|_| WrapError::BadResponse)?;
        if signature.is_empty() {
            return Err(WrapError::BadResponse);
        }
        Ok(TransitSignature {
            key_version,
            signature,
        })
    }
}

impl std::fmt::Debug for TransitSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitSigner")
            .field("addr", &self.addr)
            .field("mount", &self.mount)
            .field("key", &self.key)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// `vault:v{N}:{base64}` → the raw `nonce ‖ ciphertext ‖ tag`, checking `N` and the length.
fn parse_ciphertext(ct: &str, version: u32) -> Result<Vec<u8>, WrapError> {
    let rest = ct.strip_prefix(CT_PREFIX).ok_or(WrapError::BadResponse)?;
    let (v, b64) = rest.split_once(':').ok_or(WrapError::BadResponse)?;
    if v.parse::<u32>() != Ok(version) {
        return Err(WrapError::BadResponse);
    }
    let raw = B64.decode(b64).map_err(|_| WrapError::BadResponse)?;
    if raw.len() != NONCE_LEN + 32 + TAG_LEN {
        return Err(WrapError::BadResponse);
    }
    Ok(raw)
}

fn validate_addr(addr: &str) -> Result<String, WrapError> {
    let url = reqwest::Url::parse(addr).map_err(|_| WrapError::InvalidConfig)?;
    let ok = matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none();
    if !ok {
        return Err(WrapError::InvalidConfig);
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn default_client() -> Result<reqwest::Client, WrapError> {
    use rustls_platform_verifier::BuilderVerifierExt as _;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| WrapError::Client)?
        .with_platform_verifier()
        .map_err(|_| WrapError::Client)?
        .with_no_client_auth();
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| WrapError::Client)
}

fn transport(e: reqwest::Error) -> WrapError {
    WrapError::Transport(if e.is_timeout() {
        TransportKind::Timeout
    } else if e.is_connect() {
        TransportKind::Connect
    } else {
        TransportKind::Other
    })
}
