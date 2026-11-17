//! The decrypt path (S3 design decisions 2 and 3): fetch a version's stored envelope from the
//! control plane, unwrap its data key with the gateway's KMS credential, open the ciphertext.
//!
//! - [`MaterialSource`] fetches ciphertext and the wrapped DEK ([`ControlPlane`] over the
//!   internal material endpoint). Neither is secret.
//! - [`Unwrapper`] unwraps a DEK; every `ls_envelope::KeyWrapper` (so [`OpenBaoTransit`]) is one.
//! - [`DekCache`] keeps unwrapped DEKs for a bounded TTL (default 60 s, at most 1000 entries).
//!   Entries hold the key in `ls-envelope`'s [`DataKey`], whose `SecretKey32` is zeroized on
//!   drop, so eviction zeroizes (once any in-flight request using the key finishes).
//! - [`Decryptor::decrypt`] returns the value in [`SecretBytes`] (zeroized on drop).
//!
//! No type here that holds a key or a value implements `Debug`, `Display` or `Clone`, and no
//! error carries key material, the value or a KMS / control-plane response body.
//!
//! [`OpenBaoTransit`]: ls_envelope::OpenBaoTransit

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ls_envelope::{
    Binding, DataKey, Header, KeyWrapper, Purpose, SecretBytes, SecretKey32, WrapError, WrappedDek,
    open_version,
};
use reqwest::header::{AUTHORIZATION, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use url::Url;
use uuid::Uuid;

use crate::http_client;

/// A boxed, sendable future (the traits here are used as trait objects).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Header naming the org the gateway acts for on the internal endpoint (S3 task 1).
pub const ORG_HEADER: &str = "X-Locksmith-Org";

/// Largest material response read. A version blob is bounded by the control plane's value limit.
const MAX_MATERIAL_RESPONSE: usize = 1024 * 1024;

/// The stored envelope of one secret version. Not secret: ciphertext and a KMS-wrapped key.
pub struct Material {
    pub ciphertext: Vec<u8>,
    pub wrapped_dek: WrappedDek,
}

/// Why the material could not be fetched. No variant carries a response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterialError {
    /// The control plane has no such version for this org.
    NotFound,
    /// The control plane refused the service token.
    Denied,
    /// Unreachable, timed out or answered with an unexpected status.
    Unavailable,
    /// The answer did not parse, or names another secret, version or key.
    BadResponse,
}

/// Fetches the stored envelope of a secret version.
pub trait MaterialSource: Send + Sync {
    fn fetch(
        &self,
        secret_id: Uuid,
        version: u32,
    ) -> BoxFuture<'_, Result<Material, MaterialError>>;
}

/// Unwraps a data key with the gateway's KMS credential.
pub trait Unwrapper: Send + Sync {
    fn unwrap_dek<'a>(
        &'a self,
        wrapped: &'a WrappedDek,
        binding: &'a Binding,
    ) -> BoxFuture<'a, Result<SecretKey32, WrapError>>;
}

impl<K: KeyWrapper + Send + Sync> Unwrapper for K {
    fn unwrap_dek<'a>(
        &'a self,
        wrapped: &'a WrappedDek,
        binding: &'a Binding,
    ) -> BoxFuture<'a, Result<SecretKey32, WrapError>> {
        Box::pin(self.unwrap(wrapped, binding))
    }
}

/// The control plane's internal material endpoint, called with the gateway service token.
/// No `Debug` or `Clone`: it holds the token.
pub struct ControlPlane {
    client: reqwest::Client,
    base: Url,
    org_id: Uuid,
    token: SecretString,
}

impl ControlPlane {
    pub fn new(
        base: Url,
        org_id: Uuid,
        token: SecretString,
    ) -> Result<Self, http_client::ClientBuildError> {
        let client = http_client::build(Duration::from_secs(3), Duration::from_secs(10), None)?;
        Ok(Self {
            client,
            base,
            org_id,
            token,
        })
    }

    fn url(&self, secret_id: Uuid, version: u32) -> Result<Url, MaterialError> {
        self.base
            .join(&format!(
                "internal/v1/secrets/{secret_id}/versions/{version}/material"
            ))
            .map_err(|_| MaterialError::BadResponse)
    }

    async fn get(&self, secret_id: Uuid, version: u32) -> Result<Material, MaterialError> {
        let mut auth = HeaderValue::try_from(format!("Bearer {}", self.token.expose_secret()))
            .map_err(|_| MaterialError::Denied)?;
        auth.set_sensitive(true);
        let mut resp = self
            .client
            .get(self.url(secret_id, version)?)
            .header(AUTHORIZATION, auth)
            .header(ORG_HEADER, self.org_id.to_string())
            .send()
            .await
            .map_err(|_| MaterialError::Unavailable)?;
        match resp.status().as_u16() {
            200 => {}
            404 => return Err(MaterialError::NotFound),
            401 | 403 => return Err(MaterialError::Denied),
            _ => return Err(MaterialError::Unavailable),
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|_| MaterialError::Unavailable)? {
            if body.len() + chunk.len() > MAX_MATERIAL_RESPONSE {
                return Err(MaterialError::BadResponse);
            }
            body.extend_from_slice(&chunk);
        }
        parse_material(&body, secret_id, version)
    }
}

impl MaterialSource for ControlPlane {
    fn fetch(
        &self,
        secret_id: Uuid,
        version: u32,
    ) -> BoxFuture<'_, Result<Material, MaterialError>> {
        Box::pin(self.get(secret_id, version))
    }
}

#[derive(Deserialize)]
struct MaterialJson {
    secret_id: Uuid,
    version: u32,
    key_id: String,
    ciphertext: String,
    wrapped_dek: String,
}

/// Parse the endpoint's JSON and check it answers the question asked.
pub fn parse_material(
    body: &[u8],
    secret_id: Uuid,
    version: u32,
) -> Result<Material, MaterialError> {
    let m: MaterialJson = serde_json::from_slice(body).map_err(|_| MaterialError::BadResponse)?;
    if m.secret_id != secret_id || m.version != version {
        return Err(MaterialError::BadResponse);
    }
    let ciphertext = B64
        .decode(&m.ciphertext)
        .map_err(|_| MaterialError::BadResponse)?;
    let wrapped = B64
        .decode(&m.wrapped_dek)
        .map_err(|_| MaterialError::BadResponse)?;
    let wrapped_dek = WrappedDek::from_bytes(wrapped).map_err(|_| MaterialError::BadResponse)?;
    if wrapped_dek.key_id().to_string() != m.key_id {
        return Err(MaterialError::BadResponse);
    }
    Ok(Material {
        ciphertext,
        wrapped_dek,
    })
}

/// DEK cache bounds (design decision 3).
#[derive(Debug, Clone, Copy)]
pub struct CacheSettings {
    pub ttl: Duration,
    pub max_entries: usize,
}

impl Default for CacheSettings {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(60),
            max_entries: 1000,
        }
    }
}

type CacheKey = (Uuid, u32);

/// One cached key. No `Debug`/`Clone`: it owns a DEK.
struct CacheEntry {
    dek: Arc<DataKey>,
    inserted: Instant,
}

/// Unwrapped DEKs by (secret id, version), for at most `ttl`. Expired entries are dropped on
/// every access and by [`DekCache::purge_expired`]; dropping the last `Arc` zeroizes the key.
pub struct DekCache {
    settings: CacheSettings,
    entries: Mutex<HashMap<CacheKey, CacheEntry>>,
}

impl DekCache {
    pub fn new(settings: CacheSettings) -> Self {
        Self {
            settings,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<CacheKey, CacheEntry>> {
        // A panic while holding the lock cannot leave a half-written entry; keep serving.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get(&self, secret_id: Uuid, version: u32) -> Option<Arc<DataKey>> {
        self.get_at(secret_id, version, Instant::now())
    }

    pub fn insert(&self, secret_id: Uuid, version: u32, dek: DataKey) -> Arc<DataKey> {
        self.insert_at(secret_id, version, dek, Instant::now())
    }

    /// Drop every expired entry (zeroizing its key). Returns how many were dropped.
    pub fn purge_expired(&self) -> usize {
        self.purge_at(Instant::now())
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn expired(&self, e: &CacheEntry, now: Instant) -> bool {
        now.saturating_duration_since(e.inserted) >= self.settings.ttl
    }

    fn get_at(&self, secret_id: Uuid, version: u32, now: Instant) -> Option<Arc<DataKey>> {
        let mut map = self.lock();
        let key = (secret_id, version);
        let fresh = map.get(&key).map(|e| !self.expired(e, now))?;
        if fresh {
            map.get(&key).map(|e| e.dek.clone())
        } else {
            map.remove(&key);
            None
        }
    }

    fn insert_at(&self, secret_id: Uuid, version: u32, dek: DataKey, now: Instant) -> Arc<DataKey> {
        let dek = Arc::new(dek);
        if self.settings.max_entries == 0 || self.settings.ttl.is_zero() {
            return dek;
        }
        let mut map = self.lock();
        map.retain(|_, e| !self.expired(e, now));
        while map.len() >= self.settings.max_entries {
            let oldest = map.iter().min_by_key(|(_, e)| e.inserted).map(|(k, _)| *k);
            match oldest {
                Some(k) => {
                    map.remove(&k);
                }
                None => break,
            }
        }
        map.insert(
            (secret_id, version),
            CacheEntry {
                dek: dek.clone(),
                inserted: now,
            },
        );
        dek
    }

    fn purge_at(&self, now: Instant) -> usize {
        let mut map = self.lock();
        let before = map.len();
        map.retain(|_, e| !self.expired(e, now));
        before - map.len()
    }

    /// Purge expired entries every `every` until the returned handle is aborted, so an unused
    /// key does not outlive its TTL by more than one interval.
    pub fn spawn_sweeper(self: &Arc<Self>, every: Duration) -> tokio::task::JoinHandle<()> {
        let cache = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                match cache.upgrade() {
                    Some(c) => {
                        c.purge_expired();
                    }
                    None => return,
                }
            }
        })
    }
}

/// Why a value could not be decrypted. No variant carries key material or the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptError {
    Material(MaterialError),
    /// The KMS refused or failed to unwrap the data key.
    Unwrap(WrapError),
    /// The ciphertext did not open under the data key and binding.
    Open,
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Material(e) => write!(f, "secret material unavailable ({e:?})"),
            Self::Unwrap(e) => write!(f, "data key unwrap failed: {e}"),
            Self::Open => f.write_str("secret version did not decrypt"),
        }
    }
}

impl std::error::Error for DecryptError {}

/// Fetch, unwrap (through the cache) and open one secret version for the gateway's org.
pub struct Decryptor {
    org_id: Uuid,
    material: Arc<dyn MaterialSource>,
    unwrapper: Arc<dyn Unwrapper>,
    cache: Arc<DekCache>,
}

impl Decryptor {
    pub fn new(
        org_id: Uuid,
        material: Arc<dyn MaterialSource>,
        unwrapper: Arc<dyn Unwrapper>,
        cache: Arc<DekCache>,
    ) -> Self {
        Self {
            org_id,
            material,
            unwrapper,
            cache,
        }
    }

    pub fn cache(&self) -> &Arc<DekCache> {
        &self.cache
    }

    /// The A0-7 binding of a version for `purpose`.
    pub fn binding(&self, secret_id: Uuid, version: u32, purpose: Purpose) -> Binding {
        Binding {
            org_id: *self.org_id.as_bytes(),
            secret_id: *secret_id.as_bytes(),
            version,
            purpose,
        }
    }

    pub async fn decrypt(
        &self,
        secret_id: Uuid,
        version: u32,
    ) -> Result<SecretBytes, DecryptError> {
        let material = self
            .material
            .fetch(secret_id, version)
            .await
            .map_err(DecryptError::Material)?;
        let dek = match self.cache.get(secret_id, version) {
            Some(dek) => dek,
            None => {
                let key = self
                    .unwrapper
                    .unwrap_dek(
                        &material.wrapped_dek,
                        &self.binding(secret_id, version, Purpose::DekWrap),
                    )
                    .await
                    .map_err(DecryptError::Unwrap)?;
                let header = Header::parse(&material.ciphertext).map_err(|_| DecryptError::Open)?;
                self.cache
                    .insert(secret_id, version, DataKey::from_parts(header.key_id, key))
            }
        };
        open_version(
            &dek,
            &self.binding(secret_id, version, Purpose::SecretPayload),
            &material.ciphertext,
        )
        .map_err(|_| DecryptError::Open)
    }
}

/// Test support: seal a value as the control plane would, with a stand-in KMS wrap.
#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use ls_envelope::{WrapKeyId, seal_version};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The key id the fake KMS wraps under.
    pub fn key() -> WrapKeyId {
        WrapKeyId::new("gateway", 1).unwrap()
    }

    /// A sealed version: the stored material, plus the raw DEK the fake KMS hands back.
    pub struct Sealed {
        pub ciphertext: Vec<u8>,
        pub wrapped: Vec<u8>,
        pub dek: [u8; 32],
    }

    pub fn seal(org: Uuid, secret: Uuid, version: u32, value: &[u8]) -> Sealed {
        let binding = Binding {
            org_id: *org.as_bytes(),
            secret_id: *secret.as_bytes(),
            version,
            purpose: Purpose::SecretPayload,
        };
        let sealed = seal_version(&binding, &SecretBytes::new(value.to_vec())).unwrap();
        let (ciphertext, dek) = sealed.into_parts();
        // A structurally valid dek-wrap blob; its body is opaque to the gateway.
        // Distinct per (secret, version), so a stub KMS can answer each one.
        let mut wrapped = Header::v1(key().to_key_id()).encode().to_vec();
        wrapped.extend_from_slice(secret.as_bytes());
        wrapped.extend_from_slice(&version.to_be_bytes());
        wrapped.extend_from_slice(&[7u8; 40]);
        Sealed {
            ciphertext,
            wrapped,
            dek: *dek.expose(),
        }
    }

    impl Sealed {
        pub fn json(&self, secret: Uuid, version: u32) -> serde_json::Value {
            serde_json::json!({
                "secret_id": secret,
                "version": version,
                "key_id": key().to_string(),
                "ciphertext": B64.encode(&self.ciphertext),
                "wrapped_dek": B64.encode(&self.wrapped),
            })
        }

        /// The transit ciphertext the gateway sends to OpenBao to unwrap this DEK (base64 part).
        pub fn transit_ciphertext(&self) -> String {
            B64.encode(&self.wrapped[ls_envelope::header::HEADER_LEN..])
        }

        pub fn material(&self) -> Material {
            Material {
                ciphertext: self.ciphertext.clone(),
                wrapped_dek: WrappedDek::from_bytes(self.wrapped.clone()).unwrap(),
            }
        }
    }

    /// Serves one sealed version; counts fetches.
    pub struct FakeMaterial {
        pub sealed: Sealed,
        pub secret: Uuid,
        pub version: u32,
        pub fetches: AtomicUsize,
    }

    impl MaterialSource for FakeMaterial {
        fn fetch(
            &self,
            secret_id: Uuid,
            version: u32,
        ) -> BoxFuture<'_, Result<Material, MaterialError>> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            let found = secret_id == self.secret && version == self.version;
            Box::pin(async move {
                if found {
                    Ok(self.sealed.material())
                } else {
                    Err(MaterialError::NotFound)
                }
            })
        }
    }

    /// Returns a fixed DEK (or an error) and counts unwrap calls.
    pub struct FakeKms {
        pub dek: Option<[u8; 32]>,
        pub calls: AtomicUsize,
    }

    impl Unwrapper for FakeKms {
        fn unwrap_dek<'a>(
            &'a self,
            _wrapped: &'a WrappedDek,
            binding: &'a Binding,
        ) -> BoxFuture<'a, Result<SecretKey32, WrapError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let purpose_ok = binding.purpose == Purpose::DekWrap;
            Box::pin(async move {
                match self.dek {
                    Some(k) if purpose_ok => Ok(SecretKey32::from_bytes(k)),
                    Some(_) => Err(WrapError::Purpose),
                    None => Err(WrapError::Rejected { status: 500 }),
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use ls_envelope::{BaoToken, OpenBaoTransit};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_000000000001);
    const SECRET: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_000000000002);
    const VALUE: &[u8] = b"canary-decrypt-3f9a1c";

    fn decryptor(sealed: Sealed, kms: Arc<dyn Unwrapper>) -> (Decryptor, Arc<FakeMaterial>) {
        let material = Arc::new(FakeMaterial {
            sealed,
            secret: SECRET,
            version: 1,
            fetches: AtomicUsize::new(0),
        });
        let d = Decryptor::new(
            ORG,
            material.clone(),
            kms,
            Arc::new(DekCache::new(CacheSettings::default())),
        );
        (d, material)
    }

    #[tokio::test]
    async fn decrypt_opens_and_caches_the_dek() {
        let sealed = seal(ORG, SECRET, 1, VALUE);
        let kms = Arc::new(FakeKms {
            dek: Some(sealed.dek),
            calls: AtomicUsize::new(0),
        });
        let (d, material) = decryptor(sealed, kms.clone());
        for _ in 0..3 {
            let v = d.decrypt(SECRET, 1).await.expect("decrypts");
            assert!(v.expose() == VALUE, "value mismatch");
        }
        assert_eq!(material.fetches.load(Ordering::SeqCst), 3);
        assert_eq!(
            kms.calls.load(Ordering::SeqCst),
            1,
            "DEK cached after first unwrap"
        );
        assert_eq!(d.cache().len(), 1);
    }

    #[tokio::test]
    async fn decrypt_failures_name_the_step_only() {
        let sealed = seal(ORG, SECRET, 1, VALUE);
        let kms = Arc::new(FakeKms {
            dek: None,
            calls: AtomicUsize::new(0),
        });
        let (d, _) = decryptor(sealed, kms);
        let e = d.decrypt(SECRET, 1).await.err().unwrap();
        assert_eq!(e, DecryptError::Unwrap(WrapError::Rejected { status: 500 }));
        assert!(d.cache().is_empty(), "nothing cached on failure");
        assert_eq!(
            d.decrypt(SECRET, 2).await.err(),
            Some(DecryptError::Material(MaterialError::NotFound))
        );

        // Wrong DEK: the AEAD refuses; the error says so and nothing more.
        let sealed = seal(ORG, SECRET, 1, VALUE);
        let kms = Arc::new(FakeKms {
            dek: Some([9u8; 32]),
            calls: AtomicUsize::new(0),
        });
        let (d, _) = decryptor(sealed, kms);
        let e = d.decrypt(SECRET, 1).await.err().unwrap();
        assert_eq!(e, DecryptError::Open);
        let text = format!("{e} {e:?}");
        assert!(!text.contains("canary"), "{text}");
    }

    #[tokio::test]
    async fn decrypt_under_another_org_fails() {
        let other = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000ff);
        let sealed = seal(other, SECRET, 1, VALUE);
        let kms = Arc::new(FakeKms {
            dek: Some(sealed.dek),
            calls: AtomicUsize::new(0),
        });
        let (d, _) = decryptor(sealed, kms);
        assert_eq!(d.decrypt(SECRET, 1).await.err(), Some(DecryptError::Open));
    }

    /// The real `OpenBaoTransit` client against a stub transit endpoint: the gateway token goes
    /// out on the decrypt call and the returned key opens the version.
    #[tokio::test]
    async fn decrypt_through_openbao_transit() {
        let sealed = seal(ORG, SECRET, 1, VALUE);
        let bao = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/gateway"))
            .and(header("X-Vault-Token", "gateway-bao-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "plaintext": B64.encode(sealed.dek) }
            })))
            .expect(1)
            .mount(&bao)
            .await;
        let transit = OpenBaoTransit::new(
            &bao.uri(),
            key(),
            BaoToken::new("gateway-bao-token".to_owned()),
        )
        .unwrap();
        let (d, _) = decryptor(sealed, Arc::new(transit));
        let v = d.decrypt(SECRET, 1).await.expect("decrypts");
        assert!(v.expose() == VALUE);
        let v = d.decrypt(SECRET, 1).await.expect("cached");
        assert!(v.expose() == VALUE);
    }

    #[tokio::test]
    async fn control_plane_client_sends_token_and_org_and_parses() {
        let sealed = seal(ORG, SECRET, 1, VALUE);
        let cp = MockServer::start().await;
        let token = "s".repeat(32);
        Mock::given(method("GET"))
            .and(path(format!(
                "/internal/v1/secrets/{SECRET}/versions/1/material"
            )))
            .and(header("authorization", format!("Bearer {token}").as_str()))
            .and(header(ORG_HEADER, ORG.to_string().as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(sealed.json(SECRET, 1)))
            .mount(&cp)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&cp)
            .await;
        let client = ControlPlane::new(cp.uri().parse().unwrap(), ORG, token.into()).unwrap();
        let m = client.fetch(SECRET, 1).await.expect("material");
        assert_eq!(m.ciphertext, sealed.ciphertext);
        assert_eq!(
            client.fetch(SECRET, 2).await.err(),
            Some(MaterialError::NotFound)
        );
    }

    #[test]
    fn material_must_answer_the_question_asked() {
        let sealed = seal(ORG, SECRET, 1, VALUE);
        let ok = sealed.json(SECRET, 1).to_string();
        assert!(parse_material(ok.as_bytes(), SECRET, 1).is_ok());
        assert_eq!(
            parse_material(ok.as_bytes(), SECRET, 2).err(),
            Some(MaterialError::BadResponse)
        );
        let mut wrong_key = sealed.json(SECRET, 1);
        wrong_key["key_id"] = "other:v1".into();
        assert_eq!(
            parse_material(wrong_key.to_string().as_bytes(), SECRET, 1).err(),
            Some(MaterialError::BadResponse)
        );
        assert_eq!(
            parse_material(b"{}", SECRET, 1).err(),
            Some(MaterialError::BadResponse)
        );
    }

    fn data_key(byte: u8) -> DataKey {
        DataKey::from_parts(
            ls_envelope::KeyId([byte; 16]),
            SecretKey32::from_bytes([byte; 32]),
        )
    }

    #[test]
    fn cache_expires_after_ttl_and_drops_the_key() {
        let cache = DekCache::new(CacheSettings {
            ttl: Duration::from_secs(60),
            max_entries: 10,
        });
        let t0 = Instant::now();
        let weak = Arc::downgrade(&cache.insert_at(SECRET, 1, data_key(1), t0));
        assert!(
            cache
                .get_at(SECRET, 1, t0 + Duration::from_secs(59))
                .is_some()
        );
        assert!(weak.upgrade().is_some());
        assert!(
            cache
                .get_at(SECRET, 1, t0 + Duration::from_secs(60))
                .is_none()
        );
        // Evicted and no other holder: the DataKey (and its zeroize-on-drop key) is gone.
        assert!(weak.upgrade().is_none(), "evicted key still alive");
        assert!(cache.is_empty());

        let weak = Arc::downgrade(&cache.insert_at(SECRET, 2, data_key(2), t0));
        assert_eq!(cache.purge_at(t0 + Duration::from_secs(61)), 1);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn cache_is_bounded_and_evicts_oldest() {
        let cache = DekCache::new(CacheSettings {
            ttl: Duration::from_secs(60),
            max_entries: 2,
        });
        let t0 = Instant::now();
        let first = Arc::downgrade(&cache.insert_at(SECRET, 1, data_key(1), t0));
        cache.insert_at(SECRET, 2, data_key(2), t0 + Duration::from_secs(1));
        cache.insert_at(SECRET, 3, data_key(3), t0 + Duration::from_secs(2));
        assert_eq!(cache.len(), 2);
        assert!(first.upgrade().is_none(), "oldest evicted and dropped");
        assert!(
            cache
                .get_at(SECRET, 1, t0 + Duration::from_secs(3))
                .is_none()
        );
        assert!(
            cache
                .get_at(SECRET, 3, t0 + Duration::from_secs(3))
                .is_some()
        );
    }

    #[test]
    fn cache_disabled_keeps_nothing() {
        let cache = DekCache::new(CacheSettings {
            ttl: Duration::ZERO,
            max_entries: 10,
        });
        let weak = Arc::downgrade(&cache.insert(SECRET, 1, data_key(1)));
        assert!(cache.is_empty());
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn sweeper_purges_expired_entries() {
        let cache = Arc::new(DekCache::new(CacheSettings {
            ttl: Duration::from_millis(20),
            max_entries: 10,
        }));
        let weak = Arc::downgrade(&cache.insert(SECRET, 1, data_key(1)));
        let h = cache.spawn_sweeper(Duration::from_millis(10));
        tokio::time::sleep(Duration::from_millis(100)).await;
        h.abort();
        assert!(cache.is_empty());
        assert!(weak.upgrade().is_none());
    }
}
