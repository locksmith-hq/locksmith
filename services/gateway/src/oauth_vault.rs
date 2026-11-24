//! Sealing of OAuth connection token sets (c1-oauth-connections design decision 6).
//!
//! One token set (access token, refresh token, expiry, granted scopes) is sealed per
//! generation with `ls-envelope`: purpose [`Purpose::OAuthToken`], binding `org ‖ connection id
//! ‖ generation ‖ purpose`, under a fresh DEK. The DEK is wrapped by a [`KeyWrapper`], in
//! production the dedicated OpenBao transit key `oauth-connections` (the gateway's
//! `gateway-oauth` token may encrypt and decrypt on that key only, so the `gateway` key's
//! wrap-only / unwrap-only split for secret versions is unchanged).
//!
//! The result is the three columns of `oauth_token_material`: `ciphertext`, `wrapped_dek` and
//! `key_id`. Opening with another org, connection or generation fails, because each is part of
//! the AAD of the payload and of the DEK wrap.
//!
//! The token set lives only in [`SecretBytes`] (zeroized on drop). Nothing here implements
//! `Display`, `Debug` or `Clone` for a type holding a secret, and [`VaultError`] is a fixed slug
//! with no payload.

use ls_envelope::{
    BaoToken, Binding, DataKey, Header, KeyWrapper, OpenBaoTransit, Purpose, SecretBytes,
    WrapError, WrapKeyId, WrappedDek, open_version, seal_version,
};
use uuid::Uuid;

/// The OpenBao transit key the token sets' DEKs are wrapped with.
pub const TRANSIT_KEY: &str = "oauth-connections";

/// The name recorded in the wrapped DEK's header `key_id`. A header holds at most
/// [`WrapKeyId::MAX_NAME_LEN`] bytes, so it is shorter than [`TRANSIT_KEY`].
pub const WRAP_KEY_NAME: &str = "oauth-conn";

/// Why sealing or opening failed. A fixed slug: no key, token, ciphertext or KMS body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    /// The payload could not be encrypted.
    Seal,
    /// The KMS refused or failed to wrap the DEK.
    Wrap,
    /// The KMS refused or failed to unwrap the DEK (including a binding mismatch).
    Unwrap,
    /// The stored ciphertext or wrapped DEK is malformed.
    BadMaterial,
    /// Authentication failed: another org, connection or generation, or altered bytes.
    Integrity,
}

impl VaultError {
    pub fn slug(self) -> &'static str {
        match self {
            VaultError::Seal => "seal_failed",
            VaultError::Wrap => "wrap_failed",
            VaultError::Unwrap => "unwrap_failed",
            VaultError::BadMaterial => "bad_material",
            VaultError::Integrity => "integrity_failed",
        }
    }
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.slug())
    }
}

impl std::error::Error for VaultError {}

/// A sealed token set: the values of the `oauth_token_material` columns. Not secret, but no
/// `Debug` so it never lands in a log by accident.
pub struct SealedTokenSet {
    /// `header ‖ nonce ‖ ciphertext ‖ tag`.
    pub ciphertext: Vec<u8>,
    /// The `dek-wrap` blob.
    pub wrapped_dek: Vec<u8>,
    /// The KMS key that wrapped the DEK, as `name:vN`.
    pub key_id: String,
}

/// Seals and opens token sets. `K` wraps and unwraps the DEKs.
pub struct TokenVault<K> {
    wrapper: K,
}

impl TokenVault<OpenBaoTransit> {
    /// A vault over OpenBao transit key `oauth-connections` at `addr`, authenticated with
    /// the gateway's `gateway-oauth` token.
    pub fn openbao(addr: &str, token: BaoToken) -> Result<Self, WrapError> {
        let key = WrapKeyId::new(WRAP_KEY_NAME, 1)?;
        let transit = OpenBaoTransit::new(addr, key, token)?.with_transit_key(TRANSIT_KEY)?;
        Ok(Self::new(transit))
    }
}

impl<K: KeyWrapper + Send + Sync> TokenVault<K> {
    pub fn new(wrapper: K) -> Self {
        Self { wrapper }
    }

    /// Seal `token_set` for this org, connection and generation under a fresh DEK, and wrap
    /// the DEK.
    pub async fn seal(
        &self,
        org: Uuid,
        connection: Uuid,
        generation: u32,
        token_set: &SecretBytes,
    ) -> Result<SealedTokenSet, VaultError> {
        let payload = binding(org, connection, generation, Purpose::OAuthToken);
        let sealed = seal_version(&payload, token_set).map_err(|_| VaultError::Seal)?;
        let (ciphertext, dek) = sealed.into_parts();
        let wrap_binding = binding(org, connection, generation, Purpose::DekWrap);
        let wrapped = self
            .wrapper
            .wrap(&dek, &wrap_binding)
            .await
            .map_err(|_| VaultError::Wrap)?;
        Ok(SealedTokenSet {
            ciphertext,
            key_id: wrapped.key_id().to_string(),
            wrapped_dek: wrapped.into_bytes(),
        })
    }

    /// Unwrap the DEK and open the token set. Fails when `org`, `connection` or `generation`
    /// differ from the ones it was sealed for.
    pub async fn open(
        &self,
        org: Uuid,
        connection: Uuid,
        generation: u32,
        ciphertext: &[u8],
        wrapped_dek: &[u8],
    ) -> Result<SecretBytes, VaultError> {
        let header = Header::parse(ciphertext).map_err(|_| VaultError::BadMaterial)?;
        let wrapped =
            WrappedDek::from_bytes(wrapped_dek.to_vec()).map_err(|_| VaultError::BadMaterial)?;
        let wrap_binding = binding(org, connection, generation, Purpose::DekWrap);
        let key = self
            .wrapper
            .unwrap(&wrapped, &wrap_binding)
            .await
            .map_err(|_| VaultError::Unwrap)?;
        let dek = DataKey::from_parts(header.key_id, key);
        let payload = binding(org, connection, generation, Purpose::OAuthToken);
        open_version(&dek, &payload, ciphertext).map_err(|e| match e {
            ls_envelope::EnvelopeError::Integrity => VaultError::Integrity,
            _ => VaultError::BadMaterial,
        })
    }
}

fn binding(org: Uuid, connection: Uuid, generation: u32, purpose: Purpose) -> Binding {
    Binding {
        org_id: *org.as_bytes(),
        secret_id: *connection.as_bytes(),
        version: generation,
        purpose,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ls_envelope::{SecretKey32, WRAPPED_DEK_LEN};
    use sha2::{Digest, Sha256};

    const ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a1);
    const OTHER_ORG: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000a2);
    const CONN: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000b1);
    const OTHER_CONN: Uuid = Uuid::from_u128(0x0197c1f0_0000_7000_8000_0000000000b2);
    const CANARY: &[u8] = b"canary-oauth-token-set-5d2e9b";

    /// In-memory stand-in for transit. The DEK is masked and the blob carries a digest of the
    /// wrap binding, so an unwrap under another binding is refused, as transit's AAD does.
    /// With `check_binding` off the wrap layer accepts any binding, which isolates the payload
    /// AEAD's own binding in the tests.
    struct MemWrapper {
        check_binding: bool,
    }

    fn mask() -> [u8; 32] {
        Sha256::digest(b"test-wrapper-mask").into()
    }

    fn digest(b: &Binding) -> [u8; 28] {
        let mut h = Sha256::new();
        h.update(b.org_id);
        h.update(b.secret_id);
        h.update(b.version.to_be_bytes());
        h.update(b.purpose.label());
        let d = h.finalize();
        d[..28].try_into().unwrap()
    }

    impl KeyWrapper for MemWrapper {
        async fn wrap(&self, dek: &DataKey, binding: &Binding) -> Result<WrappedDek, WrapError> {
            if binding.purpose != Purpose::DekWrap {
                return Err(WrapError::Purpose);
            }
            let key = WrapKeyId::new(WRAP_KEY_NAME, 1)?;
            let mut blob = Header::v1(key.to_key_id()).encode().to_vec();
            blob.extend(dek.expose().iter().zip(mask()).map(|(a, m)| a ^ m));
            blob.extend_from_slice(&digest(binding));
            assert_eq!(blob.len(), WRAPPED_DEK_LEN);
            WrappedDek::from_bytes(blob)
        }

        async fn unwrap(
            &self,
            wrapped: &WrappedDek,
            binding: &Binding,
        ) -> Result<SecretKey32, WrapError> {
            if binding.purpose != Purpose::DekWrap {
                return Err(WrapError::Purpose);
            }
            let body = &wrapped.as_bytes()[ls_envelope::header::HEADER_LEN..];
            if self.check_binding && body[32..] != digest(binding) {
                return Err(WrapError::Rejected { status: 400 });
            }
            let mut k = [0u8; 32];
            for (i, m) in mask().iter().enumerate() {
                k[i] = body[i] ^ m;
            }
            Ok(SecretKey32::from_bytes(k))
        }
    }

    fn vault(check_binding: bool) -> TokenVault<MemWrapper> {
        TokenVault::new(MemWrapper { check_binding })
    }

    async fn sealed() -> SealedTokenSet {
        vault(true)
            .seal(ORG, CONN, 3, &SecretBytes::new(CANARY.to_vec()))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn round_trip() {
        let s = sealed().await;
        assert_eq!(s.key_id, "oauth-conn:v1");
        let v = vault(true)
            .open(ORG, CONN, 3, &s.ciphertext, &s.wrapped_dek)
            .await
            .unwrap();
        assert!(v.expose() == CANARY, "plaintext mismatch");
    }

    #[tokio::test]
    async fn ciphertext_never_contains_the_plaintext() {
        let s = sealed().await;
        for blob in [&s.ciphertext, &s.wrapped_dek] {
            assert!(
                !blob.windows(CANARY.len()).any(|w| w == CANARY),
                "plaintext found in stored bytes"
            );
        }
    }

    /// Each mismatch fails at the wrap layer (transit AAD) and, with that layer lax, at the
    /// payload's own AEAD binding.
    #[tokio::test]
    async fn another_org_connection_or_generation_fails() {
        let s = sealed().await;
        for (org, conn, generation) in [(OTHER_ORG, CONN, 3), (ORG, OTHER_CONN, 3), (ORG, CONN, 4)]
        {
            let strict = vault(true)
                .open(org, conn, generation, &s.ciphertext, &s.wrapped_dek)
                .await;
            assert_eq!(strict.err(), Some(VaultError::Unwrap));
            let lax = vault(false)
                .open(org, conn, generation, &s.ciphertext, &s.wrapped_dek)
                .await;
            assert_eq!(lax.err(), Some(VaultError::Integrity));
        }
    }

    /// A blob sealed for another purpose under the same key and ids does not open as a token
    /// set.
    #[tokio::test]
    async fn wrong_purpose_fails() {
        let wrapper = MemWrapper {
            check_binding: false,
        };
        let payload = binding(ORG, CONN, 3, Purpose::SecretPayload);
        let (ciphertext, dek) = seal_version(&payload, &SecretBytes::new(CANARY.to_vec()))
            .unwrap()
            .into_parts();
        let wrapped = wrapper
            .wrap(&dek, &binding(ORG, CONN, 3, Purpose::DekWrap))
            .await
            .unwrap();
        let r = TokenVault::new(wrapper)
            .open(ORG, CONN, 3, &ciphertext, wrapped.as_bytes())
            .await;
        assert_eq!(r.err(), Some(VaultError::Integrity));
    }

    #[tokio::test]
    async fn malformed_material_and_tampering_fail() {
        let s = sealed().await;
        let v = vault(true);
        let r = v
            .open(ORG, CONN, 3, &s.ciphertext[..10], &s.wrapped_dek)
            .await;
        assert_eq!(r.err(), Some(VaultError::BadMaterial));
        let r = v
            .open(ORG, CONN, 3, &s.ciphertext, &s.wrapped_dek[1..])
            .await;
        assert_eq!(r.err(), Some(VaultError::BadMaterial));
        let mut flipped = s.ciphertext.clone();
        *flipped.last_mut().unwrap() ^= 1;
        let r = v.open(ORG, CONN, 3, &flipped, &s.wrapped_dek).await;
        assert_eq!(r.err(), Some(VaultError::Integrity));
    }

    #[test]
    fn errors_are_fixed_slugs() {
        assert_eq!(VaultError::Integrity.to_string(), "integrity_failed");
        assert_eq!(VaultError::Unwrap.slug(), "unwrap_failed");
    }

    #[test]
    fn openbao_vault_builds_with_the_long_transit_key() {
        let v = TokenVault::openbao(
            "http://127.0.0.1:8200",
            BaoToken::new("test-only-not-a-token".to_owned()),
        );
        assert!(v.is_ok());
    }
}
