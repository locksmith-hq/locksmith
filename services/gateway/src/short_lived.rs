//! Short-lived scoped credentials (m1-remote-mcp task 3.3, decision H1-2): what the agent MCP
//! tool `issue_short_lived_credential` hands out.
//!
//! The credential is not the stored secret and is not derived from it. It is an opaque random
//! bearer token (`lsst_` + 256 bits, base64url) that the gateway itself accepts on
//! `POST /v1/relay`, and only there, as the agent that asked for it, for the one secret it was
//! issued for, until it expires (60 to 900 seconds, never past the grant). The gateway resolves
//! it at relay time and injects the stored value exactly as for an agent-token relay, so the
//! grant, binding, address guard, audit and redaction all still apply and the value never leaves
//! the gateway. It is the same pattern as `locksmithd`'s per-run forwarder and dummy AWS keys
//! (M7): a stand-in the relay resolves, never the real credential. Its use is a job handed to a
//! tool that must hold a bearer of its own (a subprocess, an SDK pointed at the gateway) without
//! receiving the agent's token or the stored value.
//!
//! Only the SHA-256 of a token is kept, in memory, with its scope; the token itself exists in
//! the gateway only until the tool result is serialized. An entry is destroyed at its expiry
//! (dropped on the next lookup or issue), so a token cannot outlive its minutes, and a gateway
//! restart destroys every entry. Nothing here logs or serializes a token.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Every short-lived credential starts with this, so the relay can tell it from an agent JWT.
pub const PREFIX: &str = "lsst_";

/// Shortest and longest lifetime an agent may ask for (the tool's input schema says the same).
pub const MIN_TTL_SECS: u32 = 60;
pub const MAX_TTL_SECS: u32 = 900;

/// Live credentials one agent may hold at once (bounds the store's memory).
pub const MAX_LIVE_PER_AGENT: usize = 16;

/// Length of a token: the prefix and 32 random bytes in unpadded base64url.
const TOKEN_LEN: usize = PREFIX.len() + 43;

/// What a credential lets its bearer do. Ids and a time; never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope {
    pub credential_id: Uuid,
    pub agent_id: Uuid,
    pub org_id: Uuid,
    pub secret_id: Uuid,
    pub expires_at: OffsetDateTime,
}

/// A freshly minted credential, before it is stored. No `Debug`, `Display` or `Clone`: the token
/// is in a [`SecretString`].
pub struct Minted {
    token: SecretString,
    hash: [u8; 32],
    pub scope: Scope,
}

impl Minted {
    /// The token, for the one tool result that hands it to the agent.
    pub fn token(&self) -> &SecretString {
        &self.token
    }
}

/// Why a credential was not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// The agent already holds [`MAX_LIVE_PER_AGENT`] live credentials.
    TooMany,
    /// The OS random source failed.
    Rng,
}

/// The live credentials, keyed by the SHA-256 of the token.
#[derive(Default)]
pub struct ShortLivedStore {
    live: Mutex<HashMap<[u8; 32], Scope>>,
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

impl ShortLivedStore {
    /// Mint a credential for `agent_id` in `org_id`, scoped to `secret_id`, expiring at
    /// `expires_at`. Not usable until [`ShortLivedStore::insert`], which the caller runs only once
    /// the issue is in the ledger.
    pub fn mint(
        &self,
        agent_id: Uuid,
        org_id: Uuid,
        secret_id: Uuid,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<Minted, StoreError> {
        {
            let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            live.retain(|_, s| s.expires_at > now);
            let held = live.values().filter(|s| s.agent_id == agent_id).count();
            if held >= MAX_LIVE_PER_AGENT {
                return Err(StoreError::TooMany);
            }
        }
        let mut raw = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(raw.as_mut()).map_err(|_| StoreError::Rng)?;
        let mut text = Zeroizing::new(String::with_capacity(TOKEN_LEN));
        text.push_str(PREFIX);
        URL_SAFE_NO_PAD.encode_string(raw.as_ref(), &mut text);
        let hash = digest(&text);
        Ok(Minted {
            token: SecretString::from(text.as_str()),
            hash,
            scope: Scope {
                credential_id: Uuid::now_v7(),
                agent_id,
                org_id,
                secret_id,
                expires_at,
            },
        })
    }

    /// Make a minted credential usable. Re-checks the per-agent limit (another issue may have
    /// landed since the mint).
    pub fn insert(&self, minted: &Minted, now: OffsetDateTime) -> Result<(), StoreError> {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        live.retain(|_, s| s.expires_at > now);
        let held = live
            .values()
            .filter(|s| s.agent_id == minted.scope.agent_id)
            .count();
        if held >= MAX_LIVE_PER_AGENT {
            return Err(StoreError::TooMany);
        }
        live.insert(minted.hash, minted.scope);
        Ok(())
    }

    /// The scope of a live credential. An expired one is destroyed and resolves to nothing, as
    /// does anything that is not a token this gateway issued.
    pub fn resolve(&self, token: &str, now: OffsetDateTime) -> Option<Scope> {
        if token.len() != TOKEN_LEN || !token.starts_with(PREFIX) {
            return None;
        }
        let hash = digest(token);
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        match live.get(&hash) {
            Some(s) if s.expires_at > now => Some(*s),
            Some(_) => {
                live.remove(&hash);
                None
            }
            None => None,
        }
    }

    /// Live credentials (tests and metrics).
    pub fn live(&self, now: OffsetDateTime) -> usize {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        live.retain(|_, s| s.expires_at > now);
        live.len()
    }
}

/// `now + ttl_secs`, never past the grant's expiry.
pub fn expiry(
    now: OffsetDateTime,
    ttl_secs: u32,
    grant_expires: Option<OffsetDateTime>,
) -> OffsetDateTime {
    let wanted = now + Duration::seconds(i64::from(ttl_secs));
    match grant_expires {
        Some(g) if g < wanted => g,
        _ => wanted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret as _;

    const A: Uuid = Uuid::from_u128(1);
    const B: Uuid = Uuid::from_u128(2);
    const ORG: Uuid = Uuid::from_u128(3);
    const S: Uuid = Uuid::from_u128(4);

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    #[test]
    fn minted_is_unusable_until_inserted_then_resolves_to_its_scope() {
        let store = ShortLivedStore::default();
        let t = now();
        let m = store.mint(A, ORG, S, t + Duration::minutes(5), t).unwrap();
        let token = m.token().expose_secret().to_owned();
        assert!(token.starts_with(PREFIX));
        assert_eq!(token.len(), TOKEN_LEN);
        assert_eq!(store.resolve(&token, t), None, "not live before insert");
        store.insert(&m, t).unwrap();
        assert_eq!(store.resolve(&token, t), Some(m.scope));
        // Another token, a truncated one and an agent JWT resolve to nothing.
        let other = store.mint(A, ORG, S, t + Duration::minutes(5), t).unwrap();
        assert_ne!(other.token().expose_secret(), token.as_str());
        assert_eq!(store.resolve(other.token().expose_secret(), t), None);
        assert_eq!(store.resolve(&token[..TOKEN_LEN - 1], t), None);
        assert_eq!(store.resolve("eyJhbGciOiJFZERTQSJ9.e30.sig", t), None);
    }

    #[test]
    fn expired_credential_is_destroyed() {
        let store = ShortLivedStore::default();
        let t = now();
        let m = store.mint(A, ORG, S, t + Duration::seconds(60), t).unwrap();
        store.insert(&m, t).unwrap();
        let token = m.token().expose_secret().to_owned();
        let later = t + Duration::seconds(61);
        assert_eq!(store.resolve(&token, later), None);
        assert_eq!(store.live(t), 0, "the expired entry was removed");
        assert_eq!(store.resolve(&token, t), None, "destroyed, not just hidden");
    }

    #[test]
    fn per_agent_limit_counts_live_credentials_only() {
        let store = ShortLivedStore::default();
        let t = now();
        for _ in 0..MAX_LIVE_PER_AGENT {
            let m = store.mint(A, ORG, S, t + Duration::seconds(60), t).unwrap();
            store.insert(&m, t).unwrap();
        }
        assert_eq!(
            store.mint(A, ORG, S, t + Duration::seconds(60), t).err(),
            Some(StoreError::TooMany)
        );
        // Another agent is not affected; once A's expire, A may issue again.
        assert!(store.mint(B, ORG, S, t + Duration::seconds(60), t).is_ok());
        let later = t + Duration::seconds(61);
        assert!(
            store
                .mint(A, ORG, S, later + Duration::seconds(60), later)
                .is_ok()
        );
    }

    #[test]
    fn expiry_never_passes_the_grant() {
        let t = now();
        assert_eq!(expiry(t, 600, None), t + Duration::seconds(600));
        let g = t + Duration::seconds(90);
        assert_eq!(expiry(t, 600, Some(g)), g);
        assert_eq!(
            expiry(t, 60, Some(t + Duration::hours(1))),
            t + Duration::seconds(60)
        );
    }
}
