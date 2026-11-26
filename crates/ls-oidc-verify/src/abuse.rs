//! Abuse limits for the workload token exchange (D4 design decision 6).
//!
//! - A `jti` replay cache: a verified external token whose `(issuer, jti)` was already used is
//!   refused until the token itself would have expired. In memory, per replica, best effort
//!   (documented in design.md): containment, not prevention. A token with no `jti` is accepted
//!   (GitHub and Kubernetes both set one; the claim is optional in RFC 7519).
//! - Fixed-window rate limits per policy and per source address.
//!
//! Both are built on `moka` (bounded, TTL-evicting concurrent cache) instead of hand-written maps.
//! The `jti` is hashed together with the issuer, so the cache never holds token content.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use moka::Expiry;
use moka::sync::Cache;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Default exchanges per policy per window.
pub const DEFAULT_PER_POLICY: u32 = 60;
/// Default exchanges per source address per window.
pub const DEFAULT_PER_SOURCE: u32 = 30;
/// Default number of remembered `jti` values.
pub const DEFAULT_JTI_ENTRIES: u64 = 100_000;
/// Rate-limit window.
pub const WINDOW: Duration = Duration::from_secs(60);
/// Entries kept per rate-limit table (distinct policies or sources tracked at once).
const RATE_KEYS: u64 = 50_000;

/// Limits. A rate of `0` disables that limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbuseLimits {
    pub per_policy: u32,
    pub per_source: u32,
    pub jti_entries: u64,
}

impl Default for AbuseLimits {
    fn default() -> Self {
        Self {
            per_policy: DEFAULT_PER_POLICY,
            per_source: DEFAULT_PER_SOURCE,
            jti_entries: DEFAULT_JTI_ENTRIES,
        }
    }
}

struct ByValue;

impl Expiry<[u8; 32], Duration> for ByValue {
    fn expire_after_create(&self, _: &[u8; 32], ttl: &Duration, _: Instant) -> Option<Duration> {
        Some(*ttl)
    }
}

/// The replay cache and both rate limiters.
pub struct AbuseGuard {
    limits: AbuseLimits,
    jti: Cache<[u8; 32], Duration>,
    per_policy: Cache<Uuid, Arc<AtomicU32>>,
    per_source: Cache<IpAddr, Arc<AtomicU32>>,
}

impl Default for AbuseGuard {
    fn default() -> Self {
        Self::new(AbuseLimits::default())
    }
}

fn hit<K>(cache: &Cache<K, Arc<AtomicU32>>, key: K, limit: u32) -> bool
where
    K: std::hash::Hash + Eq + Send + Sync + 'static,
{
    if limit == 0 {
        return true;
    }
    let counter = cache.get_with(key, || Arc::new(AtomicU32::new(0)));
    counter.fetch_add(1, Ordering::Relaxed) < limit
}

impl AbuseGuard {
    pub fn new(limits: AbuseLimits) -> Self {
        Self {
            limits,
            jti: Cache::builder()
                .max_capacity(limits.jti_entries.max(1))
                .expire_after(ByValue)
                .build(),
            per_policy: Cache::builder()
                .max_capacity(RATE_KEYS)
                .time_to_live(WINDOW)
                .build(),
            per_source: Cache::builder()
                .max_capacity(RATE_KEYS)
                .time_to_live(WINDOW)
                .build(),
        }
    }

    pub fn limits(&self) -> AbuseLimits {
        self.limits
    }

    /// Count one exchange attempt from `source`; `false` when over the limit.
    pub fn allow_source(&self, source: IpAddr) -> bool {
        hit(&self.per_source, source, self.limits.per_source)
    }

    /// Count one exchange attempt for `policy`; `false` when over the limit.
    pub fn allow_policy(&self, policy: Uuid) -> bool {
        hit(&self.per_policy, policy, self.limits.per_policy)
    }

    /// Record `(issuer, jti)` for `ttl`. `false` when it was already recorded (a replay).
    pub fn first_use(&self, issuer: &str, jti: &str, ttl: Duration) -> bool {
        let mut h = Sha256::new();
        h.update(issuer.as_bytes());
        h.update([0]);
        h.update(jti.as_bytes());
        let key: [u8; 32] = h.finalize().into();
        self.jti
            .entry(key)
            .or_insert_with(|| ttl.max(Duration::from_secs(1)))
            .is_fresh()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_abuse_jti_is_single_use_per_issuer() {
        let g = AbuseGuard::default();
        let ttl = Duration::from_secs(60);
        assert!(g.first_use("https://a", "j1", ttl));
        assert!(!g.first_use("https://a", "j1", ttl));
        assert!(g.first_use("https://b", "j1", ttl));
        assert!(g.first_use("https://a", "j2", ttl));
    }

    #[test]
    fn workload_abuse_jti_expires_with_the_token() {
        let g = AbuseGuard::default();
        assert!(g.first_use("i", "j", Duration::from_millis(1)));
        // The minimum TTL is one second.
        std::thread::sleep(Duration::from_millis(1100));
        assert!(g.first_use("i", "j", Duration::from_secs(60)));
    }

    #[test]
    fn workload_abuse_rate_limits_count_per_key_and_zero_disables() {
        let g = AbuseGuard::new(AbuseLimits {
            per_policy: 2,
            per_source: 0,
            jti_entries: 10,
        });
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        assert!(g.allow_policy(a) && g.allow_policy(a));
        assert!(!g.allow_policy(a));
        assert!(g.allow_policy(b));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!((0..100).all(|_| g.allow_source(ip)));
    }
}
