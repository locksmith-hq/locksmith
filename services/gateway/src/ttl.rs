//! One single-slot TTL cell for the gateway's control-plane reads (refactor-mcp-shared 1.1).
//!
//! Every cached read (revoked agent clients, tool switches) is reused for at most
//! [`MAX_CACHE_TTL`] so a revoke or a console switch takes effect within that time (m1 design
//! decision 4). Errors are never cached and a zero TTL stores nothing, so a failed read is never
//! served stale and tests can make "the next call sees the change" exact.

use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Longest time any cached control-plane read is reused. Larger configured values are clamped.
pub const MAX_CACHE_TTL: Duration = Duration::from_secs(10);

/// A single cached value that expires `ttl` after its fetch started.
pub struct TtlCell<T: Clone> {
    ttl: Duration,
    entry: Mutex<Option<(Instant, T)>>,
}

impl<T: Clone> TtlCell<T> {
    /// A cell with `ttl` clamped to [`MAX_CACHE_TTL`]; zero disables caching.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl: ttl.min(MAX_CACHE_TTL),
            entry: Mutex::new(None),
        }
    }

    /// The effective (clamped) TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The cached value while it is younger than the TTL.
    pub fn get(&self) -> Option<T> {
        let guard = self.entry.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some((at, v)) if at.elapsed() < self.ttl => Some(v.clone()),
            _ => None,
        }
    }

    /// The cached value, or the result of `fetch`. The entry is stamped with the time the fetch
    /// started, so it never outlives the TTL measured from when the source was asked. Only an
    /// `Ok` is stored, and only when the TTL is non-zero.
    pub async fn get_or_fetch<E, F, Fut>(&self, fetch: F) -> Result<T, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        if let Some(v) = self.get() {
            return Ok(v);
        }
        let started = Instant::now();
        let v = fetch().await?;
        if !self.ttl.is_zero() {
            *self.entry.lock().unwrap_or_else(|e| e.into_inner()) = Some((started, v.clone()));
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn ok(n: &AtomicUsize) -> Result<u32, ()> {
        n.fetch_add(1, Ordering::SeqCst);
        Ok(7)
    }

    #[test]
    fn ttl_is_clamped_to_the_max() {
        assert_eq!(MAX_CACHE_TTL, Duration::from_secs(10));
        assert_eq!(
            TtlCell::<u32>::new(Duration::from_secs(3600)).ttl(),
            MAX_CACHE_TTL
        );
        assert_eq!(
            TtlCell::<u32>::new(Duration::from_secs(2)).ttl(),
            Duration::from_secs(2)
        );
    }

    #[tokio::test]
    async fn serves_within_ttl_then_expires() {
        let n = AtomicUsize::new(0);
        let cell = TtlCell::new(Duration::from_millis(60));
        cell.get_or_fetch(|| ok(&n)).await.unwrap();
        cell.get_or_fetch(|| ok(&n)).await.unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(cell.get(), None, "gone at the TTL");
        cell.get_or_fetch(|| ok(&n)).await.unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_error_is_not_cached() {
        let n = AtomicUsize::new(0);
        let cell: TtlCell<u32> = TtlCell::new(Duration::from_secs(5));
        for _ in 0..2 {
            let r = cell
                .get_or_fetch(|| async {
                    n.fetch_add(1, Ordering::SeqCst);
                    Err::<u32, ()>(())
                })
                .await;
            assert!(r.is_err());
        }
        assert_eq!(n.load(Ordering::SeqCst), 2);
        assert_eq!(cell.get(), None);
    }

    #[tokio::test]
    async fn zero_ttl_stores_nothing() {
        let n = AtomicUsize::new(0);
        let cell = TtlCell::new(Duration::ZERO);
        cell.get_or_fetch(|| ok(&n)).await.unwrap();
        cell.get_or_fetch(|| ok(&n)).await.unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 2);
        assert_eq!(cell.get(), None);
    }

    #[tokio::test]
    async fn the_stamp_is_taken_when_the_fetch_starts() {
        let cell = TtlCell::new(Duration::from_millis(60));
        // A fetch that takes longer than the TTL: the stored entry is already expired.
        cell.get_or_fetch(|| async {
            tokio::time::sleep(Duration::from_millis(80)).await;
            Ok::<u32, ()>(1)
        })
        .await
        .unwrap();
        assert_eq!(cell.get(), None);
    }
}
