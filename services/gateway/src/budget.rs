//! Per-agent and per-grant call budgets (T9 task 2.1): the burst half.
//!
//! A [`BudgetGuard`] keeps one keyed `governor` limiter per distinct per-minute quota; the key
//! is `(agent, grant)` where a `None` grant is the agent-wide budget. The guard is built from the
//! budgets cached with the grants, so no budget means no limit. Callers run [`BudgetGuard::check`]
//! before they unwrap a key.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use governor::clock::{Clock, DefaultClock};
use governor::middleware::NoOpMiddleware;
use governor::state::keyed::HashMapStateStore;
use governor::{Quota, RateLimiter};
use uuid::Uuid;

use crate::grants::Grant;

type Key = (Uuid, Option<Uuid>);
type Limiter<C> =
    RateLimiter<Key, HashMapStateStore<Key>, C, NoOpMiddleware<<C as Clock>::Instant>>;

/// Why a call was refused. The slug is the `budget_exceeded` error code; no field carries a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetRefusal {
    /// The per-minute burst limit is used up; retry after the given wait.
    Burst { retry_after: Duration },
}

impl BudgetRefusal {
    pub const SLUG: &'static str = "budget_exceeded";

    /// Whole seconds for a `Retry-After` header, at least 1.
    pub fn retry_after_secs(&self) -> u64 {
        match self {
            Self::Burst { retry_after } => retry_after.as_secs().saturating_add(1),
        }
    }
}

/// Keyed burst limiters built lazily from the grants' budgets.
pub struct BudgetGuard<C: Clock = DefaultClock> {
    clock: C,
    limiters: Mutex<HashMap<u32, Arc<Limiter<C>>>>,
}

impl BudgetGuard<DefaultClock> {
    pub fn new() -> Self {
        Self::with_clock(DefaultClock::default())
    }
}

impl Default for BudgetGuard<DefaultClock> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Clock + Clone> BudgetGuard<C> {
    pub fn with_clock(clock: C) -> Self {
        Self {
            clock,
            limiters: Mutex::new(HashMap::new()),
        }
    }

    fn limiter(&self, per_minute: NonZeroU32) -> Arc<Limiter<C>> {
        let mut map = self.limiters.lock().unwrap_or_else(|p| p.into_inner());
        Arc::clone(map.entry(per_minute.get()).or_insert_with(|| {
            Arc::new(RateLimiter::hashmap_with_clock(
                Quota::per_minute(per_minute),
                self.clock.clone(),
            ))
        }))
    }

    /// Counts one call of `agent` on `grant` against the agent-wide and the grant's burst limit.
    /// A budget with no `per_minute` (or `0`, which an operator uses to mean "unset") is no limit.
    pub fn check(&self, agent: Uuid, grant: &Grant) -> Result<(), BudgetRefusal> {
        let scopes = [
            (grant.agent_budget.and_then(|b| b.per_minute), (agent, None)),
            (
                grant.budget.and_then(|b| b.per_minute),
                (agent, Some(grant.grant_id)),
            ),
        ];
        for (per_minute, key) in scopes {
            let Some(n) = per_minute.and_then(NonZeroU32::new) else {
                continue;
            };
            if let Err(not_until) = self.limiter(n).check_key(&key) {
                return Err(BudgetRefusal::Burst {
                    retry_after: not_until.wait_time_from(self.clock.now()),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::Budget;
    use governor::clock::FakeRelativeClock;

    fn grant(budget: Option<Budget>, agent_budget: Option<Budget>) -> Grant {
        Grant {
            grant_id: Uuid::new_v4(),
            secret_id: Uuid::new_v4(),
            secret_name: "s".into(),
            mode: "relay".into(),
            scope: None,
            expires_at: None,
            budget,
            agent_budget,
        }
    }

    fn per_minute(n: u32) -> Option<Budget> {
        Some(Budget {
            per_minute: Some(n),
            per_day: None,
        })
    }

    #[test]
    fn no_budget_means_no_limit() {
        let g = BudgetGuard::new();
        let gr = grant(None, None);
        let a = Uuid::new_v4();
        assert!((0..1000).all(|_| g.check(a, &gr).is_ok()));
        let zero = grant(per_minute(0), None);
        assert!((0..50).all(|_| g.check(a, &zero).is_ok()));
    }

    #[test]
    fn burst_is_refused_then_refills() {
        let clock = FakeRelativeClock::default();
        let g = BudgetGuard::with_clock(clock.clone());
        let gr = grant(per_minute(3), None);
        let a = Uuid::new_v4();
        for _ in 0..3 {
            assert!(g.check(a, &gr).is_ok());
        }
        let refused = g.check(a, &gr).unwrap_err();
        let BudgetRefusal::Burst { retry_after } = refused;
        assert!(retry_after > Duration::ZERO && retry_after <= Duration::from_secs(20));
        assert!(refused.retry_after_secs() >= 1);
        clock.advance(Duration::from_secs(20));
        assert!(g.check(a, &gr).is_ok(), "one call refilled after 60s/3");
        assert!(g.check(a, &gr).is_err());
    }

    #[test]
    fn limits_are_per_agent_and_per_grant() {
        let g = BudgetGuard::with_clock(FakeRelativeClock::default());
        let g1 = grant(per_minute(1), None);
        let g2 = grant(per_minute(1), None);
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(g.check(a, &g1).is_ok());
        assert!(g.check(a, &g1).is_err());
        assert!(g.check(a, &g2).is_ok(), "another grant of the same agent");
        assert!(g.check(b, &g1).is_ok(), "another agent");
    }

    #[test]
    fn the_agent_budget_spans_its_grants() {
        let g = BudgetGuard::with_clock(FakeRelativeClock::default());
        let agent_wide = per_minute(2);
        let (g1, g2) = (grant(None, agent_wide), grant(None, agent_wide));
        let a = Uuid::new_v4();
        assert!(g.check(a, &g1).is_ok());
        assert!(g.check(a, &g2).is_ok());
        assert!(g.check(a, &g1).is_err());
    }
}
