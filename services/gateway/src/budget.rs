//! Per-agent and per-grant call budgets (T9 tasks 2.1 and 2.2).
//!
//! A [`BudgetGuard`] keeps one keyed `governor` limiter per distinct per-minute quota (burst); the
//! key is `(agent, grant)` where a `None` grant is the agent-wide budget. The daily count is exact
//! and lives in the core: the guard leases blocks of `min(10, remaining)` calls through a
//! [`LeaseSource`] and spends them locally, so a call costs a round trip once per block. Unused
//! leased calls expire with the UTC day. The guard is fed the budgets cached with the grants, so
//! no budget means no limit. Callers run [`BudgetGuard::check`] before they unwrap a key.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use governor::clock::{Clock, DefaultClock};
use governor::middleware::NoOpMiddleware;
use governor::state::keyed::HashMapStateStore;
use governor::{Quota, RateLimiter};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::decrypt::{BoxFuture, ControlPlane, Internal};
use crate::grants::Grant;

type Key = (Uuid, Option<Uuid>);
type Limiter<C> =
    RateLimiter<Key, HashMapStateStore<Key>, C, NoOpMiddleware<<C as Clock>::Instant>>;

/// Largest block of calls one lease asks for (design decision 4).
const LEASE_BLOCK: u32 = 10;
/// The core refuses a daily limit above this (a sanity bound).
const DAILY_LIMIT_MAX: u32 = 1_000_000_000;
/// How long a caller is told to wait when the core cannot be asked.
const LEASE_RETRY: Duration = Duration::from_secs(5);
const MAX_LEASE_RESPONSE: usize = 4 * 1024;

/// Why a call was refused. The slug is the `budget_exceeded` error code; no field carries a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetRefusal {
    /// The per-minute burst limit is used up; retry after the given wait.
    Burst { retry_after: Duration },
    /// Today's (UTC) budget is spent; retry after the given wait, which ends at UTC midnight.
    Daily { retry_after: Duration },
    /// A daily budget applies but the core could not be asked, so the call is refused (fail
    /// closed: no key is unwrapped on a count that cannot be made).
    LeaseUnavailable { retry_after: Duration },
}

impl BudgetRefusal {
    pub const SLUG: &'static str = "budget_exceeded";

    /// The limit kind named in the refusal body.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Burst { .. } => "per_minute",
            Self::Daily { .. } => "per_day",
            Self::LeaseUnavailable { .. } => "per_day_unavailable",
        }
    }

    /// Whole seconds for a `Retry-After` header, at least 1.
    pub fn retry_after_secs(&self) -> u64 {
        let (Self::Burst { retry_after }
        | Self::Daily { retry_after }
        | Self::LeaseUnavailable { retry_after }) = self;
        retry_after.as_secs().saturating_add(1)
    }
}

/// What the core granted from today's budget (`POST /internal/v1/budgets/lease`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Lease {
    /// Calls granted now, between 0 and the count asked for; `0` means the day's budget is spent.
    pub granted: u32,
    /// Calls leased so far today, this lease included.
    pub used: u32,
    /// The UTC day the lease counts against (`YYYY-MM-DD`).
    pub day: String,
}

/// Why a lease could not be made. Carries no response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseError;

/// Leases blocks of calls from an agent's daily budget.
pub trait LeaseSource: Send + Sync {
    /// Asks for up to `count` calls of the budget of `agent` (or of one of its grants).
    fn lease(
        &self,
        agent: Uuid,
        grant: Option<Uuid>,
        daily_limit: u32,
        count: u32,
    ) -> BoxFuture<'_, Result<Lease, LeaseError>>;
}

#[derive(Serialize)]
struct LeaseRequest {
    agent_id: Uuid,
    grant_id: Option<Uuid>,
    daily_limit: u32,
    count: u32,
}

impl LeaseSource for ControlPlane {
    fn lease(
        &self,
        agent: Uuid,
        grant: Option<Uuid>,
        daily_limit: u32,
        count: u32,
    ) -> BoxFuture<'_, Result<Lease, LeaseError>> {
        Box::pin(async move {
            let body = serde_json::to_vec(&LeaseRequest {
                agent_id: agent,
                grant_id: grant,
                daily_limit,
                count,
            })
            .map_err(|_| LeaseError)?;
            let (status, body) = self
                .internal_post_json("internal/v1/budgets/lease", body, MAX_LEASE_RESPONSE)
                .await
                .map_err(|_: Internal| LeaseError)?;
            if status != 200 {
                return Err(LeaseError);
            }
            serde_json::from_slice(&body).map_err(|_| LeaseError)
        })
    }
}

/// What is left of one scope's leased block for one UTC day.
#[derive(Default)]
struct DayState {
    day: String,
    /// Leased calls not yet spent.
    left: u32,
    /// The core said the day's budget is spent: no more asking until the day changes.
    exhausted: bool,
}

type Now = Arc<dyn Fn() -> OffsetDateTime + Send + Sync>;

/// Keyed burst limiters built lazily from the grants' budgets.
pub struct BudgetGuard<C: Clock = DefaultClock> {
    clock: C,
    limiters: Mutex<HashMap<u32, Arc<Limiter<C>>>>,
    leases: Option<Arc<dyn LeaseSource>>,
    now: Now,
    days: Mutex<HashMap<Key, Arc<tokio::sync::Mutex<DayState>>>>,
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
            leases: None,
            now: Arc::new(OffsetDateTime::now_utc),
            days: Mutex::new(HashMap::new()),
        }
    }

    /// Daily budgets are counted through `leases`. Without it a `per_day` limit is not enforced.
    pub fn with_leases(mut self, leases: Arc<dyn LeaseSource>) -> Self {
        self.leases = Some(leases);
        self
    }

    /// Replaces the wall clock that decides the UTC day (tests).
    pub fn with_now(mut self, now: impl Fn() -> OffsetDateTime + Send + Sync + 'static) -> Self {
        self.now = Arc::new(now);
        self
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

    /// Counts one call of `agent` on `grant` against the agent-wide and the grant's budgets:
    /// burst first, then the daily lease. Run it before any key is unwrapped.
    pub async fn check(&self, agent: Uuid, grant: &Grant) -> Result<(), BudgetRefusal> {
        self.check_burst(agent, grant)?;
        let scopes = [
            (grant.agent_budget.and_then(|b| b.per_day), None),
            (grant.budget.and_then(|b| b.per_day), Some(grant.grant_id)),
        ];
        for (per_day, grant_id) in scopes {
            if let Some(limit) = per_day.filter(|n| *n > 0) {
                self.spend_daily(agent, grant_id, limit.min(DAILY_LIMIT_MAX))
                    .await?;
            }
        }
        Ok(())
    }

    /// Seconds-precision wait until the next UTC midnight.
    fn until_midnight(now: OffsetDateTime) -> Duration {
        let next = now
            .date()
            .next_day()
            .map_or(now, |d| d.midnight().assume_utc());
        Duration::from_secs((next - now).whole_seconds().max(1).unsigned_abs())
    }

    async fn spend_daily(
        &self,
        agent: Uuid,
        grant: Option<Uuid>,
        limit: u32,
    ) -> Result<(), BudgetRefusal> {
        // A limit that cannot be counted is not silently dropped: no lease source configured is
        // a deployment choice (tests, burst-only), so it is no limit.
        let Some(leases) = &self.leases else {
            return Ok(());
        };
        let now = (self.now)();
        let today = now.date().to_string();
        let daily = |retry_after| BudgetRefusal::Daily { retry_after };
        let cell = {
            let mut map = self.days.lock().unwrap_or_else(|p| p.into_inner());
            Arc::clone(map.entry((agent, grant)).or_default())
        };
        // Held across the lease so concurrent calls of one scope ask the core once.
        let mut st = cell.lock().await;
        if st.day != today {
            *st = DayState {
                day: today.clone(),
                ..DayState::default()
            };
        }
        if st.left == 0 && !st.exhausted {
            match leases
                .lease(agent, grant, limit, LEASE_BLOCK.min(limit))
                .await
            {
                Ok(l) if l.day == today => {
                    st.left = l.granted;
                    // A short or empty block means the core's counter reached the limit.
                    st.exhausted = l.granted < LEASE_BLOCK.min(limit) || l.used >= limit;
                }
                // Another day (clock skew at midnight) or no answer: ask again on the next call.
                Ok(_) | Err(LeaseError) => {
                    return Err(BudgetRefusal::LeaseUnavailable {
                        retry_after: LEASE_RETRY,
                    });
                }
            }
        }
        if st.left == 0 {
            return Err(daily(Self::until_midnight(now)));
        }
        st.left -= 1;
        Ok(())
    }

    /// The burst half of [`Self::check`]. A budget with no `per_minute` (or `0`, which an
    /// operator uses to mean "unset") is no limit.
    pub fn check_burst(&self, agent: Uuid, grant: &Grant) -> Result<(), BudgetRefusal> {
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
        assert!((0..1000).all(|_| g.check_burst(a, &gr).is_ok()));
        let zero = grant(per_minute(0), None);
        assert!((0..50).all(|_| g.check_burst(a, &zero).is_ok()));
    }

    #[test]
    fn burst_is_refused_then_refills() {
        let clock = FakeRelativeClock::default();
        let g = BudgetGuard::with_clock(clock.clone());
        let gr = grant(per_minute(3), None);
        let a = Uuid::new_v4();
        for _ in 0..3 {
            assert!(g.check_burst(a, &gr).is_ok());
        }
        let refused = g.check_burst(a, &gr).unwrap_err();
        let BudgetRefusal::Burst { retry_after } = refused else {
            panic!("burst refusal")
        };
        assert!(retry_after > Duration::ZERO && retry_after <= Duration::from_secs(20));
        assert!(refused.retry_after_secs() >= 1);
        clock.advance(Duration::from_secs(20));
        assert!(
            g.check_burst(a, &gr).is_ok(),
            "one call refilled after 60s/3"
        );
        assert!(g.check_burst(a, &gr).is_err());
    }

    #[test]
    fn limits_are_per_agent_and_per_grant() {
        let g = BudgetGuard::with_clock(FakeRelativeClock::default());
        let g1 = grant(per_minute(1), None);
        let g2 = grant(per_minute(1), None);
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(g.check_burst(a, &g1).is_ok());
        assert!(g.check_burst(a, &g1).is_err());
        assert!(
            g.check_burst(a, &g2).is_ok(),
            "another grant of the same agent"
        );
        assert!(g.check_burst(b, &g1).is_ok(), "another agent");
    }

    #[test]
    fn the_agent_budget_spans_its_grants() {
        let g = BudgetGuard::with_clock(FakeRelativeClock::default());
        let agent_wide = per_minute(2);
        let (g1, g2) = (grant(None, agent_wide), grant(None, agent_wide));
        let a = Uuid::new_v4();
        assert!(g.check_burst(a, &g1).is_ok());
        assert!(g.check_burst(a, &g2).is_ok());
        assert!(g.check_burst(a, &g1).is_err());
    }

    /// A core stub: leases from a shared counter like the real endpoint, and counts requests.
    struct StubCore {
        used: Mutex<u32>,
        asks: Mutex<Vec<(Option<Uuid>, u32, u32)>>,
        day: Mutex<String>,
        fail: bool,
    }

    impl StubCore {
        fn new(day: &str) -> Arc<Self> {
            Arc::new(Self {
                used: Mutex::new(0),
                asks: Mutex::new(Vec::new()),
                day: Mutex::new(day.into()),
                fail: false,
            })
        }
    }

    impl LeaseSource for StubCore {
        fn lease(
            &self,
            _agent: Uuid,
            grant: Option<Uuid>,
            limit: u32,
            count: u32,
        ) -> BoxFuture<'_, Result<Lease, LeaseError>> {
            self.asks.lock().unwrap().push((grant, limit, count));
            let r = if self.fail {
                Err(LeaseError)
            } else {
                let mut used = self.used.lock().unwrap();
                let granted = count.min(limit.saturating_sub(*used));
                *used += granted;
                Ok(Lease {
                    granted,
                    used: *used,
                    day: self.day.lock().unwrap().clone(),
                })
            };
            Box::pin(async move { r })
        }
    }

    fn at(s: &str) -> OffsetDateTime {
        OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).unwrap()
    }

    fn daily(n: u32) -> Option<Budget> {
        Some(Budget {
            per_minute: None,
            per_day: Some(n),
        })
    }

    fn day_guard(core: Arc<StubCore>, now: OffsetDateTime) -> BudgetGuard {
        BudgetGuard::new().with_leases(core).with_now(move || now)
    }

    #[tokio::test]
    async fn daily_calls_are_leased_in_blocks_and_refused_at_the_limit() {
        let core = StubCore::new("2026-11-26");
        let g = day_guard(core.clone(), at("2026-11-26T23:59:30Z"));
        let gr = grant(daily(25), None);
        let a = Uuid::new_v4();
        for _ in 0..25 {
            assert!(g.check(a, &gr).await.is_ok());
        }
        let refused = g.check(a, &gr).await.unwrap_err();
        assert_eq!(
            refused,
            BudgetRefusal::Daily {
                retry_after: Duration::from_secs(30)
            }
        );
        assert_eq!(refused.retry_after_secs(), 31);
        assert_eq!(refused.kind(), "per_day");
        let counts: Vec<u32> = core.asks.lock().unwrap().iter().map(|a| a.2).collect();
        assert_eq!(
            counts,
            [10, 10, 10],
            "blocks of 10 until the limit, last short"
        );
        // Once spent, further refusals cost no round trip.
        assert!(g.check(a, &gr).await.is_err());
        assert_eq!(core.asks.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn a_zero_lease_refuses_and_a_small_limit_asks_for_its_remainder() {
        let core = StubCore::new("2026-11-26");
        *core.used.lock().unwrap() = 4;
        let g = day_guard(core.clone(), at("2026-11-26T10:00:00Z"));
        let gr = grant(daily(4), None);
        let a = Uuid::new_v4();
        assert!(matches!(
            g.check(a, &gr).await,
            Err(BudgetRefusal::Daily { .. })
        ));
        assert_eq!(core.asks.lock().unwrap()[0], (Some(gr.grant_id), 4, 4));
    }

    #[tokio::test]
    async fn the_agent_wide_and_grant_budgets_are_leased_separately() {
        let core = StubCore::new("2026-11-26");
        let g = day_guard(core.clone(), at("2026-11-26T10:00:00Z"));
        let gr = grant(daily(50), daily(50));
        assert!(g.check(Uuid::new_v4(), &gr).await.is_ok());
        let asks = core.asks.lock().unwrap();
        assert_eq!(asks.len(), 2);
        assert_eq!(asks[0].0, None);
        assert_eq!(asks[1].0, Some(gr.grant_id));
    }

    #[tokio::test]
    async fn a_new_utc_day_leases_again() {
        let core = StubCore::new("2026-11-26");
        let clock = Arc::new(Mutex::new(at("2026-11-26T23:00:00Z")));
        let c2 = clock.clone();
        let g = BudgetGuard::new()
            .with_leases(core.clone())
            .with_now(move || *c2.lock().unwrap());
        let gr = grant(daily(1), None);
        let a = Uuid::new_v4();
        assert!(g.check(a, &gr).await.is_ok());
        assert!(g.check(a, &gr).await.is_err());
        *clock.lock().unwrap() = at("2026-11-27T00:00:01Z");
        *core.day.lock().unwrap() = "2026-11-27".into();
        *core.used.lock().unwrap() = 0;
        assert!(g.check(a, &gr).await.is_ok(), "the counter restarted");
    }

    #[tokio::test]
    async fn a_core_that_cannot_be_asked_refuses_and_no_budget_asks_nothing() {
        let core = Arc::new(StubCore {
            used: Mutex::new(0),
            asks: Mutex::new(Vec::new()),
            day: Mutex::new("2026-11-26".into()),
            fail: true,
        });
        let g = day_guard(core.clone(), at("2026-11-26T10:00:00Z"));
        let a = Uuid::new_v4();
        let err = g.check(a, &grant(daily(5), None)).await.unwrap_err();
        assert!(matches!(err, BudgetRefusal::LeaseUnavailable { .. }));
        assert_eq!(err.kind(), "per_day_unavailable");
        core.asks.lock().unwrap().clear();
        assert!(g.check(a, &grant(None, None)).await.is_ok());
        assert!(g.check(a, &grant(daily(0), None)).await.is_ok());
        assert!(core.asks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn concurrent_calls_never_pass_the_limit() {
        let core = StubCore::new("2026-11-26");
        let g = Arc::new(day_guard(core, at("2026-11-26T10:00:00Z")));
        let gr = Arc::new(grant(daily(30), None));
        let a = Uuid::new_v4();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..50 {
            let (g, gr) = (g.clone(), gr.clone());
            set.spawn(async move { g.check(a, &gr).await.is_ok() });
        }
        let mut ok = 0;
        while let Some(r) = set.join_next().await {
            ok += usize::from(r.unwrap());
        }
        assert_eq!(ok, 30);
    }
}
