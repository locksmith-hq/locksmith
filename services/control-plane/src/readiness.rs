//! Readiness reporting. The service uses [`crate::db::DbReadiness`] (migrations applied and
//! Postgres reachable); [`ReadyFlag`] is a fixed gate for tests.

use std::sync::atomic::{AtomicBool, Ordering};

/// Reports whether the service can serve traffic (database reachable and migrated).
pub trait Readiness: Send + Sync + 'static {
    fn is_ready(&self) -> bool;
}

/// A flag-backed readiness gate: not ready until [`ReadyFlag::set_ready`] is called.
#[derive(Debug, Default)]
pub struct ReadyFlag(AtomicBool);

impl ReadyFlag {
    pub fn new(ready: bool) -> Self {
        Self(AtomicBool::new(ready))
    }

    pub fn set_ready(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
    }
}

impl Readiness for ReadyFlag {
    fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
