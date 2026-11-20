//! The org's agent-layer MCP tool switches, as the gateway's `/mcp` reads them (m1-remote-mcp
//! task 3.4).
//!
//! Only overrides are stored (`mcp_tool_settings`); the defaults live in the tool registry, so a
//! tool with no override is at its default. The gateway reads the overrides from the control
//! plane's `GET /internal/v1/mcp/agent-tool-settings` with the service token and caches them for
//! at most [`MAX_SETTINGS_TTL`], so a switch flipped in the console takes effect within seconds
//! (the same bound as grants). A read that fails is never served from a stale cache past the TTL
//! and never replaced by the defaults: the caller fails closed (an off tool must not turn on
//! because the control plane is unreachable).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::decrypt::{BoxFuture, ControlPlane, Internal};

/// Longest time a read is reused. Larger configured values are clamped to this.
pub const MAX_SETTINGS_TTL: Duration = Duration::from_secs(10);

/// Largest settings response read: one row per tool, so a few hundred bytes in practice.
const MAX_SETTINGS_RESPONSE: usize = 64 * 1024;

const PATH: &str = "internal/v1/mcp/agent-tool-settings";

/// The settings could not be read. Carries no response text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingsError;

/// Reads the org's tool overrides (tool name to on/off).
pub trait ToolSettingsSource: Send + Sync {
    fn settings(&self) -> BoxFuture<'_, Result<HashMap<String, bool>, SettingsError>>;
}

/// Fixed switches: the tests', and the default when nothing is configured (no overrides).
#[derive(Default)]
pub struct StaticSettings(pub HashMap<String, bool>);

impl ToolSettingsSource for StaticSettings {
    fn settings(&self) -> BoxFuture<'_, Result<HashMap<String, bool>, SettingsError>> {
        let map = self.0.clone();
        Box::pin(async move { Ok(map) })
    }
}

#[derive(Deserialize)]
struct Item {
    tool: String,
    enabled: bool,
}

#[derive(Deserialize)]
struct Set {
    items: Vec<Item>,
}

/// Parse the internal endpoint's answer.
pub fn parse_settings(body: &[u8]) -> Result<HashMap<String, bool>, SettingsError> {
    let set: Set = serde_json::from_slice(body).map_err(|_| SettingsError)?;
    Ok(set.items.into_iter().map(|i| (i.tool, i.enabled)).collect())
}

impl ToolSettingsSource for ControlPlane {
    fn settings(&self) -> BoxFuture<'_, Result<HashMap<String, bool>, SettingsError>> {
        Box::pin(async move {
            match self.internal_get(PATH, MAX_SETTINGS_RESPONSE).await {
                Ok(body) => parse_settings(&body),
                Err(Internal::NotFound | Internal::Denied | Internal::Unavailable)
                | Err(Internal::BadResponse) => Err(SettingsError),
            }
        })
    }
}

/// A [`ToolSettingsSource`] that serves one read for at most the TTL. Errors are never cached.
pub struct SettingsCache {
    source: std::sync::Arc<dyn ToolSettingsSource>,
    ttl: Duration,
    entry: Mutex<Option<(Instant, HashMap<String, bool>)>>,
}

impl SettingsCache {
    pub fn new(source: std::sync::Arc<dyn ToolSettingsSource>, ttl: Duration) -> Self {
        Self {
            source,
            ttl: ttl.min(MAX_SETTINGS_TTL),
            entry: Mutex::new(None),
        }
    }

    fn cached(&self) -> Option<HashMap<String, bool>> {
        let guard = self.entry.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some((at, map)) if at.elapsed() < self.ttl => Some(map.clone()),
            _ => None,
        }
    }

    async fn read(&self) -> Result<HashMap<String, bool>, SettingsError> {
        if let Some(map) = self.cached() {
            return Ok(map);
        }
        // Stamp with the time the fetch started, so an entry never outlives the TTL measured
        // from when the control plane was asked.
        let started = Instant::now();
        let map = self.source.settings().await?;
        if !self.ttl.is_zero() {
            *self.entry.lock().unwrap_or_else(|e| e.into_inner()) = Some((started, map.clone()));
        }
        Ok(map)
    }
}

impl ToolSettingsSource for SettingsCache {
    fn settings(&self) -> BoxFuture<'_, Result<HashMap<String, bool>, SettingsError>> {
        Box::pin(self.read())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counting {
        calls: AtomicUsize,
        fail: bool,
    }

    impl ToolSettingsSource for Counting {
        fn settings(&self) -> BoxFuture<'_, Result<HashMap<String, bool>, SettingsError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let fail = self.fail;
            Box::pin(async move {
                if fail {
                    Err(SettingsError)
                } else {
                    Ok(HashMap::from([("explain_block".to_owned(), false)]))
                }
            })
        }
    }

    #[test]
    fn parse_reads_overrides_and_refuses_garbage() {
        let m = parse_settings(
            br#"{"items":[{"tool":"a","enabled":true},{"tool":"b","enabled":false}]}"#,
        )
        .unwrap();
        assert_eq!(m.get("a"), Some(&true));
        assert_eq!(m.get("b"), Some(&false));
        assert!(parse_settings(b"not json").is_err());
        assert!(parse_settings(br#"{"items":[{"tool":"a"}]}"#).is_err());
    }

    #[tokio::test]
    async fn cache_serves_within_ttl_then_refetches() {
        let src = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            fail: false,
        });
        let cache = SettingsCache::new(src.clone(), Duration::from_millis(60));
        cache.settings().await.unwrap();
        cache.settings().await.unwrap();
        assert_eq!(src.calls.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(80)).await;
        cache.settings().await.unwrap();
        assert_eq!(src.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn ttl_is_clamped_and_errors_are_not_cached() {
        let src = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            fail: true,
        });
        let cache = SettingsCache::new(src.clone(), Duration::from_secs(3600));
        assert_eq!(cache.ttl, MAX_SETTINGS_TTL);
        assert!(cache.settings().await.is_err());
        assert!(cache.settings().await.is_err());
        assert_eq!(src.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn zero_ttl_never_caches() {
        let src = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            fail: false,
        });
        let cache = SettingsCache::new(src.clone(), Duration::ZERO);
        cache.settings().await.unwrap();
        cache.settings().await.unwrap();
        assert_eq!(src.calls.load(Ordering::SeqCst), 2);
    }
}
