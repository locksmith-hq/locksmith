//! The agent-layer MCP clients and their revocation (m1-remote-mcp task 4.2).
//!
//! An agent token has no OAuth client id, so on the agent layer a client is the agent itself:
//! the gateway records it in the control plane's `mcp_clients` table on `initialize`
//! (`POST /internal/v1/mcp/agent-clients`, `client_id` = `principal` = the agent id) so the
//! console can list and revoke it. A revoked agent is refused on every `/mcp` request, tool calls
//! and a fresh `initialize` alike, by the check in [`crate::mcp_endpoint`].
//!
//! The revoked set is read from `GET /internal/v1/mcp/revoked-agent-clients` with the service
//! token and reused for at most [`MAX_CACHE_TTL`], the same bound as grants and tool switches,
//! so a revoke takes effect within that time. A read that fails is never served from a stale
//! cache past the TTL and never read as "nobody is revoked": the caller fails closed (`401`).
//! Tests use a zero TTL, which makes "the next call is refused" exact.
//!
//! Nothing here carries a token; ids and a display name only.

use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::decrypt::{BoxFuture, ControlPlane, Internal};
use crate::ttl::TtlCell;

const MAX_RESPONSE: usize = 256 * 1024;
const REVOKED_PATH: &str = "internal/v1/mcp/revoked-agent-clients";
const CLIENTS_PATH: &str = "internal/v1/mcp/agent-clients";

/// The control plane could not be read or written, or refused. Carries no response text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientsError;

/// The agent-layer client registry.
pub trait AgentClients: Send + Sync {
    /// The agents whose MCP access is revoked.
    fn revoked(&self) -> BoxFuture<'_, Result<HashSet<Uuid>, ClientsError>>;

    /// Record `agent` as an MCP client on `initialize`. `Ok(true)` when it is revoked (the row
    /// stays revoked; nothing new is created for it).
    fn record(&self, agent: Uuid, client_name: &str) -> BoxFuture<'_, Result<bool, ClientsError>>;
}

/// No registry: nobody is revoked and nothing is recorded. The default for a gateway built
/// without a control plane, and for tests that do not exercise revoke.
#[derive(Default)]
pub struct NoClients;

impl AgentClients for NoClients {
    fn revoked(&self) -> BoxFuture<'_, Result<HashSet<Uuid>, ClientsError>> {
        Box::pin(async { Ok(HashSet::new()) })
    }

    fn record(&self, _agent: Uuid, _name: &str) -> BoxFuture<'_, Result<bool, ClientsError>> {
        Box::pin(async { Ok(false) })
    }
}

#[derive(Deserialize)]
struct Item {
    agent_id: Uuid,
}

#[derive(Deserialize)]
struct RevokedSet {
    items: Vec<Item>,
}

/// Parse the internal endpoint's answer.
pub fn parse_revoked(body: &[u8]) -> Result<HashSet<Uuid>, ClientsError> {
    let set: RevokedSet = serde_json::from_slice(body).map_err(|_| ClientsError)?;
    Ok(set.items.into_iter().map(|i| i.agent_id).collect())
}

#[derive(Serialize)]
struct NewClient<'a> {
    agent_id: Uuid,
    client_name: &'a str,
}

#[derive(Deserialize)]
struct Recorded {
    revoked: bool,
}

impl AgentClients for ControlPlane {
    fn revoked(&self) -> BoxFuture<'_, Result<HashSet<Uuid>, ClientsError>> {
        Box::pin(async move {
            match self.internal_get(REVOKED_PATH, MAX_RESPONSE).await {
                Ok(body) => parse_revoked(&body),
                Err(Internal::NotFound | Internal::Denied | Internal::Unavailable)
                | Err(Internal::BadResponse) => Err(ClientsError),
            }
        })
    }

    fn record(&self, agent: Uuid, client_name: &str) -> BoxFuture<'_, Result<bool, ClientsError>> {
        let body = serde_json::to_vec(&NewClient {
            agent_id: agent,
            client_name,
        });
        Box::pin(async move {
            let body = body.map_err(|_| ClientsError)?;
            let (status, resp) = self
                .internal_post_json(CLIENTS_PATH, body, MAX_RESPONSE)
                .await
                .map_err(|_| ClientsError)?;
            if status != 200 {
                return Err(ClientsError);
            }
            serde_json::from_slice::<Recorded>(&resp)
                .map(|r| r.revoked)
                .map_err(|_| ClientsError)
        })
    }
}

/// An [`AgentClients`] that serves one read of the revoked set for at most the TTL. Errors are
/// never cached. `record` always goes to the source.
pub struct ClientsCache {
    source: std::sync::Arc<dyn AgentClients>,
    cell: TtlCell<HashSet<Uuid>>,
}

impl ClientsCache {
    pub fn new(source: std::sync::Arc<dyn AgentClients>, ttl: Duration) -> Self {
        Self {
            source,
            cell: TtlCell::new(ttl),
        }
    }

    async fn read(&self) -> Result<HashSet<Uuid>, ClientsError> {
        self.cell.get_or_fetch(|| self.source.revoked()).await
    }
}

impl AgentClients for ClientsCache {
    fn revoked(&self) -> BoxFuture<'_, Result<HashSet<Uuid>, ClientsError>> {
        Box::pin(self.read())
    }

    fn record(&self, agent: Uuid, client_name: &str) -> BoxFuture<'_, Result<bool, ClientsError>> {
        self.source.record(agent, client_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const A: Uuid = Uuid::from_u128(1);

    struct Counting {
        calls: AtomicUsize,
        fail: bool,
    }

    impl AgentClients for Counting {
        fn revoked(&self) -> BoxFuture<'_, Result<HashSet<Uuid>, ClientsError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let fail = self.fail;
            Box::pin(async move {
                if fail {
                    Err(ClientsError)
                } else {
                    Ok(HashSet::from([A]))
                }
            })
        }

        fn record(&self, _a: Uuid, _n: &str) -> BoxFuture<'_, Result<bool, ClientsError>> {
            Box::pin(async { Ok(false) })
        }
    }

    #[test]
    fn parse_reads_ids_and_refuses_garbage() {
        let s =
            parse_revoked(br#"{"items":[{"agent_id":"00000000-0000-0000-0000-000000000001"}]}"#)
                .unwrap();
        assert!(s.contains(&A));
        assert!(parse_revoked(b"nope").is_err());
        assert!(parse_revoked(br#"{"items":[{"agent_id":"x"}]}"#).is_err());
    }

    #[tokio::test]
    async fn cache_serves_within_ttl_then_refetches() {
        let src = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            fail: false,
        });
        let cache = ClientsCache::new(src.clone(), Duration::from_millis(60));
        cache.revoked().await.unwrap();
        cache.revoked().await.unwrap();
        assert_eq!(src.calls.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(80)).await;
        cache.revoked().await.unwrap();
        assert_eq!(src.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn ttl_is_clamped_errors_are_not_cached_and_zero_never_caches() {
        let src = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            fail: true,
        });
        let cache = ClientsCache::new(src.clone(), Duration::from_secs(3600));
        assert_eq!(cache.cell.ttl(), crate::ttl::MAX_CACHE_TTL);
        assert!(cache.revoked().await.is_err());
        assert!(cache.revoked().await.is_err());
        assert_eq!(src.calls.load(Ordering::SeqCst), 2);

        let ok = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            fail: false,
        });
        let zero = ClientsCache::new(ok.clone(), Duration::ZERO);
        zero.revoked().await.unwrap();
        zero.revoked().await.unwrap();
        assert_eq!(ok.calls.load(Ordering::SeqCst), 2);
    }
}
