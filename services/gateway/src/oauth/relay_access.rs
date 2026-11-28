//! What a relay through a person's connection needs from the OAuth layer (c1 task 5.1): the
//! agent's connection grant (read through the gateway role, cached at most [`GRANT_TTL`]),
//! the connection's person and provider, the host check against the provider's API hosts, and
//! the current access token ([`OAuth::access_token`], refreshed on use).
//!
//! The order is the relay's: connection known -> grant -> connection `connected` -> host ->
//! token. Every refusal is a fixed slug; nothing here carries a token except [`RelayAccess`].

use std::sync::Mutex;

use super::*;

/// A cached grant answer is used for at most this long (like `GrantCache`: a revoked grant
/// stops working within 10 s).
pub const GRANT_TTL: Duration = Duration::from_secs(10);

/// Why a relay through a connection was refused before any provider call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayAccessError {
    /// No such connection in this org (nothing to name in the ledger).
    UnknownConnection,
    /// The agent holds no unexpired grant for the connection. `403 no_grant`.
    NoGrant,
    /// The connection is `revoked` or not yet confirmed. `403 no_grant`.
    NotConnected,
    /// The target host is not one of the provider's API hosts. `403 host_not_allowed`.
    HostNotAllowed,
    /// The grant or the connection could not be read. `502 grants_unavailable`.
    Unavailable,
    /// The token could not be had.
    Token(AccessError),
}

/// A connection's person and provider, known before the grant is checked so a denial can name
/// the person in the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub person: Uuid,
    pub provider: String,
    pub status: String,
}

/// The token a relay injects, and what it records. No `Debug`, `Display` or `Clone`.
pub struct RelayAccess {
    pub access: SecretString,
    pub refresh: Option<SecretString>,
    pub person: Uuid,
    pub provider: String,
    /// The dev-only mock provider: plain HTTP and loopback are allowed for it and nothing else.
    pub dev: bool,
}

/// The agent's grant cache: `(agent, connection) -> (read at, active until)`.
#[derive(Default)]
pub struct GrantMemo(Mutex<HashMap<(Uuid, Uuid), Memo>>);

/// When the answer was read, and until when the grant is active (`None`: no grant).
type Memo = (Instant, Option<i64>);

impl GrantMemo {
    fn get(&self, key: (Uuid, Uuid), now_unix: i64) -> Option<bool> {
        let map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let (at, until) = map.get(&key)?;
        if at.elapsed() >= GRANT_TTL {
            return None;
        }
        // `Some(None)` is a cached "no grant"; an expiry inside the cache window is honoured.
        Some(until.is_some_and(|u| u > now_unix || u == i64::MAX))
    }

    fn put(&self, key: (Uuid, Uuid), active_until: Option<i64>) {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, (at, _)| at.elapsed() < GRANT_TTL);
        map.insert(key, (Instant::now(), active_until));
    }
}

impl OAuth {
    /// The connection's person, provider and status, or `None` for an unknown id.
    pub async fn connection_info(
        &self,
        connection_id: Uuid,
    ) -> Result<Option<ConnectionInfo>, RelayAccessError> {
        let row: Option<(Uuid, String, String)> = self
            .db
            .with_org(self.org_id, move |c| {
                Box::pin(async move {
                    sql::query_as(
                        "SELECT user_id, provider, status FROM oauth_connections WHERE id = $1",
                    )
                    .bind(connection_id)
                    .fetch_optional(c)
                    .await
                })
            })
            .await
            .map_err(|_| RelayAccessError::Unavailable)?;
        Ok(row.map(|(person, provider, status)| ConnectionInfo {
            person,
            provider,
            status,
        }))
    }

    /// The agent's unexpired connection grants for `GET /v1/grants`: connection id, provider,
    /// the person's display name (the local part of their email, never the full address) and
    /// the expiry. Only `connected` and `refresh_failed` connections are listed; no token.
    pub async fn agent_connection_grants(
        &self,
        agent: Uuid,
    ) -> Result<Vec<ls_oauth::ConnectionGrantListing>, RelayAccessError> {
        let rows: Vec<(Uuid, String, Option<String>, Option<time::OffsetDateTime>)> = self
            .db
            .with_org(self.org_id, move |c| {
                Box::pin(async move {
                    sql::query_as(
                        "SELECT g.connection_id, c.provider, u.email, g.expires_at \
                         FROM oauth_connection_grants g \
                         JOIN oauth_connections c ON c.org_id = g.org_id AND c.id = g.connection_id \
                         JOIN users u ON u.id = c.user_id \
                         WHERE g.agent_id = $1 \
                         AND c.status IN ('connected', 'refresh_failed') \
                         AND (g.expires_at IS NULL OR g.expires_at > now()) \
                         ORDER BY g.created_at, g.id",
                    )
                    .bind(agent)
                    .fetch_all(c)
                    .await
                })
            })
            .await
            .map_err(|_| RelayAccessError::Unavailable)?;
        Ok(rows
            .into_iter()
            .map(|(connection_id, provider, email, expires_at)| {
                let person_name = email
                    .as_deref()
                    .and_then(|e| e.split('@').next())
                    .filter(|n| !n.trim().is_empty())
                    .unwrap_or("a person")
                    .to_owned();
                ls_oauth::ConnectionGrantListing {
                    connection_id,
                    provider,
                    person_name,
                    expires_at: expires_at.and_then(|t| {
                        t.format(&time::format_description::well_known::Rfc3339)
                            .ok()
                    }),
                }
            })
            .collect())
    }

    /// Whether `agent` holds an unexpired grant for `connection_id` (cached at most
    /// [`GRANT_TTL`]).
    pub async fn agent_may_use(
        &self,
        agent: Uuid,
        connection_id: Uuid,
    ) -> Result<bool, RelayAccessError> {
        let now = now_unix();
        let key = (agent, connection_id);
        if let Some(hit) = self.grant_memo.get(key, now) {
            return Ok(hit);
        }
        let until: Option<Option<time::OffsetDateTime>> = self
            .db
            .with_org(self.org_id, move |c| {
                Box::pin(async move {
                    sql::query_scalar(
                        "SELECT expires_at FROM oauth_connection_grants \
                         WHERE agent_id = $1 AND connection_id = $2 \
                         AND (expires_at IS NULL OR expires_at > now())",
                    )
                    .bind(agent)
                    .bind(connection_id)
                    .fetch_optional(c)
                    .await
                })
            })
            .await
            .map_err(|_| RelayAccessError::Unavailable)?;
        let active = until.map(|e| e.map_or(i64::MAX, |t| t.unix_timestamp()));
        self.grant_memo.put(key, active);
        Ok(active.is_some_and(|u| u > now))
    }

    /// The checks before any token is opened, in order: grant, connection state, host and
    /// scheme. Returns whether the provider is the dev mock (loopback allowed). The token is
    /// opened later by [`Self::relay_token`], after the ledger took the attempt.
    pub async fn authorize_relay(
        &self,
        agent: Uuid,
        connection_id: Uuid,
        info: &ConnectionInfo,
        scheme: &str,
        host: &str,
    ) -> Result<bool, RelayAccessError> {
        if !self.agent_may_use(agent, connection_id).await? {
            return Err(RelayAccessError::NoGrant);
        }
        if info.status != "connected" && info.status != "refresh_failed" {
            return Err(RelayAccessError::NotConnected);
        }
        let dev = info.provider == "mock";
        // The registry's `api_hosts` are `host` or, for a non-default port, `host:port`; the
        // token goes only over HTTPS (plain HTTP for the dev mock only).
        let allowed = (scheme == "https" || (dev && scheme == "http"))
            && self
                .providers
                .get(&info.provider)
                .is_some_and(|p| p.def.api_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)));
        if !allowed {
            return Err(RelayAccessError::HostNotAllowed);
        }
        Ok(dev)
    }

    /// Open (refreshing when due) the token of an authorised relay.
    pub async fn relay_token(
        self: &Arc<Self>,
        agent: Uuid,
        connection_id: Uuid,
        dev: bool,
    ) -> Result<RelayAccess, RelayAccessError> {
        let t = self
            .access_token(connection_id, Some(agent))
            .await
            .map_err(RelayAccessError::Token)?;
        Ok(RelayAccess {
            access: t.token,
            refresh: t.refresh,
            person: t.person,
            provider: t.provider,
            dev,
        })
    }

    /// [`Self::authorize_relay`] then [`Self::relay_token`].
    pub async fn relay_access(
        self: &Arc<Self>,
        agent: Uuid,
        connection_id: Uuid,
        info: &ConnectionInfo,
        scheme: &str,
        host: &str,
    ) -> Result<RelayAccess, RelayAccessError> {
        let dev = self
            .authorize_relay(agent, connection_id, info, scheme, host)
            .await?;
        self.relay_token(agent, connection_id, dev).await
    }
}
