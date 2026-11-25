//! Refresh on use (c1 design decision 8): a relay that finds the access token within
//! [`REFRESH_WINDOW`] of expiry refreshes it under a row lock on the material row, reseals the
//! new token set as generation + 1 and commits before the lock drops. Two gateway replicas
//! (or two relays) that race make exactly one provider call: the loser blocks on the lock,
//! re-reads the generation and uses the winner's token.
//!
//! `invalid_grant` marks the connection `refresh_failed` (the person must reconnect); any other
//! failure keeps the stored generation and the connection `connected`, so a retry can succeed.

use secrecy::SecretString;
use uuid::Uuid;

use super::*;
use crate::audit::{OAuthEvent, OAuthEventKind, RefreshFailure};
use ls_oauth::Reason;

/// A token this close to its expiry (seconds) is refreshed before use.
pub const REFRESH_WINDOW: i64 = 60;

/// Why no usable access token could be had. Carries nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessError {
    /// No `connected` or `refresh_failed` connection with this id.
    NotFound,
    /// The provider refused the refresh token (or none is stored): the person must reconnect.
    /// Answered `409 connection_needs_reconnect`.
    NeedsReconnect,
    /// A transient provider failure; the stored token set is unchanged. Answered `502`.
    Provider,
    /// Database, KMS or ledger failure. Answered `503`.
    Unavailable,
}

impl From<sql::Error> for AccessError {
    fn from(_: sql::Error) -> Self {
        Self::Unavailable
    }
}

/// A connection's current access token with its provider. No `Debug`, `Display` or `Clone`.
pub struct AccessToken {
    pub token: SecretString,
    pub provider: String,
    /// The person who owns the connection.
    pub person: Uuid,
}

/// What one locked refresh attempt decided (the transaction commits either way).
enum Step {
    Ready(AccessToken),
    /// The refresh token was refused: `refresh_failed` is committed.
    Failed {
        provider: String,
        person: Uuid,
    },
    Provider,
}

type Material = (String, Uuid, String, i32, Vec<u8>, Vec<u8>);

impl OAuth {
    /// The access token of `connection_id`, refreshed first when it expires within
    /// [`REFRESH_WINDOW`]. `agent` is recorded on an `oauth.refresh_failed` event.
    pub async fn access_token(
        self: &Arc<Self>,
        connection_id: Uuid,
        agent: Option<Uuid>,
    ) -> Result<AccessToken, AccessError> {
        let now = now_unix();
        // Fast path: no lock while the token is fresh.
        if let Some(t) = self.read_fresh(connection_id, now).await? {
            return Ok(t);
        }
        let step = self.refresh_locked(connection_id).await?;
        match step {
            Step::Ready(t) => Ok(t),
            Step::Provider => Err(AccessError::Provider),
            Step::Failed { provider, person } => {
                let ev = OAuthEvent {
                    kind: OAuthEventKind::RefreshFailed(RefreshFailure::InvalidGrant),
                    person,
                    provider,
                    connection_id: Some(connection_id),
                    agent_id: agent,
                };
                if !self.append(ev).await {
                    tracing::warn!("oauth: refresh_failed not recorded");
                }
                Err(AccessError::NeedsReconnect)
            }
        }
    }

    /// The token when the connection is `connected` and not about to expire.
    async fn read_fresh(
        &self,
        connection_id: Uuid,
        now: i64,
    ) -> Result<Option<AccessToken>, AccessError> {
        let (vault, org) = (Arc::clone(&self.vault), self.org_id);
        let row: Option<Material> = self
            .db
            .with_org(self.org_id, move |c| {
                Box::pin(async move { load(c, connection_id, false).await })
            })
            .await?;
        let (status, person, provider, generation, ciphertext, wrapped) =
            row.ok_or(AccessError::NotFound)?;
        match status.as_str() {
            "connected" => {}
            "refresh_failed" => return Err(AccessError::NeedsReconnect),
            _ => return Err(AccessError::NotFound),
        }
        let set = open_set(
            &*vault,
            org,
            connection_id,
            generation,
            &ciphertext,
            &wrapped,
        )
        .await?;
        if set.expires_at.is_some_and(|e| e <= now + REFRESH_WINDOW) {
            return Ok(None);
        }
        Ok(Some(AccessToken {
            token: set.access,
            provider,
            person,
        }))
    }

    /// Lock the material row, re-check, and refresh when still due.
    async fn refresh_locked(self: &Arc<Self>, connection_id: Uuid) -> Result<Step, AccessError> {
        let o = Arc::clone(self);
        let (vault, org) = (Arc::clone(&self.vault), self.org_id);
        self.db
            .with_org(org, move |c| {
                Box::pin(async move {
                    let now = now_unix();
                    let row = load(c, connection_id, true).await?;
                    let (status, person, provider, generation, ciphertext, wrapped) =
                        row.ok_or(AccessError::NotFound)?;
                    match status.as_str() {
                        "connected" => {}
                        "refresh_failed" => return Err(AccessError::NeedsReconnect),
                        _ => return Err(AccessError::NotFound),
                    }
                    // Another relay may have refreshed while this one waited for the lock.
                    let set = open_set(
                        &*vault,
                        org,
                        connection_id,
                        generation,
                        &ciphertext,
                        &wrapped,
                    )
                    .await?;
                    if !set.expires_at.is_some_and(|e| e <= now + REFRESH_WINDOW) {
                        return Ok(Step::Ready(AccessToken {
                            token: set.access,
                            provider,
                            person,
                        }));
                    }
                    let Some(p) = o.providers.get(&provider) else {
                        return Err(AccessError::Unavailable);
                    };
                    let Some(old_refresh) = set.refresh.as_ref() else {
                        mark_failed(c, connection_id, "no_refresh_token").await?;
                        return Ok(Step::Failed { provider, person });
                    };
                    let fresh = match p.client.refresh(old_refresh).await {
                        Ok(t) => t,
                        Err(e) if e.reason == Reason::InvalidGrant => {
                            mark_failed(c, connection_id, "invalid_grant").await?;
                            return Ok(Step::Failed { provider, person });
                        }
                        Err(_) => return Ok(Step::Provider),
                    };
                    let next = generation.checked_add(1).ok_or(AccessError::Unavailable)?;
                    let next_u32 = u32::try_from(next).map_err(|_| AccessError::Unavailable)?;
                    // The provider may keep the refresh token and omit scopes: carry both over.
                    let merged = Tokens {
                        refresh: fresh.refresh.or_else(|| Some(clone_secret(old_refresh))),
                        scopes: if fresh.scopes.is_empty() {
                            set.scopes.clone()
                        } else {
                            fresh.scopes
                        },
                        access: fresh.access,
                        expires_in: fresh.expires_in,
                    };
                    let plain = encode_token_set(&merged, &merged.scopes, now)
                        .ok_or(AccessError::Unavailable)?;
                    let sealed = vault
                        .seal(org, connection_id, next_u32, &plain)
                        .await
                        .map_err(|_| AccessError::Unavailable)?;
                    drop(plain);
                    sql::query(
                        "UPDATE oauth_token_material SET generation = $2, ciphertext = $3, \
                         wrapped_dek = $4, key_id = $5 WHERE connection_id = $1",
                    )
                    .bind(connection_id)
                    .bind(next)
                    .bind(sealed.ciphertext)
                    .bind(sealed.wrapped_dek)
                    .bind(sealed.key_id)
                    .execute(&mut *c)
                    .await?;
                    sql::query(
                        "UPDATE oauth_connections SET generation = $2, last_refreshed_at = now(), \
                         last_error_code = NULL, \
                         expires_at = CASE WHEN $3::bigint IS NULL THEN NULL \
                             ELSE to_timestamp($3::bigint) END, \
                         scopes = $4 \
                     WHERE id = $1",
                    )
                    .bind(connection_id)
                    .bind(next)
                    .bind(merged.expires_in.map(|d| now.saturating_add(secs(d))))
                    .bind(merged.scopes)
                    .execute(&mut *c)
                    .await?;
                    Ok(Step::Ready(AccessToken {
                        token: merged.access,
                        provider,
                        person,
                    }))
                })
            })
            .await
    }
}

fn secs(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

fn clone_secret(s: &SecretString) -> SecretString {
    SecretString::from(s.expose_secret().to_owned())
}

/// The connection and its sealed material; `lock` takes the material row `FOR UPDATE`.
async fn load(
    c: &mut sql::PgConnection,
    connection_id: Uuid,
    lock: bool,
) -> Result<Option<Material>, sql::Error> {
    let q = if lock {
        "SELECT c.status, c.user_id, c.provider, m.generation, m.ciphertext, m.wrapped_dek \
         FROM oauth_connections c JOIN oauth_token_material m ON m.connection_id = c.id \
         WHERE c.id = $1 FOR UPDATE OF m"
    } else {
        "SELECT c.status, c.user_id, c.provider, m.generation, m.ciphertext, m.wrapped_dek \
         FROM oauth_connections c JOIN oauth_token_material m ON m.connection_id = c.id \
         WHERE c.id = $1"
    };
    sql::query_as(q).bind(connection_id).fetch_optional(c).await
}

async fn open_set(
    vault: &dyn Sealer,
    org: Uuid,
    connection_id: Uuid,
    generation: i32,
    ciphertext: &[u8],
    wrapped: &[u8],
) -> Result<TokenSet, AccessError> {
    let generation = u32::try_from(generation).map_err(|_| AccessError::Unavailable)?;
    let plain = vault
        .open(org, connection_id, generation, ciphertext, wrapped)
        .await
        .map_err(|_| AccessError::Unavailable)?;
    decode_token_set(&plain).ok_or(AccessError::Unavailable)
}

async fn mark_failed(
    c: &mut sql::PgConnection,
    connection_id: Uuid,
    code: &str,
) -> Result<(), sql::Error> {
    sql::query(
        "UPDATE oauth_connections SET status = 'refresh_failed', last_error_code = $2 \
         WHERE id = $1",
    )
    .bind(connection_id)
    .bind(code)
    .execute(c)
    .await?;
    Ok(())
}
