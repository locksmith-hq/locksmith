//! `POST /v1/workload-tokens`: exchange an external OIDC token for an agent token (D4 design
//! decisions 1, 2, 7 and 8).
//!
//! The body names a trust policy by its non-secret `lsw_` handle and carries the external JWT.
//! The handle opens the org under row-level security and selects one policy; the JWT is verified
//! against that policy's stored issuer and audience, its claims must satisfy every condition,
//! and only then is an ordinary agent token minted for the policy's agent (the same
//! `AgentTokenSigner::mint` as `POST /v1/agent-tokens`). Grants stay the only thing deciding what
//! the token can do at the gateway.
//!
//! Every failure after the body parses is the same `401`. The reason is a static label on the
//! `exchange_workload_token` span and, once the policy is known, in a `workload_identity.denied`
//! ledger event. The external token never reaches a span, a log line, an error or the ledger: it
//! is held in [`ExternalToken`] (no `Debug`, `Display`, `Clone` or `Serialize`).

use axum::Json;
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
use tracing::Instrument;
use utoipa::ToSchema;
use uuid::Uuid;

use super::agents::{AgentToken, no_store};
use super::extract::SecretJson;
use super::responses::TokenErrors;
use crate::agent_token::MintedToken;
use crate::app::AppState;
use crate::audit;
use crate::auth::external::ExternalToken;
use crate::db::sql::{self, Row};
use crate::problem::{ApiError, Kind};
use crate::workload::{self, Condition};

/// A `last_used_at` write is skipped when the stored value is newer than this many seconds.
const LAST_USED_THROTTLE_SECS: i64 = 300;

/// The peer address of the connection, when the server provides it (`main` serves with connect
/// info; in-process test requests have none, and then no per-source limit applies). Behind a
/// reverse proxy this is the proxy's address; forwarded headers are deliberately not trusted.
pub struct Peer(Option<IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for Peer {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(a)| a.ip().to_canonical()),
        ))
    }
}

/// Request body of a workload token exchange. No `Debug`.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadTokenRequest {
    /// The policy handle (`lsw_...`) from the workload identity. Not a secret.
    pub policy: String,
    /// The external OIDC token (GitHub Actions or Kubernetes). Used once, never stored or logged.
    #[schema(value_type = String, format = Password, write_only)]
    pub token: ExternalToken,
}

#[utoipa::path(
    post,
    path = "/v1/workload-tokens",
    operation_id = "create_workload_token",
    tag = "workload-identities",
    summary = "Exchange an external workload token for an agent token",
    description = "Verifies the external OIDC token against the policy's stored issuer and audience, checks the policy's claim conditions, and returns the same 15-minute agent token as `POST /v1/agent-tokens` for the policy's agent. An unknown policy, an invalid or mismatching token and an unreachable issuer are all the same `401`.",
    request_body = WorkloadTokenRequest,
    responses(
        (status = 200, description = "A token", body = AgentToken,
            headers(("Cache-Control" = String, description = "`no-store`"))),
        TokenErrors,
    ),
)]
pub async fn exchange(
    State(state): State<AppState>,
    Peer(peer): Peer,
    SecretJson(input): SecretJson<WorkloadTokenRequest>,
) -> Result<Response, ApiError> {
    let span = tracing::info_span!(
        "exchange_workload_token",
        policy.id = tracing::field::Empty,
        agent.id = tracing::field::Empty,
        org.id = tracing::field::Empty,
        outcome = tracing::field::Empty,
        reason = tracing::field::Empty,
    );
    let minted = run(&state, peer, input)
        .instrument(span.clone())
        .await
        .inspect_err(|d| {
            span.record("outcome", "denied")
                .record("reason", d.reason());
            tracing::info!(parent: &span, reason = d.reason(), "workload token exchange refused");
        })
        .map_err(Denial::into_error)?;
    span.record("outcome", "ok");
    tracing::info!(parent: &span, "workload token exchanged");
    Ok(no_store(
        Json(AgentToken {
            access_token: minted.token,
            token_type: "Bearer",
            expires_in: minted.ttl.as_secs(),
            expires_at: minted.expires_at,
        })
        .into_response(),
    ))
}

/// Why an exchange failed. Recorded on the span, never returned: every credential failure is
/// the same `401`.
enum Denial {
    NotConfigured,
    /// The handle did not parse.
    Malformed,
    /// No such policy in that org.
    UnknownPolicy,
    /// The verifier refused the external token (its static label).
    Token(&'static str),
    /// The token verified but the policy's conditions did not hold.
    Claims,
    /// A rate limit was exceeded (`rate_limit_source` or `rate_limit_policy`).
    RateLimited(&'static str),
    /// The token's `jti` was already used.
    Replay,
    Database(Kind),
    Internal,
}

impl Denial {
    fn reason(&self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Malformed => "malformed",
            Self::UnknownPolicy => "unknown_policy",
            Self::Token(label) => label,
            Self::Claims => "claims",
            Self::RateLimited(label) => label,
            Self::Replay => "replay",
            Self::Database(_) => "database_error",
            Self::Internal => "internal_error",
        }
    }

    fn into_error(self) -> ApiError {
        match self {
            Self::NotConfigured => ApiError::new(
                Kind::Unavailable,
                "workload token exchange is not configured",
            ),
            Self::Malformed
            | Self::UnknownPolicy
            | Self::Token(_)
            | Self::Claims
            | Self::RateLimited(_)
            | Self::Replay => ApiError::unauthenticated(),
            Self::Database(kind) => ApiError::bare(kind),
            Self::Internal => ApiError::bare(Kind::Internal),
        }
    }
}

/// The stored policy fields the exchange needs.
struct Policy {
    issuer: String,
    audience: String,
    agent_id: Uuid,
    conditions: Vec<Condition>,
}

fn db_denial(e: sql::Error) -> Denial {
    Denial::Database(ApiError::from(e).kind)
}

async fn run(
    state: &AppState,
    source: Option<IpAddr>,
    input: WorkloadTokenRequest,
) -> Result<MintedToken, Denial> {
    let (Some(signer), Some(verifier)) = (state.agent_signer(), state.workload_verifier()) else {
        return Err(Denial::NotConfigured);
    };
    let abuse = state.workload_abuse();
    // Limits run before any database or issuer work. A refusal is not written to the ledger: a
    // flood must not turn into ledger writes. The span and a warn-free info event carry it.
    if source.is_some_and(|ip| !abuse.allow_source(ip)) {
        return Err(Denial::RateLimited("rate_limit_source"));
    }
    let (org_id, policy_id) = workload::parse_handle(&input.policy).ok_or(Denial::Malformed)?;
    if !abuse.allow_policy(policy_id) {
        return Err(Denial::RateLimited("rate_limit_policy"));
    }
    let span = tracing::Span::current();
    span.record("policy.id", tracing::field::display(policy_id));
    span.record("org.id", tracing::field::display(org_id));

    let policy = load_policy(state, org_id, policy_id).await?;
    span.record("agent.id", tracing::field::display(policy.agent_id));

    let verified = verifier
        .verify_external(
            &input.token,
            crate::auth::external::TrustAnchor {
                issuer: &policy.issuer,
                audience: &policy.audience,
            },
        )
        .await;
    drop(input);
    let outcome = match verified {
        Err(refused) => Err(Denial::Token(refused.0)),
        Ok(claims) if workload::matches(&policy.conditions, &claims.as_value()) => {
            // Only the claims the policy names are ever recorded.
            tracing::info!(
                parent: &span,
                claims = %named_claims(&policy.conditions, &claims.0),
                "external token matched the policy"
            );
            if is_replay(abuse, &policy.issuer, &claims.0) {
                Err(Denial::Replay)
            } else {
                signer
                    .mint(policy.agent_id, org_id, OffsetDateTime::now_utc())
                    .map_err(|_| Denial::Internal)
            }
        }
        Ok(_) => Err(Denial::Claims),
    };
    match outcome {
        Ok(minted) => {
            // The token is only returned once the exchange is on the ledger (fail closed).
            record_exchanged(state, org_id, policy_id, &policy).await?;
            Ok(minted)
        }
        Err(denial) => {
            record_denied(state, org_id, policy_id, &policy, denial.reason()).await;
            Err(denial)
        }
    }
}

async fn load_policy(state: &AppState, org_id: Uuid, policy_id: Uuid) -> Result<Policy, Denial> {
    let row = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                sql::query(
                    "SELECT issuer, audience, agent_id, conditions::text AS conditions \
                     FROM workload_identities WHERE id = $1",
                )
                .bind(policy_id)
                .fetch_optional(c)
                .await
            })
        })
        .await
        .map_err(db_denial)?;
    let row = row.ok_or(Denial::UnknownPolicy)?;
    let parse = |r: &sql::PgRow| -> sql::Result<Policy> {
        let stored: Vec<Condition> = serde_json::from_str(r.try_get::<&str, _>("conditions")?)
            .map_err(|e| sql::Error::Decode(e.into()))?;
        Ok(Policy {
            issuer: r.try_get("issuer")?,
            audience: r.try_get("audience")?,
            agent_id: r.try_get("agent_id")?,
            conditions: stored,
        })
    };
    parse(&row).map_err(|_| Denial::Internal)
}

async fn record_exchanged(
    state: &AppState,
    org_id: Uuid,
    policy_id: Uuid,
    policy: &Policy,
) -> Result<(), Denial> {
    let event = audit::workload_identity_exchanged(policy_id, policy.agent_id, &policy.issuer);
    state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                // Throttled: at most one write per policy per few minutes.
                sql::query(
                    "UPDATE workload_identities SET last_used_at = now() WHERE id = $1 \
                     AND (last_used_at IS NULL \
                          OR last_used_at < now() - make_interval(secs => $2))",
                )
                .bind(policy_id)
                .bind(LAST_USED_THROTTLE_SECS as f64)
                .execute(&mut *c)
                .await?;
                audit::append(c, org_id, &event).await?;
                Ok::<_, ApiError>(())
            })
        })
        .await
        .map_err(|e| Denial::Database(e.kind))
}

/// Best effort: a refusal is still a `401` when the ledger write fails.
async fn record_denied(
    state: &AppState,
    org_id: Uuid,
    policy_id: Uuid,
    policy: &Policy,
    reason: &'static str,
) {
    let code = ls_audit::Code::try_new(reason).unwrap_or(ls_audit::Code::new("refused"));
    let event = audit::workload_identity_denied(policy_id, policy.agent_id, &policy.issuer, code);
    let result = state
        .db()
        .with_org(org_id, move |c| {
            Box::pin(async move {
                audit::append(c, org_id, &event).await?;
                Ok::<_, ApiError>(())
            })
        })
        .await;
    if result.is_err() {
        tracing::warn!("workload_identity.denied event could not be recorded");
    }
}

/// Records the token's `jti` and reports whether it was already used. Without a `jti` there is
/// nothing to remember (best effort, design decision 6). The entry lives as long as the token
/// would still verify (`exp` plus the verifier's leeway).
fn is_replay(
    abuse: &crate::auth::abuse::AbuseGuard,
    issuer: &str,
    claims: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    let Some(jti) = claims.get("jti").and_then(|v| v.as_str()) else {
        return false;
    };
    let exp = claims
        .get("exp")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let ttl = Duration::from_secs(
        exp.saturating_add(crate::auth::external::LEEWAY_SECS)
            .saturating_sub(now),
    );
    !abuse.first_use(issuer, jti, ttl)
}

/// `claim=value` pairs for the claims the policy names, nothing else from the token.
fn named_claims(
    conditions: &[Condition],
    claims: &serde_json::Map<String, serde_json::Value>,
) -> String {
    let mut out = Vec::new();
    for c in conditions {
        if let Some(v) = claims.get(&c.claim).and_then(|v| v.as_str()) {
            out.push(format!("{}={v}", c.claim));
        }
    }
    out.join(" ")
}
