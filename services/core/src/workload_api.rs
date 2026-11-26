//! `POST /v1/workload-tokens/verify` (task 3.2): verify an external OIDC token against a stored
//! workload policy.
//!
//! The policy handle (`lsw_...`) names the org and the policy; the policy row is read inside a
//! transaction bound to that org (RLS). The token is checked by `ls_oidc_verify`, the same code
//! the control plane exchanges with, against the policy's stored issuer and audience, then
//! against the policy's claim conditions, then for `jti` replay. Every credential failure is a
//! 200 with `valid: false` and a coarse reason; 400 is for bodies that do not parse and 503 for
//! a missing or unreachable database. The external token is used once and never logged.

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use ls_audit::pg::bind_org;
use ls_oidc_verify::Refused;
use ls_oidc_verify::external::{ExternalToken, LEEWAY_SECS, TrustAnchor};
use ls_oidc_verify::workload::{Condition, matches, parse_handle};
use serde::{Deserialize, Serialize};
use sqlx_core::query::query;
use sqlx_core::row::Row as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::app::AppState;
use crate::audit_api::problem;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyRequest {
    policy: String,
    token: ExternalToken,
}

#[derive(Serialize)]
struct Verdict {
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

fn verdict(v: Verdict) -> Response {
    (
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(v),
    )
        .into_response()
}

fn invalid(reason: &'static str) -> Response {
    verdict(Verdict {
        valid: false,
        agent_id: None,
        org_id: None,
        policy_id: None,
        reason: Some(reason),
    })
}

/// The contract's coarse reason for a verifier label. The verifier folds signature, audience and
/// expiry failures into one `invalid`, so those and the issuer and lifetime checks are all
/// `not_trusted`.
fn reason_of(Refused(label): Refused) -> &'static str {
    match label {
        "unknown_key" => "unknown_key",
        "malformed" | "too_large" | "no_kid" | "algorithm" => "malformed",
        _ => "not_trusted",
    }
}

struct Policy {
    issuer: String,
    audience: String,
    agent_id: Uuid,
    conditions: Vec<Condition>,
}

pub async fn verify(State(state): State<AppState>, body: Bytes) -> Response {
    let Ok(req) = serde_json::from_slice::<VerifyRequest>(&body) else {
        return problem(StatusCode::BAD_REQUEST, "malformed request");
    };
    let Some((org_id, policy_id)) = parse_handle(&req.policy) else {
        return problem(StatusCode::BAD_REQUEST, "malformed policy handle");
    };
    let (Some(pool), Some(verifier)) = (state.pool(), state.workload_verifier()) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "not configured");
    };
    let abuse = state.workload_abuse();
    if !abuse.allow_policy(policy_id) {
        return invalid("not_trusted");
    }
    let unavailable = || problem(StatusCode::SERVICE_UNAVAILABLE, "database unavailable");
    let Ok(mut tx) = pool.begin().await else {
        return unavailable();
    };
    if bind_org(&mut tx, org_id).await.is_err() {
        return unavailable();
    }
    let row = query(
        "SELECT issuer, audience, agent_id, conditions::text AS conditions \
         FROM workload_identities WHERE id = $1",
    )
    .bind(policy_id)
    .fetch_optional(&mut *tx)
    .await;
    // Read only: nothing to commit.
    drop(tx);
    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => return invalid("not_trusted"),
        Err(_) => return unavailable(),
    };
    let parsed = (|| -> Result<Policy, sqlx_core::Error> {
        let stored: Vec<Condition> = serde_json::from_str(row.try_get::<&str, _>("conditions")?)
            .map_err(|e| sqlx_core::Error::Decode(e.into()))?;
        Ok(Policy {
            issuer: row.try_get("issuer")?,
            audience: row.try_get("audience")?,
            agent_id: row.try_get("agent_id")?,
            conditions: stored,
        })
    })();
    let Ok(policy) = parsed else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "policy unreadable");
    };

    let verified = verifier
        .verify_external(
            &req.token,
            TrustAnchor {
                issuer: &policy.issuer,
                audience: &policy.audience,
            },
        )
        .await;
    drop(req);
    let claims = match verified {
        Ok(c) => c,
        Err(refused) => return invalid(reason_of(refused)),
    };
    if !matches(&policy.conditions, &claims.as_value()) || is_replay(state, &policy, &claims.0) {
        return invalid("not_trusted");
    }
    verdict(Verdict {
        valid: true,
        agent_id: Some(policy.agent_id),
        org_id: Some(org_id),
        policy_id: Some(policy_id),
        reason: None,
    })
}

/// Records the token's `jti` and reports whether it was already used (best effort: a token
/// without `jti` is not tracked). The entry lives as long as the token would still verify.
fn is_replay(
    state: AppState,
    policy: &Policy,
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
    let ttl = Duration::from_secs(exp.saturating_add(LEEWAY_SECS).saturating_sub(now));
    !state.workload_abuse().first_use(&policy.issuer, jti, ttl)
}
