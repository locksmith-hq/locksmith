//! `POST /v1/agent-tokens/mint` and `/verify` (task 3.2): the 15-minute EdDSA agent token.
//!
//! The token format, claims and verification are `ls_agent_token`, the same code the control
//! plane and the gateway use. The core makes no decision on whether the agent may have a token
//! (the caller does). Tokens are bearer credentials: they are never logged, and every response
//! is `no-store`. A token that fails verification is a 200 with `valid: false` and a coarse
//! reason, never an error.

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use ls_agent_token::{AgentTokenSigner, MintedToken, VerifyError};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit_api::problem;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MintRequest {
    agent_id: Uuid,
    org_id: Uuid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyRequest {
    token: String,
}

#[derive(Serialize)]
struct MintResponse {
    token: String,
    token_type: &'static str,
    expires_in: u64,
    expires_at: String,
}

#[derive(Serialize)]
struct Verdict {
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

fn no_store(body: impl Serialize) -> Response {
    (
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(body),
    )
        .into_response()
}

fn rfc3339(t: OffsetDateTime) -> Option<String> {
    t.format(&Rfc3339).ok()
}

/// Mint for `agent_id` in `org_id`; shared with the workload-token endpoint.
pub(crate) fn mint_response(signer: &AgentTokenSigner, agent: Uuid, org: Uuid) -> Response {
    let minted: MintedToken = match signer.mint(agent, org, OffsetDateTime::now_utc()) {
        Ok(m) => m,
        Err(_) => return problem(StatusCode::SERVICE_UNAVAILABLE, "token signing unavailable"),
    };
    let Some(expires_at) = rfc3339(minted.expires_at) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "token signing unavailable");
    };
    no_store(MintResponse {
        token: minted.token,
        token_type: "Bearer",
        expires_in: minted.ttl.as_secs(),
        expires_at,
    })
}

/// `GET /v1/agent-tokens/jwks`: the public key set agent tokens verify against (public keys only).
/// The NestJS API serves it at `/.well-known/jwks.json`; empty when signing is not configured there,
/// but the core answers 503 so the caller can tell "not configured" from "no keys".
pub async fn jwks(State(state): State<AppState>) -> Response {
    let Some(signer) = state.agent_signer() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "agent signing key not configured",
        );
    };
    Json(ls_agent_token::JwkSet {
        keys: vec![signer.jwk().clone()],
    })
    .into_response()
}

pub async fn mint(State(state): State<AppState>, body: Bytes) -> Response {
    let Ok(req) = serde_json::from_slice::<MintRequest>(&body) else {
        return problem(StatusCode::BAD_REQUEST, "malformed request");
    };
    let Some(signer) = state.agent_signer() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "agent signing key not configured",
        );
    };
    mint_response(signer, req.agent_id, req.org_id)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadMintRequest {
    agent_id: Uuid,
    org_id: Uuid,
    /// Recorded by the caller on its own ledger; the token format has no policy claim.
    #[allow(dead_code)]
    policy_id: Uuid,
}

/// `POST /v1/workload-tokens/mint`: the same token as `mint`, for the agent bound to a workload
/// identity policy whose external token the caller already verified.
pub async fn mint_workload(State(state): State<AppState>, body: Bytes) -> Response {
    let Ok(req) = serde_json::from_slice::<WorkloadMintRequest>(&body) else {
        return problem(StatusCode::BAD_REQUEST, "malformed request");
    };
    let Some(signer) = state.agent_signer() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "agent signing key not configured",
        );
    };
    mint_response(signer, req.agent_id, req.org_id)
}

fn refused(reason: &'static str) -> Response {
    no_store(Verdict {
        valid: false,
        agent_id: None,
        org_id: None,
        expires_at: None,
        reason: Some(reason),
    })
}

pub async fn verify(State(state): State<AppState>, body: Bytes) -> Response {
    let Ok(req) = serde_json::from_slice::<VerifyRequest>(&body) else {
        return problem(StatusCode::BAD_REQUEST, "malformed request");
    };
    let Some(signer) = state.agent_signer() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "agent signing key not configured",
        );
    };
    let Ok(header) = jsonwebtoken::decode_header(&req.token) else {
        return refused("malformed");
    };
    if header.kid.as_deref() != Some(signer.jwk().kid.as_str()) {
        return refused("unknown_key");
    }
    let Some(key) = signer.jwk().decoding_key() else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "token signing unavailable");
    };
    match ls_agent_token::verify(&req.token, &key) {
        Ok(c) => no_store(Verdict {
            valid: true,
            agent_id: Some(c.sub),
            org_id: Some(c.org),
            expires_at: OffsetDateTime::from_unix_timestamp(c.exp)
                .ok()
                .and_then(rfc3339),
            reason: None,
        }),
        Err(e) => refused(match e {
            VerifyError::Expired => "expired",
            VerifyError::WrongAudience => "wrong_audience",
            VerifyError::BadSignature => "bad_signature",
            VerifyError::Malformed => "malformed",
        }),
    }
}
