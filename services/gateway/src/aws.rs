//! `POST /v1/aws/credentials` (D2 task 3): short-lived, scoped AWS credentials for an agent.
//!
//! Order of checks, all before the base credential is decrypted: agent token, request shape and
//! duration floor, grants read, AWS binding selection, the binding's `vend` opt-in, an unexpired
//! `delegate` grant for the binding, the session policy rendered from the grant's allow-list
//! ([`render_session_policy`]: empty or too-broad grants are refused) and the duration clamp.
//! Only then is the base credential decrypted and STS `AssumeRole` called through
//! [`ls_proxy::aws::sts::assume_role`] on a blocking thread. The base credential lives inside that
//! blocking task only and is dropped (zeroized) when it ends; the response body is built and
//! checked there, so it is refused when it carries any part of the base credential.
//!
//! The agent cannot supply or widen the policy: the request has no policy field, and unknown
//! fields (a `policy` among them) are ignored. Errors are fixed slugs; STS error text is never
//! returned, logged or recorded. Every refusal after the binding is known appends one
//! `aws.credentials.denied` event; an issue appends `aws.credentials.issued` before the answer
//! is sent, and the credentials are withheld (`500 audit_failed`) when the ledger does not take
//! it (fail closed). Events hold the binding's secret id, region, duration and outcome only.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ls_proxy::aws::Credentials;
use ls_proxy::aws::sts::assume_role;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::{AuditError, AwsEvent, AwsEventKind, Outcome};
use crate::aws_policy::{
    AwsBinding, MIN_DURATION_SECS, PolicyError, clamp_duration, render_session_policy,
};
use crate::decrypt::{DecryptError, MaterialError};
use crate::grants::{Grant, delegate_grant};
use crate::relay::{Relay, error};

/// AWS route options.
#[derive(Debug, Clone, Default)]
pub struct AwsOptions {
    /// STS endpoint override (moto in tests and the local smoke). `None`: the regional AWS
    /// endpoint `https://sts.<region>.amazonaws.com/`.
    pub sts_endpoint: Option<String>,
}

/// The agent's request. Every field is optional; unknown fields are ignored (an agent-supplied
/// `policy` has no effect).
#[derive(Deserialize, Default)]
struct CredentialsRequest {
    /// The binding's base-credential secret id.
    #[serde(default)]
    secret_id: Option<Uuid>,
    /// The bound role, as an alternative to `secret_id`.
    #[serde(default)]
    role_arn: Option<String>,
    /// Requested lifetime; default 900 s, clamped to the grant and binding, below 900 is a `400`.
    #[serde(default)]
    duration_secs: Option<u32>,
}

/// The AWS CLI `credential_process` document (Version 1).
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct CredentialProcess<'a> {
    version: u8,
    access_key_id: &'a str,
    secret_access_key: &'a str,
    session_token: &'a str,
    expiration: String,
}

/// A refusal or failure: the ledger outcome, the status and the fixed slug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Failure {
    outcome: Outcome,
    status: StatusCode,
    slug: &'static str,
}

const fn failure(outcome: Outcome, status: StatusCode, slug: &'static str) -> Failure {
    Failure {
        outcome,
        status,
        slug,
    }
}

const STS_ERROR: Failure = failure(Outcome::UpstreamError, StatusCode::BAD_GATEWAY, "sts_error");
const STS_UNREACHABLE: Failure = failure(
    Outcome::UpstreamUnreachable,
    StatusCode::BAD_GATEWAY,
    "sts_unreachable",
);
const REDACTION_FAILED: Failure = failure(
    Outcome::RedactionFailed,
    StatusCode::BAD_GATEWAY,
    "redaction_failed",
);
const SECRET_UNUSABLE: Failure = failure(
    Outcome::InjectFailed,
    StatusCode::BAD_GATEWAY,
    "secret_unusable",
);

fn policy_failure(e: PolicyError) -> Failure {
    failure(Outcome::Denied, StatusCode::FORBIDDEN, e.as_str())
}

/// Parse the stored base credential `{"access_key_id","secret_access_key"[,"session_token"]}`.
/// The secret parts go straight into zeroizing buffers; errors carry nothing.
fn parse_base(value: &[u8]) -> Option<Credentials> {
    #[derive(Deserialize)]
    struct Stored {
        access_key_id: String,
        secret_access_key: String,
        #[serde(default)]
        session_token: Option<String>,
    }
    let s: Stored = serde_json::from_slice(value).ok()?;
    let creds = Credentials {
        access_key_id: s.access_key_id,
        secret_access_key: Zeroizing::new(s.secret_access_key),
        session_token: s.session_token.map(Zeroizing::new),
    };
    let ok = !creds.access_key_id.is_empty() && !creds.secret_access_key.is_empty();
    ok.then_some(creds)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Whether `body` carries any part of the base credential.
fn leaks_base(body: &[u8], base: &Credentials) -> bool {
    contains(body, base.access_key_id.as_bytes())
        || contains(body, base.secret_access_key.as_bytes())
        || base
            .session_token
            .as_ref()
            .is_some_and(|t| contains(body, t.as_bytes()))
}

/// What the blocking STS task needs. Owns the base credential; dropping it zeroizes the secret.
struct StsCall {
    base: Credentials,
    region: String,
    role_arn: String,
    external_id: Option<String>,
    session_name: String,
    policy: String,
    duration_secs: u32,
    endpoint: Option<String>,
}

/// Call STS and build the response body. The base credential is dropped when this returns.
fn issue(call: StsCall) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let StsCall {
        base,
        region,
        role_arn,
        external_id,
        session_name,
        policy,
        duration_secs,
        endpoint,
    } = call;
    let (tmp, expiry) = assume_role(
        &base,
        &region,
        &role_arn,
        external_id.as_deref(),
        &session_name,
        Some(&policy),
        duration_secs,
        endpoint.as_deref(),
    )
    // The error text carries AWS's code and message, which may echo request details: it is
    // classified and dropped, never logged or returned.
    .map_err(|e| {
        if e.contains("request failed") {
            STS_UNREACHABLE
        } else {
            STS_ERROR
        }
    })?;
    let token = tmp.session_token.as_ref().ok_or(STS_ERROR)?;
    let expiration = OffsetDateTime::from_unix_timestamp(expiry)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .ok_or(STS_ERROR)?;
    let body = Zeroizing::new(
        serde_json::to_vec(&CredentialProcess {
            version: 1,
            access_key_id: &tmp.access_key_id,
            secret_access_key: &tmp.secret_access_key,
            session_token: token,
            expiration,
        })
        .map_err(|_| STS_ERROR)?,
    );
    if leaks_base(&body, &base) {
        return Err(REDACTION_FAILED);
    }
    Ok(body)
}

/// Pick the binding: by `secret_id` and/or `role_arn` when given, else the one AWS binding (or
/// the one the agent holds a delegate grant for). `Err` is the refusal.
fn select<'a>(
    bindings: &'a [AwsBinding],
    req: &CredentialsRequest,
    grants: &[Grant],
    now: OffsetDateTime,
) -> Result<&'a AwsBinding, Failure> {
    let named: Vec<&AwsBinding> = bindings
        .iter()
        .filter(|b| req.secret_id.is_none_or(|s| s == b.secret_id))
        .filter(|b| req.role_arn.as_deref().is_none_or(|r| r == b.role_arn))
        .collect();
    match named.as_slice() {
        [] => Err(failure(Outcome::Denied, StatusCode::FORBIDDEN, "not_bound")),
        [one] => Ok(one),
        many => {
            let granted: Vec<&&AwsBinding> = many
                .iter()
                .filter(|b| delegate_grant(grants, b.secret_id, now).is_some())
                .collect();
            match granted.as_slice() {
                [one] => Ok(one),
                [] => Err(failure(Outcome::NoGrant, StatusCode::FORBIDDEN, "no_grant")),
                _ => Err(failure(
                    Outcome::Denied,
                    StatusCode::BAD_REQUEST,
                    "binding_ambiguous",
                )),
            }
        }
    }
}

fn event(
    kind: AwsEventKind,
    agent_id: Uuid,
    binding: &AwsBinding,
    duration: Option<u32>,
) -> AwsEvent {
    AwsEvent {
        kind,
        agent_id,
        secret_id: binding.secret_id,
        region: binding.region.clone(),
        duration_secs: duration,
    }
}

/// One admitted-binding call: records refusals and the issue.
struct Call<'a> {
    relay: &'a Relay,
    agent_id: Uuid,
    binding: &'a AwsBinding,
    duration: Option<u32>,
    request_id: &'a str,
}

impl Call<'_> {
    /// Record `f` as `aws.credentials.denied` (one try: the call is refused either way) and
    /// answer with its slug.
    async fn refuse(&self, f: Failure) -> Response {
        tracing::info!(
            agent.id = %self.agent_id,
            aws.role_arn = %self.binding.role_arn,
            aws.region = %self.binding.region,
            outcome = f.outcome.as_str(),
            reason = f.slug,
            "aws credentials refused"
        );
        let ev = event(
            AwsEventKind::Denied(f.outcome),
            self.agent_id,
            self.binding,
            self.duration,
        );
        if self.relay.audit().append_aws(ev).await.is_err() {
            tracing::error!("aws denied event not appended");
        }
        error(f.status, f.slug, self.request_id)
    }

    /// Record the issue, retried like a relay outcome. `false` when the ledger did not take it.
    async fn record_issued(&self) -> bool {
        let ev = event(
            AwsEventKind::Issued,
            self.agent_id,
            self.binding,
            self.duration,
        );
        let opts = self.relay.options();
        let mut wait = opts.outcome_retry_backoff;
        for try_no in 0..=opts.outcome_retries {
            match self.relay.audit().append_aws(ev.clone()).await {
                Ok(_) => return true,
                Err(AuditError::Rejected) => break,
                Err(AuditError::Unavailable) => {
                    if try_no < opts.outcome_retries {
                        tokio::time::sleep(wait).await;
                        wait = wait.saturating_mul(2);
                    }
                }
            }
        }
        tracing::error!("aws issued event not appended; credentials withheld");
        false
    }
}

/// The handler. See the module docs for the order of checks.
pub async fn handle(relay: Arc<Relay>, headers: HeaderMap, body: Bytes) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let agent = match relay.auth().authenticate(&headers).await {
        Ok(a) => a,
        Err(e) => {
            tracing::info!(reason = e.as_str(), "aws: agent token refused");
            return error(StatusCode::UNAUTHORIZED, "unauthenticated", &request_id);
        }
    };
    let req: CredentialsRequest = if body.iter().all(u8::is_ascii_whitespace) {
        CredentialsRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_request", &request_id),
        }
    };
    if req.duration_secs.is_some_and(|d| d < MIN_DURATION_SECS) {
        return error(StatusCode::BAD_REQUEST, "duration_too_short", &request_id);
    }
    let grants = match relay.grants().grants(agent.agent_id).await {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(reason = e.as_str(), "aws: agent grants could not be read");
            return error(StatusCode::BAD_GATEWAY, "grants_unavailable", &request_id);
        }
    };
    let now = OffsetDateTime::now_utc();
    let binding = match select(&relay.bindings().aws_bindings, &req, &grants, now) {
        Ok(b) => b,
        Err(f) => {
            // No single binding to name in the ledger: logs only.
            tracing::info!(agent.id = %agent.agent_id, reason = f.slug, "aws credentials refused");
            return error(f.status, f.slug, &request_id);
        }
    };
    let mut call = Call {
        relay: &relay,
        agent_id: agent.agent_id,
        binding,
        duration: None,
        request_id: &request_id,
    };
    // Off by default (H1-2): the binding must opt in.
    if !binding.vend {
        return call
            .refuse(failure(
                Outcome::Denied,
                StatusCode::FORBIDDEN,
                "vend_disabled",
            ))
            .await;
    }
    let Some(grant) = delegate_grant(&grants, binding.secret_id, now) else {
        return call
            .refuse(failure(Outcome::NoGrant, StatusCode::FORBIDDEN, "no_grant"))
            .await;
    };
    let scope = grant.scope.clone().unwrap_or_default();
    drop(grants);
    let duration = clamp_duration(binding, &scope, req.duration_secs);
    call.duration = Some(duration);
    let policy = match render_session_policy(binding, &scope) {
        Ok(p) => p,
        Err(e) => return call.refuse(policy_failure(e)).await,
    };

    // Every check passed: decrypt the base credential.
    let value = match relay
        .decryptor()
        .decrypt(binding.secret_id, binding.version)
        .await
    {
        Ok(v) => v,
        Err(DecryptError::Material(MaterialError::NotFound)) => {
            return call
                .refuse(failure(
                    Outcome::MaterialError,
                    StatusCode::BAD_GATEWAY,
                    "secret_unavailable",
                ))
                .await;
        }
        Err(_) => {
            return call
                .refuse(failure(
                    Outcome::DecryptFailed,
                    StatusCode::BAD_GATEWAY,
                    "secret_unavailable",
                ))
                .await;
        }
    };
    let base = parse_base(value.expose());
    drop(value);
    let Some(base) = base else {
        return call.refuse(SECRET_UNUSABLE).await;
    };
    let sts = StsCall {
        base,
        region: binding.region.clone(),
        role_arn: binding.role_arn.clone(),
        external_id: binding.external_id.clone(),
        session_name: format!("locksmith-{}", agent.agent_id.simple()),
        policy,
        duration_secs: duration,
        endpoint: relay.aws().sts_endpoint.clone(),
    };
    let body = match tokio::task::spawn_blocking(move || issue(sts)).await {
        Ok(Ok(b)) => b,
        Ok(Err(f)) => return call.refuse(f).await,
        Err(_) => {
            return call
                .refuse(failure(
                    Outcome::UpstreamError,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                ))
                .await;
        }
    };
    // The ledger takes the issue before the agent sees the credentials (fail closed).
    if !call.record_issued().await {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "audit_failed",
            &request_id,
        );
    }
    tracing::info!(
        agent.id = %agent.agent_id,
        aws.role_arn = %binding.role_arn,
        aws.region = %binding.region,
        aws.duration_secs = duration,
        "aws credentials issued"
    );
    let mut r = (StatusCode::OK, Bytes::from(body.to_vec())).into_response();
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        h.insert("x-request-id", v);
    }
    r
}

/// Axum entry point: `503` until the gateway is configured.
pub async fn route(
    State(state): State<crate::app::AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match state.relay() {
        Some(relay) => handle(relay, headers, body).await,
        None => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            &Uuid::new_v4().to_string(),
        ),
    }
}

#[cfg(test)]
#[path = "aws_tests.rs"]
mod tests;
