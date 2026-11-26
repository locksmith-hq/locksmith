//! `POST /v1/audit/events` (task 3.1): chain one allow-listed event onto an org's ledger.
//!
//! The body goes through [`AppendRequest::to_event`], so no request string reaches the ledger
//! as-is. With an `idempotency_key` the event must be a `relay.outcome` whose `attempt_id`
//! attribute equals the key; the append then goes through `ls_audit::pg::append_outcome_once`
//! (the same code the control plane calls). Errors are problem+json with static text.

use std::fmt::Write as _;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use ls_audit::kind;
use ls_audit::pg::{Appended, Once, append_in_tx, append_outcome_once, bind_org};
use serde::Serialize;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit_event::{AppendRequest, Refused};

#[derive(Serialize)]
struct AppendResponse {
    id: Uuid,
    seq: u64,
    hash: String,
    deduplicated: bool,
}

pub(crate) fn problem(status: StatusCode, detail: &'static str) -> Response {
    let body = serde_json::json!({
        "type": "about:blank",
        "title": status.canonical_reason().unwrap_or("error"),
        "status": status.as_u16(),
        "detail": detail,
    });
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        )],
        body.to_string(),
    )
        .into_response()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn response(a: Appended, deduplicated: bool) -> Response {
    let body = AppendResponse {
        id: a.id,
        seq: a.seq,
        hash: hex(&a.hash),
        deduplicated,
    };
    (
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(body),
    )
        .into_response()
}

pub async fn append_event(State(state): State<AppState>, body: Bytes) -> Response {
    let Ok(req) = serde_json::from_slice::<AppendRequest>(&body) else {
        return problem(StatusCode::BAD_REQUEST, "malformed request");
    };
    let event = match req.to_event() {
        Ok(e) => e,
        Err(Refused(why)) => return problem(StatusCode::BAD_REQUEST, why),
    };
    if let Some(key) = req.idempotency_key {
        let matches = event.kind == kind::RELAY_OUTCOME
            && req
                .attrs
                .get(ls_audit::attr::ATTEMPT_ID.as_str())
                .and_then(|v| v.as_str())
                .and_then(|v| Uuid::try_parse(v).ok())
                == Some(key);
        if !matches {
            return problem(
                StatusCode::BAD_REQUEST,
                "idempotency_key needs a relay.outcome with a matching attempt_id",
            );
        }
    }
    let Some(pool) = state.pool() else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "database not configured");
    };
    let unavailable = |_| problem(StatusCode::SERVICE_UNAVAILABLE, "database unavailable");
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => return unavailable(e),
    };
    if let Err(e) = bind_org(&mut tx, req.org_id).await {
        return unavailable(e);
    }
    let result = match req.idempotency_key {
        Some(key) => append_outcome_once(&mut tx, req.org_id, key, &event).await,
        None => append_in_tx(&mut tx, req.org_id, &event)
            .await
            .map(Once::Appended),
    };
    let once = match result {
        Ok(o) => o,
        Err(e) => return unavailable(e),
    };
    if let Err(e) = tx.commit().await {
        return unavailable(e);
    }
    match once {
        Once::Appended(a) => response(a, false),
        Once::Existing(a) => response(a, true),
        Once::Conflict => problem(
            StatusCode::BAD_REQUEST,
            "idempotency_key already used by a different event",
        ),
    }
}
