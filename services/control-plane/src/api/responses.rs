//! Shared OpenAPI error responses (`application/problem+json`, body [`Problem`]).
//!
//! Every `#[utoipa::path]` lists exactly one of these sets next to its success response, so no
//! route spells a problem response out by hand. Pick the set that matches the handler: reads,
//! lists, creates (no parent to look up), writes (parent or target looked up), deletes.

use utoipa::IntoResponses;

use crate::problem::Problem;

/// `GET` of one resource.
#[derive(Debug, IntoResponses)]
#[allow(dead_code)] // OpenAPI description only; never constructed.
pub enum ReadErrors {
    #[response(
        status = 401,
        description = "Missing or invalid org binding",
        content_type = "application/problem+json"
    )]
    Unauthenticated(Problem),
    #[response(
        status = 403,
        description = "Email verification required",
        content_type = "application/problem+json"
    )]
    EmailNotVerified(Problem),
    #[response(
        status = 404,
        description = "Not found",
        content_type = "application/problem+json"
    )]
    NotFound(Problem),
    #[response(
        status = 503,
        description = "Service unavailable",
        content_type = "application/problem+json"
    )]
    Unavailable(Problem),
}

/// `GET` of a collection (paging parameters, optional parent).
#[derive(Debug, IntoResponses)]
#[allow(dead_code)] // OpenAPI description only; never constructed.
pub enum ListErrors {
    #[response(
        status = 400,
        description = "Invalid request",
        content_type = "application/problem+json"
    )]
    Invalid(Problem),
    #[response(
        status = 401,
        description = "Missing or invalid org binding",
        content_type = "application/problem+json"
    )]
    Unauthenticated(Problem),
    #[response(
        status = 403,
        description = "Email verification required",
        content_type = "application/problem+json"
    )]
    EmailNotVerified(Problem),
    #[response(
        status = 404,
        description = "Not found",
        content_type = "application/problem+json"
    )]
    NotFound(Problem),
    #[response(
        status = 503,
        description = "Service unavailable",
        content_type = "application/problem+json"
    )]
    Unavailable(Problem),
}

/// `POST` of a top-level resource: no parent to look up, but names can conflict.
#[derive(Debug, IntoResponses)]
#[allow(dead_code)] // OpenAPI description only; never constructed.
pub enum CreateErrors {
    #[response(
        status = 400,
        description = "Invalid request",
        content_type = "application/problem+json"
    )]
    Invalid(Problem),
    #[response(
        status = 401,
        description = "Missing or invalid org binding",
        content_type = "application/problem+json"
    )]
    Unauthenticated(Problem),
    #[response(
        status = 403,
        description = "Email verification required",
        content_type = "application/problem+json"
    )]
    EmailNotVerified(Problem),
    #[response(
        status = 409,
        description = "Conflict",
        content_type = "application/problem+json"
    )]
    Conflict(Problem),
    #[response(
        status = 503,
        description = "Service unavailable",
        content_type = "application/problem+json"
    )]
    Unavailable(Problem),
}

/// `POST` under a parent, and `PATCH`: the target or parent can be missing and names can conflict.
#[derive(Debug, IntoResponses)]
#[allow(dead_code)] // OpenAPI description only; never constructed.
pub enum WriteErrors {
    #[response(
        status = 400,
        description = "Invalid request",
        content_type = "application/problem+json"
    )]
    Invalid(Problem),
    #[response(
        status = 401,
        description = "Missing or invalid org binding",
        content_type = "application/problem+json"
    )]
    Unauthenticated(Problem),
    #[response(
        status = 403,
        description = "Email verification required",
        content_type = "application/problem+json"
    )]
    EmailNotVerified(Problem),
    #[response(
        status = 404,
        description = "Not found",
        content_type = "application/problem+json"
    )]
    NotFound(Problem),
    #[response(
        status = 409,
        description = "Conflict",
        content_type = "application/problem+json"
    )]
    Conflict(Problem),
    #[response(
        status = 503,
        description = "Service unavailable",
        content_type = "application/problem+json"
    )]
    Unavailable(Problem),
}

/// `DELETE`: `409` while children still reference the resource.
#[derive(Debug, IntoResponses)]
#[allow(dead_code)] // OpenAPI description only; never constructed.
pub enum DeleteErrors {
    #[response(
        status = 401,
        description = "Missing or invalid org binding",
        content_type = "application/problem+json"
    )]
    Unauthenticated(Problem),
    #[response(
        status = 403,
        description = "Email verification required",
        content_type = "application/problem+json"
    )]
    EmailNotVerified(Problem),
    #[response(
        status = 404,
        description = "Not found",
        content_type = "application/problem+json"
    )]
    NotFound(Problem),
    #[response(
        status = 409,
        description = "Conflict",
        content_type = "application/problem+json"
    )]
    Conflict(Problem),
    #[response(
        status = 503,
        description = "Service unavailable",
        content_type = "application/problem+json"
    )]
    Unavailable(Problem),
}

/// Dev-only org create: there is no org yet, so no `404`, and names are not unique.
#[derive(Debug, IntoResponses)]
#[allow(dead_code)] // OpenAPI description only; never constructed.
pub enum DevCreateErrors {
    #[response(
        status = 400,
        description = "Invalid request",
        content_type = "application/problem+json"
    )]
    Invalid(Problem),
    #[response(
        status = 401,
        description = "Missing or invalid org binding",
        content_type = "application/problem+json"
    )]
    Unauthenticated(Problem),
    #[response(
        status = 403,
        description = "Email verification required",
        content_type = "application/problem+json"
    )]
    EmailNotVerified(Problem),
    #[response(
        status = 503,
        description = "Service unavailable",
        content_type = "application/problem+json"
    )]
    Unavailable(Problem),
}

/// `POST` of a secret version: a raw value body that is size and media-type checked, and a key
/// service that can be down.
#[derive(Debug, IntoResponses)]
#[allow(dead_code)] // OpenAPI description only; never constructed.
pub enum VersionWriteErrors {
    #[response(
        status = 400,
        description = "Invalid request",
        content_type = "application/problem+json"
    )]
    Invalid(Problem),
    #[response(
        status = 401,
        description = "Missing or invalid org binding",
        content_type = "application/problem+json"
    )]
    Unauthenticated(Problem),
    #[response(
        status = 403,
        description = "Email verification required",
        content_type = "application/problem+json"
    )]
    EmailNotVerified(Problem),
    #[response(
        status = 404,
        description = "Not found",
        content_type = "application/problem+json"
    )]
    NotFound(Problem),
    #[response(
        status = 413,
        description = "Request body too large",
        content_type = "application/problem+json"
    )]
    TooLarge(Problem),
    #[response(
        status = 415,
        description = "Unsupported media type",
        content_type = "application/problem+json"
    )]
    UnsupportedMediaType(Problem),
    #[response(
        status = 503,
        description = "Service or key service unavailable",
        content_type = "application/problem+json"
    )]
    Unavailable(Problem),
}

/// Internal (service-token) `GET` of one resource.
#[derive(Debug, IntoResponses)]
#[allow(dead_code)] // OpenAPI description only; never constructed.
pub enum InternalReadErrors {
    #[response(
        status = 401,
        description = "Missing or invalid service token or org header",
        content_type = "application/problem+json"
    )]
    Unauthenticated(Problem),
    #[response(
        status = 403,
        description = "Email verification required",
        content_type = "application/problem+json"
    )]
    EmailNotVerified(Problem),
    #[response(
        status = 404,
        description = "Not found (including another org's secret)",
        content_type = "application/problem+json"
    )]
    NotFound(Problem),
    #[response(
        status = 503,
        description = "Service unavailable",
        content_type = "application/problem+json"
    )]
    Unavailable(Problem),
}

/// Internal (service-token) `POST` of a JSON body.
#[derive(Debug, IntoResponses)]
#[allow(dead_code)] // OpenAPI description only; never constructed.
pub enum InternalWriteErrors {
    #[response(
        status = 400,
        description = "Invalid request",
        content_type = "application/problem+json"
    )]
    Invalid(Problem),
    #[response(
        status = 401,
        description = "Missing or invalid service token or org header",
        content_type = "application/problem+json"
    )]
    Unauthenticated(Problem),
    #[response(
        status = 403,
        description = "Email verification required",
        content_type = "application/problem+json"
    )]
    EmailNotVerified(Problem),
    #[response(
        status = 413,
        description = "Request body too large",
        content_type = "application/problem+json"
    )]
    TooLarge(Problem),
    #[response(
        status = 415,
        description = "Unsupported media type",
        content_type = "application/problem+json"
    )]
    UnsupportedMediaType(Problem),
    #[response(
        status = 503,
        description = "Service unavailable",
        content_type = "application/problem+json"
    )]
    Unavailable(Problem),
}

/// `POST /v1/agent-tokens`: a credential in the body, so `401` for any bad, unknown or replaced
/// enrollment secret, and `503` when no signing key is configured.
#[derive(Debug, IntoResponses)]
#[allow(dead_code)] // OpenAPI description only; never constructed.
pub enum TokenErrors {
    #[response(
        status = 400,
        description = "Invalid request",
        content_type = "application/problem+json"
    )]
    Invalid(Problem),
    #[response(
        status = 401,
        description = "Invalid, unknown or replaced enrollment secret",
        content_type = "application/problem+json"
    )]
    Unauthenticated(Problem),
    #[response(
        status = 403,
        description = "Email verification required",
        content_type = "application/problem+json"
    )]
    EmailNotVerified(Problem),
    #[response(
        status = 413,
        description = "Request body too large",
        content_type = "application/problem+json"
    )]
    TooLarge(Problem),
    #[response(
        status = 415,
        description = "Unsupported media type",
        content_type = "application/problem+json"
    )]
    UnsupportedMediaType(Problem),
    #[response(
        status = 503,
        description = "Service unavailable or token signing not configured",
        content_type = "application/problem+json"
    )]
    Unavailable(Problem),
}

/// Org, member and invite routes (T6): every failure the contract allows. `404` is uniform
/// (non-member, wrong org, bad invite token), `409` is the last-owner and non-empty-org rule.
#[derive(Debug, IntoResponses)]
#[allow(dead_code)] // OpenAPI description only; never constructed.
pub enum MemberErrors {
    #[response(
        status = 400,
        description = "Invalid request",
        content_type = "application/problem+json"
    )]
    Invalid(Problem),
    #[response(
        status = 401,
        description = "Missing or invalid org binding",
        content_type = "application/problem+json"
    )]
    Unauthenticated(Problem),
    #[response(
        status = 403,
        description = "Email verification required, or the caller's role does not allow this",
        content_type = "application/problem+json"
    )]
    EmailNotVerified(Problem),
    #[response(
        status = 404,
        description = "Not found (also: not a member, or an invalid invite)",
        content_type = "application/problem+json"
    )]
    NotFound(Problem),
    #[response(
        status = 409,
        description = "Conflict (last owner, or org still has secrets)",
        content_type = "application/problem+json"
    )]
    Conflict(Problem),
    #[response(
        status = 501,
        description = "Not implemented yet",
        content_type = "application/problem+json"
    )]
    NotImplemented(Problem),
    #[response(
        status = 503,
        description = "Service unavailable",
        content_type = "application/problem+json"
    )]
    Unavailable(Problem),
}
