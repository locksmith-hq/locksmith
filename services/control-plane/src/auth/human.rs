//! Human access-token verification (T1 design decisions 1 and 8).
//!
//! A bearer token is accepted only when its signature verifies against a key in the issuer's
//! JWKS, with the algorithm fixed by that key's type (RS256 or ES256; never `none`, never
//! HS*), and its `iss`, `aud` and `exp` match. No issuer SDK is involved: the issuer is plain
//! configuration (Cognito, Keycloak or any OIDC provider).
//!
//! Failures are all the same to the caller (`401`, no reason). The reason class is kept only as
//! a static label on the `verify_jwt` span; token text never reaches a log, span or error.

use std::time::Duration;

use serde::Deserialize;
use tracing::Instrument as _;

use super::jwks::{DEFAULT_MAX_AGE, DEFAULT_MIN_REFRESH, JwksCache, JwksError};
use super::jwt;

pub use super::jwt::{LEEWAY_SECS, MAX_TOKEN_BYTES};

/// Issuer settings. Public values only: no secret is involved in verifying a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanAuthConfig {
    /// The `iss` claim every token must carry, compared exactly.
    pub issuer: String,
    /// The `aud` every token must include (the API's client id or resource identifier).
    pub audience: String,
    /// Where the issuer publishes its signing keys.
    pub jwks_url: String,
}

/// The verified identity in a token. `subject` is stable per issuer (OIDC Core 5.7); email is
/// informational and never a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanIdentity {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    /// The OAuth client the token was issued to (`client_id`, else `azp`), when the issuer sets
    /// one. Used by the MCP route to bind a call to an `mcp_clients` row.
    pub client_id: Option<String>,
    /// When the person last signed in at the issuer (`auth_time`, unix seconds), when present.
    /// A refresh keeps it, so a revoke can tell an old grant from a fresh sign-in.
    pub auth_time: Option<i64>,
}

pub use ls_oidc_verify::Refused;

#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    client_id: Option<String>,
    azp: Option<String>,
    auth_time: Option<i64>,
}

/// Verifier for one issuer.
pub struct HumanAuth {
    issuer: String,
    audience: String,
    jwks: JwksCache,
}

impl HumanAuth {
    pub fn new(config: &HumanAuthConfig) -> Result<Self, JwksError> {
        Self::with_refresh(config, DEFAULT_MIN_REFRESH, DEFAULT_MAX_AGE)
    }

    /// As [`Self::new`] with explicit JWKS refresh timing (tests).
    pub fn with_refresh(
        config: &HumanAuthConfig,
        min_refresh: Duration,
        max_age: Duration,
    ) -> Result<Self, JwksError> {
        Ok(Self {
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            jwks: JwksCache::new(config.jwks_url.clone(), min_refresh, max_age)?,
        })
    }

    /// Verify `token`. Runs in a `verify_jwt` span carrying the configured issuer and the outcome.
    pub async fn verify(&self, token: &str) -> Result<HumanIdentity, Refused> {
        let span = tracing::info_span!(
            "verify_jwt",
            issuer = %self.issuer,
            outcome = tracing::field::Empty,
            reason = tracing::field::Empty,
        );
        let result = self.verify_inner(token).instrument(span.clone()).await;
        match &result {
            Ok(_) => span.record("outcome", "ok"),
            Err(Refused(reason)) => span.record("outcome", "rejected").record("reason", *reason),
        };
        result
    }

    async fn verify_inner(&self, token: &str) -> Result<HumanIdentity, Refused> {
        let (header_alg, kid) = jwt::pre_check(token)?;
        let key = self.jwks.key(&kid).await.ok_or(Refused("unknown_key"))?;
        jwt::pin_alg(key.alg, header_alg)?;
        let validation = jwt::validation(
            key.alg,
            &self.issuer,
            &self.audience,
            &["exp", "iss", "aud", "sub"],
        );

        let data = jsonwebtoken::decode::<Claims>(token, &key.key, &validation)
            .map_err(|_| Refused("invalid"))?;
        let c = data.claims;
        if c.sub.is_empty() {
            return Err(Refused("invalid"));
        }
        Ok(HumanIdentity {
            issuer: c.iss,
            subject: c.sub,
            email: c.email,
            email_verified: c.email_verified.unwrap_or(false),
            client_id: c
                .client_id
                .or(c.azp)
                .map(|id| id.trim().to_owned())
                .filter(|id| !id.is_empty()),
            auth_time: c.auth_time,
        })
    }
}
