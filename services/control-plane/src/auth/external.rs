//! Verification of external workload identity tokens (D4 design decisions 3, 5, 6, 7).
//!
//! A GitHub Actions or Kubernetes OIDC JWT is accepted for a policy only when:
//!
//! - its header names an allowed asymmetric algorithm (RS256 or ES256: no `none`, no HS*) and a
//!   `kid`, and the key published under that `kid` by the *policy's* issuer has that same
//!   algorithm (one rate-limited JWKS refresh for an unknown `kid`). `jku`, `x5u` and `x5c`
//!   headers are ignored;
//! - the signature verifies, `iss` equals the stored issuer, `aud` contains the policy audience,
//!   `exp` and `nbf` hold with [`LEEWAY_SECS`] of skew, and `exp - iat` is at most the configured
//!   maximum lifetime.
//!
//! The token lives in [`ExternalToken`] (no `Debug`, `Display`, `Clone` or `Serialize`). Every
//! failure is the same opaque [`Refused`] with a static reason label for the span; no token text
//! reaches an error, log or span.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, Validation};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use tracing::Instrument as _;

use super::human::Refused;
use super::issuers::IssuerRegistry;

/// Clock skew tolerated on `exp`, `nbf` and `iat`.
pub const LEEWAY_SECS: u64 = 60;
/// Longest external token examined; anything larger is refused before parsing.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;
/// Default maximum `exp - iat` (D4 decision 6): GitHub issues about 10 minutes, projected
/// Kubernetes tokens at least 10 minutes.
pub const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(3600);
/// Algorithms an external token may use. The key decides which one applies.
const ALLOWED: [Algorithm; 2] = [Algorithm::RS256, Algorithm::ES256];

/// A presented external JWT. Deliberately has no `Debug`, `Display`, `Clone` or `Serialize`:
/// it is read once, verified and dropped (zeroized by `SecretString`).
pub struct ExternalToken(SecretString);

impl ExternalToken {
    pub fn new(token: SecretString) -> Self {
        Self(token)
    }

    fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl From<String> for ExternalToken {
    fn from(s: String) -> Self {
        Self(SecretString::from(s))
    }
}

impl<'de> Deserialize<'de> for ExternalToken {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Mismatched types are reported by serde without echoing the value.
        String::deserialize(d).map(Self::from)
    }
}

/// What a policy pins for verification: the stored issuer URL and audience.
#[derive(Debug, Clone, Copy)]
pub struct TrustAnchor<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
}

/// The verified claim set of an external token. Contains no token text; it may hold identifying
/// claims (repository, actor), so callers copy out only the claims a policy names.
pub struct ExternalClaims(pub Map<String, Value>);

impl ExternalClaims {
    pub fn as_value(&self) -> Value {
        Value::Object(self.0.clone())
    }
}

#[derive(Deserialize)]
struct Unverified {
    iss: Option<String>,
}

/// Verifies external tokens against per-issuer keys from an [`IssuerRegistry`].
pub struct ExternalVerifier {
    issuers: IssuerRegistry,
    max_lifetime: Duration,
}

impl ExternalVerifier {
    pub fn new(issuers: IssuerRegistry, max_lifetime: Duration) -> Self {
        Self {
            issuers,
            max_lifetime,
        }
    }

    pub fn issuers(&self) -> &IssuerRegistry {
        &self.issuers
    }

    /// Verify `token` for the policy anchored at `anchor`. Runs in a `verify_external_jwt` span
    /// carrying the stored issuer, the outcome and, on refusal, a static reason.
    pub async fn verify_external(
        &self,
        token: &ExternalToken,
        anchor: TrustAnchor<'_>,
    ) -> Result<ExternalClaims, Refused> {
        let span = tracing::info_span!(
            "verify_external_jwt",
            issuer = %anchor.issuer,
            outcome = tracing::field::Empty,
            reason = tracing::field::Empty,
        );
        let result = self
            .verify_inner(token.expose(), anchor)
            .instrument(span.clone())
            .await;
        match &result {
            Ok(_) => span.record("outcome", "ok"),
            Err(Refused(reason)) => span.record("outcome", "rejected").record("reason", *reason),
        };
        result
    }

    async fn verify_inner(
        &self,
        token: &str,
        anchor: TrustAnchor<'_>,
    ) -> Result<ExternalClaims, Refused> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(Refused("too_large"));
        }
        // `Algorithm` has no `none` and no unknown values: a header naming either fails here.
        let header = jsonwebtoken::decode_header(token).map_err(|_| Refused("malformed"))?;
        if !ALLOWED.contains(&header.alg) {
            return Err(Refused("algorithm"));
        }
        let kid = header.kid.as_deref().ok_or(Refused("no_kid"))?;
        // A token naming another issuer is refused before any outbound request. The signed `iss`
        // is checked again below; this only spares the issuer a fetch for an obvious mismatch.
        if unverified_issuer(token).as_deref() != Some(anchor.issuer) {
            return Err(Refused("issuer"));
        }
        let key = self
            .issuers
            .key(anchor.issuer, kid)
            .await
            .map_err(|e| Refused(e.label()))?
            .ok_or(Refused("unknown_key"))?;
        // The key, not the token, fixes the algorithm: a token cannot pick another one.
        if key.alg != header.alg {
            return Err(Refused("algorithm"));
        }

        let mut validation = Validation::new(key.alg);
        validation.set_issuer(&[anchor.issuer]);
        validation.set_audience(&[anchor.audience]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
        validation.leeway = LEEWAY_SECS;
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let data = jsonwebtoken::decode::<Map<String, Value>>(token, &key.key, &validation)
            .map_err(|_| Refused("invalid"))?;
        let claims = data.claims;
        check_lifetime(&claims, self.max_lifetime)?;
        if claims
            .get("sub")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(Refused("invalid"));
        }
        Ok(ExternalClaims(claims))
    }
}

/// `iat` present, not in the future beyond the leeway, and `exp - iat` within `max`.
fn check_lifetime(claims: &Map<String, Value>, max: Duration) -> Result<(), Refused> {
    let iat = claims
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(Refused("invalid"))?;
    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or(Refused("invalid"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if iat > now.saturating_add(LEEWAY_SECS) || exp < iat {
        return Err(Refused("invalid"));
    }
    if exp - iat > max.as_secs() {
        return Err(Refused("lifetime"));
    }
    Ok(())
}

/// The `iss` of an unverified token, for routing checks only.
fn unverified_issuer(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice::<Unverified>(&bytes).ok()?.iss
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn workload_verify_lifetime_cap_and_iat_checks() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let c = |iat: u64, exp: u64| json!({"iat": iat, "exp": exp}).as_object().unwrap().clone();
        let hour = Duration::from_secs(3600);
        assert!(check_lifetime(&c(now, now + 600), hour).is_ok());
        assert!(check_lifetime(&c(now, now + 3600), hour).is_ok());
        assert_eq!(
            check_lifetime(&c(now, now + 3601), hour),
            Err(Refused("lifetime"))
        );
        assert_eq!(
            check_lifetime(&c(now + 600, now + 900), hour),
            Err(Refused("invalid"))
        );
        assert_eq!(
            check_lifetime(&c(now, now - 1), hour),
            Err(Refused("invalid"))
        );
        let no_iat = json!({"exp": now + 60}).as_object().unwrap().clone();
        assert_eq!(check_lifetime(&no_iat, hour), Err(Refused("invalid")));
    }

    #[test]
    fn workload_verify_external_token_deserializes_without_echoing() {
        let t: ExternalToken = serde_json::from_str(r#""abc.def.ghi""#).unwrap();
        assert_eq!(t.expose(), "abc.def.ghi");
        let err = serde_json::from_str::<ExternalToken>(r#"{"t": "canary-value"}"#)
            .err()
            .unwrap();
        assert!(!err.to_string().contains("canary-value"));
    }

    #[test]
    fn workload_verify_unverified_issuer_reads_the_payload_only() {
        let enc = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
        let t = format!(
            "{}.{}.sig",
            enc(&json!({"alg": "ES256"})),
            enc(&json!({"iss": "https://a"}))
        );
        assert_eq!(unverified_issuer(&t).as_deref(), Some("https://a"));
        assert_eq!(unverified_issuer("junk"), None);
    }
}
