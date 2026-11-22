//! Pre-decode rules shared by the human ([`super::human`]) and external workload
//! ([`super::external`]) token verifiers (refactor-cp-auth-shared design decisions 1 and 2).
//!
//! Each verifier keeps its own key source, required claims and post-checks; only the security
//! rules that must never drift apart live here. Failure labels are the static strings the
//! verifiers always used (`too_large`, `malformed`, `algorithm`, `no_kid`). No token text is
//! ever placed in an error.

use jsonwebtoken::{Algorithm, Validation};

use super::human::Refused;

/// Clock skew tolerated on `exp`, `nbf` (and `iat` for workload tokens).
pub const LEEWAY_SECS: u64 = 60;
/// Longest bearer token examined; anything larger is refused before parsing.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;
/// Algorithms a token may use. The key decides which one applies to it.
pub const ALLOWED: [Algorithm; 2] = [Algorithm::RS256, Algorithm::ES256];

/// Size, header parse, allowed algorithm and `kid`, in that order. Returns the header's
/// algorithm and `kid`.
pub fn pre_check(token: &str) -> Result<(Algorithm, String), Refused> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(Refused("too_large"));
    }
    // `Algorithm` has no `none` and no unknown values: a header naming either fails here.
    let header = jsonwebtoken::decode_header(token).map_err(|_| Refused("malformed"))?;
    if !ALLOWED.contains(&header.alg) {
        return Err(Refused("algorithm"));
    }
    let kid = header.kid.ok_or(Refused("no_kid"))?;
    Ok((header.alg, kid))
}

/// The key, not the token, fixes the algorithm: refuse a header algorithm that differs from
/// the verification key's.
pub fn pin_alg(key_alg: Algorithm, header_alg: Algorithm) -> Result<(), Refused> {
    if key_alg == header_alg {
        Ok(())
    } else {
        Err(Refused("algorithm"))
    }
}

/// Validation for `alg` with exact `iss`, `aud`, the given required claims, the shared leeway
/// and `exp`/`nbf` checks on.
pub fn validation(alg: Algorithm, issuer: &str, audience: &str, required: &[&str]) -> Validation {
    let mut v = Validation::new(alg);
    v.set_issuer(&[issuer]);
    v.set_audience(&[audience]);
    v.set_required_spec_claims(required);
    v.leeway = LEEWAY_SECS;
    v.validate_exp = true;
    v.validate_nbf = true;
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

    fn token(header: &str) -> String {
        format!("{}.{}.sig", B64.encode(header), B64.encode("{}"))
    }

    #[test]
    fn jwt_pre_check_oversized() {
        let t = "a".repeat(MAX_TOKEN_BYTES + 1);
        assert_eq!(pre_check(&t), Err(Refused("too_large")));
    }

    #[test]
    fn jwt_pre_check_malformed() {
        assert_eq!(pre_check("not-a-jwt"), Err(Refused("malformed")));
    }

    #[test]
    fn jwt_pre_check_refuses_none_and_hs256() {
        for h in [r#"{"alg":"none","kid":"k"}"#, r#"{"alg":"HS256","kid":"k"}"#] {
            let r = pre_check(&token(h));
            // `none` does not parse at all; HS256 parses and is not allowed.
            assert!(matches!(r, Err(Refused("malformed" | "algorithm"))), "{h}");
        }
        assert_eq!(
            pre_check(&token(r#"{"alg":"HS256","kid":"k"}"#)),
            Err(Refused("algorithm"))
        );
    }

    #[test]
    fn jwt_pre_check_missing_kid() {
        assert_eq!(
            pre_check(&token(r#"{"alg":"RS256"}"#)),
            Err(Refused("no_kid"))
        );
    }

    #[test]
    fn jwt_pre_check_accepts_allowed_alg_with_kid() {
        assert_eq!(
            pre_check(&token(r#"{"alg":"ES256","kid":"k1"}"#)),
            Ok((Algorithm::ES256, "k1".to_string()))
        );
    }

    #[test]
    fn jwt_pin_alg_mismatch() {
        assert_eq!(
            pin_alg(Algorithm::RS256, Algorithm::ES256),
            Err(Refused("algorithm"))
        );
        assert_eq!(pin_alg(Algorithm::ES256, Algorithm::ES256), Ok(()));
    }
}
