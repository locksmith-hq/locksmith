//! Workload identity trust policies (D4 design decisions 2, 3, 4).
//!
//! Pure functions only: create-time validation of a policy, the claim matcher, and the
//! `lsw_` routing handle. Nothing here holds a secret; the handle carries ids, like `lse_`.
//!
//! Handle format: `lsw_` + base64url (no padding) of `org_id(16) || policy_id(16)`. The ids
//! are routing data so the exchange endpoint can open the org under row-level security and
//! load exactly one policy before it looks at the external token.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub const HANDLE_PREFIX: &str = "lsw_";
/// The only issuer a `github` policy can name.
pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
const MAX_CONDITIONS: usize = 16;
const MAX_VALUE_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IssuerKind {
    Github,
    Oidc,
}

impl IssuerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Oidc => "oidc",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "github" => Some(Self::Github),
            "oidc" => Some(Self::Oidc),
            _ => None,
        }
    }

    /// The claim that must be pinned by an `eq` or `prefix` condition.
    fn subject_claims(self) -> &'static [&'static str] {
        match self {
            Self::Github => &["repository", "sub"],
            Self::Oidc => &["sub"],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    /// The claim equals the value.
    Eq,
    /// The claim starts with the value (an `eq`-style pattern with one trailing `*`).
    Prefix,
}

/// One claim test. Conditions are ANDed; a missing claim fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    pub claim: String,
    pub op: Op,
    pub value: String,
}

/// Why a policy was refused at create time. Static text, safe to return to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    Name,
    IssuerNotHttps,
    IssuerNotAllowed,
    Audience,
    NoConditions,
    TooManyConditions,
    BadCondition,
    BareWildcard,
    NoSubjectPin,
}

impl PolicyError {
    pub fn detail(self) -> &'static str {
        match self {
            Self::Name => "name must not be empty",
            Self::IssuerNotHttps => {
                "issuer must be an https URL without credentials, query or fragment"
            }
            Self::IssuerNotAllowed => "a github policy can only use the GitHub Actions issuer",
            Self::Audience => "audience is required",
            Self::NoConditions => "at least one condition is required",
            Self::TooManyConditions => "too many conditions",
            Self::BadCondition => {
                "a condition needs a claim name and a value (a trailing * is the only wildcard)"
            }
            Self::BareWildcard => "a bare * is not allowed; pin the claim to a value",
            Self::NoSubjectPin => "a condition must pin the subject (repository or sub)",
        }
    }
}

/// A validated policy ready to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPolicy {
    pub issuer_kind: IssuerKind,
    pub issuer: String,
    pub audience: String,
    pub conditions: Vec<Condition>,
}

/// A condition as sent by the caller: `value` may end in one `*`.
#[derive(Debug, Clone, Deserialize)]
pub struct ConditionInput {
    pub claim: String,
    pub value: String,
}

/// Validate a create request. `issuer` is ignored (fixed) for `github`.
pub fn validate(
    name: &str,
    kind: IssuerKind,
    issuer: Option<&str>,
    audience: &str,
    inputs: &[ConditionInput],
) -> Result<ValidatedPolicy, PolicyError> {
    if name.trim().is_empty() {
        return Err(PolicyError::Name);
    }
    let issuer = match kind {
        IssuerKind::Github => match issuer {
            None => GITHUB_ISSUER.to_owned(),
            Some(i) if i.trim_end_matches('/') == GITHUB_ISSUER => GITHUB_ISSUER.to_owned(),
            Some(_) => return Err(PolicyError::IssuerNotAllowed),
        },
        IssuerKind::Oidc => normalise_issuer(issuer.unwrap_or(""))?,
    };
    if audience.trim().is_empty() {
        return Err(PolicyError::Audience);
    }
    if inputs.is_empty() {
        return Err(PolicyError::NoConditions);
    }
    if inputs.len() > MAX_CONDITIONS {
        return Err(PolicyError::TooManyConditions);
    }
    let mut conditions = Vec::with_capacity(inputs.len());
    for i in inputs {
        conditions.push(parse_condition(i)?);
    }
    let pinned = conditions
        .iter()
        .any(|c| kind.subject_claims().contains(&c.claim.as_str()));
    if !pinned {
        return Err(PolicyError::NoSubjectPin);
    }
    Ok(ValidatedPolicy {
        issuer_kind: kind,
        issuer,
        audience: audience.trim().to_owned(),
        conditions,
    })
}

fn normalise_issuer(raw: &str) -> Result<String, PolicyError> {
    let rest = raw
        .strip_prefix("https://")
        .ok_or(PolicyError::IssuerNotHttps)?;
    let host_part = rest.split('/').next().unwrap_or("");
    if host_part.is_empty()
        || host_part.contains('@')
        || raw.contains('?')
        || raw.contains('#')
        || raw.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(PolicyError::IssuerNotHttps);
    }
    Ok(raw.trim_end_matches('/').to_owned())
}

fn parse_condition(i: &ConditionInput) -> Result<Condition, PolicyError> {
    let claim = i.claim.trim();
    let value = i.value.as_str();
    if claim.is_empty() || value.is_empty() || value.len() > MAX_VALUE_LEN || claim.len() > 64 {
        return Err(PolicyError::BadCondition);
    }
    if value == "*" {
        return Err(PolicyError::BareWildcard);
    }
    let star = value.matches('*').count();
    let (op, v) = match value.strip_suffix('*') {
        Some(prefix) if star == 1 => (Op::Prefix, prefix),
        None if star == 0 => (Op::Eq, value),
        _ => return Err(PolicyError::BadCondition),
    };
    Ok(Condition {
        claim: claim.to_owned(),
        op,
        value: v.to_owned(),
    })
}

/// True when every condition holds on `claims`. A missing or non-string claim fails; an
/// empty condition list never matches (fail closed).
pub fn matches(conditions: &[Condition], claims: &Value) -> bool {
    if conditions.is_empty() {
        return false;
    }
    conditions
        .iter()
        .all(|c| match claims.get(&c.claim).and_then(Value::as_str) {
            Some(actual) => match c.op {
                Op::Eq => actual == c.value,
                // An empty stored prefix would match everything: treat it as no match.
                Op::Prefix => !c.value.is_empty() && actual.starts_with(&c.value),
            },
            None => false,
        })
}

/// The `lsw_` handle for a policy.
pub fn encode_handle(org_id: Uuid, policy_id: Uuid) -> String {
    let mut raw = [0u8; 32];
    raw[..16].copy_from_slice(org_id.as_bytes());
    raw[16..].copy_from_slice(policy_id.as_bytes());
    format!("{HANDLE_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw))
}

/// Parse a handle into `(org_id, policy_id)`; `None` for anything malformed.
pub fn parse_handle(text: &str) -> Option<(Uuid, Uuid)> {
    let raw = URL_SAFE_NO_PAD
        .decode(text.trim().strip_prefix(HANDLE_PREFIX)?)
        .ok()?;
    if raw.len() != 32 {
        return None;
    }
    Some((
        Uuid::from_slice(&raw[..16]).ok()?,
        Uuid::from_slice(&raw[16..]).ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ci(claim: &str, value: &str) -> ConditionInput {
        ConditionInput {
            claim: claim.into(),
            value: value.into(),
        }
    }

    fn gh(inputs: &[ConditionInput]) -> Result<ValidatedPolicy, PolicyError> {
        validate(
            "ci",
            IssuerKind::Github,
            None,
            "https://locksmith.example",
            inputs,
        )
    }

    #[test]
    fn github_policy_pins_repository_and_fixes_issuer() {
        let p = gh(&[ci("repository", "acme/app"), ci("ref", "refs/heads/main")]).unwrap();
        assert_eq!(p.issuer, GITHUB_ISSUER);
        assert_eq!(p.conditions[0].op, Op::Eq);
    }

    #[test]
    fn github_issuer_cannot_be_overridden() {
        let r = validate(
            "ci",
            IssuerKind::Github,
            Some("https://evil.example"),
            "a",
            &[ci("repository", "a/b")],
        );
        assert_eq!(r.unwrap_err(), PolicyError::IssuerNotAllowed);
    }

    #[test]
    fn subject_pin_is_required() {
        assert_eq!(
            gh(&[ci("ref", "refs/heads/main")]).unwrap_err(),
            PolicyError::NoSubjectPin
        );
        assert_eq!(gh(&[]).unwrap_err(), PolicyError::NoConditions);
    }

    #[test]
    fn bare_wildcard_and_inner_wildcards_are_refused() {
        assert_eq!(
            gh(&[ci("repository", "*")]).unwrap_err(),
            PolicyError::BareWildcard
        );
        assert_eq!(
            gh(&[ci("repository", "ac*me/app")]).unwrap_err(),
            PolicyError::BadCondition
        );
        assert_eq!(
            gh(&[ci("repository", "a**")]).unwrap_err(),
            PolicyError::BadCondition
        );
        assert_eq!(
            gh(&[ci("repository", "")]).unwrap_err(),
            PolicyError::BadCondition
        );
    }

    #[test]
    fn trailing_star_becomes_a_prefix_condition() {
        let p = gh(&[ci("repository", "acme/*")]).unwrap();
        assert_eq!(
            p.conditions[0],
            Condition {
                claim: "repository".into(),
                op: Op::Prefix,
                value: "acme/".into()
            }
        );
    }

    #[test]
    fn oidc_issuer_must_be_plain_https() {
        let ok = |i: &str| {
            validate(
                "k",
                IssuerKind::Oidc,
                Some(i),
                "a",
                &[ci("sub", "system:serviceaccount:ns:sa")],
            )
        };
        assert_eq!(
            ok("https://k8s.example/").unwrap().issuer,
            "https://k8s.example"
        );
        for bad in [
            "http://k8s.example",
            "k8s.example",
            "https://",
            "https://u:p@k8s.example",
            "https://k8s.example?x=1",
            "https://k8s.example#f",
            "https://a b",
        ] {
            assert_eq!(ok(bad).unwrap_err(), PolicyError::IssuerNotHttps, "{bad}");
        }
        assert_eq!(
            validate("k", IssuerKind::Oidc, None, "a", &[ci("sub", "x")]).unwrap_err(),
            PolicyError::IssuerNotHttps
        );
    }

    #[test]
    fn oidc_needs_a_sub_pin_not_repository() {
        let r = validate(
            "k",
            IssuerKind::Oidc,
            Some("https://k8s.example"),
            "a",
            &[ci("repository", "a/b")],
        );
        assert_eq!(r.unwrap_err(), PolicyError::NoSubjectPin);
    }

    #[test]
    fn audience_and_name_are_required() {
        assert_eq!(
            validate(
                "ci",
                IssuerKind::Github,
                None,
                " ",
                &[ci("repository", "a/b")]
            )
            .unwrap_err(),
            PolicyError::Audience
        );
        assert_eq!(
            validate(
                " ",
                IssuerKind::Github,
                None,
                "a",
                &[ci("repository", "a/b")]
            )
            .unwrap_err(),
            PolicyError::Name
        );
    }

    #[test]
    fn matcher_uses_and_semantics_and_fails_on_missing_claims() {
        let p = gh(&[ci("repository", "acme/app"), ci("ref", "refs/heads/*")]).unwrap();
        let ok = json!({"repository": "acme/app", "ref": "refs/heads/main", "actor": "x"});
        assert!(matches(&p.conditions, &ok));
        assert!(!matches(&p.conditions, &json!({"repository": "acme/app"})));
        assert!(!matches(
            &p.conditions,
            &json!({"repository": "acme/other", "ref": "refs/heads/main"})
        ));
        assert!(!matches(
            &p.conditions,
            &json!({"repository": "acme/app", "ref": "refs/tags/v1"})
        ));
        assert!(!matches(
            &p.conditions,
            &json!({"repository": ["acme/app"], "ref": "refs/heads/main"})
        ));
        assert!(!matches(&[], &ok));
    }

    #[test]
    fn kubernetes_sub_form_matches_exactly() {
        let p = validate(
            "k",
            IssuerKind::Oidc,
            Some("https://k8s.example"),
            "a",
            &[ci("sub", "system:serviceaccount:prod:deployer")],
        )
        .unwrap();
        assert!(matches(
            &p.conditions,
            &json!({"sub": "system:serviceaccount:prod:deployer"})
        ));
        assert!(!matches(
            &p.conditions,
            &json!({"sub": "system:serviceaccount:prod:deployer2"})
        ));
    }

    #[test]
    fn handle_round_trips_and_rejects_junk() {
        let (o, p) = (Uuid::now_v7(), Uuid::now_v7());
        let h = encode_handle(o, p);
        assert!(h.starts_with(HANDLE_PREFIX));
        assert_eq!(parse_handle(&h), Some((o, p)));
        for bad in ["", "lsw_", "lsw_!!", "lse_AAAA", &h[..h.len() - 2]] {
            assert_eq!(parse_handle(bad), None, "{bad}");
        }
    }
}
