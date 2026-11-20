//! AWS credential vending: binding shape and the session policy rendered from a grant (D2).
//!
//! The agent never supplies a policy. The gateway renders one from the grant's allow-list and
//! hands it to STS `AssumeRole`, so the issued credentials can only narrow the role. The renderer
//! emits compact JSON (moto's IAM mode fails signature checks on spaces) and enforces the STS
//! limit of 2048 packed characters itself, because neither moto nor the call site checks it.

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use serde_json::json;

/// STS rejects an inline session policy over this many characters.
pub const MAX_POLICY_CHARS: usize = 2048;
/// Default and bounds for credential lifetime (STS minimum is 15 minutes).
pub const DEFAULT_DURATION_SECS: u32 = 900;
pub const MIN_DURATION_SECS: u32 = 900;
pub const MAX_DURATION_SECS: u32 = 3600;

/// Actions that mint further credentials; always denied inside the session.
const CREDENTIAL_MINTING: &[&str] = &[
    "sts:AssumeRole",
    "sts:AssumeRoleWithSAML",
    "sts:AssumeRoleWithWebIdentity",
    "sts:AssumeRoot",
    "sts:GetFederationToken",
    "sts:GetSessionToken",
];

/// An AWS binding in the gateway's bindings file (`[[aws_binding]]`). Holds no secret: the base
/// credential is a sealed secret named by `secret_id`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsBinding {
    pub secret_id: uuid::Uuid,
    pub role_arn: String,
    pub region: String,
    #[serde(default)]
    pub external_id: Option<String>,
    /// Off by default: the binding must opt in to vending credentials to the agent (H1-2).
    #[serde(default)]
    pub vend: bool,
    /// Permit an allow-list that grants everything (`*`); otherwise such a grant is refused.
    #[serde(default)]
    pub unrestricted: bool,
    /// Cap on the lifetime of vended credentials, seconds.
    #[serde(default = "default_max_duration")]
    pub max_duration_secs: u32,
}

fn default_max_duration() -> u32 {
    DEFAULT_DURATION_SECS
}

/// The allow-list a `delegate` grant carries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AwsGrantScope {
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    pub max_duration_secs: Option<u32>,
}

/// Why a binding or grant could not produce a session policy. Names only, never values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// No actions, or no resources: nothing to allow.
    Empty,
    /// A grant that allows everything on a binding without `unrestricted`.
    TooBroad,
    /// An action or resource is not a plausible IAM string.
    Invalid,
    /// The rendered policy exceeds [`MAX_POLICY_CHARS`].
    TooLarge,
}

impl PolicyError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty_grant",
            Self::TooBroad => "grant_too_broad",
            Self::Invalid => "invalid_grant",
            Self::TooLarge => "policy_too_large",
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn valid_action(a: &str) -> bool {
    let Some((svc, name)) = a.split_once(':') else {
        return a == "*";
    };
    !svc.is_empty()
        && !name.is_empty()
        && [svc, name].iter().all(|p| {
            p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"*?-_".contains(&b))
        })
}

fn valid_resource(r: &str) -> bool {
    r == "*"
        || (r.starts_with("arn:")
            && r.len() <= 512
            && r.bytes()
                .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\'))
}

/// Render the STS session policy for `scope` under `binding`. Actions and resources only; the
/// result never allows more than `scope` names, and credential-minting actions are denied.
pub fn render_session_policy(
    binding: &AwsBinding,
    scope: &AwsGrantScope,
) -> Result<String, PolicyError> {
    if scope.actions.is_empty() || scope.resources.is_empty() {
        return Err(PolicyError::Empty);
    }
    if !scope.actions.iter().all(|a| valid_action(a))
        || !scope.resources.iter().all(|r| valid_resource(r))
    {
        return Err(PolicyError::Invalid);
    }
    let broad = scope.actions.iter().any(|a| a == "*" || a == "*:*")
        || scope.resources.iter().any(|r| r == "*" || r == "arn:*");
    if broad && !binding.unrestricted {
        return Err(PolicyError::TooBroad);
    }
    // Sorted and de-duplicated: stable output, smaller policy.
    let actions: BTreeSet<&str> = scope.actions.iter().map(String::as_str).collect();
    let resources: BTreeSet<&str> = scope.resources.iter().map(String::as_str).collect();
    let policy = json!({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": actions, "Resource": resources},
            {"Effect": "Deny", "Action": CREDENTIAL_MINTING, "Resource": "*"},
        ]
    })
    .to_string();
    if policy.chars().count() > MAX_POLICY_CHARS {
        return Err(PolicyError::TooLarge);
    }
    Ok(policy)
}

/// Credential lifetime: the request (or the default), clamped to the grant, the binding and the
/// STS bounds.
pub fn clamp_duration(binding: &AwsBinding, scope: &AwsGrantScope, requested: Option<u32>) -> u32 {
    let cap = binding
        .max_duration_secs
        .min(scope.max_duration_secs.unwrap_or(u32::MAX))
        .min(MAX_DURATION_SECS);
    requested
        .unwrap_or(DEFAULT_DURATION_SECS)
        .min(cap)
        .max(MIN_DURATION_SECS)
}

#[cfg(test)]
mod aws_policy_tests {
    use super::*;
    use proptest::prelude::*;

    /// Fixture binding (shape documented in design.md decision 4).
    const FIXTURE: &str = r#"
secret_id = "11111111-1111-4111-8111-111111111111"
role_arn = "arn:aws:iam::123456789012:role/locksmith-agent"
region = "us-east-1"
external_id = "ext-1"
vend = true
max_duration_secs = 1800
"#;

    fn binding(unrestricted: bool) -> AwsBinding {
        let mut b: AwsBinding = toml::from_str(FIXTURE).unwrap();
        b.unrestricted = unrestricted;
        b
    }

    fn scope(actions: &[&str], resources: &[&str]) -> AwsGrantScope {
        AwsGrantScope {
            actions: actions.iter().map(|s| (*s).to_owned()).collect(),
            resources: resources.iter().map(|s| (*s).to_owned()).collect(),
            max_duration_secs: None,
        }
    }

    #[test]
    fn aws_policy_binding_fixture_parses_with_defaults() {
        let b = binding(false);
        assert!(b.vend && !b.unrestricted && b.max_duration_secs == 1800);
        let bad = toml::from_str::<AwsBinding>(&format!("{FIXTURE}\nextra = 1"));
        assert!(bad.is_err(), "unknown fields rejected");
    }

    #[test]
    fn aws_policy_renders_actions_and_resources_only() {
        let s = scope(
            &["s3:GetObject", "s3:ListBucket"],
            &["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
        );
        let p = render_session_policy(&binding(false), &s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&p).unwrap();
        assert_eq!(v["Statement"][0]["Effect"], "Allow");
        assert_eq!(
            v["Statement"][0]["Action"],
            json!(["s3:GetObject", "s3:ListBucket"])
        );
        assert_eq!(v["Statement"][1]["Effect"], "Deny");
        assert!(!p.contains(' '), "compact JSON");
    }

    #[test]
    fn aws_policy_refuses_empty_grants() {
        for s in [
            scope(&[], &["arn:aws:s3:::b"]),
            scope(&["s3:GetObject"], &[]),
        ] {
            assert_eq!(
                render_session_policy(&binding(true), &s),
                Err(PolicyError::Empty)
            );
        }
    }

    #[test]
    fn aws_policy_refuses_broad_unless_unrestricted() {
        for s in [
            scope(&["*"], &["arn:aws:s3:::b"]),
            scope(&["s3:Get*"], &["*"]),
        ] {
            assert_eq!(
                render_session_policy(&binding(false), &s),
                Err(PolicyError::TooBroad)
            );
            assert!(render_session_policy(&binding(true), &s).is_ok());
        }
    }

    #[test]
    fn aws_policy_rejects_malformed_entries() {
        for s in [
            scope(&["s3 GetObject"], &["*"]),
            scope(&["s3:Get\"Object"], &["arn:aws:s3:::b"]),
            scope(&["s3:GetObject"], &["not-an-arn"]),
        ] {
            assert_eq!(
                render_session_policy(&binding(true), &s),
                Err(PolicyError::Invalid)
            );
        }
    }

    #[test]
    fn aws_policy_enforces_size_limit() {
        let many: Vec<String> = (0..200)
            .map(|i| format!("arn:aws:s3:::bucket-{i:04}/*"))
            .collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        let s = scope(&["s3:GetObject"], &refs);
        assert_eq!(
            render_session_policy(&binding(false), &s),
            Err(PolicyError::TooLarge)
        );
    }

    #[test]
    fn aws_policy_clamps_duration() {
        let b = binding(false); // cap 1800
        let mut s = scope(&["s3:GetObject"], &["arn:aws:s3:::b"]);
        assert_eq!(clamp_duration(&b, &s, None), 900);
        assert_eq!(clamp_duration(&b, &s, Some(7200)), 1800);
        assert_eq!(clamp_duration(&b, &s, Some(10)), 900);
        s.max_duration_secs = Some(1000);
        assert_eq!(clamp_duration(&b, &s, Some(3600)), 1000);
    }

    proptest! {
        /// The Allow statement lists exactly the grant's actions and resources: never widened.
        #[test]
        fn aws_policy_never_widens_the_grant(
            actions in proptest::collection::vec("[a-z0-9]{1,8}:[A-Za-z]{1,12}", 1..6),
            names in proptest::collection::vec("[a-z0-9-]{1,12}", 1..4),
        ) {
            let resources: Vec<String> = names.iter().map(|n| format!("arn:aws:s3:::{n}/*")).collect();
            let s = AwsGrantScope { actions: actions.clone(), resources: resources.clone(), max_duration_secs: None };
            let p = render_session_policy(&binding(false), &s).unwrap();
            let v: serde_json::Value = serde_json::from_str(&p).unwrap();
            let got = |k: &str| -> BTreeSet<String> {
                v["Statement"][0][k].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_owned()).collect()
            };
            prop_assert_eq!(got("Action"), actions.into_iter().collect::<BTreeSet<_>>());
            prop_assert_eq!(got("Resource"), resources.into_iter().collect::<BTreeSet<_>>());
            prop_assert_eq!(v["Statement"].as_array().unwrap().len(), 2);
            prop_assert_eq!(v["Statement"][1]["Effect"].as_str(), Some("Deny"));
        }
    }
}
