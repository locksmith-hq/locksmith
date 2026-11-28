//! What an organization may use: its plan, paid features and limits.
//!
//! This crate is the seam between the open-source core and paid code, which is not in this repository. The
//! core asks an [`EntitlementSource`]; with no license the answer is [`FreeTier`]. A paid source
//! in the private repository implements the same trait. Nothing in this repository depends on paid code.
//!
//! Rule (AGENTS.md): licensing never blocks unlock or export. [`Entitlements::allows`] makes that
//! structural: core operations are not features, so no plan can gate them.

use std::collections::BTreeSet;
use std::fmt;

/// A paid capability. Add a variant only together with the code that checks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    SamlSso,
    Scim,
    SecretRotation,
    DynamicSecrets,
    AuditStreaming,
    SubOrganizations,
}

impl Feature {
    pub const ALL: [Feature; 6] = [
        Feature::SamlSso,
        Feature::Scim,
        Feature::SecretRotation,
        Feature::DynamicSecrets,
        Feature::AuditStreaming,
        Feature::SubOrganizations,
    ];

    /// Stable wire name, used in license files and error messages.
    pub fn key(self) -> &'static str {
        match self {
            Feature::SamlSso => "saml_sso",
            Feature::Scim => "scim",
            Feature::SecretRotation => "secret_rotation",
            Feature::DynamicSecrets => "dynamic_secrets",
            Feature::AuditStreaming => "audit_streaming",
            Feature::SubOrganizations => "sub_organizations",
        }
    }

    pub fn from_key(key: &str) -> Option<Feature> {
        Feature::ALL.into_iter().find(|f| f.key() == key)
    }
}

/// Core operations. Deliberately separate from [`Feature`]: they cannot be gated by a plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreOp {
    Unlock,
    Export,
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    Free,
    Enterprise,
}

/// Caps on an organization. `None` is unlimited. The free tier has no caps yet: the owner sets
/// them when the first paid plan ships.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    pub members: Option<u32>,
    pub identities: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entitlements {
    plan: Plan,
    features: BTreeSet<Feature>,
    limits: Limits,
}

/// The feature is not part of the organization's plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotEntitled(pub Feature);

impl fmt::Display for NotEntitled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is not included in this plan", self.0.key())
    }
}

impl std::error::Error for NotEntitled {}

impl Entitlements {
    /// No license: no paid features, no caps.
    pub fn free() -> Self {
        Entitlements {
            plan: Plan::Free,
            features: BTreeSet::new(),
            limits: Limits::default(),
        }
    }

    pub fn enterprise(features: impl IntoIterator<Item = Feature>, limits: Limits) -> Self {
        Entitlements {
            plan: Plan::Enterprise,
            features: features.into_iter().collect(),
            limits,
        }
    }

    pub fn plan(&self) -> Plan {
        self.plan
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub fn has(&self, feature: Feature) -> bool {
        self.features.contains(&feature)
    }

    /// Call at the top of a paid code path.
    pub fn require(&self, feature: Feature) -> Result<(), NotEntitled> {
        if self.has(feature) {
            Ok(())
        } else {
            Err(NotEntitled(feature))
        }
    }

    /// Core operations are always allowed, whatever the plan (including a lapsed license).
    pub fn allows(&self, _op: CoreOp) -> bool {
        true
    }
}

/// Where an organization's entitlements come from.
pub trait EntitlementSource: Send + Sync {
    /// Never fails: a source that cannot answer returns [`Entitlements::free`].
    fn entitlements(&self, org: &str) -> Entitlements;
}

/// The open-source default.
#[derive(Clone, Copy, Debug, Default)]
pub struct FreeTier;

impl EntitlementSource for FreeTier {
    fn entitlements(&self, _org: &str) -> Entitlements {
        Entitlements::free()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_has_no_paid_feature_and_no_caps() {
        let e = FreeTier.entitlements("org");
        assert_eq!(e.plan(), Plan::Free);
        assert_eq!(e.limits(), Limits::default());
        for f in Feature::ALL {
            assert!(!e.has(f));
            assert_eq!(e.require(f), Err(NotEntitled(f)));
        }
    }

    #[test]
    fn enterprise_grants_exactly_what_it_lists() {
        let e = Entitlements::enterprise(
            [Feature::Scim],
            Limits {
                members: Some(50),
                identities: None,
            },
        );
        assert!(e.has(Feature::Scim) && e.require(Feature::Scim).is_ok());
        assert!(!e.has(Feature::SamlSso));
        assert_eq!(e.limits().members, Some(50));
    }

    #[test]
    fn core_operations_are_allowed_on_every_plan() {
        for e in [
            Entitlements::free(),
            Entitlements::enterprise([], Limits::default()),
        ] {
            for op in [CoreOp::Unlock, CoreOp::Export, CoreOp::Read, CoreOp::Write] {
                assert!(e.allows(op));
            }
        }
    }

    #[test]
    fn feature_keys_round_trip_and_are_unique() {
        let mut seen = BTreeSet::new();
        for f in Feature::ALL {
            assert_eq!(Feature::from_key(f.key()), Some(f));
            assert!(seen.insert(f.key()));
        }
        assert_eq!(Feature::from_key("nope"), None);
    }

    #[test]
    fn not_entitled_names_the_feature() {
        assert_eq!(
            NotEntitled(Feature::SamlSso).to_string(),
            "saml_sso is not included in this plan"
        );
    }
}
