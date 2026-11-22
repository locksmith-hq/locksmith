//! Locksmith Enterprise License. Source-available: see `ee/LICENSE`.
//!
//! Verifies a signed offline license file into [`Entitlements`]. A license is a JSON body plus a
//! detached minisign signature, checked against the license-signing public key that the operator
//! of the deployment supplies. Any problem (bad signature, expired, unreadable, unknown plan)
//! yields the free tier, never an error that stops the server: licensing must not block unlock or
//! export, so the worst outcome of a bad license is losing paid features.

use ls_entitlements::{EntitlementSource, Entitlements, Feature, Limits};
use serde::Deserialize;

#[derive(Debug, PartialEq, Eq)]
pub enum LicenseError {
    BadSignature,
    Malformed,
    Expired,
    UnknownPlan,
}

#[derive(Deserialize)]
struct Body {
    plan: String,
    /// Unix seconds; the license stops granting features after this.
    expires: u64,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    members: Option<u32>,
    #[serde(default)]
    identities: Option<u32>,
}

/// Check `signature` over `body` with the minisign public key `pubkey_b64`, then read the plan.
pub fn verify(
    pubkey_b64: &str,
    body: &[u8],
    signature: &str,
    now_unix: u64,
) -> Result<Entitlements, LicenseError> {
    let pk = minisign_verify::PublicKey::from_base64(pubkey_b64.trim())
        .map_err(|_| LicenseError::BadSignature)?;
    let sig =
        minisign_verify::Signature::decode(signature).map_err(|_| LicenseError::BadSignature)?;
    pk.verify(body, &sig, false)
        .map_err(|_| LicenseError::BadSignature)?;
    let b: Body = serde_json::from_slice(body).map_err(|_| LicenseError::Malformed)?;
    if now_unix >= b.expires {
        return Err(LicenseError::Expired);
    }
    if b.plan != "enterprise" {
        return Err(LicenseError::UnknownPlan);
    }
    // Unknown feature names are ignored: a newer license still works on an older server.
    let features = b.features.iter().filter_map(|k| Feature::from_key(k));
    Ok(Entitlements::enterprise(
        features,
        Limits {
            members: b.members,
            identities: b.identities,
        },
    ))
}

/// Entitlements for a deployment: the verified license, or the free tier.
pub struct LicenseSource {
    verified: Option<Entitlements>,
    /// Why the license was not applied, for the operator's log. `None` when applied or absent.
    pub rejected: Option<LicenseError>,
}

impl LicenseSource {
    /// `license` is `(body, signature)` when the operator supplied one.
    pub fn load(pubkey_b64: &str, license: Option<(&[u8], &str)>, now_unix: u64) -> Self {
        match license.map(|(body, sig)| verify(pubkey_b64, body, sig, now_unix)) {
            Some(Ok(e)) => LicenseSource {
                verified: Some(e),
                rejected: None,
            },
            Some(Err(why)) => LicenseSource {
                verified: None,
                rejected: Some(why),
            },
            None => LicenseSource {
                verified: None,
                rejected: None,
            },
        }
    }
}

impl EntitlementSource for LicenseSource {
    fn entitlements(&self, _org: &str) -> Entitlements {
        self.verified.clone().unwrap_or_else(Entitlements::free)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ls_entitlements::{CoreOp, Plan};

    fn sign(kp: &minisign::KeyPair, body: &[u8]) -> String {
        minisign::sign(Some(&kp.pk), &kp.sk, std::io::Cursor::new(body), None, None)
            .unwrap()
            .to_string()
    }

    const NOW: u64 = 1_800_000_000;
    fn body(extra: &str) -> Vec<u8> {
        format!(r#"{{"plan":"enterprise","expires":{},"features":["scim","from_the_future"],"members":25{extra}}}"#, NOW + 100).into_bytes()
    }

    #[test]
    fn valid_license_grants_its_features_and_ignores_unknown_ones() {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let b = body("");
        let src = LicenseSource::load(&kp.pk.to_base64(), Some((&b, &sign(&kp, &b))), NOW);
        let e = src.entitlements("org");
        assert_eq!(e.plan(), Plan::Enterprise);
        assert!(e.has(Feature::Scim) && !e.has(Feature::SamlSso));
        assert_eq!(e.limits().members, Some(25));
        assert!(src.rejected.is_none());
    }

    #[test]
    fn tampered_body_wrong_key_and_garbage_fall_back_to_free() {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let other = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let b = body("");
        let sig = sign(&kp, &b);
        let tampered = body(r#","features":["saml_sso"]"#);
        for (pk, data, s) in [
            (kp.pk.to_base64(), tampered, sig.clone()),
            (other.pk.to_base64(), b.clone(), sig.clone()),
            (kp.pk.to_base64(), b.clone(), "not a signature".to_string()),
            ("not a key".to_string(), b.clone(), sig.clone()),
        ] {
            let src = LicenseSource::load(&pk, Some((&data, &s)), NOW);
            assert_eq!(src.rejected, Some(LicenseError::BadSignature));
            assert_eq!(src.entitlements("org"), Entitlements::free());
        }
    }

    #[test]
    fn expired_malformed_and_unknown_plan_are_rejected_for_their_reason() {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let pk = kp.pk.to_base64();
        let expired = br#"{"plan":"enterprise","expires":10}"#.to_vec();
        let junk = b"{not json".to_vec();
        let other = format!(r#"{{"plan":"gold","expires":{}}}"#, NOW + 1).into_bytes();
        for (data, why) in [
            (expired, LicenseError::Expired),
            (junk, LicenseError::Malformed),
            (other, LicenseError::UnknownPlan),
        ] {
            assert_eq!(verify(&pk, &data, &sign(&kp, &data), NOW), Err(why));
        }
    }

    #[test]
    fn no_license_is_free_without_a_complaint() {
        let src = LicenseSource::load("irrelevant", None, NOW);
        assert!(src.rejected.is_none());
        assert_eq!(src.entitlements("org"), Entitlements::free());
    }

    #[test]
    fn a_lapsed_license_never_blocks_core_operations() {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let b = br#"{"plan":"enterprise","expires":1}"#.to_vec();
        let src = LicenseSource::load(&kp.pk.to_base64(), Some((&b, &sign(&kp, &b))), NOW);
        let e = src.entitlements("org");
        assert_eq!(src.rejected, Some(LicenseError::Expired));
        for op in [CoreOp::Unlock, CoreOp::Export, CoreOp::Read, CoreOp::Write] {
            assert!(e.allows(op));
        }
    }
}
