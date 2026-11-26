//! Verification of external OIDC tokens: JWT pre-checks, the issuer JWKS cache with its guarded
//! fetcher, external workload-token verification, abuse limits and workload policy parsing.
//!
//! Shared by the control plane and the core service (B2 task 3.2), moved from
//! `services/control-plane` with no behaviour change.

pub mod abuse;
pub mod external;
pub mod issuers;
pub mod jwks;
pub mod jwt;
pub mod workload;

/// A refused token. Deliberately opaque: the only content is a static label for traces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused(pub &'static str);
