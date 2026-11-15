//! M7 AWS delegation: a local SigV4 re-signing relay. Agents get per-session dummy credentials;
//! the relay verifies each request's signature with the dummy secret, checks project policy,
//! re-signs with the real credentials (held by the daemon) and forwards to AWS.
//!
//! Modules: `sigv4` (signing and verification, incl. S3 streaming chunks), `model` (vendored
//! operation table: request -> service, action, resource), `policy` (`[aws]` policy evaluation),
//! `relay` (the HTTP server), `sts` (AssumeRole for upstream roles and the contained fallback).

pub mod model;
pub mod policy;
pub mod relay;
pub mod sigv4;
pub mod sts;

use crate::Deny;
use std::net::SocketAddr;
use zeroize::Zeroizing;

/// AWS credentials. No Debug/Clone: the secret parts never leave the daemon/relay.
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Option<Zeroizing<String>>,
}

/// One AWS API call as the relay understood it (after signature verification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// Signing name from the credential scope, e.g. `s3`, `dynamodb`.
    pub service: String,
    pub region: String,
    /// IAM action, e.g. `s3:ListBucket`. `None` when the operation is unknown (denied).
    pub action: Option<String>,
    /// Resource ARN when it can be derived from the request, else `*`.
    pub resource: String,
}

/// What the daemon allows for one dummy access key (looked up per request).
pub struct AwsSession {
    pub lease: String,
    /// The dummy secret the agent was given: used only to verify inbound signatures.
    pub dummy_secret: Zeroizing<String>,
    /// Real credentials for re-signing (long-lived keys or STS from an assumed role).
    pub upstream: Credentials,
    pub policy: policy::Policy,
}

/// Implemented by `locksmithd`.
pub trait AwsAuthority: Send + Sync {
    /// Resolve a dummy access key id for a request from `client` (peer-to-PID and lease checks,
    /// like the Git and HTTP relays). Refusals are audited by the daemon.
    fn session(
        &self,
        access_key_id: &str,
        client: SocketAddr,
        server: SocketAddr,
    ) -> Result<AwsSession, Deny>;

    /// Record the policy decision for `call` (ACCESS when allowed, BLOCKED with `rule` when not).
    fn record(&self, s: &AwsSession, call: &Call, allowed: bool, rule: &str);
}
