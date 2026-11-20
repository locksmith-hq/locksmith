//! Locksmith gateway: the service that holds the decrypt capability and relays HTTP calls with
//! a secret injected, so the caller never holds the value (S3).
//!
//! Modules: [`config`], [`auth`] (agent tokens verified through the control plane's JWKS),
//! [`grants`] (`GET /v1/grants`), [`decrypt`] (material fetch, DEK unwrap and cache, open), [`egress`]
//! (host allowlist, address guard, pinned client), [`relay`] (`POST /v1/relay`: inject, call,
//! redact), [`aws`] (`POST /v1/aws/credentials`: short-lived STS credentials, D2), [`audit`] (relay events in the org's audit ledger), [`app`] (the router).

pub mod app;
pub mod audit;
pub mod auth;
pub mod aws;
pub mod aws_policy;
pub mod config;
pub mod decrypt;
pub mod egress;
pub mod git;
pub mod grants;
pub mod http_client;
pub mod relay;
