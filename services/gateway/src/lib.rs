//! Locksmith gateway: the service that holds the decrypt capability and relays HTTP calls with
//! a secret injected, so the caller never holds the value (S3).
//!
//! Modules: [`config`], [`decrypt`] (material fetch, DEK unwrap and cache, open), [`egress`]
//! (host allowlist, address guard, pinned client), [`app`] (the router).

pub mod app;
pub mod config;
pub mod decrypt;
pub mod egress;
pub mod http_client;
