//! Locksmith gateway: the service that holds the decrypt capability and relays HTTP calls with
//! a secret injected, so the caller never holds the value (S3).
//!
//! This is the skeleton (task 2): configuration, health and the router. The relay, decrypt and
//! redaction paths arrive in task 3.

pub mod app;
pub mod config;
