//! Locksmith core service (change b2-rust-core): the internal Rust service the NestJS API
//! calls for audit, token, enrollment-secret and DEK operations. Never exposed publicly and never
//! returns plaintext vault secrets or key bytes (the one credential it returns is a new agent
//! enrollment secret, shown once).

pub mod agent_token_api;
pub mod app;
pub mod audit_api;
pub mod audit_event;
pub mod auth;
pub mod checkpoint_api;
pub mod config;
pub mod dek_api;
pub mod enrollment_api;
pub mod telemetry;
pub mod workload_api;
