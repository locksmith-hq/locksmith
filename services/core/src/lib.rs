//! Locksmith core service (change b2-rust-core): the internal Rust service the NestJS API
//! calls for audit, token and DEK operations. Never exposed publicly and never returns
//! plaintext secrets or key bytes.

pub mod app;
pub mod auth;
pub mod config;
pub mod telemetry;
