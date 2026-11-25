//! Locksmith gateway: the service that holds the decrypt capability and relays HTTP calls with
//! a secret injected, so the caller never holds the value (S3).
//!
//! Modules: [`config`], [`auth`] (agent tokens verified through the control plane's JWKS),
//! [`grants`] (`GET /v1/grants`), [`decrypt`] (material fetch, DEK unwrap and cache, open), [`egress`]
//! (host allowlist, address guard, pinned client), [`relay`] (`POST /v1/relay`: inject, call,
//! redact), [`pg`] (the Postgres listener, D3), [`mcp_endpoint`] (`/mcp`, the agent MCP server), [`oauth`] (`POST /v1/oauth/connect` and `GET /oauth/callback`, C1), [`oauth_vault`] (OAuth token sets sealed per generation), [`short_lived`] (the MCP short-lived credentials `/v1/relay` accepts), [`aws`] (`POST /v1/aws/credentials`: short-lived STS credentials, D2), [`audit`] (relay events in the org's audit ledger), [`app`] (the router).

pub mod app;
pub mod audit;
pub mod auth;
pub mod aws;
pub mod aws_policy;
pub mod bindings_publish;
pub mod config;
pub mod decrypt;
pub mod egress;
pub mod git;
pub mod grants;
pub mod http_client;
pub mod mcp_clients;
pub mod mcp_endpoint;
pub mod mcp_settings;
mod mcp_tools;
pub mod oauth;
pub mod oauth_vault;
pub mod pg;
pub mod relay;
pub mod short_lived;
pub mod ttl;
