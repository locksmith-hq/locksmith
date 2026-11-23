# Proposal: B2 Rust core service

## Why

Owner decision OC-9 G1 (2026-11-22): when the control-plane API moves to NestJS (`b1-nestjs-api`), the operations that touch keys or audit integrity stay in Rust behind a small internal API, the "core": audit append and checkpoint signing, agent and workload token mint and verify, and DEK wrap and unwrap through KMS. The NestJS process then holds ids, ciphertext and verdicts, never plaintext values or key bytes.

This work was task group 5 (5.2, 5.3) of `b1-nestjs-api`, a 44-task change on the critical path of every Phase 2 feature held by one worker. It needs nothing from the NestJS side, so it is split out (PM 2026-11-23, #653) for a second worker to build in parallel.

## What Changes

- A Contract group first: `services/core/openapi.json` (internal only) for exactly the OC-9 G1 operations, a generated TypeScript client `packages/core-client`, and fixtures, so B1 task 5.4 can build against it before the service lands.
- A new Rust service `services/core` (package `ls-core-service`; the name `ls-core` is already the shared-types library in `crates/ls-core`) built from the existing code in `services/control-plane` (`audit.rs`, `checkpoint.rs`, `agent_token.rs`, `workload.rs`, `kms.rs`) and crates (`ls-audit`, `ls-envelope`), with no behaviour change.
- Caller authentication between the API and the core, contract tests, a compose service on the internal network and `just core-check`.

**Usable outcome:** `just up` starts the core; the NestJS API (and any test) can append an audit event, mint and verify an agent or workload token, and wrap and unwrap a DEK over an internal API, without the caller ever holding key bytes.

Out of scope: the NestJS side that calls the core (B1 task 5.4); removing the in-process code from the Rust control plane (it keeps calling it until B1 cuts its paths over); new crypto, new token formats or any change to the public `openapi.json`; the gateway.

Depends on: none. B1 task 5.4 needs this change's Contract group.

## Capabilities

### New Capabilities
- `core-service`: the internal Rust API that owns audit integrity, token mint and verify, and key wrap for the NestJS API.

### Modified Capabilities

## Impact

- Code: new `services/core`, `packages/core-client`; `infra/compose`; `justfile` (`core-check`, `test ls-core-service`); `scripts/tree-check.sh` and `docs/testing.md` entries.
- Shared code may move from `services/control-plane` into a library crate so both services use it; the control plane's behaviour and tests do not change.
