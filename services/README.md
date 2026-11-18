# services/

Backend services built with Rust and axum. Each service is a Cargo crate in this directory.

Language rule: Rust only. No `package.json` here (enforced by `scripts/tree-check.sh`). Anything that touches secrets lives in Rust.

Test commands for each service: [docs/testing.md](../docs/testing.md).
