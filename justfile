ci: fmt lint test-rust test-web tree-check

fmt:
    cargo fmt --all --check

lint:
    cargo clippy --workspace --all-targets -- -D warnings
    npm run lint

test-rust:
    cargo test --workspace

test-web:
    npm run build && npm test

# Tauri app: not in the root workspace, so fmt/lint/test-rust skip it.
desktop-test:
    cargo fmt --manifest-path apps/desktop/src-tauri/Cargo.toml --check
    cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
    cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml

# Regenerate packages/api-types from crates/ls-ipc (ts-rs).
api-types:
    cargo test -p ls-ipc --features ts export_bindings

tree-check:
    scripts/tree-check.sh

dev app:
    npm run build -w apps/{{app}}

# Build and install Locksmith.app (smith, locksmithd, desktop) locally on macOS.
desktop-install:
    bash scripts/dev-install-desktop.sh
