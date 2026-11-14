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

tree-check:
    scripts/tree-check.sh

dev app:
    npm run build -w apps/{{app}}
