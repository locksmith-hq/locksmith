set positional-arguments

ci: fmt lint test-rust test-web tree-check task-guard

fmt:
    cargo fmt --all --check

lint:
    cargo clippy --workspace --all-targets -- -D warnings
    npm run lint

# a0-spikes' rls tests need `just up` (like ls-e2e); its header and lint tests run here.
test-rust:
    cargo nextest run --workspace --exclude ls-e2e -E 'not (package(a0-spikes) & binary(rls))'
    cargo test --workspace --exclude ls-e2e --doc

test-web:
    npm run build && npm test

# Tauri app: not in the root workspace, so fmt/lint/test-rust skip it.
desktop-test:
    cargo fmt --manifest-path apps/desktop/src-tauri/Cargo.toml --check
    cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
    cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml

# Build every app for the host OS (web console + desktop binary); each change's Local verification runs it.
apps-build: desktop-test
    npm run build
    cd apps/desktop && npm exec -- tauri build --debug --no-bundle

# Regenerate packages/api-types from crates/ls-ipc (ts-rs).
api-types:
    cargo test -p ls-ipc --features ts export_bindings

tree-check:
    scripts/tree-check.sh

# Agents on change branches may only tick OpenSpec tasks, not rewrite them.
task-guard:
    scripts/check-task-edits.test.sh
    scripts/change-status.test.sh
    scripts/owner-replies.test.sh
    scripts/check-task-edits.sh
    scripts/check-agent-docs.sh

dev app:
    npm run build -w apps/{{app}}

# Build and install Locksmith.app (smith, locksmithd, locksmith-mcp, desktop) locally on macOS.
desktop-install:
    bash scripts/dev-install-desktop.sh

# Local dev harness (infra/compose): Postgres, Grafana LGTM, OpenBao, WireMock.
# Dev values come from infra/compose/.env.example. Export OPENBAO_IMAGE etc. in the shell to override.
compose := "docker compose -f infra/compose/compose.yaml --env-file infra/compose/.env.example"

up:
    {{compose}} up -d --wait

down:
    {{compose}} down

reset:
    {{compose}} down -v

logs svc:
    {{compose}} logs --tail=200 {{svc}}

psql *args:
    {{compose}} exec postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$@"' -- "$@"

ps:
    {{compose}} ps

# Verify the running stack (needs `just up`).
harness-check:
    bash scripts/harness-check.sh

# Start each MCP server in .mcp.json and make one read call (needs `just up`).
mcp-check:
    bash scripts/mcp-check.sh

# Canaries (fake secrets for leak tests) live in gitignored infra/compose/.canaries (mode 0600).
# `just canary new` mints one and prints its id; `just canary list` prints ids, never values.
# LOCKSMITH_CANARIES overrides the file.
canary action:
    #!/usr/bin/env bash
    set -euo pipefail
    case "$1" in new|list) ;; *) echo "usage: just canary new|list" >&2; exit 2 ;; esac
    exec python3 -I tests/kit/oracle.py "canary-$1" --file "${LOCKSMITH_CANARIES:-infra/compose/.canaries}"

# Scan Postgres, Loki and Tempo (needs `just up`), plus any --dir/--transcript, for every active
# canary. Prints `LEAK <encoding> <source>:<where>` (never a value) and exits non-zero on a hit or
# SOURCE-UNREACHABLE. Usage: just leak-scan [--explain] [--dir P] [--transcript P]
leak-scan *args:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    eval "$(grep -E '^POSTGRES_(USER|PASSWORD|DB)=' "$root/infra/compose/.env.example")"
    export PGHOST=127.0.0.1 PGPORT=5432 PGUSER="$POSTGRES_USER" PGPASSWORD="$POSTGRES_PASSWORD" PGDATABASE="$POSTGRES_DB"
    canaries="${LOCKSMITH_CANARIES:-$root/infra/compose/.canaries}"
    cd {{quote(invocation_directory())}}
    exec python3 -I "$root/tests/kit/oracle.py" scan --canary-file "$canaries" --stack "$@"

# Run locksmith-api against `just up`: dev auth on, loopback bind, OTLP to the LGTM container.
api:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    set -a; . "$root/infra/compose/.env.example"; set +a
    export LOCKSMITH_DEV_AUTH=1 LOCKSMITH_BIND=127.0.0.1:8080 OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
    cd "$root" && exec cargo run -q -p ls-control-plane --bin locksmith-api

# Run locksmith-gateway against `just up` and `just api`. Needs LOCKSMITH_GATEWAY_BINDINGS (a TOML
# file naming the org and bindings; see tests/e2e/tests/relay.rs for the shape). The gateway connects
# as locksmith_app until the locksmith_gateway role lands (S3 progress notes).
gateway:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    set -a; . "$root/infra/compose/.env.example"; set +a
    : "${LOCKSMITH_GATEWAY_BINDINGS:?set LOCKSMITH_GATEWAY_BINDINGS to a bindings TOML file}"
    export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
    cd "$root" && exec cargo run -q -p ls-gateway --bin locksmith-gateway

# S3 relay smoke test (needs `just up` and `just api`): the test starts its own gateway, relays a
# canary secret to the WireMock upstream and checks nothing leaks back. Run `just leak-scan` after.
relay-smoke:
    cargo build -q -p ls-gateway --bin locksmith-gateway
    cargo nextest run -p ls-e2e --test relay

# End-to-end tests against the local stack (needs `just up`).
test-e2e:
    cargo nextest run -p ls-e2e
