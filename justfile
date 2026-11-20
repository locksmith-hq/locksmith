set positional-arguments

ci: fmt lint test-rust test-web tree-check task-guard public-check

fmt:
    cargo fmt --all --check

lint:
    cargo clippy --workspace --all-targets -- -D warnings
    npm run lint

# a0-spikes' rls tests need `just up` (like ls-e2e); its header and lint tests run here.
test-rust:
    cargo nextest run --workspace --exclude ls-e2e -E 'not (package(a0-spikes) & binary(rls))'
    cargo test --workspace --exclude ls-e2e --doc

# Rust tests without Docker or the `just up` stack (macOS ci-platforms); filter in .config/nextest.toml.
test-rust-portable:
    cargo nextest run --workspace --profile portable
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

# Plants a build error in each app and checks apps-build's npm build step fails on it.
apps-build-test:
    scripts/apps-build.test.sh

# Regenerate packages/api-types from crates/ls-ipc (ts-rs).
api-types:
    cargo test -p ls-ipc --features ts export_bindings

tree-check:
    scripts/tree-check.sh

# Agents on change branches may only tick OpenSpec tasks, not rewrite them.
task-guard:
    scripts/check-task-edits.test.sh
    scripts/change-status.test.sh
    scripts/agent-identity.sh selftest
    scripts/route.sh selftest
    scripts/check-task-edits.sh
    scripts/check-agent-docs.sh

# Public-readiness hygiene: licences, root docs, links, denylist, secret canary.
public-check:
    scripts/public-check.test.sh
    scripts/public-check.sh

dev app:
    npm run build -w apps/{{app}}

# Build and install Locksmith.app (smith, locksmithd, locksmith-mcp, desktop) locally on macOS.
desktop-install:
    bash scripts/dev-install-desktop.sh

# D1 smoke: clone and push through the gateway's /git route to a real `git http-backend` fixture,
# plus the smith-cli `git setup` checks. Self-contained (no `just up` needed).
git-smoke:
    cargo nextest run -p ls-gateway git_clone_and_push_through_gateway git_fetch_only_grant_cannot_push
    cargo nextest run -p smith-cli git

# Local dev harness (infra/compose): Postgres, Grafana LGTM, OpenBao, WireMock.
# Dev values come from infra/compose/.env.example. Export OPENBAO_IMAGE etc. in the shell to override.
compose := "docker compose -f infra/compose/compose.yaml --env-file infra/compose/.env.example"

# `up` also writes the audit checkpoint public key to the verifier config (S5 task 4.1).
# Includes the Keycloak issuer and mail catcher (compose profile `auth`, T1); `up-lite` skips them.
up:
    {{compose}} --profile auth up -d --wait
    bash scripts/audit-verifier-config.sh

up-lite:
    {{compose}} up -d --wait
    bash scripts/audit-verifier-config.sh

down:
    {{compose}} --profile auth down

reset:
    {{compose}} --profile auth down -v

logs svc:
    {{compose}} --profile auth logs --tail=200 {{svc}}

psql *args:
    {{compose}} exec postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$@"' -- "$@"

ps:
    {{compose}} --profile auth ps

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

# S5 audit ledger CLI against `just up`, as the `audit_verifier` role. The export directory is
# LOCKSMITH_AUDIT_EXPORT_DIR (default infra/compose/.audit-export, gitignored); extra args (e.g.
# --json) go to locksmith-audit.
audit-export *args:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    eval "$(grep -E '^(POSTGRES_DB|LOCKSMITH_AUDIT_VERIFIER_PASSWORD)=' "$root/infra/compose/.env.example")"
    export LOCKSMITH_AUDIT_DATABASE_URL="postgres://audit_verifier:${LOCKSMITH_AUDIT_VERIFIER_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}"
    dir="${LOCKSMITH_AUDIT_EXPORT_DIR:-$root/infra/compose/.audit-export}"
    cd "$root" && exec cargo run -q -p locksmith-audit -- export --dir "$dir" "$@"

# Verify every org's chain and checkpoints in the database. When an export exists, also trust its
# signed checkpoints (`--checkpoints-from`, so a rewrite or truncation shows even after the
# `audit_checkpoints` rows are deleted) and verify the export itself offline (`--dir`).
audit-verify *args:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    eval "$(grep -E '^(POSTGRES_DB|LOCKSMITH_AUDIT_VERIFIER_PASSWORD)=' "$root/infra/compose/.env.example")"
    export LOCKSMITH_AUDIT_DATABASE_URL="postgres://audit_verifier:${LOCKSMITH_AUDIT_VERIFIER_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}"
    dir="${LOCKSMITH_AUDIT_EXPORT_DIR:-$root/infra/compose/.audit-export}"
    cd "$root"
    bin="cargo run -q -p locksmith-audit --"
    if [ ! -d "$dir" ]; then
      echo "audit-verify: no export at $dir, so the database is checked against its own checkpoint rows only (run just audit-export)" >&2
      exec $bin verify --db "$@"
    fi
    rc=0
    $bin verify --db --checkpoints-from "$dir" "$@" || rc=$?
    $bin verify --dir "$dir" "$@" || { c=$?; [ "$rc" -ge "$c" ] || rc=$c; }
    exit "$rc"

# The audit tamper test (needs `just up`): in a scratch database on the compose Postgres, tamper as
# locksmith_owner (edit a field, delete a row, swap seqs, truncate past a checkpoint, edit exported
# lines, rewrite history and delete the checkpoint rows) and check each fails verify while the
# untouched ledger passes. `just ci` runs the same test against a throwaway container.
audit-tamper-test:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    eval "$(grep -E '^POSTGRES_(USER|PASSWORD)=' "$root/infra/compose/.env.example")"
    export LOCKSMITH_AUDIT_TEST_ADMIN_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:5432/postgres"
    cd "$root" && exec cargo nextest run -p locksmith-audit --test tamper

# S5 audit smoke (needs `just up` and `just api`): an agent relays a canary through `smith`, oha
# drives 200 relays/s when installed (prints relay and append p99), a signed checkpoint covers the
# head, then export, `audit-verify` (--db and --dir) and `leak-scan` over the stack and the export.
audit-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    cd "$root"
    cargo build -q -p ls-gateway --bin locksmith-gateway
    cargo build -q -p smith-cli --bin smith
    cargo build -q -p locksmith-audit
    AUDIT_SMOKE_LOAD="${AUDIT_SMOKE_LOAD:-1}" cargo nextest run -p ls-e2e --test audit --no-capture
    dir="${LOCKSMITH_AUDIT_EXPORT_DIR:-$root/infra/compose/.audit-export}"
    just audit-export
    just audit-verify
    just leak-scan --explain --require-coverage --dir "$dir"

# Run locksmith-api against `just up`: dev auth on, loopback bind, OTLP to the LGTM container.
api:
    #!/usr/bin/env bash
    set -euo pipefail
    root={{quote(justfile_directory())}}
    set -a; . "$root/infra/compose/.env.example"; set +a
    export LOCKSMITH_DEV_AUTH=1 LOCKSMITH_ALLOW_DEV_AUTH=1 LOCKSMITH_BIND=127.0.0.1:8080 OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
    cd "$root" && exec cargo run -q -p ls-control-plane --bin locksmith-api

# T1 sign-up, verify, sign-in (auth code + PKCE), reset and API calls against Keycloak (needs `just up` and `just api`).
auth-e2e:
    python3 -I scripts/auth-e2e.py

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

# S4 connector smoke test (needs `just up` and `just api`): registers an agent, grants a canary
# secret and relays to the WireMock upstream through `smith` and the MCP tools; asserts the upstream
# saw the secret and the agent did not. Run `just leak-scan` after.
connector-smoke:
    cargo build -q -p ls-gateway --bin locksmith-gateway
    cargo build -q -p smith-cli --bin smith
    cargo build -q -p locksmith-mcp
    cargo nextest run -p ls-e2e --test connector

# S6 stack adversarial gate (needs `just up` and `just api`; fails fast without them): every
# gateway case with skips as failures, then `leak-scan` over the stack, the audit export and the
# kept artifacts. `--agent claude` adds the live prompts (no claude CLI or key: `skip live`, fails).
adversarial-gate *args:
    @bash tests/adversarial/gate.sh "$@"

# End-to-end tests against the local stack (needs `just up`).
test-e2e:
    cargo nextest run -p ls-e2e

# Run one component's tests by directory name (see docs/testing.md): `just test control-plane`.
test name:
    #!/usr/bin/env bash
    set -euo pipefail
    n="$1"
    dir=""
    for d in crates/"$n" services/"$n" apps/"$n" packages/"$n" integrations/"$n" tests/"$n"; do
      [ -d "$d" ] && dir="$d" && break
    done
    run() { echo "+ $*" >&2; "$@"; }
    if [ -z "$dir" ] || ! grep -q "^| \`$dir\` |" docs/testing.md; then
      echo "just test: unknown component '$n'. Valid names:" >&2
      sed -n 's/^| `[a-z0-9]*\/\([a-z0-9_.-]*\)` |.*/  \1/p' docs/testing.md >&2
      exit 1
    fi
    case "$dir" in
      apps/desktop) run just desktop-test; run npm test --workspace apps/desktop ;;
      apps/web) run npm test --workspace apps/web ;;
      tests/e2e) run just test-e2e ;;
      tests/adversarial) run bash tests/adversarial/run.sh selftest ;;
      tests/kit) run bash tests/kit/leak_scan_test.sh ;;
      *)
        pkg=$(cargo metadata --no-deps --format-version 1 | jq -r --arg m "$PWD/$dir/Cargo.toml" '.packages[]|select(.manifest_path==$m)|.name')
        if [ -n "$pkg" ]; then run cargo nextest run -p "$pkg" --no-tests pass
        elif [ -f "$dir/package.json" ] && jq -e '.scripts.test' "$dir/package.json" >/dev/null; then run npm test --workspace "$dir"
        else
          cov=$(awk -F'|' -v d="\`$dir\`" '$2 ~ d {print $6}' docs/testing.md)
          echo "just test: $n has no tests of its own; covered by:$cov" >&2
          tgt=$(grep -o '`[a-z]*/[a-z0-9_-]*`' <<<"$cov" | head -1 | tr -d '`' || true)
          if [ -n "$tgt" ]; then run just test "${tgt#*/}"
          elif grep -q 'just test-web' <<<"$cov"; then run just test-web; fi
        fi ;;
    esac
